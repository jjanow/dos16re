"""Read embedded Microsoft LINK, Microsoft MOVE, and Borland VROOMM overlay members."""

from collections import defaultdict
from dataclasses import dataclass
from struct import Struct

from .mz import Address, LoadedMZ, MZError, MZExecutable, read_mz_header, read_mz_relocations
from .overlays import Descriptor, LinkedFixup, LinkedOverlay

_WORD = Struct("<H")
_PAIR = Struct("<2H")
_DWORD = Struct("<I")
_FB_HEADER = Struct("<4sIII")
_FB_SEGMENT = Struct("<4H")
_FB_DESCRIPTOR = Struct("<BBHI3H")
_FB_DESCRIPTOR_SIZE = 0x20
_FB_STUB = Struct("<BBHB")
_LINK_MAX_SEGMENTS = 256
_MOVE_STUB_SIZE = 6

type _LinkDirectory = tuple[int, dict[int, tuple[int, ...]]]
type _MoveSegments = tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class _LinkMember:
    source: str
    header_offset: int
    file_offset: int
    image: bytes
    relocations: tuple[Address, ...]
    min_alloc_paragraphs: int

    @property
    def allocation_paragraphs(self) -> int:
        return _align(len(self.image), 16) // 16 + self.min_alloc_paragraphs


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _link_offsets(data: bytes, cursor: int) -> list[int]:
    padded = _align(cursor, 512)
    return [offset for offset in sorted({cursor, padded}) if data.startswith(b"MZ", offset)
            and not any(data[cursor:offset])]


def embedded_overlays(data: bytes, executable: MZExecutable, loaded: LoadedMZ, source: str,
                      link_files: tuple[tuple[str, bytes], ...] = ()) -> tuple[list[LinkedOverlay], list[dict]]:
    start = executable.header.file_size
    link = _link_offsets(data, start)
    borland = [offset for offset in sorted({start, _align(start, 16), _align(start, 512)})
               if data[offset:offset + 2] == b"FB" and len(data) >= offset + 4
               and (data.startswith(b"FBOV", offset) or data[offset + 2:offset + 4].isalpha())]
    if len(link) + len(borland) > 1:
        raise MZError("ambiguous appended DOS overlay header positions")
    overlays, diagnostics, end = [], [], start
    if link or link_files:
        if borland:
            raise MZError("Microsoft LINK overlay files cannot be combined with embedded Borland overlays")
        members: dict[int, _LinkMember] = {}
        if link:
            end = _read_link_members(data, link[0], source, members)
        if link and (move := _move_directory(loaded, members)):
            if link_files:
                raise MZError("Microsoft MOVE overlays use embedded members")
            overlays = _move_overlays(loaded, members, *move)
        else:
            for name, contents in link_files:
                member_end = _read_link_members(contents, 0, name, members)
                if any(contents[member_end:]):
                    diagnostics.append(_trailer(contents, member_end, name))
            overlays, link_diagnostics = _load_static_link(loaded, members)
            diagnostics.extend(link_diagnostics)
    elif borland:
        overlays, diagnostics, end = _read_vroomm(data, borland[0], executable, source)
    if any(data[end:]):
        diagnostics.append(_trailer(data, end, source))
    return overlays, diagnostics


def _trailer(data: bytes, end: int, source: str) -> dict:
    size = len(data) - end
    return {"code": "unmapped_trailer", "source": source, "file_offset": end, "size": size,
            "message": f"{size} bytes after the decoded DOS module(s) in {source} remain unmapped"}


def _link_directory_at(loaded: LoadedMZ, selectors: range,
                       members: dict[int, _LinkMember]) -> _LinkDirectory | None:
    image = loaded.image
    numbers = image[selectors.stop:selectors.stop + len(selectors)]
    if len(numbers) != len(selectors) or numbers[0] != 0 or set(numbers) != {0, *members}:
        return None
    segments = defaultdict(set)
    for number, position in zip(numbers, selectors, strict=True):
        if number:
            segment, = _WORD.unpack_from(image, position)
            segments[number].add((segment - loaded.base_segment) & 0xFFFF)
    # LINK reserves one OVERLAY_AREA for all members. A member's first code segment can follow
    # the start of that window if its segment alignment requires padding.
    runtime = min(min(values) for values in segments.values())
    initialized = {}
    for number, values in segments.items():
        member = members[number]
        size = len(member.image)
        end = runtime * 16 + size
        backed = tuple(sorted(value for value in values if value * 16 < end))
        if end > len(image) or not backed:
            return None
        if len(backed) != len(values):
            # When LINK omits a trailing empty or uninitialized segment from the file,
            # its member header measures minimum allocation from the load module origin.
            # A zero-length segment can start at the allocation end.
            allocation_end = (size // 16 + member.min_alloc_paragraphs) * 16
            if max(values) * 16 > min(allocation_end, len(image)):
                return None
        initialized[number] = backed
    return runtime, initialized


def _link_directory(
    loaded: LoadedMZ, members: dict[int, _LinkMember],
) -> tuple[_LinkDirectory | None, str | None]:
    """Find the resident selector words and matching overlay-number bytes."""
    # EXEPACK can compress the resident overlay directory and its relocation table.
    image = loaded.image
    positions = {site.linear for site in loaded.relocations}
    candidates = []
    overlay_count = max(members) + 1
    for start in sorted(positions):
        if start < _PAIR.size:
            continue
        count, count_overlays = _PAIR.unpack_from(image, start - _PAIR.size)
        if not len(members) < count <= _LINK_MAX_SEGMENTS or count_overlays != overlay_count:
            continue
        selectors = range(start, start + _WORD.size * count, _WORD.size)
        if all(position in positions for position in selectors):
            directory = _link_directory_at(loaded, selectors, members)
            if directory is not None:
                candidates.append(directory)

    if not candidates:
        # If the count words are unavailable, require adjacent arrays with a complete run of
        # relocated selector words and independent support from member fixups.
        # See https://github.com/fenugrec/overlazy for the paired arrays in Microsoft C 5.1 output.
        for start in sorted(position for position in positions if position - _WORD.size not in positions):
            end = start
            while end in positions and end - start <= _WORD.size * _LINK_MAX_SEGMENTS:
                end += _WORD.size
            selectors = range(start, end, _WORD.size)
            if not len(members) < len(selectors) <= _LINK_MAX_SEGMENTS:
                continue
            directory = _link_directory_at(loaded, selectors, members)
            if directory is None:
                continue
            runtime, _ = directory
            if any(member.relocations for member in members.values()) and all(
                0 <= address.linear - runtime * 16 <= len(member.image) - _WORD.size
                for member in members.values() for address in member.relocations
            ):
                candidates.append(directory)
    if len(candidates) != 1:
        reason = "could not locate" if not candidates else "found multiple candidates for"
        return None, f"{reason} the Microsoft LINK segment directory; overlay relocations and runtime addresses are unavailable"
    return candidates[0], None


def _read_link_members(data: bytes, start: int, source: str, members: dict[int, _LinkMember]) -> int:
    while True:
        content = memoryview(data)[start:]
        try:
            header = read_mz_header(content)
            relocations = read_mz_relocations(content, header)
        except MZError as error:
            raise MZError(f"Microsoft LINK member in {source} at file offset {start:#x}: {error}") from error
        number = header.overlay_number
        if number == 0 or number in members or header.header_size == header.file_size:
            raise MZError(f"invalid or duplicate Microsoft LINK overlay {number} in {source} at file offset {start:#x}")
        file_offset, end = start + header.header_size, start + header.file_size
        members[number] = _LinkMember(source, start, file_offset, data[file_offset:end], relocations,
                                      header.min_alloc_paragraphs)
        locations = _link_offsets(data, end)
        if not locations:
            return end
        start = locations[0]


def _load_static_link(loaded: LoadedMZ, members: dict[int, _LinkMember]) -> tuple[list[LinkedOverlay], list[dict]]:
    directory, reason = _link_directory(loaded, members)
    runtime, backed_by_member = directory if directory is not None else (None, {})
    overlays = []
    for number, member in members.items():
        name = f"link_{number:04x}"
        backed = backed_by_member.get(number, ())
        fixups = []
        entries = ()
        if runtime is not None:
            entries = tuple((segment - runtime) * 16 for segment in backed)
            for address in member.relocations:
                offset = address.linear - runtime * 16
                if not 0 <= offset <= len(member.image) - 2:
                    raise MZError(f"Microsoft LINK overlay {number} relocation {address} lies outside its own image")
                value, = _WORD.unpack_from(member.image, offset)
                fixups.append(LinkedFixup(offset, value - runtime, name) if value in backed else
                              LinkedFixup(offset, value))
        runtime_segment = None if runtime is None else loaded.base_segment + runtime
        overlays.append(LinkedOverlay(member.source, name, member.image, member.file_offset, "MS_LINK", number,
                                      runtime_segment, entries, fixups=tuple(fixups)))
    diagnostics = [{"code": "overlay_layout_partial", "message": reason}] if reason else []
    return overlays, diagnostics


def _move_directory(loaded: LoadedMZ, members: dict[int, _LinkMember]) -> tuple[_MoveSegments, int] | None:
    """Find MOVE's counted segment arrays, file offsets, sizes, and interrupt vector."""
    numbers = [0, *range(1, len(members) + 1)]
    if members.keys() != set(numbers[1:]):
        return None
    image = loaded.image
    offsets = _DWORD.pack(0) + b"".join(_DWORD.pack(members[number].header_offset) for number in numbers[1:])
    sizes = b"".join(_DWORD.pack(members[number].allocation_paragraphs) for number in numbers[1:])
    candidates = []
    file_table = image.find(offsets)
    while file_table != -1:
        size_table = file_table + len(offsets)
        vector = size_table + _DWORD.size + len(sizes)
        if vector < len(image) and image.startswith(sizes, size_table + _DWORD.size):
            # $$CGSN and $$COVL precede $$MPGSNBASE and $$MPGSNOVL, both arrays of words.
            for start in range(file_table - _PAIR.size - 4, max(-1, file_table - 4 * 0x10000), -4):
                segment_count, overlay_count = _PAIR.unpack_from(image, start)
                if (overlay_count != len(numbers)
                        or start + _PAIR.size + segment_count * 4 != file_table):
                    continue
                segment_table = start + _PAIR.size
                number_table = segment_table + segment_count * _WORD.size
                member_numbers = [number for number, in _WORD.iter_unpack(image[number_table:file_table])]
                if set(member_numbers) == set(numbers):
                    adjustments = (offset for offset, in _WORD.iter_unpack(image[segment_table:number_table]))
                    candidates.append((tuple(zip(member_numbers, adjustments, strict=True)), image[vector]))
        file_table = image.find(offsets, file_table + 1)
    return candidates[0] if len(candidates) == 1 else None


def _move_overlays(loaded: LoadedMZ, members: dict[int, _LinkMember],
                   directory: _MoveSegments, vector: int) -> list[LinkedOverlay]:
    root = loaded.image
    fixups = {}
    stubs = {}
    root_sites = {site.linear for site in loaded.relocations}
    references = [(root, root_sites, loaded.base_segment)]
    # MZ member fixups are relative to their payload and always add the resident load segment.
    for number, member in members.items():
        sites = [site.linear for site in member.relocations]
        if any(site + _WORD.size > len(member.image) for site in sites):
            raise MZError(f"Microsoft MOVE overlay {number} relocation lies outside its image")
        ordered = sorted(sites)
        if any(right < left + _WORD.size for left, right in zip(ordered, ordered[1:])):
            raise MZError(f"Microsoft MOVE overlay {number} has overlapping relocations")
        fixups[number] = tuple(LinkedFixup(site, _WORD.unpack_from(member.image, site)[0]) for site in sites)
        references.append((member.image, sites, 0))
    trap = bytes((0xCD, vector))
    for image, sites, base in references:
        for site in sites:
            if site < _WORD.size:
                continue
            ip, selector = _PAIR.unpack_from(image, site - _WORD.size)
            segment = (selector - base) & 0xFFFF
            start = segment * 16 + ip
            end = start + _MOVE_STUB_SIZE
            if (end > len(root) or not root.startswith(trap, start)
                    or not root_sites.isdisjoint(range(max(0, start - 1), end))):
                continue
            index, offset = _PAIR.unpack_from(root, start + len(trap))
            if index >= len(directory):
                continue
            number, adjustment = directory[index]
            target = (offset + adjustment) & 0xFFFF
            if number and target < len(members[number].image):
                stubs.setdefault(start, (number, Address((segment + loaded.base_segment) & 0xFFFF, ip), target))

    # Overlapping candidate instructions cannot both be dispatch stubs.
    ordered = sorted(stubs)
    ambiguous = {site for left, right in zip(ordered, ordered[1:])
                 if right < left + _MOVE_STUB_SIZE for site in (left, right)}
    by_member = defaultdict(list)
    for start in ordered:
        if start not in ambiguous:
            number, stub, target = stubs[start]
            by_member[number].append((stub, target))
    return [
        LinkedOverlay(member.source, f"move_{number:04x}", member.image, member.file_offset, "MS_MOVE", number,
                      entries=tuple(sorted({target for _, target in by_member[number]})), fixups=fixups[number],
                      resident_stubs=tuple(by_member[number]), allocation_size=member.allocation_paragraphs * 16)
        for number, member in members.items()
    ]


def _vroomm_directory(data: bytes, start: int, header_size: int, root_size: int) -> tuple[int, int, tuple]:
    while data[start:start + 2] == b"FB":
        if start + _FB_HEADER.size > len(data):
            raise MZError("truncated Borland FB section header")
        tag, size, directory, count = _FB_HEADER.unpack_from(data, start)
        payload = start + _FB_HEADER.size
        end = payload + size
        if end > len(data):
            raise MZError(f"truncated Borland {tag.decode('ascii', 'replace')} section")
        if tag == b"FBOV":
            if not count or not header_size <= directory <= directory + count * _FB_SEGMENT.size <= root_size:
                raise MZError("Borland VROOMM segment directory lies outside the resident module")
            return payload, end, tuple(_FB_SEGMENT.iter_unpack(data[directory:directory + count * _FB_SEGMENT.size]))
        start = end
    return start, start, ()


def _read_vroomm(data: bytes, start: int, executable: MZExecutable,
                 source: str) -> tuple[list[LinkedOverlay], list[dict], int]:
    payload, end, directory = _vroomm_directory(data, start, executable.header.header_size,
                                                executable.header.file_size)
    if not directory:
        return [], [], start
    root = executable.image
    descriptors = {}
    ranges = []
    resident_ranges = []
    for number, (segment, limit, flags, _) in enumerate(directory):
        if not flags & 2 or not limit:
            continue
        offset = segment * 16
        stub_start = offset + _FB_DESCRIPTOR_SIZE
        if stub_start > len(root):
            raise MZError(f"Borland VROOMM descriptor for segment {segment:04x} is truncated")
        opcode, interrupt, _, relative, code_size, fixup_size, count = _FB_DESCRIPTOR.unpack_from(root, offset)
        file_offset = payload + relative
        stub_end = stub_start + count * _FB_STUB.size
        if (opcode != 0xCD or fixup_size % 2 or stub_end > len(root)
                or stub_end - offset > 0x10000 or file_offset + code_size + fixup_size > end):
            raise MZError(f"invalid Borland VROOMM descriptor for segment {segment:04x}")
        resident_ranges.append((offset, stub_end))
        if not code_size:
            # The shipped Borland compilers have header-only descriptors for empty code segments.
            if fixup_size or count or limit != _FB_DESCRIPTOR_SIZE:
                raise MZError(f"invalid Borland VROOMM descriptor for segment {segment:04x}")
            continue
        entries = []
        for stub_opcode, vector, target, _ in _FB_STUB.iter_unpack(root[stub_start:stub_end]):
            if (stub_opcode, vector) != (opcode, interrupt) or target >= code_size:
                raise MZError(f"invalid Borland VROOMM stub for segment {segment:04x}")
            entries.append(target)
        descriptor = Descriptor(segment, file_offset, code_size, fixup_size, tuple(entries))
        descriptors[number] = descriptor
        ranges.append((file_offset, descriptor.end))
    ranges.sort()
    resident_ranges.sort()
    if not descriptors or any(left[1] > right[0] for spans in (ranges, resident_ranges)
                              for left, right in zip(spans, spans[1:])):
        raise MZError("Borland VROOMM has missing or overlapping overlay ranges")

    overlays, diagnostics = [], []
    for number, descriptor in descriptors.items():
        code_end = descriptor.file_offset + descriptor.code_size
        code = data[descriptor.file_offset:code_end]
        fixups = []
        unresolved = 0
        unknown_flags = 0
        offsets = tuple(offset for offset, in _WORD.iter_unpack(data[code_end:descriptor.end]))
        segment_bytes = {byte for offset in offsets for byte in (offset, offset + 1)}
        if len(segment_bytes) != len(offsets) * _WORD.size:
            raise MZError(f"Borland VROOMM segment {descriptor.segment:04x} has overlapping fixups")
        for offset in offsets:
            if offset + 2 > len(code):
                raise MZError(f"Borland VROOMM fixup lies outside segment {descriptor.segment:04x}")
            value, = _WORD.unpack_from(code, offset)
            index, flags = divmod(value, 8)
            if index >= len(directory):
                raise MZError(f"Borland VROOMM fixup names missing segment index {index}")
            fixups.append(LinkedFixup(offset, directory[index][0]))
            # Turbo C++ 1.01 emits bit 2. The original manager masks it off before the table lookup.
            if flags & ~(0x01 | 0x04):
                unknown_flags += 1
            if flags & 1:
                pointer = _function_ref_fixup(code, offset, descriptors.get(index))
                if pointer is None or not segment_bytes.isdisjoint(range(pointer.offset, pointer.offset + _WORD.size)):
                    unresolved += 1
                else:
                    fixups.append(pointer)
        if unresolved:
            diagnostics.append({"code": "overlay_fixups_partial", "message":
                                f"Borland VROOMM segment {descriptor.segment:04x} has "
                                f"{unresolved} unresolved function-pointer offsets"})
        if unknown_flags:
            diagnostics.append({"code": "overlay_fixups_partial", "message":
                                f"Borland VROOMM segment {descriptor.segment:04x} has "
                                f"{unknown_flags} fixups with unrecognized flags"})
        overlays.append(LinkedOverlay(source, f"vroomm_{descriptor.segment:04x}", code, descriptor.file_offset,
                                      "VROOMM", number, entries=descriptor.entries, descriptor=descriptor,
                                      fixups=tuple(fixups)))
    return overlays, diagnostics, end


def _function_ref_fixup(code: bytes, offset: int, descriptor: Descriptor | None) -> LinkedFixup | None:
    # The overlay manager matches two adjacent MOV-immediate/PUSH pairs using the same register.
    # The flag marks the immediate that holds the segment.
    if descriptor is None or not 0 < offset <= len(code) - 7:
        return None
    move = code[offset - 1]
    push = 0x50 + (move - 0xB8)
    if (not 0xB8 <= move <= 0xBF or move == 0xBC or code[offset + 2] != push
            or code[offset + 3] != move or code[offset + 6] != push):
        return None
    offset_site = offset + 4
    target, = _WORD.unpack_from(code, offset_site)
    matches = [index for index, entry in enumerate(descriptor.entries) if entry == target]
    if len(matches) != 1:
        return None
    return LinkedFixup(offset_site, _FB_DESCRIPTOR_SIZE + _FB_STUB.size * matches[0], segment=False)
