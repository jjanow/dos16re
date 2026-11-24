"""Read embedded Microsoft LINK and Borland VROOMM overlay members."""

from collections import defaultdict
from struct import Struct

from .mz import Address, MZError, MZExecutable, read_mz_header, read_mz_relocations
from .overlays import Descriptor, LinkedFixup, LinkedOverlay

_WORD = Struct("<H")
_PAIR = Struct("<2H")
_FB_HEADER = Struct("<4sIII")
_FB_SEGMENT = Struct("<4H")
_FB_DESCRIPTOR = Struct("<BBHI3H")
_FB_STUB = Struct("<BBHB")
_LINK_MAX_SEGMENTS = 256

type _LinkMembers = dict[int, tuple[int, bytes, tuple[Address, ...]]]
type _LinkDirectory = tuple[int, dict[int, tuple[int, ...]]]


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _link_offsets(data: bytes, cursor: int) -> list[int]:
    padded = _align(cursor, 512)
    return [offset for offset in sorted({cursor, padded}) if data.startswith(b"MZ", offset)
            and not any(data[cursor:offset])]


def embedded_overlays(data: bytes, executable: MZExecutable, source: str,
                      base: int) -> tuple[list[LinkedOverlay], list[dict]]:
    start = executable.header.file_size
    link = _link_offsets(data, start)
    borland = [offset for offset in sorted({start, _align(start, 16), _align(start, 512)})
               if data[offset:offset + 2] == b"FB" and len(data) >= offset + 4
               and (data.startswith(b"FBOV", offset) or data[offset + 2:offset + 4].isalpha())]
    if len(link) + len(borland) > 1:
        raise MZError("ambiguous appended DOS overlay header positions")
    overlays, diagnostics, end = [], [], start
    if link:
        overlays, diagnostics, end = _read_link(data, link[0], executable, source, base)
    elif borland:
        overlays, diagnostics, end = _read_vroomm(data, borland[0], executable, source)
    if any(data[end:]):
        diagnostics.append({"code": "unmapped_trailer", "message":
                            f"{len(data) - end} bytes after the decoded DOS module(s) remain unmapped",
                            "file_offset": end, "size": len(data) - end})
    return overlays, diagnostics


def _link_directory_at(image: bytes, selectors: range, members: _LinkMembers) -> _LinkDirectory | None:
    numbers = image[selectors.stop:selectors.stop + len(selectors)]
    if len(numbers) != len(selectors) or numbers[0] != 0 or set(numbers) != {0, *members}:
        return None
    segments = defaultdict(set)
    for number, position in zip(numbers, selectors, strict=True):
        if number:
            segments[number].add(_WORD.unpack_from(image, position)[0])
    # LINK reserves one OVERLAY_AREA for all members. A member's first code segment can follow
    # the start of that window if its segment alignment requires padding.
    runtime = min(min(values) for values in segments.values())
    for number, values in segments.items():
        size = len(members[number][1])
        if runtime * 16 + size > len(image) or (max(values) - runtime) * 16 >= size:
            return None
    return runtime, {number: tuple(sorted(values)) for number, values in segments.items()}


def _link_directory(executable: MZExecutable, members: _LinkMembers) -> tuple[_LinkDirectory | None, str | None]:
    """Find the resident selector words and matching overlay-number bytes."""
    image = executable.image
    positions = {site.linear for site in executable.relocations}
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
            directory = _link_directory_at(image, selectors, members)
            if directory is not None:
                candidates.append(directory)

    if not candidates:
        # Some layouts expose the adjacent arrays without the LINK 3.65 count words. Require
        # a complete run of relocated selector words and independent support from member fixups.
        # See https://github.com/fenugrec/overlazy for the paired arrays in Microsoft C 5.1 output.
        for start in sorted(position for position in positions if position - _WORD.size not in positions):
            end = start
            while end in positions and end - start <= _WORD.size * _LINK_MAX_SEGMENTS:
                end += _WORD.size
            selectors = range(start, end, _WORD.size)
            if not len(members) < len(selectors) <= _LINK_MAX_SEGMENTS:
                continue
            directory = _link_directory_at(image, selectors, members)
            if directory is None:
                continue
            runtime, _ = directory
            if any(relocations for _, _, relocations in members.values()) and all(
                0 <= address.linear - runtime * 16 <= len(code) - _WORD.size
                for _, code, relocations in members.values() for address in relocations
            ):
                candidates.append(directory)
    if len(candidates) != 1:
        reason = "could not locate" if not candidates else "found multiple candidates for"
        return None, f"{reason} the Microsoft LINK segment directory; overlay relocations and runtime addresses are unavailable"
    return candidates[0], None


def _read_link(data: bytes, start: int, executable: MZExecutable, source: str,
               base: int) -> tuple[list[LinkedOverlay], list[dict], int]:
    members: _LinkMembers = {}
    while True:
        content = memoryview(data)[start:]
        try:
            header = read_mz_header(content)
            relocations = read_mz_relocations(content, header)
        except MZError as error:
            raise MZError(f"Microsoft LINK member at file offset {start:#x}: {error}") from error
        number = header.overlay_number
        if number == 0 or number in members or header.header_size == header.file_size:
            raise MZError(f"invalid or duplicate Microsoft LINK overlay {number} at file offset {start:#x}")
        file_offset, end = start + header.header_size, start + header.file_size
        members[number] = (file_offset, data[file_offset:end], relocations)
        locations = _link_offsets(data, end)
        if not locations:
            break
        start = locations[0]

    directory, reason = _link_directory(executable, members)
    runtime, segments_by_member = directory if directory is not None else (None, {})
    overlays = []
    for number, (file_offset, image, relocations) in members.items():
        name = f"link_{number:04x}"
        segments = segments_by_member.get(number, ())
        fixups = []
        entries = ()
        if runtime is not None:
            entries = tuple((segment - runtime) * 16 for segment in segments)
            for address in relocations:
                offset = address.linear - runtime * 16
                if not 0 <= offset <= len(image) - 2:
                    raise MZError(f"Microsoft LINK overlay {number} relocation {address} lies outside its own image")
                value, = _WORD.unpack_from(image, offset)
                fixups.append(LinkedFixup(offset, value - runtime, name) if value in segments else
                              LinkedFixup(offset, value))
        runtime_segment = None if runtime is None else base + runtime
        overlays.append(LinkedOverlay(source, name, image, file_offset, "MS_LINK", number,
                                      runtime_segment, entries, fixups=tuple(fixups)))
    diagnostics = [{"code": "overlay_layout_partial", "message": reason}] if reason else []
    return overlays, diagnostics, end


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
        if offset + 32 > len(root):
            raise MZError(f"Borland VROOMM descriptor for segment {segment:04x} is truncated")
        opcode, interrupt, _, relative, code_size, fixup_size, count = _FB_DESCRIPTOR.unpack_from(root, offset)
        file_offset = payload + relative
        stub_end = offset + 32 + count * _FB_STUB.size
        if (opcode != 0xCD or not code_size or fixup_size % 2 or stub_end > len(root)
                or stub_end - offset > 0x10000 or file_offset + code_size + fixup_size > end):
            raise MZError(f"invalid Borland VROOMM descriptor for segment {segment:04x}")
        entries = []
        for stub_opcode, vector, target, _ in _FB_STUB.iter_unpack(root[offset + 32:stub_end]):
            if (stub_opcode, vector) != (opcode, interrupt) or target >= code_size:
                raise MZError(f"invalid Borland VROOMM stub for segment {segment:04x}")
            entries.append(target)
        descriptor = Descriptor(segment, file_offset, code_size, fixup_size, tuple(entries))
        descriptors[number] = descriptor
        ranges.append((file_offset, descriptor.end))
        resident_ranges.append((offset, stub_end))
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
            if flags & ~1:
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
    return LinkedFixup(offset_site, 32 + _FB_STUB.size * matches[0], segment=False)
