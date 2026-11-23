"""Load Classic Macintosh 68k applications and reconstruct the A5 jump table."""

from dataclasses import dataclass
from struct import Struct, pack_into, unpack_from

from .errors import CodedError
from .hfs import HfsDisk, is_hfs_disk
from .image import DEFAULT_M68K_BASE, MAC68K_FORMAT, MAP_VERSION, M68K_ADDRESS_LIMIT

_FORK_HEADER = Struct(">4I")
_APPLE_FORKS = {b"\0\x05\x16\0": "applesingle", b"\0\x05\x16\x07": "appledouble"}
_CODE = b"CODE"
_CODE0_HEADER = Struct(">4I")
_LOADER_ENTRY = Struct(">4H")
_LOADSEG = 0xA9F0
_JMP_ABSL = 0x4EF9


class MacintoshError(CodedError):
    """A malformed or unsupported Classic Macintosh 68k application."""


@dataclass(frozen=True)
class _Resource:
    type: bytes
    id: int
    name: str | None
    offset: int
    size: int
    attributes: int


def _is_macbinary(data: bytes) -> bool:
    return len(data) >= 128 and data[0] == data[74] == data[82] == 0 and 1 <= data[1] <= 63 and (
        data[102:106] == b"mBIN" or data[65:69] == b"APPL"
    )


def is_macintosh(data: bytes) -> bool:
    if bytes(data[:4]) in _APPLE_FORKS or _is_macbinary(data) or is_hfs_disk(data):
        return True
    if len(data) < _FORK_HEADER.size:
        return False
    start, map_at, size, map_size = _FORK_HEADER.unpack_from(data)
    if not 16 <= start <= start + size <= map_at <= map_at + map_size <= len(data) or map_size < 30:
        return False
    types = map_at + unpack_from(">H", data, map_at + 24)[0]
    if not map_at + 28 <= types <= map_at + map_size - 2:
        return False
    count = (unpack_from(">H", data, types)[0] + 1) & 0xFFFF
    return types + 2 + count * 8 <= map_at + map_size and any(
        data[at:at + 4] == _CODE for at in range(types + 2, types + 2 + count * 8, 8)
    )


def _resource_fork(data: bytes) -> tuple[bytes, int, str]:
    wrapper = _APPLE_FORKS.get(bytes(data[:4]))
    if wrapper is not None:
        if len(data) < 26 or unpack_from(">I", data, 4)[0] not in (0x00010000, 0x00020000):
            raise MacintoshError("invalid AppleSingle or AppleDouble header")
        count = unpack_from(">H", data, 24)[0]
        end = 26 + 12 * count
        if end > len(data):
            raise MacintoshError("truncated AppleSingle or AppleDouble entry table")
        forks = [
            (at, size) for entry, at, size in Struct(">3I").iter_unpack(data[26:end]) if entry == 2
        ]
        if len(forks) != 1:
            raise MacintoshError("expected one resource fork entry in AppleSingle or AppleDouble")
        offset, size = forks[0]
        if not end <= offset <= offset + size <= len(data):
            raise MacintoshError("invalid AppleSingle or AppleDouble resource fork extent")
    elif _is_macbinary(data):
        data_size, size = unpack_from(">2I", data, 83)
        version = data[122]
        secondary = unpack_from(">H", data, 120)[0] if version >= 129 or data[102:106] == b"mBIN" else 0
        offset = 128 + ((secondary + 127) & ~127) + ((data_size + 127) & ~127)
        if not size or offset + size > len(data):
            raise MacintoshError("missing or truncated MacBinary resource fork")
        wrapper = "macbinary"
    else:
        return data, 0, "resource_fork"
    return data[offset:offset + size], offset, wrapper


def _parse_resources(fork: bytes) -> dict[tuple[bytes, int], _Resource]:
    if len(fork) < _FORK_HEADER.size:
        raise MacintoshError("truncated Macintosh resource fork header")
    start, map_at, size, map_size = _FORK_HEADER.unpack_from(fork)
    end, map_end = start + size, map_at + map_size
    if not 16 <= start <= end <= map_at <= map_end <= len(fork) or map_size < 30:
        raise MacintoshError("invalid Macintosh resource fork layout")
    types, names = (map_at + offset for offset in unpack_from(">2H", fork, map_at + 24))
    if not map_at + 28 <= types <= types + 2 <= names <= map_end:
        raise MacintoshError("invalid Macintosh resource map lists")
    count = (unpack_from(">H", fork, types)[0] + 1) & 0xFFFF
    types_end = types + 2 + 8 * count
    if types_end > names:
        raise MacintoshError("truncated Macintosh resource type list")
    resources = {}
    for at in range(types + 2, types_end, 8):
        resource_type, raw_count, offset = unpack_from(">4sHH", fork, at)
        refs = types + offset
        if not types_end <= refs <= refs + 12 * (raw_count + 1) <= names:
            raise MacintoshError("invalid Macintosh resource reference list")
        for ref in range(refs, refs + 12 * (raw_count + 1), 12):
            resource_id, name_at, flags_offset = unpack_from(">hHI", fork, ref)
            data_at = start + (flags_offset & 0xFFFFFF)
            if data_at + 4 > end:
                raise MacintoshError("invalid Macintosh resource data offset")
            length = unpack_from(">I", fork, data_at)[0]
            if data_at + 4 + length > end:
                raise MacintoshError("truncated Macintosh resource data")
            name = None
            if name_at != 0xFFFF:
                position = names + name_at
                if position >= map_end or position + 1 + fork[position] > map_end:
                    raise MacintoshError("truncated Macintosh resource name")
                name = fork[position + 1:position + 1 + fork[position]].decode("mac_roman")
            key = resource_type, resource_id
            if key in resources:
                raise MacintoshError(f"duplicate Macintosh {resource_type!r} resource {resource_id}")
            resources[key] = _Resource(resource_type, resource_id, name, data_at + 4, length, flags_offset >> 24)
    return resources


def _source_spans(
    spans: tuple[tuple[int, int, int], ...], offset: int, size: int, unit_offset: int = 0,
) -> list[dict]:
    result = []
    for logical, physical, length in spans:
        start, end = max(logical, offset), min(logical + length, offset + size)
        if start < end:
            result.append({"offset": unit_offset + start - offset, "file_offset": physical + start - logical,
                           "size": end - start})
    return result


def _location(unit: dict, offset: int) -> dict:
    linear = unit["linear"] + offset
    return {"unit_address": f"{unit['name']}:{offset:04x}", "linear": linear}


def _think_data(
    fork: bytes, data: _Resource, zero: _Resource, size: int,
) -> tuple[bytes, list[tuple[int, int, int]]] | None:
    """Expand the THINK C DATA/ZERO stream and record which output spans came from DATA."""
    if data.size % 2 or zero.size % 2 or data.size > size:
        return None
    zeros = [count for (count,) in Struct(">H").iter_unpack(fork[zero.offset:zero.offset + zero.size])]
    if data.size + sum(zeros) != size:
        return None
    initialized = bytearray()
    copies = []
    data_end = data.offset + data.size
    runs = iter(zeros)
    chunk_start = data.offset
    chunk_destination = 0
    for at in range(data.offset, data_end, 2):
        word = fork[at:at + 2]
        initialized.extend(word)
        if word == b"\0\0":
            amount = next(runs, None)
            if amount is None:
                return None
            if amount:
                copies.append((chunk_destination, chunk_start, at + 2 - chunk_start))
                initialized.extend(bytes(amount))
                chunk_start, chunk_destination = at + 2, len(initialized)
    if chunk_start < data_end:
        copies.append((chunk_destination, chunk_start, data_end - chunk_start))
    return (bytes(initialized), copies) if next(runs, None) is None else None


def _apply_think_relocations(
    image: bytearray, fork: bytes, resource: _Resource, unit: dict, displacement_bias: int,
    a5: int, strings: int,
) -> None:
    data = fork[resource.offset:resource.offset + resource.size]
    if len(data) % 2 or resource.attributes & 1:
        raise MacintoshError(f"invalid Macintosh {resource.type.decode('ascii')} {resource.id} relocation resource")
    sites = set()
    for (entry,) in Struct(">H").iter_unpack(data):
        # Both tables store an even signed displacement and use bit 0 to select STRS instead of A5.
        displacement = entry & ~1
        if displacement & 0x8000:
            displacement -= 0x10000
        offset = displacement + displacement_bias
        if not 0 <= offset <= unit["size"] - 4 or any(site in sites for site in (offset - 2, offset, offset + 2)):
            raise MacintoshError(f"invalid Macintosh relocation in {unit['name']} at offset {offset:x}")
        sites.add(offset)
        at = unit["image_offset"] + offset
        original = unpack_from(">I", image, at)[0]
        value = (original + (strings if entry & 1 else a5)) & 0xFFFFFFFF
        pack_into(">I", image, at, value)
        unit["relocations"].append({"offset": offset, "width": 4, "original": original, "value": value,
                                    "resource": resource.type.decode("ascii"), "resource_id": resource.id})


def build_macintosh_image(
    data: bytes, program: str, base: int = DEFAULT_M68K_BASE, *, disk_file: str | None = None,
) -> tuple[bytes, dict]:
    """Place all classic CODE segments and the A5 world in a fixed analysis address space."""
    if not 0 <= base < M68K_ADDRESS_LIMIT or base % 2:
        raise MacintoshError("Macintosh base address must be even and within the 24-bit address space")
    if is_hfs_disk(data) or disk_file is not None:
        disk = HfsDisk(data)
        member = disk.read_resource_fork(disk_file)
        fork, spans, wrapper, disk_file = member.data, member.spans, disk.container, member.name
    else:
        fork, offset, wrapper = _resource_fork(data)
        spans = ((0, offset, len(fork)),)
    resources = _parse_resources(fork)
    code0 = resources.get((_CODE, 0))
    if code0 is None or code0.size < _CODE0_HEADER.size:
        raise MacintoshError("expected a classic 68k CODE 0 jump table")
    if code0.attributes & 1:
        raise MacintoshError("compressed Macintosh CODE 0 resource is unsupported")
    above, below, jump_size, jump_offset = _CODE0_HEADER.unpack_from(fork, code0.offset)
    if not jump_size or jump_size % _LOADER_ENTRY.size or jump_size > code0.size - _CODE0_HEADER.size:
        raise MacintoshError("invalid Macintosh CODE 0 jump table size")
    if jump_offset % 2 or jump_offset + jump_size > above:
        raise MacintoshError("invalid Macintosh A5 jump table placement")
    if base + above + below > M68K_ADDRESS_LIMIT:
        raise MacintoshError("Macintosh layout exceeds the 24-bit address space")

    image = bytearray()
    units = []

    def add_unit(
        name: str, kind: str, size: int, offset: int | None = None, resource: _Resource | None = None,
    ) -> dict:
        start = len(image)
        if base + start + size > M68K_ADDRESS_LIMIT:
            raise MacintoshError("Macintosh layout exceeds the 24-bit address space")
        unit = {
            "name": name, "kind": kind, "linear": base + start, "image_offset": start, "size": size,
            "file_size": 0, "file_offset": None, "symbols": [], "relocations": [],
        }
        if offset is None:
            image.extend(bytes(size))
        else:
            image.extend(fork[offset:offset + size])
            placement = _source_spans(spans, offset, size)
            unit.update(source=program, file_size=size,
                        file_offset=placement[0]["file_offset"] if placement else None)
            if len(placement) > 1:
                unit["file_spans"] = placement
            if disk_file is not None:
                unit.update(disk_file=disk_file, file_offset_kind="container")
        if resource is not None:
            unit.update(resource_type=resource.type.decode("mac_roman"), resource_id=resource.id)
            if resource.name is not None:
                unit["resource_name"] = resource.name
        if size:
            units.append(unit)
        return unit

    segments = {}
    for (kind, resource_id), resource in sorted(resources.items()):
        if kind != _CODE or resource_id == 0:
            continue
        if resource.attributes & 1:
            raise MacintoshError(f"compressed Macintosh CODE {resource_id} resource is unsupported")
        if resource.size < 6:
            raise MacintoshError(f"truncated Macintosh CODE {resource_id} segment")
        header, count = unpack_from(">2H", fork, resource.offset)
        if header == 0xFFFF:
            raise MacintoshError("MPW far-model Macintosh CODE segments are unsupported")
        image.extend(bytes(len(image) & 1))
        unit = add_unit(f"code{resource_id}", "code", resource.size - 4, resource.offset + 4, resource)
        unit.update(jump_header=header, jump_entries=count)
        segments[resource_id] = unit
    if not segments:
        raise MacintoshError("Macintosh resource fork has no executable CODE segments")

    applied = set()
    initialized = None
    data, zero, strings = (resources.get((kind, 0)) for kind in (b"DATA", b"ZERO", b"STRS"))
    if data and zero and strings and not ((data.attributes | zero.attributes | strings.attributes) & 1):
        # Purgeable STRS 0 is a chunk marker in the THINK runtime. Such split string heaps need another layout.
        if strings.size and not strings.attributes & 0x20:
            initialized = _think_data(fork, data, zero, below)
    if initialized is not None:
        image.extend(bytes(len(image) & 1))
        string_unit = add_unit("strs", "data", strings.size, strings.offset, strings)
        string_unit["symbols"].append({"name": "MacStrings", "offset": 0})
        applied.update((resource.type, resource.id) for resource in (data, zero, strings))

    image.extend(bytes((len(image) + below) & 1))
    globals_ = add_unit("a5_globals", "data" if initialized is not None else "bss", below)
    a5 = base + len(image)
    if initialized is not None:
        contents, copies = initialized
        start = globals_["image_offset"]
        image[start:start + below] = contents
        globals_.update(source=program, file_size=below, file_spans=[
            span for destination, offset, size in copies for span in _source_spans(spans, offset, size, destination)
        ])
        if disk_file is not None:
            globals_.update(disk_file=disk_file, file_offset_kind="container")
        data_reloc = resources.get((b"DREL", 0))
        if data_reloc is not None:
            _apply_think_relocations(image, fork, data_reloc, globals_, below, a5, string_unit["linear"])
            applied.add((data_reloc.type, data_reloc.id))
        for resource_id, unit in segments.items():
            code_reloc = resources.get((b"CREL", resource_id))
            # The compiler sets the segment header's high bit when the segment loader applies these fixups.
            if unit["jump_header"] & 0x8000 and code_reloc is not None:
                _apply_think_relocations(image, fork, code_reloc, unit, -4, a5, string_unit["linear"])
                applied.add((code_reloc.type, code_reloc.id))
    params = add_unit("a5_params", "bss", jump_offset)
    jump_at = code0.offset + _CODE0_HEADER.size
    table = add_unit("a5_jump", "code", jump_size, jump_at, code0)
    add_unit("a5_tail", "bss", above - jump_offset - jump_size)
    (params if jump_offset else table)["symbols"].append({"name": "A5World", "offset": 0})
    jumps = []
    for offset in range(0, jump_size, _LOADER_ENTRY.size):
        target_offset, move, segment, loadseg = _LOADER_ENTRY.unpack_from(fork, jump_at + offset)
        if move != 0x3F3C or loadseg != _LOADSEG:
            raise MacintoshError(f"unsupported Macintosh CODE 0 jump table entry at offset 0x{offset:x}")
        if segment >= 0x8000:
            segment -= 0x10000
        unit = segments.get(segment)
        if unit is None or target_offset % 2 or target_offset + 2 > unit["size"]:
            raise MacintoshError(f"invalid Macintosh jump target CODE {segment} offset 0x{target_offset:x}")
        stub, target = _location(table, offset + 2), _location(unit, target_offset)
        pack_into(">HI", image, table["image_offset"] + offset + 2, _JMP_ABSL, target["linear"])
        table["relocations"].extend((
            {"offset": offset + 2, "width": 2, "original": move, "value": _JMP_ABSL},
            {"offset": offset + 4, "width": 4, "original": (segment & 0xFFFF) << 16 | loadseg,
             "value": target["linear"]},
        ))
        a5_offset = jump_offset + offset + 2
        table["symbols"].append({"name": f"JT_{a5_offset:04x}", "offset": offset + 2})
        jumps.append({"a5_offset": a5_offset, "stub": stub, "target": target})
    program_map = {
        "version": MAP_VERSION, "format": MAC68K_FORMAT, "program": program, "base_address": base,
        "container": wrapper, "a5": {"linear": a5, "above": above, "below": below, "jump_offset": jump_offset},
        "entry": jumps[0]["target"], "a5_jumps": jumps, "units": units,
    }
    if disk_file is not None:
        program_map["disk_file"] = disk_file
    pending = [resource for key, resource in resources.items()
               if resource.type in (b"CREL", b"DREL", b"DATA", b"STRS", b"ZERO") and key not in applied]
    if pending:
        program_map["unapplied_resources"] = [
            {"type": resource.type.decode("mac_roman"), "id": resource.id, "size": resource.size}
            for resource in pending
        ]
    return bytes(image), program_map
