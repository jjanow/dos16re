"""Build an analysis image with all supplied DOS overlays resident."""

from collections import defaultdict
from dataclasses import dataclass
from struct import Struct, pack, unpack_from

from .mz import Address, LoadedMZ, MZError

_DESCRIPTOR = Struct("<4xI3H")
_TRAP = b"\xcd\x3f"
_HEADER_SIZE = 0x20
_STUB_SIZE = 5
_WORD = Struct("<H")
_IMAGE_LIMIT = 0x100000


@dataclass(frozen=True)
class Overlay:
    source: str
    name: str
    image: bytes
    segment: int | None = None


@dataclass(frozen=True)
class Descriptor:
    segment: int
    file_offset: int
    code_size: int
    fixup_size: int
    entries: tuple[int, ...]

    @property
    def end(self) -> int:
        return self.file_offset + self.code_size + self.fixup_size


def address_record(address: Address) -> dict[str, int]:
    return {"segment": address.segment, "offset": address.offset, "linear": address.linear}


def _directory(root: bytes, bank: bytes) -> list[Descriptor]:
    first_unit = 4
    if bank.startswith(b"FBOV"):
        first_unit = 8
        if len(bank) < first_unit or unpack_from("<I", bank, 4)[0] != len(bank) - first_unit:
            raise MZError("FBOV header size does not match the overlay file")

    candidates = defaultdict(list)
    for start in range(0, len(root) - _HEADER_SIZE + 1, 16):
        if root[start:start + 4] != _TRAP + b"\0\0":
            continue
        file_offset, code_size, fixup_size, count = _DESCRIPTOR.unpack_from(root, start)
        stub_start = start + _HEADER_SIZE
        stub_end = stub_start + count * _STUB_SIZE
        if (
            not first_unit <= file_offset
            or file_offset + code_size + fixup_size > len(bank)
            or code_size == 0
            or fixup_size % 2
            or stub_end > len(root)
            or stub_end - start > 0x10000
        ):
            continue
        entries = []
        for stub in range(stub_start, stub_end, _STUB_SIZE):
            target, = _WORD.unpack_from(root, stub + 2)
            if root[stub:stub + 2] != _TRAP or target >= code_size:
                break
            entries.append(target)
        else:
            candidates[file_offset].append(
                Descriptor(start // 16, file_offset, code_size, fixup_size, tuple(entries))
            )

    units = []
    cursor = first_unit
    while cursor < len(bank):
        matches = candidates[cursor]
        if len(matches) != 1:
            raise MZError(
                f"expected one Turbo Pascal overlay descriptor at file offset {cursor:#x}, "
                f"found {len(matches)}"
            )
        unit = matches[0]
        units.append(unit)
        cursor = unit.end
    if not units:
        raise MZError("Turbo Pascal overlay has no units")
    by_segment = sorted(units, key=lambda unit: unit.segment)
    for left, right in zip(by_segment, by_segment[1:]):
        left_end = left.segment * 16 + _HEADER_SIZE + len(left.entries) * _STUB_SIZE
        if left_end > right.segment * 16:
            raise MZError("Turbo Pascal overlay descriptors overlap")
    return units


@dataclass(frozen=True)
class _Unit:
    name: str
    source: str
    data: bytes
    segment: int | None
    descriptor: Descriptor | None = None
    fixups: tuple[int, ...] = ()


def _read_units(root: bytes, overlays: list[Overlay]) -> list[_Unit]:
    units = []
    for overlay in overlays:
        if overlay.image.startswith((b"FBOV", b"TPOV")):
            if overlay.segment is not None:
                raise MZError("Turbo Pascal units use automatic segment placement")
            for unit in _directory(root, overlay.image):
                code_end = unit.file_offset + unit.code_size
                fixups = tuple(
                    offset for offset, in _WORD.iter_unpack(overlay.image[code_end:unit.end])
                )
                if any(offset + 2 > unit.code_size for offset in fixups):
                    raise MZError(f"overlay fixup outside unit at file offset {unit.file_offset:#x}")
                units.append(_Unit(
                    f"tpov_{unit.segment:04x}", overlay.source,
                    overlay.image[unit.file_offset:code_end], None, unit, fixups,
                ))
        else:
            if not 0 < len(overlay.image) <= 0x10000:
                raise MZError(f"raw overlay {overlay.source} must contain 1 to 65536 bytes")
            units.append(_Unit(overlay.name, overlay.source, overlay.image, overlay.segment))

    names = ["root", *(unit.name.casefold() for unit in units)]
    if len(set(names)) != len(names):
        raise MZError("duplicate overlay unit name")
    return units


def _place_units(root_end: int, units: list[_Unit]) -> list[int]:
    used = []
    for unit in units:
        if unit.segment is None:
            continue
        start = unit.segment * 16
        end = start + len(unit.data)
        if not 0 <= unit.segment <= 0xFFFF or start < root_end or end > _IMAGE_LIMIT:
            raise MZError(f"overlay {unit.name} segment is outside available image space")
        used.append((start, end))
    used.sort()
    if any(right[0] < left[1] for left, right in zip(used, used[1:])):
        raise MZError("explicit overlay segments overlap")

    segments = []
    next_start = root_end
    for unit in units:
        if unit.segment is not None:
            segments.append(unit.segment)
            continue
        start = (next_start + 15) & ~15
        for lo, hi in used:
            if start + len(unit.data) <= lo:
                break
            if start < hi:
                start = (hi + 15) & ~15
        next_start = start + len(unit.data)
        if next_start > _IMAGE_LIMIT:
            raise MZError(f"overlay {unit.name} extends past the 1 MiB image limit")
        segments.append(start // 16)
    return segments


def _unit_record(name: str, segment: int, origin: int, size: int) -> dict:
    linear = segment * 16
    return {
        "name": name, "segment": segment, "linear": linear,
        "image_offset": linear - origin, "size": size,
    }


def _rewrite(image: bytearray, index: int, opcode: int, target: Address) -> str:
    original = image[index:index + _STUB_SIZE].hex()
    image[index:index + _STUB_SIZE] = pack("<BHH", opcode, target.offset, target.segment)
    return original


def build_image(root: LoadedMZ, program: str, overlays: list[Overlay]) -> tuple[bytes, dict]:
    origin = root.base_segment * 16
    root_record = _unit_record("root", root.base_segment, origin, len(root.image))
    program_map = {
        "version": 1, "format": "MZ", "program": program,
        "entry": address_record(root.entry), "stack": address_record(root.stack),
        "relocation_count": len(root.relocations), "units": [root_record],
    }
    if root.packer:
        program_map["packer"] = root.packer
    if not overlays:
        return root.image, program_map

    units = _read_units(root.image, overlays)
    segments = _place_units(origin + max(len(root.image), 1), units)
    image = bytearray(root.image)
    stub_targets = {}
    stub_records = []
    call_records = []
    fixup_positions = [fixup.linear for fixup in root.relocations]
    for unit, segment in zip(units, segments):
        record = _unit_record(unit.name, segment, origin, len(unit.data))
        record["source"] = unit.source
        code_start = record["image_offset"]
        data = bytearray(unit.data)
        descriptor = unit.descriptor
        if descriptor is not None:
            record["file_offset"] = descriptor.file_offset
            record["entries"] = sorted(set(descriptor.entries))
            record["relocation_count"] = len(unit.fixups)
            for fixup in unit.fixups:
                old_segment, = _WORD.unpack_from(data, fixup)
                _WORD.pack_into(data, fixup, (old_segment + root.base_segment) & 0xFFFF)
                fixup_positions.append(code_start + fixup)

            stub_segment = root.base_segment + descriptor.segment
            for index, offset in enumerate(descriptor.entries):
                stub = Address(stub_segment, _HEADER_SIZE + index * _STUB_SIZE)
                target = Address(segment, offset)
                stub_targets[stub.linear] = target
                stub_records.append({
                    "address": address_record(stub),
                    "target": address_record(target),
                    "unit": unit.name,
                    "file_offset": descriptor.file_offset + offset,
                    "original": _rewrite(image, stub.linear - origin, 0xEA, target),
                })
        code_end = code_start + len(data)
        if code_end > len(image):
            image.extend(bytes(code_end - len(image)))
        image[code_start:code_end] = data
        program_map["units"].append(record)

    # Relocations identify the segment operand of direct far calls. The far jump
    # at each stub also handles indirect calls without adding a return frame.
    stub_bytes = {
        index for linear in stub_targets
        for index in range(linear - origin, linear - origin + _STUB_SIZE)
    }
    for fixup in sorted(set(fixup_positions)):
        start = fixup - 3
        if start < 0 or image[start] != 0x9A or not stub_bytes.isdisjoint(range(start, start + 5)):
            continue
        offset, segment = unpack_from("<HH", image, start + 1)
        target = stub_targets.get(Address(segment, offset).linear)
        if target is not None:
            call_records.append({
                "linear": origin + start, "target": address_record(target),
                "stub": address_record(Address(segment, offset)),
                "original": _rewrite(image, start, 0x9A, target),
            })
    if stub_records:
        program_map["stubs"] = stub_records
        program_map["calls"] = call_records
    return bytes(image), program_map
