"""Build an analysis image with all supplied DOS overlays resident."""

from collections import defaultdict
from dataclasses import asdict, dataclass
from struct import Struct, pack, unpack_from

from .jump_tables import FarTableImage, recover_jump_tables
from .mz import Address, LoadedMZ, MZError
from .signatures import detect_compiler, match_runtime

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


@dataclass(frozen=True)
class LinkedFixup:
    offset: int
    value: int
    target_unit: str | None = None
    segment: bool = True


@dataclass(frozen=True)
class LinkedOverlay:
    source: str
    name: str
    image: bytes
    file_offset: int
    format: str
    number: int
    runtime_segment: int | None = None
    entries: tuple[int, ...] = ()
    descriptor: Descriptor | None = None
    fixups: tuple[LinkedFixup, ...] = ()


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
    linked: LinkedOverlay | None = None


def _read_units(root: bytes, overlays: list[Overlay | LinkedOverlay]) -> list[_Unit]:
    units = []
    for overlay in overlays:
        if isinstance(overlay, LinkedOverlay):
            units.append(_Unit(overlay.name, overlay.source, overlay.image, None, overlay.descriptor, linked=overlay))
        elif overlay.image.startswith((b"FBOV", b"TPOV")):
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


def _place_units(root_end: int, memory_end: int, units: list[_Unit]) -> list[int]:
    """Assign segments to units without one.

    Explicit segments only have to clear the root's file image. Automatic placement also clears
    the root's uninitialized data, minimum allocation, and initial stack, which end at memory_end.
    """
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
    next_start = max(root_end, memory_end)
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


def _root_code_segments(image: bytes, program_map: dict) -> list[int]:
    """Possible code segments in the root: its load segment, the entry CS, and every relocated segment word.

    Relocated words name far call targets, but also segments loaded into registers or stored in far
    pointers, such as a driver entered through an interrupt vector."""
    root = program_map["units"][0]
    segments = {root["segment"], program_map["entry"]["segment"]}
    for position in program_map.get("relocations", ()):
        if 0 <= position < root["size"] - 1:
            segments.add(unpack_from("<H", image, position)[0])
    return sorted(
        segment for segment in segments
        if 0 <= (segment - root["segment"]) * 16 < root["size"]
    )


def _jump_table_record(unit: str, segment: int, table) -> dict:
    record = {
        "unit": unit,
        "kind": table.kind,
        "bound": table.bound,
        "address": address_record(Address(segment, table.jump)),
        "guard": address_record(Address(segment, table.guard)),
        "table": address_record(Address(segment, table.table)),
    }
    # Always present so version-1 readers find it; null for mask- and byte-bounded tables.
    record["default"] = None if table.default is None else address_record(Address(segment, table.default))
    if table.target_segments is None:
        record["targets"] = [address_record(Address(segment, offset)) for offset in table.targets]
    else:
        record["entry_size"] = 4
        record["targets"] = [
            address_record(Address(selector, offset))
            for selector, offset in zip(table.target_segments, table.targets, strict=True)
        ]
    return record


def _add_jump_tables(image: bytes, program_map: dict) -> None:
    tables = []
    units = program_map["units"]
    far_image = FarTableImage(
        image, units[0]["linear"],
        tuple((unit["image_offset"], unit["image_offset"] + unit["size"]) for unit in units),
        set(program_map.get("relocations", ())),
    )
    for unit in units:
        is_root = unit["name"] == "root"
        end = unit["image_offset"] + unit["size"]
        segments = _root_code_segments(image, program_map) if is_root else [unit["segment"], *(
            unit["segment"] + offset // 16 for offset in unit.get("segment_offsets", ()) if offset
        )]
        found = {}
        # A site belongs to the nearest code segment at or below it whose table validates.
        for segment in segments:
            start = unit["image_offset"] + (segment - unit["segment"]) * 16
            if not unit["image_offset"] <= start < end:
                continue
            for table in recover_jump_tables(
                image[start:end], flat_overlay=not is_root and "file_offset" not in unit,
                segment=segment, far_image=far_image,
            ):
                found[segment * 16 + table.jump] = _jump_table_record(unit["name"], segment, table)
        tables.extend(found[linear] for linear in sorted(found))
    if tables:
        program_map["jump_tables"] = tables


def _add_analysis(root: LoadedMZ, image: bytes, program_map: dict) -> None:
    _add_jump_tables(image, program_map)
    units = program_map["units"]
    compiler = detect_compiler(root, pascal_overlays=any("file_offset" in unit and "overlay_format" not in unit
                                                        for unit in units[1:]))
    program_map["compiler"] = None
    program_map["runtime_signatures"] = signatures = []
    if compiler is None:
        return
    program_map["compiler"] = {
        "family": compiler.family, "version": compiler.version, "evidence": compiler.evidence,
    }
    for unit in units:
        start = unit["image_offset"]
        data = image[start:start + unit["size"]]
        for offset, prototype in match_runtime(compiler, data):
            linear = unit["linear"] + offset
            segment = root.entry.segment if unit["name"] == "root" else unit["segment"]
            if not 0 <= linear - segment * 16 <= 0xFFFF:
                segment = unit["segment"] if offset <= 0xFFFF else linear >> 4
            record = asdict(prototype)
            if not prototype.far:
                del record["far"]
            signatures.append({
                **record, "unit": unit["name"], "unit_offset": offset,
                "address": address_record(Address(segment, linear - segment * 16)),
            })


def build_image(root: LoadedMZ, program: str, overlays: list[Overlay | LinkedOverlay]) -> tuple[bytes, dict]:
    origin = root.base_segment * 16
    root_record = _unit_record("root", root.base_segment, origin, len(root.image))
    program_map = {
        "version": 1, "format": "MZ", "program": program,
        "entry": address_record(root.entry), "stack": address_record(root.stack),
        "relocation_count": len(root.relocations), "units": [root_record],
        "memory_end": root.memory_end,
    }
    fixup_positions = {fixup.linear for fixup in root.relocations}
    if root.diagnostics:
        program_map["diagnostics"] = list(root.diagnostics)
    if root.toolchain:
        program_map["toolchain"] = root.toolchain
    if root.packer:
        program_map["packer"] = root.packer
    if root.file_offset is not None:
        root_record["file_offset"] = root.file_offset
    if root.dos_format != "MZ":
        program_map["dos_format"] = root.dos_format
        program_map["load_offset"] = root.load_offset
        program_map["initial_segments"] = {"ds": root.base_segment, "es": root.base_segment}
        root_record["file_spans"] = [] if root.packer else [{"offset": root.load_offset, "file_offset": 0,
                                                           "size": len(root.image) - root.load_offset}]
    root_fixups = [fixup.linear for fixup in root.relocations]
    if root_fixups != sorted(fixup_positions):
        program_map["root_relocation_order"] = root_fixups
    if not overlays:
        if fixup_positions:
            program_map["relocations"] = sorted(fixup_positions)
        _add_analysis(root, root.image, program_map)
        return root.image, program_map

    units = _read_units(root.image, overlays)
    root_end = origin + max(len(root.image), 1)
    segments = _place_units(root_end, root.memory_end, units)
    linked_segments = {unit.name: segment for unit, segment in zip(units, segments) if unit.linked is not None}
    image = bytearray(root.image)
    stub_targets = {}
    stub_records = []
    call_records = []
    overlay_edits = []
    for unit, segment in zip(units, segments):
        record = _unit_record(unit.name, segment, origin, len(unit.data))
        record["source"] = unit.source
        code_start = record["image_offset"]
        data = bytearray(unit.data)
        linked = unit.linked
        if linked is not None:
            record.update(overlay_format=linked.format, overlay_number=linked.number,
                          file_offset=linked.file_offset, entries=list(linked.entries),
                          relocation_count=sum(fixup.segment for fixup in linked.fixups))
            if linked.runtime_segment is not None:
                record["runtime_linear"] = linked.runtime_segment * 16
            if linked.format == "MS_LINK":
                record["segment_offsets"] = list(linked.entries)
            for fixup in linked.fixups:
                position = code_start + fixup.offset
                old = data[fixup.offset:fixup.offset + 2].hex()
                value = fixup.value
                if fixup.segment:
                    value += root.base_segment if fixup.target_unit is None else linked_segments[fixup.target_unit]
                    fixup_positions.add(position)
                overlay_edits.append({"image_offset": position, "original": old,
                                      "kind": "relocation" if fixup.segment else "overlay_fixup"})
                _WORD.pack_into(data, fixup.offset, value & 0xFFFF)
        descriptor = unit.descriptor
        if descriptor is not None:
            record["file_offset"] = descriptor.file_offset
            record["entries"] = sorted(set(descriptor.entries))
            if linked is None:
                record["relocation_count"] = len(unit.fixups)
            for fixup in unit.fixups:
                old_segment, = _WORD.unpack_from(data, fixup)
                _WORD.pack_into(data, fixup, (old_segment + root.base_segment) & 0xFFFF)
                fixup_positions.add(code_start + fixup)

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
    for fixup in sorted(fixup_positions):
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
    if fixup_positions:
        program_map["relocations"] = sorted(fixup_positions)
    if overlay_edits:
        program_map["overlay_edits"] = overlay_edits
    relocated = bytes(image)
    _add_analysis(root, relocated, program_map)
    return relocated, program_map
