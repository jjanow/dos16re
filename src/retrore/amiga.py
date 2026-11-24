"""Export classic AmigaDOS Hunk executables as flat, relocated 68k images."""

from dataclasses import dataclass
from struct import iter_unpack

from .image import DEFAULT_M68K_BASE as DEFAULT_BASE_ADDRESS
from .image import M68K_ADDRESS_LIMIT as ADDRESS_LIMIT
from .jump_tables import m68k_jump_table_records

HUNK_HEADER = 0x3F3
HUNK_MAGIC = HUNK_HEADER.to_bytes(4, "big")
_HUNK_OVERLAY = 0x3F5
_HUNK_BREAK = 0x3F6
_ALIGNMENT = 16
_SIZE_MASK = 0x3FFFFFFF
_LOAD_TYPES = {0x3E9: "code", 0x3EA: "data", 0x3EB: "bss"}
# Table field width, patch width, and relocation expression.
_RELOC_TYPES = {
    0x3EC: (4, 4, "absolute"),
    0x3ED: (4, 2, "pc_relative"),
    0x3EE: (4, 1, "pc_relative"),
    0x3F7: (2, 4, "absolute"),  # The AmigaDOS 2.x encoding of HUNK_RELOC32SHORT.
    0x3FC: (2, 4, "absolute"),
    0x3FD: (4, 4, "pc_relative"),
    0x3FE: (4, 2, "absolute"),
}
_THOR_HEADER = bytes.fromhex("0000 5ba0") + b"\x07Overlay"
_THOR_ID = b"THOR Overlay Manager 1.2\0"


class HunkError(ValueError):
    """A malformed or unsupported AmigaDOS executable."""


class _Reader:
    def __init__(self, data: bytes | memoryview):
        self.data = memoryview(data)
        self.position = 0

    def take(self, size: int) -> memoryview:
        start = self.position
        end = start + size
        if end > len(self.data):
            raise HunkError(f"truncated Hunk executable at file offset 0x{start:x}")
        self.position = end
        return self.data[start:end]

    def number(self, width: int = 4) -> int:
        return int.from_bytes(self.take(width), "big")

    def record_type(self) -> int:
        while True:
            record = self.number() & _SIZE_MASK
            if not record & 0x20000000:
                return record
            # Advisory records carry a longword count and can be skipped.
            self.take(4 * self.number())

    def name(self, longwords: int) -> str:
        return self.take(4 * longwords).tobytes().split(b"\0", 1)[0].decode("latin-1")


@dataclass
class _Node:
    id: str
    file_offset: int
    first: int
    last: int
    units: dict[int, dict]
    parent: "_Node | None"
    level: int
    ordinate: int

    def record(self) -> dict:
        return {
            "id": self.id, "file_offset": self.file_offset,
            "first_segment": self.first, "last_segment": self.last,
            "units": [unit["name"] for unit in self.units.values()],
            "parent": self.parent.id if self.parent else None,
            "level": self.level, "ordinate": self.ordinate,
        }


def _read_header(reader: _Reader) -> tuple[int, int, int]:
    if reader.number() != HUNK_HEADER:
        raise HunkError("missing AmigaDOS HUNK_HEADER")
    if reader.number():
        raise HunkError("AmigaDOS resident library tables are unsupported")
    count, first, last = (reader.number() for _ in range(3))
    if not 0 <= first <= last < count:
        raise HunkError("invalid AmigaDOS hunk table range")
    return count, first, last


def _allocate(reader: _Reader, node: _Node, base: int, offset: int, image: bytearray) -> None:
    if node.last - node.first + 1 > (ADDRESS_LIMIT - base - offset) // _ALIGNMENT:
        raise HunkError("Amiga hunk layout exceeds the 24-bit address space")

    for index in range(node.first, node.last + 1):
        allocation = reader.number()
        size = (allocation & _SIZE_MASK) * 4
        memory_type = allocation >> 30
        flags = reader.number() if memory_type == 3 else memory_type << 1
        if base + offset + size > ADDRESS_LIMIT:
            raise HunkError("Amiga hunk layout exceeds the 24-bit address space")
        unit = {
            "name": f"h{index}" if node.parent is None else f"{node.id}_h{index}",
            "linear": base + offset, "image_offset": offset, "size": size, "memory_flags": flags,
        }
        node.units[index] = unit
        # Empty hunks still have a distinct address in the analysis layout.
        end = offset + size
        offset = _next_unit_offset(unit)
    image.extend(bytes(end - len(image)))


def _next_unit_offset(unit: dict) -> int:
    return unit["image_offset"] + max(_ALIGNMENT, (unit["size"] + _ALIGNMENT - 1) & -_ALIGNMENT)


def _read_relocations(
    reader: _Reader, record: int, unit: dict, units: dict[int, dict], image: bytearray,
) -> list[dict]:
    field_width, width, kind = _RELOC_TYPES[record]
    # Kickstart 3.0 reads compact HUNK_RELRELOC32 fields, as emitted by AROS elf2hunk.
    # A nonempty documented long table begins with a zero high word (at most 65535 fixes).
    compact_relative = record == 0x3FD and any(reader.data[reader.position:reader.position + 2])
    if compact_relative:
        field_width = 2
    relocations = []
    while count := reader.number(field_width):
        index = reader.number(field_width)
        if (target := units.get(index)) is None:
            raise HunkError(f"invalid or inactive relocation target h{index} in {unit['name']}")
        for _ in range(count):
            offset = reader.number(field_width)
            if (width > 1 and offset % 2) or offset + width > unit["size"]:
                raise HunkError(f"invalid relocation offset 0x{offset:x} in {unit['name']}")
            position = unit["image_offset"] + offset
            raw = image[position:position + width]
            original = int.from_bytes(raw, "big")
            if kind == "pc_relative":
                addend = int.from_bytes(raw, "big", signed=True)
                origin = unit["linear"] if compact_relative else unit["linear"] + offset
                value = target["linear"] + addend - origin
                if width < 4 and not -(1 << (width * 8 - 1)) <= value < 1 << (width * 8 - 1):
                    raise HunkError(f"relative relocation out of range at {unit['name']}:0x{offset:x}")
                # AROS writes the original displacement relative to the source hunk.
                target_linear = target["linear"] + addend + (offset if compact_relative else 0)
            else:
                value = target["linear"] + original
                target_linear = value
            value &= (1 << (width * 8)) - 1
            image[position:position + width] = value.to_bytes(width, "big")
            relocation = {"offset": offset, "target": target["name"], "original": original, "value": value}
            if kind != "absolute" or width != 4:
                relocation.update(
                    kind=kind, width=width, record=record, table_field_width=field_width,
                    target_linear=target_linear & 0xFFFFFFFF,
                )
            relocations.append(relocation)
    if field_width == 2 and reader.position % 4:
        reader.take(2)
    return relocations


def _read_symbols(reader: _Reader) -> list[dict]:
    symbols = []
    while descriptor := reader.number():
        if descriptor >> 24:
            raise HunkError("unsupported AmigaDOS HUNK_SYMBOL type")
        name = reader.name(descriptor)
        symbols.append({"name": name, "offset": reader.number()})
    return symbols


def _read_debug(reader: _Reader, unit: dict, diagnostics: list[dict]) -> None:
    size = 4 * reader.number()
    start = reader.position - 8
    payload = reader.take(size)
    is_line_debug = payload[4:8] == b"LINE"
    unit.setdefault("debug_records", []).append({
        "format": "LINE" if is_line_debug else None, "file_offset": start, "size": size + 8,
    })
    if not is_line_debug:
        return

    try:
        lines = _Reader(payload)
        base = lines.number()
        lines.take(4)
        filename = lines.name(lines.number())
        if not filename or (size - lines.position) % 8:
            raise HunkError("invalid source name or line table size")
        locations = []
        for line, offset in iter_unpack(">II", payload[lines.position:]):
            offset = base + (offset & 0xFFFFFF)
            if offset >= unit["file_size"]:
                raise HunkError(f"source line offset 0x{offset:x} is outside initialized bytes")
            locations.append({
                "file": filename, "line": line & 0xFFFFFF, "offset": offset,
                "record_file_offset": start,
            })
        if locations:
            unit.setdefault("source_lines", []).extend(locations)
    except HunkError as error:
        diagnostics.append({
            "code": "hunk_debug_line_invalid", "unit": unit["name"], "file_offset": start,
            "message": f"ignored malformed Amiga HUNK_DEBUG LINE record: {error}",
        })


def _load_unit(reader: _Reader, unit: dict, units: dict[int, dict], image: bytearray, diagnostics: list[dict]) -> None:
    record = reader.record_type()
    if record == 0x3E8:  # HUNK_NAME
        unit["section_name"] = reader.name(reader.number())
        record = reader.record_type()
    kind = _LOAD_TYPES.get(record)
    if kind is None:
        raise HunkError(f"expected CODE, DATA, or BSS for {unit['name']}, found 0x{record:x}")
    size = reader.number() * 4
    if size > unit["size"]:
        raise HunkError(f"{unit['name']} payload exceeds its allocation")

    unit.update(kind=kind, file_offset=None, file_size=0, relocations=[], symbols=[])
    if kind != "bss":
        unit.update(file_offset=reader.position, file_size=size)
        start = unit["image_offset"]
        image[start:start + size] = reader.take(size)

    while (record := reader.record_type()) != 0x3F2:  # HUNK_END
        if record in _RELOC_TYPES:
            unit["relocations"].extend(_read_relocations(reader, record, unit, units, image))
        elif record == 0x3F0:  # HUNK_SYMBOL
            unit["symbols"].extend(_read_symbols(reader))
        elif record == 0x3F1:  # HUNK_DEBUG
            _read_debug(reader, unit, diagnostics)
        else:
            raise HunkError(f"unsupported AmigaDOS hunk type 0x{record:x} in {unit['name']}")


def _load_node(
    reader: _Reader, node: _Node, base: int, offset: int, image: bytearray, diagnostics: list[dict],
) -> None:
    _allocate(reader, node, base, offset, image)
    active = node.units.copy()
    ancestor = node.parent
    while ancestor is not None:
        active.update(ancestor.units)
        ancestor = ancestor.parent
    for unit in node.units.values():
        _load_unit(reader, unit, active, image, diagnostics)


def _read_overlay_table(reader: _Reader) -> tuple[dict, dict, list[tuple[int, int, int]]]:
    start = reader.position - 4
    size = (reader.number() + 1) * 4
    table = _Reader(reader.take(size))
    depth = table.number()
    if not 2 <= depth <= size // 4 or (size // 4 - depth) % 8:
        raise HunkError("unsupported AmigaDOS HUNK_OVERLAY table (expected a hierarchical ALink/BLink/SLink table)")
    if any(table.take((depth - 1) * 4)):
        raise HunkError("invalid AmigaDOS HUNK_OVERLAY initial ordinates")

    nodes = {}
    entries = []
    for number, row in enumerate(iter_unpack(">8I", table.data[table.position:])):
        position, _, _, level, ordinate, first, target, offset = row
        # The overlay manager ignores both reserved words. Original linkers can leave them nonzero.
        next_node = (level, ordinate, first)
        prior_node = nodes.setdefault(position, next_node)
        if (not 1 <= level < depth or not ordinate
                or position < reader.position or position % 4 or prior_node != next_node):
            raise HunkError(f"invalid AmigaDOS HUNK_OVERLAY table entry {number}")
        entries.append((position, target, offset))
    if not nodes:
        raise HunkError("AmigaDOS HUNK_OVERLAY table contains no nodes")
    return {"manager": "hierarchical", "depth": depth, "file_offset": start, "size": size + 8}, nodes, entries


def _load_overlays(
    reader: _Reader, root: _Node, count: int, base: int, image: bytearray, diagnostics: list[dict],
) -> tuple[list[_Node], dict]:
    tree, table_nodes, entries = _read_overlay_table(reader)
    nodes = [root]
    ancestors = [root]
    last_ordinate = {}
    node_ids = {root.id}
    # The root is already terminated by HUNK_OVERLAY, but a BREAK may precede the first node.
    if (min(table_nodes) == reader.position + 4
            and reader.data[reader.position:reader.position + 4] == _HUNK_BREAK.to_bytes(4, "big")):
        reader.take(4)
    for position, (level, ordinate, expected_first) in sorted(table_nodes.items()):
        if reader.position != position:
            raise HunkError(f"AmigaDOS HUNK_OVERLAY references incomplete or unlisted node at file offset 0x{position:x}")
        node_count, first, last = _read_header(reader)
        if node_count != count or first != expected_first:
            raise HunkError(f"AmigaDOS HUNK_OVERLAY node header disagrees with table at file offset 0x{position:x}")
        # The original overlay directive emits nodes in tree order. ALink restarts
        # ordinates for each parent, while other hierarchical managers number the level.
        parent = ancestors[level - 1] if level <= len(ancestors) else None
        if parent is None or first != parent.last + 1 or ordinate <= last_ordinate.get(parent.id, 0):
            raise HunkError(f"ambiguous AmigaDOS HUNK_OVERLAY ancestry at file offset 0x{position:x}")
        last_ordinate[parent.id] = ordinate
        node_id = f"ov{level}_{ordinate}"
        if node_id in node_ids:
            node_id = f"{parent.id}_{node_id}"
        node_ids.add(node_id)
        node = _Node(node_id, position, first, last, {}, parent, level, ordinate)
        previous = nodes[-1]
        _load_node(reader, node, base, _next_unit_offset(previous.units[previous.last]), image, diagnostics)
        if reader.record_type() != _HUNK_BREAK:
            raise HunkError(f"missing HUNK_BREAK after AmigaDOS overlay {node.id}")
        nodes.append(node)
        ancestors[level:] = [node]
    if reader.position != len(reader.data):
        raise HunkError(f"unlisted bytes after AmigaDOS HUNK_OVERLAY nodes at file offset 0x{reader.position:x}")

    tree["segment_table_size"] = count
    tree["nodes"] = [node.record() for node in nodes]
    tree["entries"] = _overlay_entries(tree, entries, nodes)
    for node in nodes:
        for index, unit in node.units.items():
            unit.update(overlay_node=node.id, segment_index=index)
    return nodes, tree


def _overlay_entries(tree: dict, entries: list[tuple[int, int, int]], nodes: list[_Node]) -> list[dict]:
    by_position = {node.file_offset: node for node in nodes}
    start = tree["file_offset"] + 8 + tree["depth"] * 4
    results = []
    for index, (position, target, offset) in enumerate(entries):
        node = by_position[position]
        unit = node.units.get(target)
        if unit is None or offset > unit["size"]:
            raise HunkError(f"invalid AmigaDOS HUNK_OVERLAY symbol target in table entry {index}")
        entry = {
            "index": index, "node": node.id, "file_offset": start + index * 32,
            "unit_address": f"{unit['name']}:{offset:04x}", "linear": unit["linear"] + offset,
            "kind": unit["kind"],
            "entry_point": unit["kind"] == "code" and not offset % 2 and offset + 2 <= unit["file_size"],
        }
        # Some linkers emit symbols at the exact end of a segment. Preserve their coordinates
        # as table evidence, without treating them as addresses of initialized instructions.
        if offset == unit["size"]:
            entry["at_boundary"] = True
        results.append(entry)
    return results


def _recognize_overlay_manager(data: bytes, unit: dict) -> dict | None:
    # The THOR example in the AmigaDOS RKRM starts with BRA.W and the LoadSeg overlay header.
    start = unit["file_offset"]
    end = start + unit["file_size"]
    header = data[start:min(end, start + 44 + len(_THOR_ID))]
    if (header[:2] != b"\x60\0" or header[4:8] != b"\0\0\xab\xcd"
            or header[24:36] != _THOR_HEADER or header[44:] != _THOR_ID):
        return None
    unit["symbols"].extend({"name": name, "offset": offset} for offset, name in (
        (8, "oh_FileHandle"), (12, "oh_OVTab"), (16, "oh_Segments"), (20, "oh_GlobVec"),
    ))
    return {
        "family": "THOR Overlay Manager", "version": "1.2", "evidence": "overlay manager header and identifier",
        "unit_address": "h0:0000", "file_offset": start,
    }


def build_hunk_image(data: bytes, program: str, base: int = DEFAULT_BASE_ADDRESS) -> tuple[bytes, dict]:
    """Lay out and relocate resident hunks and hierarchical AmigaDOS overlays."""
    if not 0 <= base < ADDRESS_LIMIT or base % _ALIGNMENT:
        raise HunkError("Amiga base address must be 16-byte aligned and within the 24-bit address space")
    reader = _Reader(data)
    count, first, last = _read_header(reader)
    if first:
        raise HunkError("AmigaDOS HUNK_OVERLAY root must start at segment h0")
    root = _Node("root", 0, first, last, {}, None, 0, 0)
    diagnostics = []
    image = bytearray()
    try:
        _load_node(reader, root, base, 0, image, diagnostics)
    except HunkError as error:
        if last != count - 1:
            raise HunkError(f"invalid root for AmigaDOS HUNK_OVERLAY: {error}") from error
        raise
    if root.units[0]["kind"] != "code" or not root.units[0]["file_size"]:
        raise HunkError("AmigaDOS entry point requires CODE in h0")

    nodes = [root]
    program_map = {
        "version": 1, "format": "HUNK", "program": program, "base_address": base,
        "entry": {"unit_address": "h0:0000", "linear": base},
    }
    if reader.position != len(data):
        record = reader.record_type()
        if record != _HUNK_OVERLAY:
            prefix = "missing AmigaDOS HUNK_OVERLAY table, " if last != count - 1 else ""
            raise HunkError(f"{prefix}unexpected AmigaDOS record 0x{record:x} after the root hunks")
        try:
            nodes, program_map["overlay_tree"] = _load_overlays(reader, root, count, base, image, diagnostics)
        except HunkError as error:
            raise HunkError(f"AmigaDOS HUNK_OVERLAY load failed: {error}") from error
        if manager := _recognize_overlay_manager(data, root.units[0]):
            program_map["toolchain"] = manager
    elif last != count - 1:
        raise HunkError("missing AmigaDOS HUNK_OVERLAY table after the root hunks")
    units = [unit for node in nodes for unit in node.units.values()]
    program_map["units"] = units
    if diagnostics:
        program_map["diagnostics"] = diagnostics
    tables = [table for unit in units if unit["kind"] == "code"
              for table in m68k_jump_table_records(image, unit, units=units)]
    if tables:
        program_map["jump_tables"] = tables
    return bytes(image), program_map
