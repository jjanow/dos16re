"""Export classic AmigaDOS Hunk executables as flat, relocated 68k images."""

from struct import pack_into, unpack_from

from .image import DEFAULT_M68K_BASE as DEFAULT_BASE_ADDRESS
from .image import M68K_ADDRESS_LIMIT as ADDRESS_LIMIT
from .jump_tables import m68k_jump_table_records

HUNK_HEADER = 0x3F3
HUNK_MAGIC = HUNK_HEADER.to_bytes(4, "big")
_ALIGNMENT = 16
_SIZE_MASK = 0x3FFFFFFF
_LOAD_TYPES = {0x3E9: "code", 0x3EA: "data", 0x3EB: "bss"}
_RELOC_TYPES = {0x3EC: 4, 0x3F7: 2, 0x3FC: 2}


class HunkError(ValueError):
    """A malformed or unsupported AmigaDOS executable."""


class _Reader:
    def __init__(self, data: bytes):
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
            if record in (0x3F5, 0x3F6):
                raise HunkError("AmigaDOS HUNK_OVERLAY/BREAK executables are unsupported")
            if not record & 0x20000000:
                return record
            # Advisory records carry a longword count and can be skipped.
            self.take(4 * self.number())


def _read_layout(reader: _Reader, base: int) -> list[dict]:
    if reader.number() != HUNK_HEADER:
        raise HunkError("missing AmigaDOS HUNK_HEADER")
    if reader.number():
        raise HunkError("AmigaDOS resident library tables are unsupported")
    count, first, last = (reader.number() for _ in range(3))
    if not 0 <= first <= last < count:
        raise HunkError("invalid AmigaDOS hunk table range")
    if first or last != count - 1:
        raise HunkError("AmigaDOS HUNK_OVERLAY executables are unsupported")
    if count > (ADDRESS_LIMIT - base) // _ALIGNMENT:
        raise HunkError("Amiga hunk layout exceeds the 24-bit address space")

    units = []
    offset = 0
    for index in range(count):
        allocation = reader.number()
        size = (allocation & _SIZE_MASK) * 4
        memory_type = allocation >> 30
        flags = reader.number() if memory_type == 3 else memory_type << 1
        if base + offset + size > ADDRESS_LIMIT:
            raise HunkError("Amiga hunk layout exceeds the 24-bit address space")
        units.append({
            "name": f"h{index}", "linear": base + offset, "image_offset": offset,
            "size": size, "memory_flags": flags,
        })
        # Empty hunks still have a distinct address in the analysis layout.
        offset += max(_ALIGNMENT, (size + _ALIGNMENT - 1) & -_ALIGNMENT)
    return units


def _read_relocations(reader: _Reader, width: int, unit: dict, units: list[dict], image: bytearray) -> list[dict]:
    relocations = []
    while count := reader.number(width):
        target = reader.number(width)
        if target >= len(units):
            raise HunkError(f"invalid relocation target h{target} in {unit['name']}")
        for _ in range(count):
            offset = reader.number(width)
            if offset % 2 or offset + 4 > unit["size"]:
                raise HunkError(f"invalid relocation offset 0x{offset:x} in {unit['name']}")
            position = unit["image_offset"] + offset
            original = unpack_from(">I", image, position)[0]
            value = (original + units[target]["linear"]) & 0xFFFFFFFF
            pack_into(">I", image, position, value)
            relocations.append({
                "offset": offset, "target": units[target]["name"], "original": original, "value": value,
            })
    if width == 2 and reader.position % 4:
        reader.take(2)
    return relocations


def _read_symbols(reader: _Reader) -> list[dict]:
    symbols = []
    while length := reader.number():
        if length >> 24:
            raise HunkError("unsupported AmigaDOS HUNK_SYMBOL type")
        name = reader.take(4 * length).tobytes().split(b"\0", 1)[0].decode("latin-1")
        symbols.append({"name": name, "offset": reader.number()})
    return symbols


def _load_unit(reader: _Reader, unit: dict, units: list[dict], image: bytearray) -> None:
    record = reader.record_type()
    if record == 0x3E8:  # HUNK_NAME
        reader.take(4 * reader.number())
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
            unit["relocations"].extend(_read_relocations(reader, _RELOC_TYPES[record], unit, units, image))
        elif record == 0x3F0:  # HUNK_SYMBOL
            unit["symbols"].extend(_read_symbols(reader))
        elif record == 0x3F1:  # HUNK_DEBUG
            reader.take(4 * reader.number())
        else:
            raise HunkError(f"unsupported AmigaDOS hunk type 0x{record:x} in {unit['name']}")


def build_hunk_image(data: bytes, program: str, base: int = DEFAULT_BASE_ADDRESS) -> tuple[bytes, dict]:
    """Lay out and relocate the resident hunks of an AmigaDOS executable."""
    if not 0 <= base < ADDRESS_LIMIT or base % _ALIGNMENT:
        raise HunkError("Amiga base address must be 16-byte aligned and within the 24-bit address space")
    reader = _Reader(data)
    units = _read_layout(reader, base)
    last = units[-1]
    image = bytearray(last["image_offset"] + last["size"])
    for unit in units:
        _load_unit(reader, unit, units, image)
    if units[0]["kind"] != "code" or not units[0]["file_size"]:
        raise HunkError("AmigaDOS entry point requires CODE in h0")
    if reader.position != len(data):
        record = reader.record_type()
        raise HunkError(f"unexpected AmigaDOS record 0x{record:x} after the last hunk")
    program_map = {
        "version": 1, "format": "HUNK", "program": program, "base_address": base,
        "entry": {"unit_address": "h0:0000", "linear": base}, "units": units,
    }
    tables = [table for unit in units if unit["kind"] == "code"
              for table in m68k_jump_table_records(image, unit, units=units)]
    if tables:
        program_map["jump_tables"] = tables
    return bytes(image), program_map
