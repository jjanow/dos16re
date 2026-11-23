"""Export Atari ST GEMDOS executables as flat, relocated 68k images."""

from collections.abc import Iterator
from struct import Struct, pack_into, unpack_from

from .image import DEFAULT_M68K_BASE, M68K_ADDRESS_LIMIT
from .jump_tables import m68k_jump_table_records

PRG_MAGIC = b"\x60\x1a"
_HEADER = Struct(">2s6IH")
_SYMBOL = Struct(">8sHI")


class PrgError(ValueError):
    """A malformed Atari ST GEMDOS executable."""


def _relocation_offsets(table: memoryview) -> Iterator[int]:
    if len(table) < 4:
        raise PrgError("truncated GEMDOS relocation table")
    offset = unpack_from(">I", table)[0]
    if offset == 0:
        return
    yield offset
    for delta in table[4:]:
        if delta == 0:
            return
        if delta == 1:
            offset += 254
        else:
            offset += delta
            yield offset
    raise PrgError("unterminated GEMDOS relocation table")


def _import_symbols(table: memoryview, units: list[dict]) -> None:
    # DRI records have fixed-size slots. GST uses an extra slot for long names.
    if len(table) % _SYMBOL.size:
        return
    by_type = dict(zip((0x0200, 0x0400, 0x0100), units, strict=True))
    position = 0
    while position < len(table):
        name, flags, value = _SYMBOL.unpack_from(table, position)
        position += _SYMBOL.size
        if (flags & 0x00FF) == 0x48:
            if position == len(table):
                return
            name += bytes(table[position:position + _SYMBOL.size])
            position += _SYMBOL.size
            flags &= ~0x48
        # Skip equates, register and external symbols, and module/library markers.
        unit = by_type.get(flags & ~0xA000)
        if unit is None:
            continue
        name = name.split(b"\0", 1)[0].decode("latin-1")
        offset = value - unit["image_offset"]
        if name and 0 <= offset < unit["size"]:
            unit["symbols"].append({"name": name, "offset": offset})


def build_prg_image(data: bytes, program: str, base: int = DEFAULT_M68K_BASE) -> tuple[bytes, dict]:
    """Place TEXT, DATA, and BSS consecutively and apply TEXT-relative fixups."""
    if not 0 <= base < M68K_ADDRESS_LIMIT or base % 2:
        raise PrgError("Atari ST base address must be even and within the 24-bit address space")
    if len(data) < _HEADER.size:
        raise PrgError("truncated GEMDOS program header")
    magic, text_size, data_size, bss_size, symbol_size, reserved, flags, absolute = _HEADER.unpack_from(data)
    if magic != PRG_MAGIC:
        raise PrgError("missing GEMDOS 0x601a magic")
    if text_size < 2:
        raise PrgError("GEMDOS entry point requires a TEXT segment of at least two bytes")

    initialized = text_size + data_size
    if base + initialized + bss_size > M68K_ADDRESS_LIMIT:
        raise PrgError("Atari ST layout exceeds the 24-bit address space")
    symbol_start = _HEADER.size + initialized
    relocation_start = symbol_start + symbol_size
    if relocation_start > len(data):
        raise PrgError("truncated GEMDOS TEXT, DATA, or symbol table")

    units = [
        {"name": name, "kind": kind, "linear": base + start, "image_offset": start, "size": size,
         "file_offset": _HEADER.size + start if kind != "bss" else None,
         "file_size": size if kind != "bss" else 0, "symbols": [], "relocations": []}
        for name, kind, start, size in (
            ("text", "code", 0, text_size), ("data", "data", text_size, data_size),
            ("bss", "bss", initialized, bss_size),
        )
    ]
    view = memoryview(data)
    if reserved == 0 and symbol_size:
        _import_symbols(view[symbol_start:relocation_start], units)
    image = bytearray(view[_HEADER.size:symbol_start])
    if not absolute:
        for offset in _relocation_offsets(view[relocation_start:]):
            if offset % 2 or offset + 4 > initialized:
                raise PrgError(f"invalid GEMDOS relocation offset 0x{offset:x}")
            original = unpack_from(">I", image, offset)[0]
            value = (original + base) & 0xFFFFFFFF
            pack_into(">I", image, offset, value)
            unit = units[0] if offset < text_size else units[1]
            unit["relocations"].append({"offset": offset - unit["image_offset"], "original": original, "value": value})
    image.extend(bytes(bss_size))
    program_map = {
        "version": 1, "format": "PRG", "program": program, "base_address": base,
        "header": {"reserved": reserved, "flags": flags, "absolute": bool(absolute),
                   "symbol_table_size": symbol_size},
        "entry": {"unit_address": "text:0000", "linear": base}, "units": units,
    }
    tables = m68k_jump_table_records(image, units[0], units=units)
    if tables:
        program_map["jump_tables"] = tables
    return bytes(image), program_map
