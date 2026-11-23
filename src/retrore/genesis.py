"""Export a linear Sega Genesis / Mega Drive cartridge in its 68000 address space."""

from struct import iter_unpack, unpack_from

from .image import GENESIS_FORMAT, MAP_VERSION, M68K_ADDRESS_LIMIT

_HEADER_START = 0x100
_CODE_START = 0x200
_CART_END = 0x400000
_SYSTEM_NAMES = (b"SEGA", b"SEGAGENESIS", b"SEGAMEGADRIVE")
_VECTOR_NAMES = {
    0: "INITIAL_SSP", 1: "RESET_VECTOR", 2: "BUS_ERROR_VECTOR", 3: "ADDRESS_ERROR_VECTOR",
    4: "ILLEGAL_INSTRUCTION_VECTOR", 5: "DIVIDE_BY_ZERO_VECTOR", 6: "CHK_VECTOR", 7: "TRAPV_VECTOR",
    8: "PRIVILEGE_VIOLATION_VECTOR", 9: "TRACE_VECTOR", 10: "LINE_A_VECTOR", 11: "LINE_F_VECTOR",
    15: "UNINITIALIZED_INTERRUPT_VECTOR", 24: "SPURIOUS_INTERRUPT_VECTOR",
    26: "EXTERNAL_INTERRUPT_VECTOR", 28: "HBLANK_VECTOR", 30: "VBLANK_VECTOR",
    **{index: f"IRQ{index - 24}_VECTOR" for index in (25, 27, 29, 31)},
    **{index: f"TRAP_{index - 32}_VECTOR" for index in range(32, 48)},
}
_HARDWARE = {
    0xA04000: ("YM2612_ADDRESS_0", 1), 0xA04001: ("YM2612_DATA_0", 1),
    0xA04002: ("YM2612_ADDRESS_1", 1), 0xA04003: ("YM2612_DATA_1", 1),
    0xA06000: ("Z80_BANK", 1), 0xA10001: ("VERSION", 1),
    0xA10003: ("DATA_PORT_1", 1), 0xA10005: ("DATA_PORT_2", 1), 0xA10007: ("DATA_PORT_EXP", 1),
    0xA10009: ("CONTROL_PORT_1", 1), 0xA1000B: ("CONTROL_PORT_2", 1), 0xA1000D: ("CONTROL_PORT_EXP", 1),
    0xA11100: ("Z80_BUS_REQUEST", 2), 0xA11200: ("Z80_RESET", 2),
    0xA130F1: ("CART_RAM_CONTROL", 1), 0xA14000: ("TMSS", 4),
    0xC00000: ("VDP_DATA", 2), 0xC00002: ("VDP_DATA_MIRROR", 2),
    0xC00004: ("VDP_CONTROL", 2), 0xC00006: ("VDP_CONTROL_MIRROR", 2),
    0xC00008: ("VDP_HV_COUNTER", 2), 0xC00011: ("PSG", 1),
}


class GenesisError(ValueError):
    """An invalid or unsupported Genesis cartridge or memory view."""


def is_genesis(data: bytes) -> bool:
    return b"".join(data[_HEADER_START:0x110].split()) in _SYSTEM_NAMES


def _text(data: bytes, start: int, end: int) -> str:
    return data[start:end].decode("ascii", errors="replace").strip(" \0")


def _external_ram(data: bytes) -> dict | None:
    if data[0x1B0:0x1B2] != b"RA":
        return None
    flags, device, start, end = unpack_from(">BBII", data, 0x1B2)
    return {
        "start": start, "end": end, "nonvolatile": bool(flags & 0x40),
        "bus": ("word", "other", "even", "odd")[(flags >> 3) & 3],
        "device": {0: "unspecified", 1: "sram", 2: "eeprom"}.get(device >> 5, "other"),
        "flags": flags, "device_byte": device,
    }


def _region(name: str, linear: int, size: int, kind: str, **details) -> dict:
    return {"name": name, "linear": linear, "size": size, "read": kind,
            "write": "none" if kind == "rom" else kind, **details}


def _sram_region(declared: dict | None, override: tuple[int, int] | None, rom_size: int) -> dict | None:
    if override is not None:
        start, end = override
        bus = "word" if (start ^ end) & 1 else ("odd" if start & 1 else "even")
    elif declared and declared["device"] in ("sram", "unspecified") and declared["bus"] != "other":
        start, end, bus = (declared[key] for key in ("start", "end", "bus"))
    else:
        return None

    first, last = (start & 1, end & 1)
    if not 0 <= start <= end < _CART_END or (first, last) != {"word": (0, 1), "even": (0, 0), "odd": (1, 1)}[bus]:
        if override is not None:
            raise GenesisError("SRAM range must use valid byte lanes within 000000–3fffff")
        return None
    if (start & ~1) < rom_size:
        if override is not None:
            raise GenesisError("SRAM override overlaps the linear ROM")
        return None
    # Map the word-aligned bus aperture. The header or override specifies which lanes contain SRAM.
    base, limit = start & ~1, (end | 1) + 1
    return _region("cart_sram", base, limit - base, "ram", bus=bus, start=start, end=end,
                   capacity=end - start + 1 if bus == "word" else (end - start) // 2 + 1,
                   source="override" if override is not None else "header")


def _memory_map(rom_size: int, sram: dict | None) -> list[dict]:
    regions = [_region("cart_rom", 0, rom_size, "rom")]
    if sram is not None:
        regions.append(sram)
    regions.extend((
        _region("z80_ram", 0xA00000, 0x2000, "ram"),
        _region("ym2612", 0xA04000, 4, "io"),
        _region("z80_bank", 0xA06000, 2, "io"),
        _region("system_io", 0xA10000, 0x20, "io"),
        _region("z80_bus_request", 0xA11100, 2, "io"),
        _region("z80_reset", 0xA11200, 2, "io"),
        _region("cart_control", 0xA130F0, 0x10, "io"),
        _region("tmss", 0xA14000, 4, "io"),
        _region("vdp", 0xC00000, 0x20, "io"),
        _region("work_ram", 0xFF0000, 0x10000, "ram"),
    ))
    return regions


def build_genesis_image(
    data: bytes, program: str, *, entries: list[int] | None = None, sram: tuple[int, int] | None = None,
) -> tuple[bytes, dict]:
    if len(data) < _CODE_START + 2 or not is_genesis(data):
        raise GenesisError("expected a raw Genesis / Mega Drive ROM with a Sega header at file offset 100")
    if len(data) & 1:
        raise GenesisError("Genesis ROM length must be even")
    rom_start, rom_end, ram_start, ram_end = unpack_from(">4I", data, 0x1A0)
    if rom_start != 0 or max(len(data), rom_end + 1) > _CART_END:
        raise GenesisError("only linear Genesis ROMs at address 0 up to 4 MiB are supported")
    if rom_end >= len(data):
        raise GenesisError(f"truncated Genesis ROM: header ends at {rom_end:06x}, file ends at {len(data) - 1:06x}")

    external_ram = _external_ram(data)
    sram_region = _sram_region(external_ram, sram, len(data))
    cartridge = {
        "system": _text(data, 0x100, 0x110), "copyright": _text(data, 0x110, 0x120),
        "domestic_title": _text(data, 0x120, 0x150), "overseas_title": _text(data, 0x150, 0x180),
        "product": _text(data, 0x180, 0x18E), "checksum": unpack_from(">H", data, 0x18E)[0],
        "computed_checksum": sum(word for word, in iter_unpack(">H", memoryview(data)[_CODE_START:])) & 0xFFFF,
        "io_support": _text(data, 0x190, 0x1A0), "region": _text(data, 0x1F0, 0x200),
        "rom": {"start": rom_start, "end": rom_end, "file_offset": 0, "size": len(data)},
        "work_ram": {"start": ram_start, "end": ram_end}, "external_ram": external_ram,
    }
    vectors = []
    for index, (value,) in enumerate(iter_unpack(">I", data[:_HEADER_START])):
        vector = {"name": _VECTOR_NAMES.get(index, f"VECTOR_{index:02X}"),
                  "linear": index * 4, "value": value}
        target = value & (M68K_ADDRESS_LIMIT - 1)
        if index and _CODE_START <= target < len(data) and target % 2 == 0:
            vector["target"] = target
        vectors.append(vector)

    entry_addresses = [vector["target"] for vector in vectors if "target" in vector]
    for address in entries or ():
        if not _CODE_START <= address < len(data) or address % 2:
            raise GenesisError(f"Genesis entry {address:x} must be even and within the cartridge code range")
        entry_addresses.append(address)
    entry_records = [{"linear": address, "unit_address": f"rom:{address - _CODE_START:04x}"}
                     for address in dict.fromkeys(entry_addresses)]
    units = []
    for name, start, end in (("vectors", 0, _HEADER_START), ("header", _HEADER_START, _CODE_START),
                             ("rom", _CODE_START, len(data))):
        units.append({
            "name": name, "kind": "code" if name == "rom" else "data", "writable": False,
            "linear": start, "size": end - start, "image_offset": start, "file_offset": start,
            "file_size": end - start, "source": program, "relocations": [], "symbols": [],
        })
    units[0]["symbols"] = [{"name": vector["name"], "offset": vector["linear"]} for vector in vectors]
    return data, {
        "version": MAP_VERSION, "format": GENESIS_FORMAT, "program": program, "base_address": 0,
        "memory_view": "linear", "cartridge": cartridge, "initial_ssp": vectors[0]["value"],
        "units": units, "memory_map": _memory_map(len(data), sram_region), "vectors": vectors,
        "hardware_labels": [{"linear": address, "name": name, "width": width}
                            for address, (name, width) in _HARDWARE.items()],
        "entry": entry_records[0] if entry_records else None, "entries": entry_records,
    }
