"""Export a selected NES or Famicom cartridge CPU address space."""

from struct import unpack_from

from .errors import CodedError
from .image import MAP_VERSION, NES_FORMAT

NES_MAGIC = b"NES\x1a"
_HEADER_SIZE = 16
_TRAINER_SIZE = 512
_PRG_BANK_SIZE = 0x2000
_VECTOR_START = 0xFFFA
_VECTORS = ("NMI_VECTOR", "RESET_VECTOR", "IRQ_VECTOR")
_HARDWARE = {
    0x2000: "PPUCTRL", 0x2001: "PPUMASK", 0x2002: "PPUSTATUS",
    0x2003: "OAMADDR", 0x2004: "OAMDATA", 0x2005: "PPUSCROLL",
    0x2006: "PPUADDR", 0x2007: "PPUDATA", 0x4014: "OAMDMA",
    0x4015: "APUSTATUS", 0x4016: "JOY1", 0x4017: "JOY2_FRAME_COUNTER",
}


class NesError(CodedError):
    """An invalid or unsupported NES cartridge or memory view."""


def _rom_size(low: int, high: int, unit: int) -> int:
    if high == 0xF:
        return (1 << (low >> 2)) * (2 * (low & 3) + 1)
    return (high << 8 | low) * unit


def _ram_size(shift: int) -> int:
    return 64 << shift if shift else 0


def _cartridge(data: bytes) -> dict:
    if not data.startswith(NES_MAGIC) or len(data) < _HEADER_SIZE:
        raise NesError("expected a complete iNES or NES 2.0 header")
    flags6, flags7 = data[6:8]
    version = flags7 & 0x0C
    if version not in (0, 8):
        raise NesError("unsupported iNES header version")
    if flags7 & 3:
        raise NesError("only standard NES / Famicom cartridges are supported")
    nes2 = version == 8
    mapper = (flags7 & 0xF0) | (flags6 >> 4)
    submapper = None
    battery = bool(flags6 & 2)
    if nes2:
        mapper |= (data[8] & 0xF) << 8
        submapper = data[8] >> 4
        prg_size = _rom_size(data[4], data[9] & 0xF, 0x4000)
        chr_size = _rom_size(data[5], data[9] >> 4, 0x2000)
        prg_ram, prg_nvram = _ram_size(data[10] & 0xF), _ram_size(data[10] >> 4)
        chr_ram, chr_nvram = _ram_size(data[11] & 0xF), _ram_size(data[11] >> 4)
    else:
        prg_size, chr_size = data[4] * 0x4000, data[5] * 0x2000
        work_ram = (data[8] or 1) * 0x2000 if data[8] or battery or mapper == 4 else 0
        prg_ram, prg_nvram = (0, work_ram) if battery else (work_ram, 0)
        chr_ram, chr_nvram = (0 if chr_size else 0x2000), 0
    trainer_size = _TRAINER_SIZE if flags6 & 4 else 0
    prg_offset = _HEADER_SIZE + trainer_size
    chr_offset = prg_offset + prg_size
    end = chr_offset + chr_size
    if not prg_size:
        raise NesError("cartridge has no PRG ROM")
    for label, needed in (("trainer", prg_offset), ("PRG ROM", chr_offset), ("CHR ROM", end)):
        if len(data) < needed:
            raise NesError(f"truncated NES {label}: expected at least {needed} file bytes, got {len(data)}")
    return {
        "header": "NES 2.0" if nes2 else "iNES", "mapper": mapper, "submapper": submapper,
        "battery": battery, "mirroring": "four-screen" if flags6 & 8 else "vertical" if flags6 & 1 else "horizontal",
        "trainer": {"file_offset": _HEADER_SIZE, "size": trainer_size} if trainer_size else None,
        "prg_rom": {"file_offset": prg_offset, "size": prg_size},
        "chr_rom": {"file_offset": chr_offset, "size": chr_size},
        "prg_ram_size": prg_ram, "prg_nvram_size": prg_nvram,
        "chr_ram_size": chr_ram, "chr_nvram_size": chr_nvram,
        "trailing_size": len(data) - end,
    }


def _prg_slots(cartridge: dict, mode: int | None, r6: int | None, r7: int | None) -> tuple[str, dict | None, list]:
    """Return the bank and selection source in each successive PRG window."""
    mapper, submapper = cartridge["mapper"], cartridge["submapper"]
    size = cartridge["prg_rom"]["size"]
    if mapper == 0 and submapper in (None, 0):
        if any(value is not None for value in (mode, r6, r7)):
            raise NesError("NES PRG mode and bank options require mapper 4 (MMC3)")
        if size not in (0x4000, 0x8000):
            raise NesError("NROM requires 16 or 32 KiB of PRG ROM")
        return "NROM", None, [(0, "fixed"), (size // 0x4000 - 1, "fixed")]
    if mapper != 4 or submapper not in (None, 0):
        suffix = "" if submapper is None else f", submapper {submapper}"
        raise NesError(f"unsupported NES mapper {mapper}{suffix}; expected NROM or MMC3")
    count, remainder = divmod(size, _PRG_BANK_SIZE)
    if remainder or not 4 <= count <= 64 or count & (count - 1):
        raise NesError("MMC3 requires a power of two from 4 to 64 PRG banks of 8 KiB")
    mode = 0 if mode is None else mode
    r6 = 0 if r6 is None else r6
    r7 = 1 if r7 is None else r7
    if mode not in (0, 1):
        raise NesError("MMC3 PRG mode must be 0 or 1")
    for register, bank in (("R6", r6), ("R7", r7)):
        if not 0 <= bank < count:
            raise NesError(f"MMC3 {register} bank {bank:x} is outside the available range 0–{count - 1:x}")
    slots = [(r6, "r6"), (r7, "r7"), (count - 2, "fixed"), (count - 1, "fixed")]
    if mode == 1:
        slots[0], slots[2] = slots[2], slots[0]
    return "MMC3", {"mode": mode, "r6": r6, "r7": r7}, slots


def _memory_map(cartridge: dict, view: str) -> list[dict]:
    work_ram = cartridge["prg_ram_size"] + cartridge["prg_nvram_size"]
    regions = [
        (0x0000, 0x0100, "zero_page", "ram", "ram"),
        (0x0100, 0x0200, "stack", "ram", "ram"),
        (0x0200, 0x0800, "ram", "ram", "ram"),
        (0x0800, 0x2000, "ram_mirrors", "ram", "ram"),
        (0x2000, 0x2008, "ppu", "io", "io"),
        (0x2008, 0x4000, "ppu_mirrors", "io", "io"),
        (0x4000, 0x4018, "apu_io", "io", "io"),
        (0x4018, 0x4020, "disabled_io", "open_bus", "none"),
        (0x4020, 0x6000, "expansion", "open_bus", "none"),
    ]
    if work_ram:
        regions.append((0x6000, 0x8000, "prg_ram", "ram", "ram"))
    elif cartridge["trainer"]:
        regions.extend([
            (0x6000, 0x7000, "cart_open_low", "open_bus", "none"),
            (0x7000, 0x7200, "trainer", "ram", "ram"),
            (0x7200, 0x8000, "cart_open_high", "open_bus", "none"),
        ])
    else:
        regions.append((0x6000, 0x8000, "cart_open", "open_bus", "none"))
    regions.append((0x8000, 0x10000, "prg_rom", "rom", "mapper" if view == "MMC3" else "none"))
    return [{"linear": start, "size": end - start, "name": name, "read": read, "write": write}
            for start, end, name, read, write in regions]


def build_nes_image(
    data: bytes, program: str, *, mode: int | None = None, r6: int | None = None, r7: int | None = None,
    entries: list[int] | None = None,
) -> tuple[bytes, dict]:
    cartridge = _cartridge(data)
    view, prg_registers, slots = _prg_slots(cartridge, mode, r6, r7)
    if cartridge["prg_ram_size"] + cartridge["prg_nvram_size"] > 0x2000:
        raise NesError("more than 8 KiB of NES cartridge RAM is unsupported")
    trainer = cartridge["trainer"]
    origin = 0x7000 if trainer else 0x8000
    image = bytearray(0x10000 - origin)
    units = []

    def place(name: str, address: int, size: int, file_offset: int, *, rom: bool, **details) -> None:
        offset = address - origin
        image[offset:offset + size] = data[file_offset:file_offset + size]
        units.append({
            "name": name, "kind": "rom" if rom else "ram", "linear": address, "size": size,
            "image_offset": offset, "file_size": size, "file_offset": file_offset, "source": program,
            "writable": not rom, **details,
        })

    if trainer:
        place("trainer", 0x7000, trainer["size"], trainer["file_offset"], rom=False)
    size = 0x8000 // len(slots)
    for index, (bank, selection) in enumerate(slots):
        address = 0x8000 + index * size
        place(f"prg_{address:04x}", address, size, cartridge["prg_rom"]["file_offset"] + bank * size,
              rom=True, bank=bank, selection=selection)

    vectors = [{"name": name, "linear": _VECTOR_START + index * 2, "target": target}
               for index, (name, target) in enumerate(zip(_VECTORS, unpack_from("<3H", image, len(image) - 6)))]
    units[-1]["symbols"] = [{"name": vector["name"], "offset": vector["linear"] - units[-1]["linear"]}
                            for vector in vectors]
    rom_code = range(0x8000, _VECTOR_START)
    trainer_code = range(origin, origin + _TRAINER_SIZE) if trainer else range(0)
    if not entries:
        # Prefer reset as the primary entry, retaining any mapped interrupt handlers.
        entries = [vector["target"] for vector in (vectors[1], vectors[0], vectors[2])
                   if vector["target"] in rom_code or vector["target"] in trainer_code]
    entry_records = []
    for address in dict.fromkeys(entries):
        if address in trainer_code:
            unit_address = f"trainer:{address - origin:04x}"
        elif address in rom_code:
            start = 0x8000 + (address - 0x8000) // size * size
            unit_address = f"prg_{start:04x}:{address - start:04x}"
        else:
            raise NesError(f"NES entry {address:x} is outside the loaded program code range")
        entry_records.append({"linear": address, "unit_address": unit_address})
    return bytes(image), {
        "version": MAP_VERSION, "format": NES_FORMAT, "program": program, "base_address": origin,
        "memory_view": view, "prg_registers": prg_registers, "cartridge": cartridge, "units": units,
        "memory_map": _memory_map(cartridge, view), "vectors": vectors,
        "hardware_labels": [{"linear": address, "name": name} for address, name in _HARDWARE.items()],
        "entry": entry_records[0] if entry_records else None, "entries": entry_records,
    }
