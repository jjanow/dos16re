"""Build static Commodore 64 memory images from PRG files or D64 members."""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import accumulate
from struct import unpack_from

from .image import C64_ADDRESS_LIMIT, C64_FORMAT

DEFAULT_BANK = 7
_SECTOR_SIZE = 256
_TRACK_STARTS = tuple(accumulate((21,) * 17 + (19,) * 7 + (18,) * 6 + (17,) * 12, initial=0))
_BASIC_START = 0x0801


class C64Error(ValueError):
    """An invalid Commodore 64 disk, program, or memory layout."""


class D64Image:
    """Read PRG files from a standard sector image, optionally with error bytes."""

    def __init__(self, data: bytes):
        for tracks in (35, 40, 42):
            sectors = _TRACK_STARTS[tracks]
            size = sectors * _SECTOR_SIZE
            if len(data) in (size, size + sectors):
                self._data = memoryview(data)[:size]
                self._tracks = tracks
                break
        else:
            raise C64Error("expected a 35-, 40-, or 42-track D64 image")

    def _chain(self, track: int, sector: int) -> Iterator[memoryview]:
        seen = set()
        while track:
            if not (1 <= track <= self._tracks
                    and 0 <= sector < _TRACK_STARTS[track] - _TRACK_STARTS[track - 1]):
                raise C64Error(f"invalid D64 track/sector {track}/{sector}")
            if (track, sector) in seen:
                raise C64Error(f"D64 sector chain loops at {track}/{sector}")
            seen.add((track, sector))
            offset = (_TRACK_STARTS[track - 1] + sector) * _SECTOR_SIZE
            block = self._data[offset:offset + _SECTOR_SIZE]
            yield block
            track, sector = block[:2]

    def read_prg(self, name: str) -> bytes:
        if not name.isascii() or not 1 <= len(name) <= 16:
            raise C64Error("expected a D64 filename of 1 to 16 ASCII characters")
        encoded = name.upper().encode("ascii").ljust(16, b"\xa0")
        matches = []
        for block in self._chain(18, 1):
            for offset in range(0, _SECTOR_SIZE, 32):
                file_type = block[offset + 2]
                if file_type & 0x87 == 0x82 and block[offset + 5:offset + 21] == encoded:
                    matches.append(tuple(block[offset + 3:offset + 5]))
        if len(matches) != 1:
            reason = "ambiguous" if matches else "not found"
            raise C64Error(f"D64 PRG {name!r} {reason}")

        contents = bytearray()
        for block in self._chain(*matches[0]):
            next_track, link = block[:2]
            if next_track == 0 and link == 0:
                raise C64Error("invalid final D64 file sector length")
            end = _SECTOR_SIZE if next_track else link + 1
            contents.extend(block[2:end])
        return bytes(contents)


@dataclass(frozen=True)
class PrgUnit:
    name: str
    source: str
    data: bytes
    address: int | None = None
    disk_file: str | None = None


def memory_map(bank: int) -> list[dict]:
    """Return the stock CPU read and write mapping for the effective 6510 port bits."""
    if not 0 <= bank <= 7:
        raise C64Error("C64 bank must be between 0 and 7")
    loram, hiram, charen = bank & 1, bank & 2, bank & 4
    basic_enabled = loram and hiram
    io_enabled = (loram or hiram) and charen
    regions = [
        (0, 2, "cpu_port", "io", "io"),
        (2, 0x0100, "zero_page", "ram", "ram"),
        (0x0100, 0x0200, "stack", "ram", "ram"),
        (0x0200, 0xA000, "low_ram", "ram", "ram"),
        (0xA000, 0xC000, "basic_rom" if basic_enabled else "basic_ram", "rom" if basic_enabled else "ram", "ram"),
        (0xC000, 0xD000, "high_ram", "ram", "ram"),
    ]
    if io_enabled:
        regions.extend((start, end, name, "io", "io") for start, end, name in (
            (0xD000, 0xD400, "vic"), (0xD400, 0xD800, "sid"), (0xD800, 0xDC00, "color_ram"),
            (0xDC00, 0xDD00, "cia1"), (0xDD00, 0xDE00, "cia2"), (0xDE00, 0xE000, "expansion_io"),
        ))
    else:
        rom = bool(loram or hiram)
        regions.append((0xD000, 0xE000, "character_rom" if rom else "io_ram", "rom" if rom else "ram", "ram"))
    regions.append((0xE000, C64_ADDRESS_LIMIT, "kernal_rom" if hiram else "kernal_ram", "rom" if hiram else "ram", "ram"))
    return [
        {"name": name, "linear": start, "size": end - start, "read": read, "write": write}
        for start, end, name, read, write in regions
    ]


def _basic_sys(payload: bytes, address: int) -> int | None:
    if address != _BASIC_START or len(payload) < 8:
        return None
    next_line = unpack_from("<H", payload)[0] - address
    if not 5 <= next_line <= len(payload) - 2 or payload[next_line - 1:next_line + 2] != bytes(3):
        return None
    match = re.fullmatch(rb" *\x9e *([0-9]{1,5}) *", payload[4:next_line - 1])
    if match:
        entry = int(match[1])
        if address + next_line + 2 <= entry < address + len(payload):
            return entry
    return None


def build_c64_image(
    units: list[PrgUnit], program: str, *, bank: int = DEFAULT_BANK, entries: list[int] | None = None,
) -> tuple[bytes, dict]:
    """Place co-resident payloads at their load addresses for one CPU memory view."""
    regions = memory_map(bank)
    if not units:
        raise C64Error("expected at least one C64 PRG")
    placements = []
    names = set()
    detected_entry = None
    for unit in units:
        name = unit.name.casefold()
        if not name or ":" in name or name.startswith("c64_") or name in names:
            raise C64Error(f"invalid or duplicate C64 unit name {unit.name!r}")
        names.add(name)
        if len(unit.data) < 3:
            raise C64Error(f"C64 PRG {unit.name!r} needs a two-byte load address and a payload")
        file_address = unpack_from("<H", unit.data)[0]
        address = file_address if unit.address is None else unit.address
        payload = unit.data[2:]
        end = address + len(payload)
        if not 0 <= address < end <= C64_ADDRESS_LIMIT:
            raise C64Error(f"C64 PRG {unit.name!r} exceeds the 16-bit address space")
        for region in regions:
            start = region["linear"]
            if region["read"] != "ram" and address < start + region["size"] and start < end:
                raise C64Error(f"C64 PRG {unit.name!r} overlaps {region['name']} in bank {bank}")
        if not placements and not entries and address == file_address:
            detected_entry = _basic_sys(payload, address)
        placements.append((address, end, unit, payload, file_address))

    placements.sort(key=lambda placement: placement[0])
    origin = placements[0][0]
    image = bytearray(placements[-1][1] - origin)
    records = []
    previous_end = origin
    for address, end, unit, payload, file_address in placements:
        if address < previous_end:
            raise C64Error(f"C64 PRG {unit.name!r} overlaps another unit at {address:04x}")
        image[address - origin:end - origin] = payload
        records.append({
            "name": unit.name, "kind": "ram", "linear": address, "size": len(payload),
            "image_offset": address - origin, "file_offset": 2, "file_size": len(payload),
            "load_address": file_address, "source": unit.source, "disk_file": unit.disk_file,
        })
        previous_end = end

    entry_records = []
    for entry in dict.fromkeys(entries or ([] if detected_entry is None else [detected_entry])):
        containing = next(
            (record for record in records if record["linear"] <= entry < record["linear"] + record["size"]), None,
        )
        if containing is None:
            raise C64Error(f"C64 entry {entry:x} is outside the loaded PRGs")
        offset = entry - containing["linear"]
        entry_records.append({"linear": entry, "unit_address": f"{containing['name']}:{offset:04x}"})

    return bytes(image), {
        "version": 1, "format": C64_FORMAT, "program": program, "base_address": origin,
        "bank": bank, "memory_map": regions, "units": records,
        "entry": entry_records[0] if entry_records else None, "entries": entry_records,
    }
