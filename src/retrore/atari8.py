"""Read Atari DOS binary loads and ATR disks into a static XL/XE CPU view."""

from dataclasses import dataclass
from itertools import groupby
from struct import unpack_from

from .image import ATARI8_FORMAT, MOS6502_ADDRESS_LIMIT

ATR_MAGIC = b"\x96\x02"
XEX_MAGIC = b"\xff\xff"
DEFAULT_PORTB = 0xFF
_RUNAD = 0x02E0
_INITAD = 0x02E2
_ATR_HEADER = 16
_BOOT_SECTOR_SIZE = 128


class Atari8Error(ValueError):
    """An invalid Atari 8-bit binary, disk image, or memory layout."""


@dataclass(frozen=True)
class Segment:
    address: int
    data: bytes
    file_offset: int = 0

    @property
    def end(self) -> int:
        return self.address + len(self.data)


@dataclass(frozen=True)
class Atari8Binary:
    segments: tuple[Segment, ...]
    kind: str
    run_address: int | None = None
    init_addresses: tuple[int, ...] = ()
    boot_entry: int | None = None

    @classmethod
    def from_xex(cls, data: bytes, name: str) -> "Atari8Binary":
        if not data.startswith(XEX_MAGIC):
            raise Atari8Error(f"Atari binary {name!r} needs an ffff XEX header")
        segments = []
        init_addresses = []
        vectors = bytearray(4)
        init_bytes = set()
        offset = 2
        while offset < len(data):
            if data[offset:offset + 2] == XEX_MAGIC:
                offset += 2
                continue
            if offset + 4 > len(data):
                raise Atari8Error(f"truncated XEX header in {name!r} at offset {offset:#x}")
            start, last = unpack_from("<HH", data, offset)
            offset += 4
            size = last - start + 1
            if size <= 0 or offset + size > len(data):
                raise Atari8Error(f"invalid or truncated XEX segment in {name!r} at {start:04x}-{last:04x}")
            segment = Segment(start, data[offset:offset + size], offset)
            if not segments:
                # Atari DOS defaults RUNAD to the first segment address.
                vectors[:2] = start.to_bytes(2, "little")
            segments.append(segment)
            for address in range(max(start, _RUNAD), min(last + 1, _INITAD + 2)):
                vectors[address - _RUNAD] = segment.data[address - start]
                if address >= _INITAD:
                    init_bytes.add(address)
            if len(init_bytes) == 2:
                init_addresses.append(unpack_from("<H", vectors, 2)[0])
                init_bytes.clear()
            offset += size
        if not segments:
            raise Atari8Error(f"XEX binary {name!r} contains no segments")
        return cls(tuple(segments), "xex", unpack_from("<H", vectors)[0], tuple(init_addresses))


class AtrImage:
    """Read an ATR with 128-byte boot sectors and 128- or 256-byte data sectors."""

    def __init__(self, data: bytes):
        if len(data) < _ATR_HEADER or not data.startswith(ATR_MAGIC):
            raise Atari8Error("expected a 16-byte Atari ATR header")
        low, self.sector_size, high = unpack_from("<HHH", data, 2)
        size = (low | high << 16) * 16
        if size != len(data) - _ATR_HEADER:
            raise Atari8Error("ATR header size does not match the disk data")
        self._data = memoryview(data)[_ATR_HEADER:]
        first_sectors = min(size // _BOOT_SECTOR_SIZE, 3)
        self._boot_size = first_sectors * _BOOT_SECTOR_SIZE
        if self.sector_size not in (128, 256) or size == 0 or (size - self._boot_size) % self.sector_size:
            raise Atari8Error("invalid ATR geometry (expected 128-byte boot sectors and 128- or 256-byte data sectors)")
        self.sector_count = first_sectors + (size - self._boot_size) // self.sector_size

    def _sector_location(self, number: int) -> tuple[int, int]:
        if not 1 <= number <= self.sector_count:
            raise Atari8Error(f"ATR sector {number} is outside the disk")
        if number <= 3:
            return (number - 1) * _BOOT_SECTOR_SIZE, _BOOT_SECTOR_SIZE
        return self._boot_size + (number - 4) * self.sector_size, self.sector_size

    def _sector(self, number: int) -> memoryview:
        start, size = self._sector_location(number)
        return self._data[start:start + size]

    def boot_binary(self) -> Atari8Binary:
        _, count, address, init = unpack_from("<BBHH", self._sector(1))
        count = count or 256
        if count > self.sector_count:
            raise Atari8Error(f"ATR boot header requests {count} sectors beyond the end of the disk")
        segments = []
        for number in range(1, count + 1):
            start, _ = self._sector_location(number)
            payload = bytes(self._data[start:start + _BOOT_SECTOR_SIZE])
            segments.append(Segment(address, payload, _ATR_HEADER + start))
            address += _BOOT_SECTOR_SIZE
        return Atari8Binary(tuple(segments), "boot", init_addresses=(init,), boot_entry=segments[0].address + 6)

    def read_file(self, name: str) -> bytes:
        if self.sector_count < 368 or self._sector(360)[0] != 2:
            raise Atari8Error("ATR has no supported Atari DOS 2.x directory")
        matches = []
        for index in range(64):
            offset, slot = divmod(index, 8)
            directory = self._sector(361 + offset)
            entry = directory[slot * 16:slot * 16 + 16]
            if entry[0] == 0:
                break
            # Ignore the lock bit. DOS 2.5 uses $03 for a closed enhanced-density entry.
            flag = entry[0] & 0xDF
            if flag != 0x42 and not (self.sector_count >= 1024 and flag == 0x03):
                continue
            stem = bytes(entry[5:13]).decode("ascii", errors="replace").rstrip()
            suffix = bytes(entry[13:16]).decode("ascii", errors="replace").rstrip()
            filename = f"{stem}.{suffix}" if suffix else stem
            if filename.upper() == name.upper():
                count, start = unpack_from("<HH", entry, 1)
                matches.append((index, count, start))
        if len(matches) != 1:
            reason = "ambiguous" if matches else "not found"
            raise Atari8Error(f"ATR disk member {name!r} {reason}")

        index, count, number = matches[0]
        contents = bytearray()
        seen = set()
        while number:
            if number in seen:
                raise Atari8Error(f"ATR disk member {name!r} has a sector loop at {number}")
            seen.add(number)
            sector = self._sector(number)
            if number <= 3 or 360 <= number <= 368 or sector[-3] >> 2 != index:
                raise Atari8Error(f"ATR disk member {name!r} has an invalid file link to sector {number}")
            size = sector[-1]
            if size > len(sector) - 3:
                raise Atari8Error(f"invalid byte count in ATR file sector {number}")
            contents.extend(sector[:size])
            number = (sector[-3] & 3) << 8 | sector[-2]
        if len(seen) != count:
            raise Atari8Error(f"ATR disk member {name!r} has a mismatched sector count")
        return bytes(contents)


@dataclass(frozen=True)
class Atari8Source:
    name: str
    source: str
    binary: Atari8Binary
    disk_file: str | None = None


def memory_map(portb: int) -> list[dict]:
    """Describe the effective stock 130XE CPU map without an external cartridge."""
    if not 0 <= portb <= 0xFF:
        raise Atari8Error("Atari XL/XE PORTB must be between 00 and ff")
    os_rom = bool(portb & 1)
    basic_rom = (portb & 2) == 0
    self_test = (portb & 0x81) == 1
    cpu_ram = "main_ram" if portb & 0x10 else f"xe_bank{(portb >> 2) & 3}"
    window = [(0x4000, 0x8000, cpu_ram, "ram")]
    if self_test:
        window = [
            (0x4000, 0x5000, cpu_ram, "ram"),
            (0x5000, 0x5800, "self_test", "rom"),
            (0x5800, 0x8000, f"{cpu_ram}_high", "ram"),
        ]
    regions = [
        (0x0000, 0x0100, "zero_page", "ram"),
        (0x0100, 0x0200, "stack", "ram"),
        (0x0200, 0x4000, "low_ram", "ram"),
        *window,
        (0x8000, 0xA000, "high_ram", "ram"),
        (0xA000, 0xC000, "basic_rom" if basic_rom else "basic_ram", "rom" if basic_rom else "ram"),
        (0xC000, 0xD000, "os_rom_low" if os_rom else "os_ram_low", "rom" if os_rom else "ram"),
        (0xD000, 0xD100, "gtia", "io"),
        (0xD100, 0xD200, "pbi", "io"),
        (0xD200, 0xD300, "pokey", "io"),
        (0xD300, 0xD400, "pia", "io"),
        (0xD400, 0xD500, "antic", "io"),
        (0xD500, 0xD600, "cartridge_io", "io"),
        (0xD600, 0xD800, "expansion_io", "io"),
        (0xD800, MOS6502_ADDRESS_LIMIT, "os_rom_high" if os_rom else "os_ram_high", "rom" if os_rom else "ram"),
    ]
    return [
        {"name": name, "linear": start, "size": end - start, "read": kind,
         "write": "none" if kind == "rom" else kind}
        for start, end, name, kind in regions
    ]


def build_atari8_image(
    sources: list[Atari8Source], program: str, *, portb: int = DEFAULT_PORTB, entries: list[int] | None = None,
) -> tuple[bytes, dict]:
    """Apply file segments in order and export the visible, initialized RAM ranges."""
    regions = memory_map(portb)
    image = bytearray(MOS6502_ADDRESS_LIMIT)
    owners = [None] * MOS6502_ADDRESS_LIMIT
    source_records = []
    names = set()
    for index, source in enumerate(sources):
        name = source.name.casefold()
        if not name or ":" in name or name.startswith("atari8_") or name in names:
            raise Atari8Error(f"invalid or duplicate Atari 8-bit source name {source.name!r}")
        names.add(name)
        segments = []
        unmapped_writes = []
        binary = source.binary
        for segment in binary.segments:
            if not 0 <= segment.address < segment.end <= MOS6502_ADDRESS_LIMIT:
                raise Atari8Error(f"Atari 8-bit source {source.name!r} is empty or exceeds the 16-bit address space")
            segments.append({"linear": segment.address, "size": len(segment.data), "file_offset": segment.file_offset})
            for region in regions:
                start = max(region["linear"], segment.address)
                end = min(region["linear"] + region["size"], segment.end)
                if start >= end:
                    continue
                offset = start - segment.address
                if region["read"] == "ram":
                    image[start:end] = segment.data[offset:offset + end - start]
                    owners[start:end] = [index] * (end - start)
                elif binary.kind == "xex":
                    unmapped_writes.append({"linear": start, "size": end - start, "region": region["name"],
                                            "file_offset": segment.file_offset + offset})
                else:
                    raise Atari8Error(f"Atari 8-bit source {source.name!r} overlaps {region['name']} in PORTB {portb:02x}")
        source_records.append({
            "name": source.name, "source": source.source, "kind": binary.kind, "disk_file": source.disk_file,
            "segments": segments, "run_address": binary.run_address, "init_addresses": binary.init_addresses,
            "boot_entry": binary.boot_entry, "unmapped_writes": unmapped_writes,
        })

    ranges = []
    for index, addresses in groupby(range(MOS6502_ADDRESS_LIMIT), key=owners.__getitem__):
        if index is not None:
            start = next(addresses)
            size = 1 + sum(1 for _ in addresses)
            ranges.append((index, start, size))
    if not ranges:
        raise Atari8Error("no Atari 8-bit bytes are loaded into visible RAM")
    unit_counts = [0] * len(sources)
    for index, _, _ in ranges:
        unit_counts[index] += 1
    origin = ranges[0][1]
    units = []
    for index, start, size in ranges:
        source = sources[index]
        name = source.name if unit_counts[index] == 1 else f"{source.name}_{start:04x}"
        units.append({
            "name": name, "kind": "ram", "linear": start, "size": size, "image_offset": start - origin,
            "file_size": size, "source": source.source, "disk_file": source.disk_file,
        })
    if len({unit["name"].casefold() for unit in units}) != len(units):
        raise Atari8Error("duplicate Atari 8-bit memory block name")

    if not entries:
        entries = []
        for index, source in enumerate(sources):
            binary = source.binary
            for address in (binary.boot_entry, binary.run_address, *binary.init_addresses):
                # A later file can replace the code at an earlier file's entry.
                if address is not None and owners[address] is not None and owners[address] <= index:
                    entries.append(address)
    entry_records = []
    for address in dict.fromkeys(entries):
        unit = next((unit for unit in units if unit["linear"] <= address < unit["linear"] + unit["size"]), None)
        if unit is None:
            raise Atari8Error(f"Atari 8-bit entry {address:x} is outside the loaded RAM")
        offset = address - unit["linear"]
        entry_records.append({"linear": address, "unit_address": f"{unit['name']}:{offset:04x}"})

    _, last, size = ranges[-1]
    return bytes(image[origin:last + size]), {
        "version": 1, "format": ATARI8_FORMAT, "program": program, "base_address": origin, "portb": portb,
        "memory_map": regions, "sources": source_records, "units": units,
        "entry": entry_records[0] if entry_records else None, "entries": entry_records,
    }
