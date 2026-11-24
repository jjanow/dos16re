"""Load binary files into a static Apple II Plus memory view."""

from collections.abc import Iterator
from dataclasses import asdict, dataclass
from struct import unpack_from

from .image import APPLE2_FORMAT, MOS6502_ADDRESS_LIMIT, SourceSpan, slice_source_spans

DEFAULT_LC = 0xC082
DISK_SUFFIXES = (".dsk", ".do", ".po", ".d13")
_SECTOR_SIZE = 256
_TRACKS = 35
_SECTOR_ORDERS = {
    "physical": tuple(range(16)),
    "dos": (0, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 15),
    "prodos": (0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15),
}
_LOW_ASCII = bytes(value & 0x7F for value in range(256))
_RDOS21_CATALOG_MARKER = bytes(value | 0x80 for value in b"<NAME>")


class Apple2Error(ValueError):
    """An invalid Apple II disk, binary, or memory layout."""


@dataclass(frozen=True)
class Binary:
    payload: bytes
    load_address: int | None
    file_offset: int = 0
    container_spans: tuple[SourceSpan, ...] = ()

    @classmethod
    def from_dos(cls, data: bytes, name: str, spans: tuple[SourceSpan, ...] = ()) -> "Binary":
        if len(data) < 4:
            raise Apple2Error(f"Apple II binary {name!r} needs a four-byte DOS header")
        address, length = unpack_from("<HH", data)
        if not 0 < length <= len(data) - 4:
            raise Apple2Error(f"invalid length in DOS binary {name!r}")
        return cls(data[4:4 + length], address, 4, slice_source_spans(spans, 4, length))


def _filename(data: memoryview) -> str:
    return bytes(data).translate(_LOW_ASCII).decode("ascii").rstrip(" ")


class SectorImage:
    """Read binary members from DOS 3.3 or RDOS sector images."""

    def __init__(self, data: bytes, *, order: str | None = None):
        if len(data) not in (_TRACKS * 13 * _SECTOR_SIZE, _TRACKS * 16 * _SECTOR_SIZE):
            raise Apple2Error("expected a 35-track Apple II sector image (13 or 16 sectors per track)")
        if order is not None and order not in _SECTOR_ORDERS:
            raise Apple2Error(f"unknown Apple II sector order {order!r}")
        self._data = memoryview(data)
        self._stride = len(data) // _TRACKS // _SECTOR_SIZE
        self._sectors = self._stride
        self.order = order or "dos"
        self._slots = self._sector_slots("dos", self.order)

        first = self._sector(1, 0)
        signature = _filename(first[:24])
        if signature.startswith("RDOS 3.3") and self._stride == 16:
            self.filesystem = "RDOS 3.3"
            self._slots = self._sector_slots("prodos", self.order)
        elif signature.startswith("RDOS 2.1"):
            self.filesystem = "RDOS 2.1"
            self._sectors = 13
            if order is None:
                self.order = self._rdos21_order()
            self._slots = self._sector_slots("physical", self.order)
        else:
            if self._stride != 16 or tuple(self._sector(17, 0)[0x34:0x38]) != (35, 16, 0, 1):
                raise Apple2Error("expected an Apple DOS 3.3 or SSI RDOS 2.1/3.3 disk catalog")
            self.filesystem = "DOS 3.3"

    def _sector_slots(self, filesystem_order: str, image_order: str) -> tuple[int, ...]:
        if self._stride == 13:
            return tuple(range(13))
        image_slots = _SECTOR_ORDERS[image_order]
        return tuple(image_slots.index(sector) for sector in _SECTOR_ORDERS[filesystem_order])

    def _rdos21_order(self) -> str:
        if self._stride == 16:
            # RDOS catalog code has a high-bit <NAME> string in physical track 1, sector 12.
            for candidate in ("physical", "dos", "prodos"):
                slots = self._sector_slots("physical", candidate)
                start = (self._stride + slots[12]) * _SECTOR_SIZE + 0xA2
                if self._data[start:start + len(_RDOS21_CATALOG_MARKER)] == _RDOS21_CATALOG_MARKER:
                    return candidate
        return "physical"

    def _sector_offset(self, track: int, sector: int) -> int:
        if not (0 <= track < _TRACKS and 0 <= sector < self._sectors):
            raise Apple2Error(f"invalid Apple II track/sector {track}/{sector}")
        return (track * self._stride + self._slots[sector]) * _SECTOR_SIZE

    def _sector(self, track: int, sector: int) -> memoryview:
        start = self._sector_offset(track, sector)
        return self._data[start:start + _SECTOR_SIZE]

    def _chain(self, track: int, sector: int) -> Iterator[memoryview]:
        seen = set()
        while track:
            if (track, sector) in seen:
                raise Apple2Error(f"Apple DOS sector chain loops at {track}/{sector}")
            seen.add((track, sector))
            block = self._sector(track, sector)
            yield block
            track, sector = block[1:3]

    def _dos_catalog(self) -> Iterator[tuple[str, memoryview]]:
        for block in self._chain(*self._sector(17, 0)[1:3]):
            for offset in range(11, _SECTOR_SIZE, 35):
                entry = block[offset:offset + 35]
                if entry[0] == 0:
                    break
                if entry[0] != 0xFF:
                    yield _filename(entry[3:33]), entry

    def _rdos_catalog(self) -> Iterator[tuple[str, memoryview]]:
        for sector in range(11 if self._sectors == 13 else 16):
            block = self._sector(1, sector)
            for offset in range(0, _SECTOR_SIZE, 32):
                entry = block[offset:offset + 32]
                if entry[0] == 0:
                    return
                if entry[0] != 0x80:
                    yield _filename(entry[:24]), entry

    def read_binary(self, name: str) -> Binary:
        dos = self.filesystem == "DOS 3.3"
        catalog = self._dos_catalog() if dos else self._rdos_catalog()
        matches = [entry for member, entry in catalog if member.upper() == name.upper()]
        if len(matches) != 1:
            reason = "ambiguous" if matches else "not found"
            raise Apple2Error(f"Apple II disk member {name!r} {reason}")
        entry = matches[0]
        if dos:
            if entry[2] & 0x7F != 4:
                raise Apple2Error(f"Apple DOS disk member {name!r} is not a binary (type B)")
            return self._read_dos_binary(entry, name)
        if entry[24] & 0x7F != ord("B"):
            raise Apple2Error(f"RDOS disk member {name!r} is not a binary (type B)")
        return self._read_rdos_binary(entry, name)

    def _read_dos_binary(self, entry: memoryview, name: str) -> Binary:
        sectors = {}
        for block in self._chain(*entry[:2]):
            index = unpack_from("<H", block, 5)[0]
            for offset in range(12, _SECTOR_SIZE, 2):
                track, sector = block[offset:offset + 2]
                if track:
                    if index in sectors:
                        raise Apple2Error(f"overlapping track/sector lists for DOS binary {name!r}")
                    sectors[index] = self._sector_offset(track, sector)
                index += 1

        if 0 not in sectors:
            raise Apple2Error(f"missing first data sector for DOS binary {name!r}")
        length = unpack_from("<H", self._data, sectors[0] + 2)[0]
        blocks = (length + 4 + _SECTOR_SIZE - 1) // _SECTOR_SIZE
        try:
            offsets = [sectors[index] for index in range(blocks)]
        except KeyError as error:
            raise Apple2Error(f"missing data sector {error.args[0]} for DOS binary {name!r}") from None
        contents, spans = self._binary_sectors(offsets)
        return Binary.from_dos(contents, name, spans)

    def _read_rdos_binary(self, entry: memoryview, name: str) -> Binary:
        address, length, start = unpack_from("<HHH", entry, 26)
        count = entry[25]
        if not 0 < length <= count * _SECTOR_SIZE or start + count > _TRACKS * self._sectors:
            raise Apple2Error(f"invalid sector range or length for RDOS binary {name!r}")
        blocks = (length + _SECTOR_SIZE - 1) // _SECTOR_SIZE
        offsets = [self._sector_offset(*divmod(index, self._sectors)) for index in range(start, start + blocks)]
        payload, spans = self._binary_sectors(offsets)
        return Binary(payload[:length], address, container_spans=slice_source_spans(spans, 0, length))

    def _binary_sectors(self, offsets: list[int]) -> tuple[bytes, tuple[SourceSpan, ...]]:
        payload = b"".join(self._data[start:start + _SECTOR_SIZE] for start in offsets)
        spans = tuple(SourceSpan(index * _SECTOR_SIZE, start, _SECTOR_SIZE) for index, start in enumerate(offsets))
        return payload, spans


@dataclass(frozen=True)
class Apple2Unit:
    name: str
    source: str
    binary: Binary
    address: int | None = None
    disk_file: str | None = None


def memory_map(lc: int) -> list[dict]:
    """Describe the effective read and write targets of the Language Card and main memory."""
    if not 0xC080 <= lc <= 0xC08F:
        raise Apple2Error("Apple II Language Card switch must be between c080 and c08f")
    mode = lc & 3
    bank = 1 if lc & 8 else 2
    ram_visible = mode in (0, 3)
    lc_read = "ram" if ram_visible else "rom"
    lc_write = "ram" if mode & 1 else "none"
    regions = [
        (0x0000, 0x0100, "zero_page", "ram", "ram"),
        (0x0100, 0x0200, "stack", "ram", "ram"),
        (0x0200, 0xC000, "main_ram", "ram", "ram"),
        (0xC000, 0xC080, "soft_switches", "io", "io"),
        (0xC080, 0xC090, "language_card_switches", "io", "io"),
        (0xC090, 0xC100, "slot_io", "io", "io"),
        (0xC100, 0xC800, "slot_rom", "rom", "none"),
        (0xC800, 0xD000, "expansion_rom", "rom", "none"),
        (0xD000, 0xE000, f"lc_bank{bank}" if ram_visible else "system_rom_low", lc_read, lc_write),
        (0xE000, MOS6502_ADDRESS_LIMIT, "lc_shared" if ram_visible else "system_rom_high", lc_read, lc_write),
    ]
    return [
        {"name": name, "linear": start, "size": end - start, "read": read, "write": write}
        for start, end, name, read, write in regions
    ]


def build_apple2_image(
    units: list[Apple2Unit], program: str, *, lc: int = DEFAULT_LC, entries: list[int] | None = None,
) -> tuple[bytes, dict]:
    """Place co-resident binaries at their addresses in one Apple II memory view."""
    regions = memory_map(lc)
    if not units:
        raise Apple2Error("expected at least one Apple II binary")
    non_ram = [region for region in regions if region["read"] != "ram"]
    placements = []
    names = set()
    for unit in units:
        name = unit.name.casefold()
        if not name or ":" in name or name.startswith("apple2_") or name in names:
            raise Apple2Error(f"invalid or duplicate Apple II unit name {unit.name!r}")
        names.add(name)
        address = unit.binary.load_address if unit.address is None else unit.address
        if address is None:
            raise Apple2Error(f"raw Apple II unit {unit.name!r} requires a load address")
        end = address + len(unit.binary.payload)
        if not 0 <= address < end <= MOS6502_ADDRESS_LIMIT:
            raise Apple2Error(f"Apple II binary {unit.name!r} is empty or exceeds the 16-bit address space")
        if any(address < region["linear"] + region["size"] and end > region["linear"] for region in non_ram):
            raise Apple2Error(f"Apple II binary {unit.name!r} is outside visible RAM with switch {lc:04x}")
        placements.append((address, end, unit))

    placements.sort(key=lambda placement: placement[0])
    origin = placements[0][0]
    image = bytearray(placements[-1][1] - origin)
    records = []
    previous_end = origin
    for address, end, unit in placements:
        if address < previous_end:
            raise Apple2Error(f"Apple II binary {unit.name!r} overlaps another unit at {address:04x}")
        payload = unit.binary.payload
        image[address - origin:end - origin] = payload
        records.append({
            "name": unit.name, "kind": "ram", "linear": address, "size": len(payload),
            "image_offset": address - origin, "file_offset": unit.binary.file_offset, "file_size": len(payload),
            "load_address": unit.binary.load_address, "source": unit.source, "disk_file": unit.disk_file,
            "writable": address < 0xC000 or bool(lc & 1),
        })
        if unit.binary.container_spans:
            records[-1]["container_spans"] = [asdict(span) for span in unit.binary.container_spans]
        previous_end = end

    entry_records = []
    for entry in dict.fromkeys(entries or []):
        containing = next(
            (record for record in records if record["linear"] <= entry < record["linear"] + record["size"]), None,
        )
        if containing is None:
            raise Apple2Error(f"Apple II entry {entry:x} is outside the loaded binaries")
        offset = entry - containing["linear"]
        entry_records.append({"linear": entry, "unit_address": f"{containing['name']}:{offset:04x}"})

    return bytes(image), {
        "version": 1, "format": APPLE2_FORMAT, "program": program, "base_address": origin,
        "language_card": lc, "memory_map": regions, "units": records,
        "entry": entry_records[0] if entry_records else None, "entries": entry_records,
    }
