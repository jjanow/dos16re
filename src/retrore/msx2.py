"""Read MSX-DOS disk members and reconstruct a selected Z80 RAM layout."""

from collections import Counter
from dataclasses import dataclass
from itertools import groupby
from struct import unpack_from

from .image import FLAT16_ADDRESS_LIMIT, MSX2_FORMAT

COM_ADDRESS = 0x0100
_SECTOR_SIZE = 512
_FAT12_END = 0xFF8


class Msx2Error(ValueError):
    """An invalid or unsupported MSX2 input."""


class MsxDosDisk:
    """Read files from the root of a raw FAT12 floppy with a DOS BPB."""

    def __init__(self, data: bytes):
        if len(data) < _SECTOR_SIZE:
            raise Msx2Error("truncated MSX-DOS boot sector")
        sector, cluster, reserved, fats, entries, sectors, media, fat_size = unpack_from("<HBHBHHBH", data, 11)
        if (sector != _SECTOR_SIZE or not cluster or cluster & (cluster - 1) or not reserved
                or not fats or not entries or not fat_size):
            raise Msx2Error("expected a raw MSX-DOS FAT12 disk with a valid BPB")

        root_sector = reserved + fats * fat_size
        root_size = entries * 32
        first_data = root_sector + (root_size + sector - 1) // sector
        clusters = (sectors - first_data) // cluster
        self._cluster_size = cluster * sector
        self._cluster_end = clusters + 2
        self._fat = data[reserved * sector:(reserved + fat_size) * sector]
        if (not 0 < clusters <= 0xFEE or sectors * sector > len(data)
                or ((self._cluster_end - 1) * 3 // 2) + 2 > len(self._fat)
                or media < 0xF0 or self._fat[:3] != bytes((media, 0xFF, 0xFF))):
            raise Msx2Error("invalid FAT12 allocation table or disk size")

        root_start = root_sector * sector
        self._root = data[root_start:root_start + root_size]
        self._data = data[first_data * sector:sectors * sector]

    def read_file(self, name: str) -> bytes:
        for offset in range(0, len(self._root), 32):
            entry = self._root[offset:offset + 32]
            if entry[0] == 0:
                break
            if entry[0] == 0xE5 or entry[11] & 0x18:
                continue
            stem = entry[:8].decode("ascii", errors="replace").rstrip(" ")
            ext = entry[8:11].decode("ascii", errors="replace").rstrip(" ")
            filename = f"{stem}.{ext}" if ext else stem
            if filename.upper() == name.upper():
                return self._read_chain(name, *unpack_from("<HI", entry, 26))
        raise Msx2Error(f"MSX-DOS disk file {name!r} not found")

    def _read_chain(self, name: str, cluster: int, size: int) -> bytes:
        if size == 0 and cluster == 0:
            return b""
        contents = bytearray()
        seen = set()
        while len(contents) < size:
            if not 2 <= cluster < self._cluster_end or cluster in seen:
                raise Msx2Error(f"invalid FAT12 cluster chain for {name!r}")
            seen.add(cluster)
            offset = (cluster - 2) * self._cluster_size
            contents.extend(self._data[offset:offset + self._cluster_size])
            fat_offset = cluster * 3 // 2
            pair = int.from_bytes(self._fat[fat_offset:fat_offset + 2], "little")
            cluster = pair >> 4 if cluster & 1 else pair & 0xFFF
        if not _FAT12_END <= cluster <= 0xFFF:
            raise Msx2Error(f"FAT12 cluster chain does not end at the size of {name!r}")
        return bytes(contents[:size])


@dataclass(frozen=True)
class Msx2Source:
    name: str
    source: str
    address: int
    data: bytes
    disk_file: str | None = None
    file_offset: int = 0

    @property
    def end(self) -> int:
        return self.address + len(self.data)


def build_msx2_image(
    sources: list[Msx2Source], program: str, entries: list[int], *, disk: bool = False,
) -> tuple[bytes, dict]:
    """Export an MSX-DOS view with later loads replacing bytes at the same address."""
    if not sources:
        raise Msx2Error("no MSX2 inputs to load")
    image = bytearray(FLAT16_ADDRESS_LIMIT)
    owners = [None] * FLAT16_ADDRESS_LIMIT
    names = set()
    for index, source in enumerate(sources):
        name = source.name.casefold()
        if not name or ":" in name or name.startswith("msx2_") or name in names:
            raise Msx2Error(f"invalid or duplicate MSX2 source name {source.name!r}")
        names.add(name)
        if not 0 <= source.address < source.end <= FLAT16_ADDRESS_LIMIT:
            raise Msx2Error(f"MSX2 source {source.name!r} is empty or exceeds the 16-bit address space")
        image[source.address:source.end] = source.data
        owners[source.address:source.end] = [index] * len(source.data)

    ranges = []
    for index, addresses in groupby(range(FLAT16_ADDRESS_LIMIT), key=owners.__getitem__):
        if index is not None:
            start = next(addresses)
            end = start + 1 + sum(1 for _ in addresses)
            ranges.append((index, start, end))
    counts = Counter(index for index, _, _ in ranges)
    origin = ranges[0][1]
    units = []
    for index, start, end in ranges:
        source = sources[index]
        name = source.name if counts[index] == 1 and start == source.address else f"{source.name}_{start:04x}"
        units.append({
            "name": name, "kind": "ram", "linear": start, "size": end - start, "image_offset": start - origin,
            "file_size": end - start, "file_offset": source.file_offset + start - source.address,
            "source": source.source, "disk_file": source.disk_file,
        })
    if len({unit["name"].casefold() for unit in units}) != len(units):
        raise Msx2Error("duplicate MSX2 memory block name")

    entry_records = []
    for address in dict.fromkeys(entries):
        unit = next((unit for unit in units if unit["linear"] <= address < unit["linear"] + unit["size"]), None)
        if unit is None:
            raise Msx2Error(f"MSX2 entry {address:x} is outside loaded RAM")
        entry_records.append({"linear": address, "unit_address": f"{unit['name']}:{address - unit['linear']:04x}"})
    program_map = {
        "version": 1, "format": MSX2_FORMAT, "program": program, "base_address": origin, "memory_view": "msxdos",
        "memory_map": [{"name": f"page_{page}", "linear": page * 0x4000, "size": 0x4000, "read": "ram", "write": "ram"}
                       for page in range(4)],
        "sources": [{"name": source.name, "source": source.source, "disk_file": source.disk_file,
                     "linear": source.address, "size": len(source.data), "file_offset": source.file_offset}
                    for source in sources],
        "units": units, "entry": entry_records[0] if entry_records else None, "entries": entry_records,
    }
    if disk:
        program_map["disk"] = {"filesystem": "FAT12", "sector_size": _SECTOR_SIZE}
    return bytes(image[origin:ranges[-1][2]]), program_map
