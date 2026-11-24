"""Read MSX-DOS disk members and reconstruct a selected Z80 RAM layout."""

from collections.abc import Iterator
from struct import unpack_from

from .image import MSX2_FORMAT, SourceSpan
from .members import Member, select_member
from .z80 import Z80Source as Msx2Source
from .z80 import place_z80_sources

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
        self._root_offset = root_start
        self._root = data[root_start:root_start + root_size]
        self._data_offset = first_data * sector
        self._data = data[self._data_offset:sectors * sector]

    def read_file(self, name: str) -> bytes:
        return self.read_file_with_spans(name)[0]

    def read_file_with_spans(self, name: str) -> tuple[bytes, tuple[SourceSpan, ...]]:
        _, contents, spans = self.extract_file(name)
        return contents, spans

    def _catalog(self) -> Iterator[tuple[Member, int]]:
        for offset in range(0, len(self._root), 32):
            entry = self._root[offset:offset + 32]
            if entry[0] == 0:
                break
            if entry[0] == 0xE5 or entry[11] & 0x18:
                continue
            stem = entry[:8].decode("ascii", errors="replace").rstrip(" ")
            ext = entry[8:11].decode("ascii", errors="replace").rstrip(" ")
            filename = f"{stem}.{ext}" if ext else stem
            cluster, size = unpack_from("<HI", entry, 26)
            yield Member(f"file:{offset // 32 + 1}", filename, "file", size=size,
                         container_offset=self._root_offset + offset,
                         details={"start_cluster": cluster}), cluster

    def list_members(self) -> list[Member]:
        return [member for member, _ in self._catalog()]

    def extract_file(self, selector: str) -> tuple[Member, bytes, tuple[SourceSpan, ...]]:
        member, cluster = select_member(self._catalog(), selector, "MSX-DOS disk file", Msx2Error)
        contents, spans = self._read_chain(member.name, cluster, member.size)
        return member, contents, spans

    def _read_chain(self, name: str, cluster: int, size: int) -> tuple[bytes, tuple[SourceSpan, ...]]:
        if size == 0 and cluster == 0:
            return b"", ()
        contents = bytearray()
        spans = []
        seen = set()
        while len(contents) < size:
            if not 2 <= cluster < self._cluster_end or cluster in seen:
                raise Msx2Error(f"invalid FAT12 cluster chain for {name!r}")
            seen.add(cluster)
            offset = (cluster - 2) * self._cluster_size
            length = min(self._cluster_size, size - len(contents))
            spans.append(SourceSpan(len(contents), self._data_offset + offset, length))
            contents.extend(self._data[offset:offset + length])
            fat_offset = cluster * 3 // 2
            pair = int.from_bytes(self._fat[fat_offset:fat_offset + 2], "little")
            cluster = pair >> 4 if cluster & 1 else pair & 0xFFF
        if not _FAT12_END <= cluster <= 0xFFF:
            raise Msx2Error(f"FAT12 cluster chain does not end at the size of {name!r}")
        return bytes(contents), tuple(spans)


def build_msx2_image(
    sources: list[Msx2Source], program: str, entries: list[int], *, disk: bool = False,
) -> tuple[bytes, dict]:
    """Export an MSX-DOS view with later loads replacing bytes at the same address."""
    image, layout = place_z80_sources(sources, entries, "MSX2", Msx2Error)
    program_map = {
        "version": 1, "format": MSX2_FORMAT, "program": program, "memory_view": "msxdos",
        "memory_map": [{"name": f"page_{page}", "linear": page * 0x4000, "size": 0x4000, "read": "ram", "write": "ram"}
                       for page in range(4)],
        **layout,
    }
    if disk:
        program_map["disk"] = {"filesystem": "FAT12", "sector_size": _SECTOR_SIZE}
    return image, program_map
