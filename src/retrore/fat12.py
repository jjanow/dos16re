"""Read DOS FAT12 files and map them back to their disk image bytes."""

from collections.abc import Iterator
from dataclasses import dataclass
from struct import unpack_from

from .image import SourceSpan
from .members import Member, select_member

_FAT12_LIMIT = 4085
_FIRST_RESERVED = 0xFF0
_FAT12_END = 0xFF8
_ENTRY_SIZE = 32


class Fat12Error(ValueError):
    """An invalid or unsupported FAT12 input."""


@dataclass(frozen=True)
class Fat12Bpb:
    sector_size: int
    cluster_sectors: int
    reserved_sectors: int
    fats: int
    root_entries: int
    total_sectors: int
    media: int
    fat_sectors: int
    sectors_per_track: int
    heads: int

    @classmethod
    def read(cls, boot: bytes, error: type[ValueError] = Fat12Error) -> "Fat12Bpb":
        if len(boot) < 512:
            raise error("truncated FAT12 boot sector")
        sector, cluster, reserved, fats, entries, sectors, media, fat_size, track, heads = unpack_from(
            "<HBHBHHBHHH", boot, 11,
        )
        if not sectors:
            sectors, = unpack_from("<I", boot, 32)
        if (sector not in (512, 1024) or not 0 < cluster <= 128 or cluster & (cluster - 1)
                or not reserved or not fats or not entries or not sectors or not fat_size):
            raise error("expected a FAT12 disk with a valid BPB")
        return cls(sector, cluster, reserved, fats, entries, sectors, media, fat_size, track, heads)


class Fat12Disk:
    """Read a FAT12 floppy volume, optionally backed by noncontiguous sectors."""

    error = Fat12Error
    filename_encoding = "ascii"
    member_type = "FAT12 disk file"
    sector_sizes = (512, 1024)

    def __init__(self, data: bytes, *, sector_offsets: tuple[int, ...] | None = None):
        bpb = Fat12Bpb.read(data, self.error)
        sector = bpb.sector_size
        if sector not in self.sector_sizes:
            raise self.error(f"unsupported FAT12 sector size {sector}")
        root_sector = bpb.reserved_sectors + bpb.fats * bpb.fat_sectors
        root_size = bpb.root_entries * _ENTRY_SIZE
        first_data = root_sector + (root_size + sector - 1) // sector
        clusters = (bpb.total_sectors - first_data) // bpb.cluster_sectors
        self._cluster_size = bpb.cluster_sectors * sector
        self._cluster_end = min(clusters + 2, _FIRST_RESERVED)
        self._fat = data[bpb.reserved_sectors * sector:(bpb.reserved_sectors + bpb.fat_sectors) * sector]
        if (not 0 < clusters < _FAT12_LIMIT or bpb.total_sectors * sector > len(data)
                or ((clusters + 1) * 3 // 2) + 2 > len(self._fat)
                or bpb.media < 0xF0 or self._fat[:3] != bytes((bpb.media, 0xFF, 0xFF))):
            raise self.error("invalid FAT12 allocation table or disk size")
        if sector_offsets is not None and len(sector_offsets) != bpb.total_sectors:
            raise self.error("invalid FAT12 container sector map")
        self._sector_offsets = sector_offsets
        self.bpb = bpb

        self._root_offset = root_sector * sector
        self._root = data[self._root_offset:self._root_offset + root_size]
        self._data_offset = first_data * sector
        self._data = data[self._data_offset:bpb.total_sectors * sector]

    def _container_offset(self, offset: int) -> int:
        if self._sector_offsets is None:
            return offset
        sector, within = divmod(offset, self.bpb.sector_size)
        return self._sector_offsets[sector] + within

    def _spans(self, offset: int, size: int, destination: int) -> Iterator[SourceSpan]:
        if self._sector_offsets is None:
            yield SourceSpan(destination, offset, size)
            return
        sector_size = self.bpb.sector_size
        while size:
            length = min(size, sector_size - offset % sector_size)
            yield SourceSpan(destination, self._container_offset(offset), length)
            offset += length
            destination += length
            size -= length

    def _catalog(self) -> Iterator[tuple[Member, int]]:
        for offset in range(0, len(self._root), _ENTRY_SIZE):
            entry = self._root[offset:offset + _ENTRY_SIZE]
            if entry[0] == 0:
                break
            if entry[0] == 0xE5 or entry[11] & 0x18:
                continue
            name = b"\xe5" + entry[1:8] if entry[0] == 5 else entry[:8]
            stem = name.decode(self.filename_encoding, errors="replace").rstrip(" ")
            ext = entry[8:11].decode(self.filename_encoding, errors="replace").rstrip(" ")
            filename = f"{stem}.{ext}" if ext else stem
            cluster, size = unpack_from("<HI", entry, 26)
            yield Member(f"file:{offset // _ENTRY_SIZE + 1}", filename, "file", size=size,
                         container_offset=self._container_offset(self._root_offset + offset),
                         details={"start_cluster": cluster}), cluster

    def list_members(self) -> list[Member]:
        return [member for member, _ in self._catalog()]

    def extract_file(self, selector: str) -> tuple[Member, bytes, tuple[SourceSpan, ...]]:
        member, cluster = select_member(self._catalog(), selector, self.member_type, self.error)
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
                raise self.error(f"invalid FAT12 cluster chain for {name!r}")
            seen.add(cluster)
            offset = (cluster - 2) * self._cluster_size
            length = min(self._cluster_size, size - len(contents))
            spans.extend(self._spans(self._data_offset + offset, length, len(contents)))
            contents.extend(self._data[offset:offset + length])
            fat_offset = cluster * 3 // 2
            pair = int.from_bytes(self._fat[fat_offset:fat_offset + 2], "little")
            cluster = pair >> 4 if cluster & 1 else pair & 0xFFF
        if not _FAT12_END <= cluster <= 0xFFF:
            raise self.error(f"FAT12 cluster chain does not end at the size of {name!r}")
        return bytes(contents), tuple(spans)
