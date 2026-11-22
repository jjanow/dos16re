"""Read sector payloads from D88/D77 disk images."""

from dataclasses import dataclass
from itertools import groupby
from struct import unpack_from

_SHORT_HEADER_SIZE = 0x2A0
_SHORT_TRACK_COUNT = 160
_TRACK_COUNT = 164
_SECTOR_HEADER_SIZE = 16
_MEDIA_TYPES = {0x00: "2D", 0x10: "2DD", 0x20: "2HD", 0x30: "1D", 0x40: "1DD"}


class D88Error(ValueError):
    """An invalid D88 image or sector selection."""


@dataclass(frozen=True)
class D88Sector:
    record: int
    size_code: int
    file_offset: int
    data: bytes


class D88Disk:
    """One disk from a possibly concatenated D88 image."""

    def __init__(self, data: bytes, index: int = 1):
        self._data = data
        disks = []
        offset = 0
        while offset < len(data):
            if len(data) - offset < _SHORT_HEADER_SIZE:
                raise D88Error("truncated D88 disk header")
            size, = unpack_from("<I", data, offset + 0x1C)
            if not _SHORT_HEADER_SIZE <= size <= len(data) - offset:
                raise D88Error("invalid D88 disk size")
            disks.append((offset, size))
            offset += size
        if not 1 <= index <= len(disks):
            raise D88Error(f"D88 disk index {index} is out of range ({len(disks)} disks)")
        self._offset, size = disks[index - 1]
        table_start = self._offset + 0x20
        tracks = unpack_from(f"<{_SHORT_TRACK_COUNT}I", data, table_start)
        if size != _SHORT_HEADER_SIZE and _SHORT_HEADER_SIZE not in tracks:
            header_size = 0x20 + 4 * _TRACK_COUNT
            if size < header_size:
                raise D88Error("truncated D88 track table")
            tracks = unpack_from(f"<{_TRACK_COUNT}I", data, table_start)
        else:
            header_size = _SHORT_HEADER_SIZE
        tracks = tuple(track if track != size else 0 for track in tracks)
        starts = sorted(track for track in tracks if track)
        if len(set(starts)) != len(starts) or any(not header_size <= track < size for track in starts):
            raise D88Error("invalid D88 track offsets")
        self._tracks = tracks
        self._ends = dict(zip(starts, [*starts[1:], size]))
        media = data[self._offset + 0x1B]
        self._heads = 1 if media in (0x30, 0x40) else 2
        self.metadata = {
            "format": "D88", "index": index, "image_count": len(disks),
            "label": data[self._offset:self._offset + 0x11].split(b"\0", 1)[0].decode("cp932", errors="replace"),
            "media_type": _MEDIA_TYPES.get(media, f"0x{media:02x}"),
            "write_protected": bool(data[self._offset + 0x1A]),
            "track_count": len(starts),
        }

    def _track(self, index: int) -> list[D88Sector]:
        track_cylinder, track_head = divmod(index, self._heads)
        address = f"{track_cylinder}:{track_head}"
        start = self._tracks[index]
        if not start:
            raise D88Error(f"unformatted D88 track {address}")
        offset, end = self._offset + start, self._offset + self._ends[start]
        if offset + _SECTOR_HEADER_SIZE > end:
            raise D88Error(f"truncated D88 sector header on track {address}")
        count, = unpack_from("<H", self._data, offset + 4)
        if not count:
            raise D88Error(f"empty D88 track {address}")
        sectors = []
        for _ in range(count):
            if offset + _SECTOR_HEADER_SIZE > end:
                raise D88Error(f"truncated D88 sector header on track {address}")
            cylinder, head, record, size_code, repeat = unpack_from("<4BH", self._data, offset)
            size, = unpack_from("<H", self._data, offset + 14)
            offset += _SECTOR_HEADER_SIZE
            if repeat != count or offset + size > end:
                raise D88Error(f"invalid D88 sector length or count on track {address}")
            if (cylinder, head) == (track_cylinder, track_head):
                sectors.append(D88Sector(record, size_code, offset, self._data[offset:offset + size]))
            offset += size
        return sectors

    def read_sectors(self, cylinder: int, head: int, record: int, count: int = 1) -> tuple[D88Sector, ...]:
        """Read recorded IDs in ascending order, continuing onto the next track."""
        if not (0 <= head < self._heads and 0 <= cylinder * self._heads + head < len(self._tracks)
                and 0 <= record <= 255 and count > 0):
            raise D88Error("invalid D88 cylinder, head, sector ID, or sector count")
        start = cylinder * self._heads + head
        result = []
        for index in range(start, len(self._tracks)):
            track_cylinder, track_head = divmod(index, self._heads)
            sectors = sorted(self._track(index), key=lambda sector: sector.record)
            if index == start:
                sectors = [sector for sector in sectors if sector.record >= record]
                if not sectors or sectors[0].record != record:
                    raise D88Error(f"D88 sector {cylinder}:{head}:{record} not found")
            if not sectors:
                raise D88Error(f"no matching D88 sector IDs on track {track_cylinder}:{track_head}")
            for sector_id, matches in groupby(sectors, key=lambda sector: sector.record):
                sector, *duplicates = matches
                if duplicates:
                    raise D88Error(f"ambiguous D88 sector {track_cylinder}:{track_head}:{sector_id}")
                if not sector.data:
                    raise D88Error(f"empty D88 sector {track_cylinder}:{track_head}:{sector_id}")
                result.append(sector)
                if len(result) == count:
                    return tuple(result)
        raise D88Error("D88 sector span extends beyond the disk")
