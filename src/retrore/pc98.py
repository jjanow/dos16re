"""Reconstruct a selected NEC PC-98 real-mode memory layout."""

from dataclasses import asdict, dataclass

from .d88 import D88Disk, D88Sector
from .fat12 import Fat12Bpb, Fat12Disk
from .image import PC98_FORMAT, PC98_RAM_END, SourceSpan
from .members import Member
from .mz import Address
from .overlays import address_record

IPL_SEGMENT = 0x1FC0
HDM_SUFFIX = ".hdm"

_MEMORY_MAP = (
    ("conventional_ram", 0x00000, PC98_RAM_END, "ram"),
    ("text_vram", 0xA0000, 0x4000, "vram"),
    ("blue_vram", 0xA8000, 0x8000, "vram"),
    ("red_vram", 0xB0000, 0x8000, "vram"),
    ("green_vram", 0xB8000, 0x8000, "vram"),
    ("cbus_window", 0xC0000, 0x20000, "expansion"),
    ("ipl_rom", 0xE8000, 0x18000, "rom"),
)


class Pc98Error(ValueError):
    """An invalid or unsupported PC-98 load."""


class HdmDisk:
    """Read raw PC-98 2HD floppies with 77 cylinders and 1024-byte sectors."""

    _CYLINDERS = 77
    _HEADS = 2
    _RECORDS = 8
    _SECTOR_SIZE = 1024

    def __init__(self, data: bytes):
        if len(data) != self._CYLINDERS * self._HEADS * self._RECORDS * self._SECTOR_SIZE:
            raise Pc98Error("expected a 1232 KiB PC-98 HDM disk")
        self._data = data
        self.metadata = {
            "format": "HDM", "media_type": "2HD", "cylinders": self._CYLINDERS, "heads": self._HEADS,
            "sectors_per_track": self._RECORDS, "sector_size": self._SECTOR_SIZE,
        }
        self.member = Member("disk:1", "Disk 1", "disk", size=len(data), container_offset=0, details=self.metadata)

    def read_sectors(self, cylinder: int, head: int, record: int, count: int = 1) -> tuple[D88Sector, ...]:
        if not (0 <= cylinder < self._CYLINDERS and 0 <= head < self._HEADS
                and 1 <= record <= self._RECORDS and count > 0):
            raise Pc98Error("invalid HDM cylinder, head, sector ID, or sector count")
        start = (cylinder * self._HEADS + head) * self._RECORDS + record - 1
        if (start + count) * self._SECTOR_SIZE > len(self._data):
            raise Pc98Error("HDM sector span extends beyond the disk")
        sectors = []
        for index in range(start, start + count):
            offset = index * self._SECTOR_SIZE
            sectors.append(D88Sector(index % self._RECORDS + 1, 3, offset, self._data[offset:offset + self._SECTOR_SIZE]))
        return tuple(sectors)


class Pc98Fat12Disk(Fat12Disk):
    """Read a PC-98 FAT12 floppy and preserve its physical file offsets."""

    error = Pc98Error
    filename_encoding = "cp932"

    def __init__(self, disk: HdmDisk | D88Disk):
        boot, = disk.read_sectors(0, 0, 1)
        bpb = Fat12Bpb.read(boot.data, self.error)
        if bpb.sector_size != len(boot.data):
            raise Pc98Error("FAT12 BPB sector size does not match the PC-98 disk")
        if isinstance(disk, HdmDisk):
            sectors = disk.read_sectors(0, 0, 1, bpb.total_sectors)
            offsets = None
        else:
            sectors = self._d88_sectors(disk, bpb)
            offsets = tuple(sector.file_offset for sector in sectors)
        super().__init__(b"".join(sector.data for sector in sectors), sector_offsets=offsets)
        self.disk = disk

    @staticmethod
    def _d88_sectors(disk: D88Disk, bpb: Fat12Bpb) -> list[D88Sector]:
        if not 1 <= bpb.sectors_per_track <= 255 or not 1 <= bpb.heads <= 2:
            raise Pc98Error("invalid FAT12 BPB track geometry")
        sectors = []
        for start in range(0, bpb.total_sectors, bpb.sectors_per_track):
            cylinder, head = divmod(start // bpb.sectors_per_track, bpb.heads)
            count = min(bpb.sectors_per_track, bpb.total_sectors - start)
            track = [sector for sector in disk.read_track(cylinder, head) if 1 <= sector.record <= count]
            if ([sector.record for sector in track] != list(range(1, count + 1))
                    or any(len(sector.data) != bpb.sector_size for sector in track)):
                raise Pc98Error(f"FAT12 BPB geometry does not match D88 track {cylinder}:{head}")
            sectors.extend(track)
        return sectors

    @property
    def metadata(self) -> dict:
        return {**self.disk.metadata, "filesystem": "FAT12", "sector_size": self.bpb.sector_size}


@dataclass(frozen=True)
class Pc98Source:
    name: str
    source: str
    segment: int
    data: bytes
    sectors: tuple[D88Sector, ...] = ()
    chs: tuple[int, int, int] | None = None
    member: Member | None = None
    container_spans: tuple[SourceSpan, ...] = ()

    @classmethod
    def from_disk(
        cls, disk: D88Disk | HdmDisk, name: str, source: str,
        cylinder: int, head: int, record: int, count: int, segment: int,
    ) -> "Pc98Source":
        sectors = disk.read_sectors(cylinder, head, record, count)
        return cls(name, source, segment, b"".join(sector.data for sector in sectors),
                   sectors, (cylinder, head, record))


def build_pc98_image(
    sources: list[Pc98Source], program: str, entries: list[Address], disk: D88Disk | HdmDisk | None = None,
) -> tuple[bytes, dict]:
    """Place co-resident loads at their actual segments and retain their disk offsets."""
    if not sources:
        raise Pc98Error("expected at least one PC-98 load")
    reserved = {name for name, *_ in _MEMORY_MAP}
    names = set()
    units = []
    for source in sources:
        name = source.name.casefold()
        if not name or ":" in name or name in names or name in reserved:
            raise Pc98Error(f"invalid, duplicate, or reserved PC-98 unit name {source.name!r}")
        names.add(name)
        linear = 16 * source.segment
        if not source.data or not 0 <= linear < linear + len(source.data) <= PC98_RAM_END:
            raise Pc98Error(f"PC-98 unit {source.name} must contain bytes within conventional RAM")
        unit = {"name": source.name, "source": source.source, "segment": source.segment,
                "linear": linear, "size": len(source.data), "file_offset": 0}
        if source.chs is not None:
            cylinder, head, record = source.chs
            unit["disk_span"] = {"cylinder": cylinder, "head": head, "record": record, "count": len(source.sectors)}
            unit["file_offset"] = source.sectors[0].file_offset
            if disk is not None:
                unit["member_id"] = disk.member.id
                unit["file_offset_kind"] = "container"
            if len(source.sectors) > 1:
                offset = 0
                spans = []
                for sector in source.sectors:
                    spans.append({"offset": offset, "file_offset": sector.file_offset, "size": len(sector.data)})
                    offset += len(sector.data)
                unit["file_spans"] = spans
        if source.member is not None:
            unit.update(disk_file=source.member.name, member_id=source.member.id,
                        container_spans=[asdict(span) for span in source.container_spans])
        units.append(unit)

    ordered = sorted(units, key=lambda unit: unit["linear"])
    for left, right in zip(ordered, ordered[1:]):
        if left["linear"] + left["size"] > right["linear"]:
            raise Pc98Error(f"PC-98 units {left['name']} and {right['name']} overlap in this memory view")
    origin = ordered[0]["linear"]
    end = ordered[-1]["linear"] + ordered[-1]["size"]
    image = bytearray(end - origin)
    for unit, source in zip(units, sources):
        start = unit["linear"] - origin
        unit["image_offset"] = start
        image[start:start + unit["size"]] = source.data

    entries = list(dict.fromkeys(entries or [Address(sources[0].segment, 0)]))
    for entry in entries:
        if not (0 <= entry.segment <= 0xFFFF and 0 <= entry.offset <= 0xFFFF
                and any(unit["linear"] <= entry.linear < unit["linear"] + unit["size"] for unit in units)):
            raise Pc98Error(f"PC-98 entry {entry} is outside the loaded image")
    report = {
        "version": 1, "format": PC98_FORMAT, "program": program, "units": units, "image_origin": origin,
        "entry": address_record(entries[0]), "entries": [address_record(entry) for entry in entries],
        "memory_view": "pc9801", "memory_map": [
            {"name": name, "linear": start, "size": size, "kind": kind}
            for name, start, size, kind in _MEMORY_MAP
        ],
    }
    if disk is not None:
        report["disk"] = disk.metadata
    return bytes(image), report
