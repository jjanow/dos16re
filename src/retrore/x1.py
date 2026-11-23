"""Build a static Sharp X1 main-CPU view from D88 disk sectors or raw loads."""

from dataclasses import dataclass
from struct import unpack_from

from .d88 import D88_SUFFIXES as DISK_SUFFIXES
from .d88 import D88Disk
from .image import X1_FORMAT
from .z80 import Z80Source, copy_z80_source, disk_span_source, place_z80_sources

SECTOR_SIZE = 256
SECTORS_PER_TRACK = 16
IPL_ROM_END = 0x8000
MEMORY_VIEWS = ("ram", "ipl-rom")

# Main-CPU I/O devices decoded from the full 16-bit BC port address (MAME x1_io_banks).
IO_MAP = (
    ("cartridge_rom", 0x0E00, 0x04, (("CART_ROM_ADDRESS_HIGH", 0x0E00), ("CART_ROM_ADDRESS_MID", 0x0E01),
                                     ("CART_ROM_ADDRESS_LOW", 0x0E02), ("CART_ROM_DATA", 0x0E03))),
    ("fdc", 0x0FF8, 0x08, (("FDC_COMMAND_STATUS", 0x0FF8), ("FDC_TRACK", 0x0FF9), ("FDC_SECTOR", 0x0FFA),
                           ("FDC_DATA", 0x0FFB), ("FDC_DRIVE_CONTROL", 0x0FFC))),
    ("palette_blue", 0x1000, 0x100, (("PALETTE_BLUE", 0x1000),)),
    ("palette_red", 0x1100, 0x100, (("PALETTE_RED", 0x1100),)),
    ("palette_green", 0x1200, 0x100, (("PALETTE_GREEN", 0x1200),)),
    ("priority", 0x1300, 0x100, (("PRIORITY", 0x1300),)),
    ("pcg", 0x1400, 0x400, (("PCG_PLANE_1", 0x1500), ("PCG_PLANE_2", 0x1600), ("PCG_PLANE_3", 0x1700))),
    ("crtc", 0x1800, 0x100, (("CRTC_ADDRESS", 0x1800), ("CRTC_DATA", 0x1801))),
    ("sub_cpu", 0x1900, 0x100, (("SUB_CPU", 0x1900),)),
    ("ppi", 0x1A00, 0x100, (("PPI_A", 0x1A00), ("PPI_B", 0x1A01), ("PPI_C", 0x1A02), ("PPI_CONTROL", 0x1A03))),
    ("psg", 0x1B00, 0x200, (("PSG_DATA", 0x1B00), ("PSG_ADDRESS", 0x1C00))),
    ("ipl_rom_on", 0x1D00, 0x100, (("IPL_ROM_ON", 0x1D00),)),
    ("ipl_rom_off", 0x1E00, 0x100, (("IPL_ROM_OFF", 0x1E00),)),
    ("ctc", 0x1FA0, 0x0C, (("CTC_0", 0x1FA0), ("CTC_1", 0x1FA1), ("CTC_2", 0x1FA2), ("CTC_3", 0x1FA3))),
    ("attribute_vram", 0x2000, 0x1000, (("ATTRIBUTE_VRAM", 0x2000),)),
    ("text_vram", 0x3000, 0x1000, (("TEXT_VRAM", 0x3000),)),
    ("gram_blue", 0x4000, 0x4000, (("GRAM_BLUE", 0x4000),)),
    ("gram_red", 0x8000, 0x4000, (("GRAM_RED", 0x8000),)),
    ("gram_green", 0xC000, 0x4000, (("GRAM_GREEN", 0xC000),)),
)


class X1Error(ValueError):
    """An invalid or unsupported Sharp X1 load."""


def sector_address(lsn: int) -> tuple[int, int, int]:
    """Convert an X1 logical sector number to cylinder, head, and sector ID (16 sectors per side)."""
    if not 0 <= lsn <= 0xFFFF:
        raise X1Error(f"invalid X1 logical sector {lsn:x}")
    track, index = divmod(lsn, SECTORS_PER_TRACK)
    return track >> 1, track & 1, index + 1


@dataclass(frozen=True)
class IplHeader:
    """The 32-byte boot entry the X1 IPL ROM reads from sector 0:0:1."""

    name: str
    extension: str
    size: int
    load_address: int
    exec_address: int
    start_sector: int
    date: bytes

    @classmethod
    def parse(cls, data: bytes) -> "IplHeader":
        if len(data) < 0x20 or data[0] != 0x01 or data[0x0E:0x11] != b"Sys":
            raise X1Error("sector 0:0:1 has no X1 IPL boot entry (attribute 01, extension Sys); "
                          "select sectors with --x1-sector or --x1-lsn")
        size, load, start, start_sector = unpack_from("<HHH", data, 0x12) + unpack_from("<H", data, 0x1E)
        if not size or load + size > 0x10000:
            raise X1Error(f"X1 IPL entry loads {size:x} bytes at {load:x}, outside the 16-bit address space")
        return cls(
            data[1:0x0E].decode("cp932", errors="replace").rstrip(), data[0x0E:0x11].decode("ascii"),
            size, load, start, start_sector, bytes(data[0x18:0x1E]),
        )

    @property
    def sector_count(self) -> int:
        return (self.size + SECTOR_SIZE - 1) // SECTOR_SIZE

    def metadata(self) -> dict:
        cylinder, head, record = sector_address(self.start_sector)
        return {
            "name": self.name, "extension": self.extension, "size": self.size,
            "load_address": self.load_address, "exec_address": self.exec_address,
            "start_sector": self.start_sector, "start_chr": f"{cylinder}:{head}:{record}",
            "sector_count": self.sector_count, "date": self.date.hex(),
        }


def _check_geometry(source: Z80Source) -> None:
    if any(span.size != SECTOR_SIZE for span in source.file_spans[:-1]):
        raise X1Error("X1 disk loads require 256-byte sectors")


def disk_source(
    disk: D88Disk, filename: str, name: str, address: int, cylinder: int, head: int, record: int, count: int = 1,
) -> Z80Source:
    return disk_span_source(disk, filename, name, address, cylinder, head, record, count)


def lsn_source(disk: D88Disk, filename: str, name: str, address: int, lsn: int, count: int = 1) -> Z80Source:
    source = disk_span_source(disk, filename, name, address, *sector_address(lsn), count)
    _check_geometry(source)
    return source


def boot_source(disk: D88Disk, filename: str) -> tuple[Z80Source, IplHeader]:
    sector, = disk.read_sectors(0, 0, 1)
    if len(sector.data) != SECTOR_SIZE:
        raise X1Error("X1 boot requires a 256-byte sector at 0:0:1")
    header = IplHeader.parse(sector.data)
    source = disk_span_source(disk, filename, "root", header.load_address, *sector_address(header.start_sector),
                              header.sector_count, header.size)
    if len(source.data) != header.size:
        raise X1Error("X1 IPL payload is shorter than its header size")
    _check_geometry(source)
    return source, header


def copy_source(sources: list[Z80Source], address: int, size: int, destination: int) -> Z80Source:
    return copy_z80_source(sources, address, size, destination, X1Error, "X1")


def build_x1_image(
    sources: list[Z80Source], program: str, entries: list[int], view: str, disk: D88Disk | None,
    header: IplHeader | None = None,
) -> tuple[bytes, dict]:
    image, layout = place_z80_sources(sources, entries, X1_FORMAT, X1Error)
    if view == "ipl-rom" and any(unit["linear"] < IPL_ROM_END for unit in layout["units"]):
        raise X1Error("loaded bytes are hidden by the IPL ROM below 8000 for reads; select --x1-view ram")
    program_map = {
        "version": 1, "format": X1_FORMAT, "program": program, "machine": "X1",
        "memory_view": view,
        "memory_map": [
            {"name": "ipl_rom" if view == "ipl-rom" else "low_ram", "linear": 0, "size": IPL_ROM_END,
             "read": "rom" if view == "ipl-rom" else "ram", "write": "ram"},
            {"name": "high_ram", "linear": IPL_ROM_END, "size": 0x10000 - IPL_ROM_END, "read": "ram", "write": "ram"},
        ],
        "io_map": [
            {"name": name, "port": port, "size": size,
             "labels": [{"name": label, "port": address} for label, address in labels]}
            for name, port, size, labels in IO_MAP
        ],
        **layout,
    }
    if disk is not None:
        program_map["disk"] = disk.metadata
    if header is not None:
        program_map["ipl"] = header.metadata()
    return image, program_map
