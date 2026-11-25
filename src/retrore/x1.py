"""Build static Sharp X1 and X1turbo CPU views from disk sectors or raw loads."""

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
TURBO_BANK_PORT = 0x0B00
DEFAULT_TURBO_BANK = 0x10  # Expansion RAM deselected.

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

# X1turbo and its option boards (MAME x1turbo_io_banks). The kanji attribute
# plane replaces the base X1's text VRAM mirror at 3800–3FFF.
TURBO_IO_MAP = tuple(sorted((
    *(region for region in IO_MAP if region[0] != "text_vram"),
    ("fm", 0x0700, 0x02, (("FM_REGISTER_SELECT", 0x0700), ("FM_DATA_STATUS", 0x0701))),
    ("fm_ctc", 0x0704, 0x04, (("FM_CTC_0", 0x0704), ("FM_CTC_1", 0x0705),
                             ("FM_CTC_2", 0x0706), ("FM_CTC_3", 0x0707))),
    ("color_image", 0x0800, 0x04, (("COLOR_IMAGE_CONTROL", 0x0800), ("COLOR_IMAGE_STATUS", 0x0801),
                                  ("COLOR_IMAGE_CONTROL_2", 0x0802), ("COLOR_IMAGE_STATUS_2", 0x0803))),
    ("stereo", 0x0A00, 0x08, (("STEREO_BOARD", 0x0A00),)),
    ("bank_control", TURBO_BANK_PORT, 0x01, (("BANK_CONTROL", TURBO_BANK_PORT),)),
    ("rs232", 0x0C00, 0x100, (("RS232_EXPANSION", 0x0C00),)),
    ("emm", 0x0D00, 0x04, (("EMM_ADDRESS_LOW", 0x0D00), ("EMM_ADDRESS_MID", 0x0D01),
                           ("EMM_ADDRESS_HIGH", 0x0D02), ("EMM_DATA", 0x0D03))),
    ("kanji_rom", 0x0E80, 0x04, (("KANJI_ROM_LOW", 0x0E80), ("KANJI_ROM_HIGH", 0x0E81),
                                 ("KANJI_ROM_SELECT", 0x0E82))),
    ("sasi", 0x0FD0, 0x04, (("SASI_INTERFACE", 0x0FD0),)),
    ("fdc_8inch", 0x0FE8, 0x08, (("FDC_8INCH", 0x0FE8),)),
    ("dma", 0x1F80, 0x10, (("DMA_CONTROL", 0x1F80),)),
    ("sio", 0x1F90, 0x04, (("SIO_A_DATA", 0x1F90), ("SIO_A_CONTROL", 0x1F91),
                           ("SIO_B_DATA", 0x1F92), ("SIO_B_CONTROL", 0x1F93))),
    ("extended_sio_ctc", 0x1F98, 0x08, (("EXTENDED_SIO_CTC", 0x1F98),)),
    ("display_control", 0x1FD0, 0x10, (("DISPLAY_CONTROL", 0x1FD0),)),
    ("black_clip", 0x1FE0, 0x01, (("BLACK_CLIP", 0x1FE0),)),
    ("dip_switches", 0x1FF0, 0x01, (("DIP_SWITCHES", 0x1FF0),)),
    ("text_vram", 0x3000, 0x0800, (("TEXT_VRAM", 0x3000),)),
    ("kanji_vram", 0x3800, 0x0800, (("KANJI_VRAM", 0x3800),)),
), key=lambda region: region[1]))


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
    header: IplHeader | None = None, *, bank_control: int | None = None,
) -> tuple[bytes, dict]:
    turbo = bank_control is not None
    if turbo and not 0 <= bank_control <= 0xFF:
        raise X1Error("X1turbo bank control must be a byte (00–ff)")
    # X Millennium's bank window covers only 0000–7FFF. Bit 4 enables
    # expansion RAM when clear and bits 0–3 choose its page.
    bank = bank_control & 0x0F if turbo and not bank_control & 0x10 else None
    ipl_visible = bank is None and view == "ipl-rom"
    low_kind = "rom" if ipl_visible else "ram"
    low_name = "ipl_rom" if ipl_visible else "low_ram"
    if bank is not None:
        low_name = f"bank_ram_{bank:x}"
    image, layout = place_z80_sources(sources, entries, X1_FORMAT, X1Error)
    if ipl_visible and any(unit["linear"] < IPL_ROM_END for unit in layout["units"]):
        raise X1Error("loaded bytes are hidden by the IPL ROM below 8000 for reads; select --x1-view ram")
    program_map = {
        "version": 1, "format": X1_FORMAT, "program": program, "machine": "X1turbo" if turbo else "X1",
        "memory_view": view if bank is None else f"bank-{bank:x}",
        "memory_map": [
            {"name": low_name, "linear": 0, "size": IPL_ROM_END, "read": low_kind,
             "write": "ram"},
            {"name": "high_ram", "linear": IPL_ROM_END, "size": 0x10000 - IPL_ROM_END, "read": "ram", "write": "ram"},
        ],
        "io_map": [
            {"name": name, "port": port, "size": size,
             "labels": [{"name": label, "port": address} for label, address in labels]}
            for name, port, size, labels in (TURBO_IO_MAP if turbo else IO_MAP)
        ],
        **layout,
    }
    if turbo:
        program_map["bank_control"] = {"port": TURBO_BANK_PORT, "value": bank_control, "bank": bank, "ipl_view": view}
    if disk is not None:
        program_map["disk"] = disk.metadata
    if header is not None:
        program_map["ipl"] = header.metadata()
    return image, program_map
