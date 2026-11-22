"""Build a static NEC PC-8801 main-CPU view from disk sectors or raw loads."""

from .d88 import D88_SUFFIXES as DISK_SUFFIXES
from .d88 import D88Disk
from .image import PC88_FORMAT
from .z80 import SourceSpan, Z80Source, place_z80_sources

BOOT_ADDRESS = 0xC000
LOW_BANKS = ("ram", "n88-rom", "n-rom")
HIGH_BANKS = ("ram", "blue", "red", "green")


class Pc88Error(ValueError):
    """An invalid or unsupported PC-88 load."""


def disk_source(
    disk: D88Disk, filename: str, name: str, address: int, cylinder: int, head: int, record: int, count: int = 1,
) -> Z80Source:
    payload = bytearray()
    spans = []
    for sector in disk.read_sectors(cylinder, head, record, count):
        spans.append(SourceSpan(len(payload), sector.file_offset, len(sector.data)))
        payload.extend(sector.data)
    return Z80Source(name, filename, address, bytes(payload), file_spans=tuple(spans))


def boot_source(disk: D88Disk, filename: str) -> Z80Source:
    sector, = disk.read_sectors(0, 0, 1)
    if len(sector.data) != 256 or sector.size_code != 1:
        raise Pc88Error("PC-88 boot requires a 256-byte sector at 0:0:1")
    return Z80Source("root", filename, BOOT_ADDRESS, sector.data, file_offset=sector.file_offset)


def copy_source(sources: list[Z80Source], address: int, size: int, destination: int) -> Z80Source:
    end = address + size
    for source in reversed(sources):
        if source.address < end and address < source.end:
            if source.address <= address < end <= source.end:
                offset = address - source.address
                return Z80Source(
                    f"copy_{destination:04x}_from_{address:04x}_{size:x}", source.source,
                    destination, source.data[offset:offset + size],
                    file_offset=source.file_offset + offset, file_spans=source.spans(offset, size),
                )
            break
    raise Pc88Error(f"PC-88 copy {address:x}:{size:x} must fit within a single visible load")


def build_pc88_image(
    sources: list[Z80Source], program: str, entries: list[int], low: str, high: str, disk: D88Disk | None,
) -> tuple[bytes, dict]:
    image, layout = place_z80_sources(sources, entries, PC88_FORMAT, Pc88Error)
    if low != "ram" and any(unit["linear"] < 0x8000 for unit in layout["units"]):
        raise Pc88Error(f"loaded bytes are hidden by the {low} window below 8000; select --pc88-low ram")
    high_kind = "ram" if high == "ram" else f"vram_{high}"
    program_map = {
        "version": 1, "format": PC88_FORMAT, "program": program,
        "memory_view": f"{low}/{high}",
        "memory_map": [
            {"name": "low_ram" if low == "ram" else low.replace("-", "_"),
             "linear": 0, "size": 0x8000, "read": "ram" if low == "ram" else "rom", "write": "ram"},
            {"name": "mid_ram", "linear": 0x8000, "size": 0x4000, "read": "ram", "write": "ram"},
            {"name": "high_ram" if high == "ram" else high_kind,
             "linear": 0xC000, "size": 0x4000, "read": high_kind, "write": high_kind},
        ],
        **layout,
    }
    if disk is not None:
        program_map["disk"] = disk.metadata
    return image, program_map
