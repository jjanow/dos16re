"""Read MSX-DOS disk members and reconstruct a selected Z80 RAM layout."""

from .fat12 import Fat12Disk
from .image import MSX2_FORMAT, SourceSpan
from .z80 import Z80Source as Msx2Source
from .z80 import place_z80_sources

COM_ADDRESS = 0x0100
_SECTOR_SIZE = 512


class Msx2Error(ValueError):
    """An invalid or unsupported MSX2 input."""


class MsxDosDisk(Fat12Disk):
    """Read files from the root of a raw FAT12 floppy with a DOS BPB."""

    error = Msx2Error
    member_type = "MSX-DOS disk file"
    sector_sizes = (_SECTOR_SIZE,)

    def read_file(self, name: str) -> bytes:
        return self.read_file_with_spans(name)[0]

    def read_file_with_spans(self, name: str) -> tuple[bytes, tuple[SourceSpan, ...]]:
        _, contents, spans = self.extract_file(name)
        return contents, spans


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
