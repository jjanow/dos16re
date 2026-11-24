"""Discover the directory or index exposed by a supported disk or container."""

from pathlib import Path

from .apple2 import DISK_SUFFIXES, Apple2Error, SectorImage
from .atari8 import ATR_MAGIC, AtrImage
from .c64 import D64Image
from .d88 import D88_SUFFIXES, D88Disk
from .errors import CONTRACT_VERSION
from .macintosh import is_macintosh, list_macintosh_members
from .members import MemberError
from .msx2 import Msx2Error, MsxDosDisk
from .pc98 import HDM_SUFFIX, HdmDisk

CONTAINER_FORMATS = ("d64", "apple2", "atr", "fat12", "d88", "hdm", "macintosh")
MACINTOSH_SUFFIXES = (".rsrc", ".dc42", ".macbin", ".as", ".ad")


def apple2_disk_order(suffix: str, order: str | None) -> str | None:
    return order or ("prodos" if suffix == ".po" else None)


def _dsk_format(data: bytes, order: str | None) -> str:
    candidates = []
    for name, parser, error in (("apple2", lambda: SectorImage(data, order=order), Apple2Error),
                                ("fat12", lambda: MsxDosDisk(data), Msx2Error)):
        try:
            parser()
        except error:
            continue
        candidates.append(name)
    if len(candidates) == 1:
        return candidates[0]
    if candidates:
        raise MemberError("ambiguous .dsk container. Select --format apple2 or --format fat12")
    raise MemberError("no supported .dsk catalog found. Select --format apple2 or --format fat12 for details")


def inspect_members(program: Path, format_name: str | None = None, order: str | None = None) -> dict:
    """Read catalog metadata without extracting or loading the selected program."""
    data = program.read_bytes()
    suffix = program.suffix.lower()
    if format_name is None:
        if order is not None or suffix in DISK_SUFFIXES and suffix != ".dsk":
            format_name = "apple2"
        elif suffix == ".d64":
            format_name = "d64"
        elif suffix in D88_SUFFIXES:
            format_name = "d88"
        elif suffix == HDM_SUFFIX:
            format_name = "hdm"
        elif suffix == ".atr" or data.startswith(ATR_MAGIC):
            format_name = "atr"
        elif suffix in MACINTOSH_SUFFIXES or is_macintosh(data):
            format_name = "macintosh"
        elif suffix == ".dsk":
            format_name = _dsk_format(data, order)
        else:
            raise MemberError("no supported container detected. Specify --format if the filename is ambiguous")
    if order is not None and format_name != "apple2":
        raise MemberError("--apple2-disk-order requires an Apple II sector image")

    details = {}
    if format_name == "d64":
        rows = D64Image(data).list_members()
    elif format_name == "apple2":
        disk = SectorImage(data, order=apple2_disk_order(suffix, order))
        details = {"filesystem": disk.filesystem, "sector_order": disk.order}
        rows = disk.list_members()
    elif format_name == "atr":
        disk = AtrImage(data)
        details = {"sector_size": disk.sector_size, "sector_count": disk.sector_count,
                   "directory": "Atari DOS 2.x" if disk.has_directory else None}
        rows = disk.list_members()
    elif format_name == "fat12":
        rows = MsxDosDisk(data).list_members()
    elif format_name == "d88":
        rows = D88Disk.list_members(data)
    elif format_name == "hdm":
        rows = [HdmDisk(data).member]
    elif format_name == "macintosh":
        format_name, rows = list_macintosh_members(data, program.name)
    else:
        raise MemberError(f"unknown container format {format_name!r}")
    report = {"contract": CONTRACT_VERSION, "format": format_name, "source": program.name,
              "count": len(rows), "members": [member.record() for member in rows]}
    if details:
        report["details"] = details
    return report
