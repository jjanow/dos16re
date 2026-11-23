"""Read units and locations from an image export."""

import json
from dataclasses import dataclass
from pathlib import Path

from .mz import Address

DEFAULT_M68K_BASE = 0x10000
M68K_ADDRESS_LIMIT = 0x1000000
M68K_FORMATS = ("HUNK", "PRG")
C64_FORMAT = "C64_PRG"
APPLE2_FORMAT = "APPLE2"
ATARI8_FORMAT = "ATARI8"
MSX2_FORMAT = "MSX2"
PC88_FORMAT = "PC88"
PC98_FORMAT = "PC98"
X1_FORMAT = "X1"
PC98_RAM_END = 0xA0000
MOS6502_FORMATS = (C64_FORMAT, APPLE2_FORMAT, ATARI8_FORMAT)
Z80_FORMATS = (MSX2_FORMAT, PC88_FORMAT, X1_FORMAT)
FLAT16_FORMATS = (*MOS6502_FORMATS, *Z80_FORMATS)
FLAT16_ADDRESS_LIMIT = MOS6502_ADDRESS_LIMIT = 0x10000
_FLAT_LIMITS = dict.fromkeys(M68K_FORMATS, M68K_ADDRESS_LIMIT) | dict.fromkeys(FLAT16_FORMATS, FLAT16_ADDRESS_LIMIT)


class ImageError(ValueError):
    """An invalid image export."""


@dataclass(frozen=True)
class ImageUnit:
    name: str
    linear: int
    image_offset: int
    size: int
    file_size: int
    segment: int | None
    address_width: int = 8

    def location(self, offset: int) -> dict:
        linear = self.linear + offset
        if self.segment is None:
            address = f"{linear:0{self.address_width}x}"
        else:
            segmented = Address(self.segment, offset) if offset <= 0xFFFF else Address(linear >> 4, linear & 0xF)
            address = str(segmented)
        return {"address": address, "unit_address": f"{self.name}:{offset:04x}", "linear": linear}


def read_map(export: Path) -> dict:
    try:
        program = json.loads((export / "map.json").read_text(encoding="utf-8"))
        if program["version"] != 1:
            raise ValueError("unsupported map version")
        if program.get("format", "MZ") not in ("MZ", PC98_FORMAT, *_FLAT_LIMITS):
            raise ValueError("unsupported image format")
        return program
    except (KeyError, TypeError, ValueError) as error:
        raise ImageError(f"invalid map.json: {error}") from error


def read_units(export: Path, image_size: int) -> list[ImageUnit]:
    return image_units(read_map(export), image_size)


def image_units(program: dict, image_size: int) -> list[ImageUnit]:
    image_format = program.get("format", "MZ")
    flat = image_format in _FLAT_LIMITS
    address_width = 4 if image_format in FLAT16_FORMATS else 8
    try:
        units = program["units"]
        origin = program["image_origin"] if image_format == PC98_FORMAT else units[0]["linear"]
        limit = PC98_RAM_END if image_format == PC98_FORMAT else _FLAT_LIMITS.get(image_format, 0x100000)
        if type(origin) is not int or not 0 <= origin <= origin + image_size <= limit:
            if image_format == PC98_FORMAT:
                raise ValueError("image extends past PC-98 conventional RAM")
            size_limit = f"{limit >> 20} MiB" if limit >= 0x100000 else "64 KiB"
            raise ValueError(f"image extends past the {size_limit} image limit")
        placements = []
        for unit in units:
            name, linear, start, size = (unit[key] for key in ("name", "linear", "image_offset", "size"))
            if not isinstance(name, str) or not name:
                raise ValueError("missing unit name")
            if not (
                type(linear) is int and type(start) is int and origin + start == linear
                and type(size) is int and 0 <= start <= start + size <= image_size
            ):
                raise ValueError(f"invalid placement for unit {name}")
            segment = None
            file_size = size
            if flat:
                file_size = unit["file_size"]
                if type(file_size) is not int or not 0 <= file_size <= size:
                    raise ValueError(f"invalid file size for unit {name}")
            else:
                segment = unit["segment"]
                if type(segment) is not int or not 0 <= segment <= 0xFFFF or segment * 16 != linear:
                    raise ValueError(f"invalid segment for unit {name}")
            placements.append(ImageUnit(name, linear, start, size, file_size, segment, address_width))
        placements.sort(key=lambda unit: (unit.image_offset, unit.size))
        if image_format == PC98_FORMAT and placements[0].image_offset:
            raise ValueError("invalid PC-98 image origin")
        if any(left.image_offset + left.size > right.image_offset for left, right in zip(placements, placements[1:])):
            raise ValueError("image units overlap")
        return placements
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise ImageError(f"invalid map.json: {error}") from error
