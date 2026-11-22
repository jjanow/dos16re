"""Read units and locations from an image export."""

import json
from dataclasses import dataclass
from pathlib import Path

from .mz import Address

DEFAULT_M68K_BASE = 0x10000
M68K_ADDRESS_LIMIT = 0x1000000
M68K_FORMATS = ("HUNK", "PRG")


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

    def location(self, offset: int) -> dict:
        linear = self.linear + offset
        if self.segment is None:
            address = f"{linear:08x}"
        else:
            segmented = Address(self.segment, offset) if offset <= 0xFFFF else Address(linear >> 4, linear & 0xF)
            address = str(segmented)
        return {"address": address, "unit_address": f"{self.name}:{offset:04x}", "linear": linear}


def read_map(export: Path) -> dict:
    try:
        program = json.loads((export / "map.json").read_text(encoding="utf-8"))
        if program["version"] != 1:
            raise ValueError("unsupported map version")
        if program.get("format", "MZ") not in ("MZ", *M68K_FORMATS):
            raise ValueError("unsupported image format")
        return program
    except (KeyError, TypeError, ValueError) as error:
        raise ImageError(f"invalid map.json: {error}") from error


def read_units(export: Path, image_size: int) -> list[ImageUnit]:
    return image_units(read_map(export), image_size)


def image_units(program: dict, image_size: int) -> list[ImageUnit]:
    flat = program.get("format") in M68K_FORMATS
    try:
        units = program["units"]
        origin = units[0]["linear"]
        limit = M68K_ADDRESS_LIMIT if flat else 0x100000
        if type(origin) is not int or not 0 <= origin <= origin + image_size <= limit:
            raise ValueError(f"image extends past the {limit >> 20} MiB image limit")
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
            placements.append(ImageUnit(name, linear, start, size, file_size, segment))
        placements.sort(key=lambda unit: (unit.image_offset, unit.size))
        if any(left.image_offset + left.size > right.image_offset for left, right in zip(placements, placements[1:])):
            raise ValueError("image units overlap")
        return placements
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise ImageError(f"invalid map.json: {error}") from error
