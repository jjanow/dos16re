"""Read initialized unit ranges from a DOS image export."""

import json
from dataclasses import dataclass
from pathlib import Path

from .mz import Address


class ImageError(ValueError):
    """An invalid DOS image export."""


@dataclass(frozen=True)
class ImageUnit:
    name: str
    segment: int
    image_offset: int
    size: int

    @property
    def linear(self) -> int:
        return self.segment * 16

    def location(self, offset: int) -> dict:
        address = Address(self.segment, offset)
        if offset > 0xFFFF:
            address = Address(address.linear >> 4, address.linear & 0xF)
        return {"address": str(address), "unit_address": f"{self.name}:{offset:04x}", "linear": address.linear}


def read_units(export: Path, image_size: int) -> list[ImageUnit]:
    try:
        program = json.loads((export / "map.json").read_text(encoding="utf-8"))
        if program["version"] != 1:
            raise ValueError("unsupported map version")
        units = program["units"]
        origin = units[0]["linear"]
        if type(origin) is not int or not 0 <= origin <= origin + image_size <= 0x100000:
            raise ValueError("image extends past the 1 MiB image limit")
        placements = []
        for unit in units:
            name, segment, start, size = (unit[key] for key in ("name", "segment", "image_offset", "size"))
            if not isinstance(name, str) or not name:
                raise ValueError("missing unit name")
            if not (
                type(segment) is int and 0 <= segment <= 0xFFFF
                and type(start) is int and origin + start == segment * 16 == unit["linear"]
                and type(size) is int and 0 <= start <= start + size <= image_size
            ):
                raise ValueError(f"invalid placement for unit {name}")
            placements.append(ImageUnit(name, segment, start, size))
        placements.sort(key=lambda unit: (unit.image_offset, unit.size))
        if any(left.image_offset + left.size > right.image_offset for left, right in zip(placements, placements[1:])):
            raise ValueError("image units overlap")
        return placements
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise ImageError(f"invalid map.json: {error}") from error
