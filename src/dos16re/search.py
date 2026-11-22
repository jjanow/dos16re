"""Search the initialized units of an exported DOS program."""

import json
from pathlib import Path

from .mz import Address


class SearchError(ValueError):
    """An invalid search pattern or DOS image export."""


def find_bytes(export: Path, pattern: bytes, *, limit: int | None = None) -> dict:
    if not pattern:
        raise SearchError("search pattern must contain at least one byte")
    image = (export / "image.bin").read_bytes()
    matches = []
    count = 0
    for start, end, name, segment in _unit_ranges(export, len(image)):
        position = image.find(pattern, start, end)
        while position != -1:
            count += 1
            if limit is None or len(matches) < limit:
                offset = position - start
                address = Address(segment, offset)
                if offset > 0xFFFF:
                    address = Address(address.linear >> 4, address.linear & 0xF)
                matches.append({
                    "address": str(address), "unit_address": f"{name}:{offset:04x}",
                    "linear": address.linear,
                })
            position = image.find(pattern, position + 1, end)
    return {"pattern": pattern.hex(), "count": count, "matches": matches}


def _unit_ranges(export: Path, image_size: int) -> list[tuple[int, int, str, int]]:
    try:
        program = json.loads((export / "map.json").read_text(encoding="utf-8"))
        if program["version"] != 1:
            raise ValueError("unsupported map version")
        units = program["units"]
        origin = units[0]["linear"]
        if type(origin) is not int or not 0 <= origin <= origin + image_size <= 0x100000:
            raise ValueError("image extends past the 1 MiB image limit")
        ranges = []
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
            ranges.append((start, start + size, name, segment))
        ranges.sort()
        if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
            raise ValueError("image units overlap")
        return ranges
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise SearchError(f"invalid map.json: {error}") from error
