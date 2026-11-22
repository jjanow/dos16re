"""Search the initialized units of an exported DOS program."""

from pathlib import Path

from .image import ImageError, read_units


class SearchError(ValueError):
    """An invalid search pattern or DOS image export."""


def find_bytes(export: Path, pattern: bytes, *, limit: int | None = None) -> dict:
    if not pattern:
        raise SearchError("search pattern must contain at least one byte")
    image = (export / "image.bin").read_bytes()
    matches = []
    count = 0
    try:
        units = read_units(export, len(image))
    except ImageError as error:
        raise SearchError(str(error)) from error
    for unit in units:
        start, end = unit.image_offset, unit.image_offset + unit.size
        position = image.find(pattern, start, end)
        while position != -1:
            count += 1
            if limit is None or len(matches) < limit:
                matches.append(unit.location(position - start))
            position = image.find(pattern, position + 1, end)
    return {"pattern": pattern.hex(), "count": count, "matches": matches}
