"""Search file-backed portions of an exported program."""

from pathlib import Path

from .image import image_units, read_map


class SearchError(ValueError):
    """An invalid search pattern or image export."""


def find_bytes(export: Path, pattern: bytes | str | int, *, width: int = 2, limit: int | None = None) -> dict:
    image = (export / "image.bin").read_bytes()
    try:
        program = read_map(export)
        units = image_units(program, len(image))
        amiga = program.get("format") == "HUNK"
        if isinstance(pattern, str):
            pattern = pattern.encode("latin-1" if amiga else "cp437")
        elif isinstance(pattern, int):
            pattern = pattern.to_bytes(width, "big" if amiga else "little", signed=pattern < 0)
    except (ValueError, OverflowError) as error:
        raise SearchError(str(error)) from error
    if not pattern:
        raise SearchError("search pattern must contain at least one byte")
    matches = []
    count = 0
    for unit in units:
        start, end = unit.image_offset, unit.image_offset + unit.file_size
        position = image.find(pattern, start, end)
        while position != -1:
            count += 1
            if limit is None or len(matches) < limit:
                matches.append(unit.location(position - start))
            position = image.find(pattern, position + 1, end)
    return {"pattern": pattern.hex(), "count": count, "matches": matches}
