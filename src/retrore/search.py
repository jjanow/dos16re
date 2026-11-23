"""Search file-backed portions of an exported program."""

from pathlib import Path

from .image import FLAT16_FORMATS, M68K_FORMATS, PC98_FORMAT, ImageError, image_units, read_map

_STRING_ENCODINGS = {
    "MZ": "cp437", "HUNK": "latin-1", "PRG": "ascii", PC98_FORMAT: "cp932",
} | dict.fromkeys(FLAT16_FORMATS, "ascii")


WIDTHS = (1, 2, 4, 8)


class SearchError(ValueError):
    """An invalid search pattern or image export."""


def search_pattern(
    *, hex_bytes: str | None = None, string: str | None = None, constant: str | int | None = None,
    width: int | None = None,
) -> tuple[bytes | str | int, int]:
    """Return the pattern and constant width for exactly one of hex bytes, a string, or a constant.

    A constant is an integer or a decimal or 0x-prefixed string. `width` applies only to constants.
    """
    given = [name for name, value in (("bytes", hex_bytes), ("string", string), ("constant", constant))
             if value is not None]
    if len(given) != 1:
        raise SearchError("specify exactly one of bytes, string, or constant")
    if width is not None and constant is None:
        raise SearchError("--width requires --constant")
    if width is not None and (type(width) is not int or width not in WIDTHS):
        raise SearchError(f"width must be one of {', '.join(map(str, WIDTHS))}")
    try:
        if hex_bytes is not None:
            if not isinstance(hex_bytes, str):
                raise ValueError("bytes must be a string of hexadecimal digits")
            return bytes.fromhex(hex_bytes), width or 2
        if string is not None:
            if not isinstance(string, str):
                raise ValueError("string must be a string")
            return string, width or 2
        if isinstance(constant, str):
            base = 16 if constant.lstrip("+-").lower().startswith("0x") else 10
            return int(constant, base), width or 2
        if type(constant) is not int:
            raise ValueError("constant must be an integer or a decimal or 0x-prefixed string")
        return constant, width or 2
    except ValueError as error:
        raise SearchError(str(error)) from error


def find_bytes(export: Path, pattern: bytes | str | int, *, width: int = 2, limit: int | None = None) -> dict:
    image = (export / "image.bin").read_bytes()
    try:
        program = read_map(export)
        units = image_units(program, len(image))
        image_format = program.get("format", "MZ")
        if isinstance(pattern, str):
            pattern = pattern.encode(_STRING_ENCODINGS[image_format])
        elif isinstance(pattern, int):
            pattern = pattern.to_bytes(width, "big" if image_format in M68K_FORMATS else "little", signed=pattern < 0)
    except ImageError:
        raise
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
