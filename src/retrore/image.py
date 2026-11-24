"""Read units and locations from an image export."""

import json
from dataclasses import dataclass
from pathlib import Path

from .errors import CodedError
from .mz import Address

# Major version of map.json. Writers set "version" to this value; additive fields keep it unchanged.
MAP_VERSION = 1

DEFAULT_M68K_BASE = 0x10000
M68K_ADDRESS_LIMIT = 0x1000000
X68K_FORMAT = "X68K"
MAC68K_FORMAT = "MAC68K"
GENESIS_FORMAT = "GENESIS"
M68K_FORMATS = ("HUNK", "PRG", X68K_FORMAT, MAC68K_FORMAT, GENESIS_FORMAT)
C64_FORMAT = "C64_PRG"
APPLE2_FORMAT = "APPLE2"
ATARI8_FORMAT = "ATARI8"
NES_FORMAT = "NES"
MSX2_FORMAT = "MSX2"
PC88_FORMAT = "PC88"
PC98_FORMAT = "PC98"
X1_FORMAT = "X1"
PC98_RAM_END = 0xA0000
MOS6502_FORMATS = (C64_FORMAT, APPLE2_FORMAT, ATARI8_FORMAT, NES_FORMAT)
Z80_FORMATS = (MSX2_FORMAT, PC88_FORMAT, X1_FORMAT)
FLAT16_FORMATS = (*MOS6502_FORMATS, *Z80_FORMATS)
FLAT16_ADDRESS_LIMIT = MOS6502_ADDRESS_LIMIT = 0x10000
_FLAT_LIMITS = dict.fromkeys(M68K_FORMATS, M68K_ADDRESS_LIMIT) | dict.fromkeys(FLAT16_FORMATS, FLAT16_ADDRESS_LIMIT)


class ImageError(CodedError):
    """An invalid image export."""

    default_code = "export_invalid"


class RuntimePlacementError(ValueError):
    """An invalid runtime image placement."""


@dataclass(frozen=True)
class SourceSpan:
    offset: int
    file_offset: int
    size: int


def slice_source_spans(spans: tuple[SourceSpan, ...], offset: int, size: int) -> tuple[SourceSpan, ...]:
    """Return source spans for a slice, with offsets relative to its beginning."""
    result = []
    for span in spans:
        start = max(span.offset, offset)
        end = min(span.offset + span.size, offset + size)
        if start < end:
            result.append(SourceSpan(start - offset, span.file_offset + start - span.offset, end - start))
    return tuple(result)


def check_map_version(program: object) -> int:
    """Return a map's major version. Maps without "version" predate versioning and read as version 1."""
    if not isinstance(program, dict):
        raise ImageError("invalid map.json: expected a JSON object")
    version = program.get("version", 1)
    if type(version) is not int or version < 1:
        raise ImageError(f"invalid map.json: version must be a positive integer, not {version!r}")
    if version > MAP_VERSION:
        raise ImageError(
            f"map.json version {version} is newer than supported version {MAP_VERSION}",
            code="unsupported_map_version",
        )
    return version


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


def dos_runtime_units(
    units: list[ImageUnit], root_segment: int | None, overlay_segments: dict[str, int],
) -> list[tuple[int, ImageUnit]]:
    if not units or units[0].name != "root":
        raise RuntimePlacementError("the first image unit must be root")
    root = units[0]
    overlays = {unit.name.casefold(): unit for unit in units[1:]}
    placements = [(root.segment if root_segment is None else root_segment, root)]
    placed = set()
    for name, segment in overlay_segments.items():
        key = name.casefold()
        unit = overlays.get(key)
        if unit is None:
            raise RuntimePlacementError(f"unknown overlay unit {name}")
        if key in placed:
            raise RuntimePlacementError(f"runtime segment specified twice for {unit.name}")
        placed.add(key)
        placements.append((segment, unit))

    ranges = []
    for segment, unit in placements:
        if type(segment) is not int or not 0 <= segment <= 0xFFFF or segment * 16 + unit.size > 0x100000:
            raise RuntimePlacementError(f"runtime placement for {unit.name} is outside the first MiB")
        if unit.size:
            ranges.append((segment * 16, unit))
    ranges.sort(key=lambda item: item[0])
    for (left_start, left), (right_start, right) in zip(ranges, ranges[1:]):
        if left_start + left.size > right_start:
            raise RuntimePlacementError(f"runtime ranges overlap for {left.name} and {right.name}")
    return ranges


def explicit_runtime_units(
    units: list[ImageUnit], placements: dict[str, int | None], image_format: str,
) -> dict[str, int]:
    """Place exported units in a caller-supplied linear address view."""
    units_by_name = {unit.name.casefold(): unit for unit in units}
    overrides = {}
    for name, start in placements.items():
        key = name.casefold()
        if key not in units_by_name:
            raise RuntimePlacementError(f"unknown runtime unit {name}")
        if key in overrides:
            raise RuntimePlacementError(f"runtime placement specified twice for {name}")
        overrides[key] = start
    limit = _FLAT_LIMITS.get(image_format, 0x100000)
    ranges = []
    for unit in units:
        start = overrides.get(unit.name.casefold(), unit.linear)
        if start is None:
            continue
        if type(start) is not int or not 0 <= start < limit or start + unit.size > limit:
            raise RuntimePlacementError(f"runtime placement for {unit.name} exceeds the platform address space")
        if unit.size:
            ranges.append((start, unit))
    ranges.sort(key=lambda item: item[0])
    for (start, unit), (next_start, next_unit) in zip(ranges, ranges[1:]):
        if start + unit.size > next_start:
            raise RuntimePlacementError(f"runtime ranges overlap for {unit.name} and {next_unit.name}")
    return {unit.name: start for start, unit in ranges}


def read_map(export: Path) -> dict:
    try:
        program = json.loads((export / "map.json").read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ImageError(f"map.json not found in {export}") from error
    except (UnicodeError, ValueError) as error:
        raise ImageError(f"invalid map.json: {error}") from error
    check_map_version(program)
    try:
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
