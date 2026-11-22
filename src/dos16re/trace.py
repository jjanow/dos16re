"""Map DOSBox-X debugger instruction logs onto an exported DOS image."""

import re
from bisect import bisect_right
from collections import Counter
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

from .ghidra import trace_coverage
from .image import ImageUnit, read_units
from .mz import Address

_TRACE_LINE = re.compile(r"^\s*(?:\d+\.\d+\s+)?([0-9a-fA-F]{4}):([0-9a-fA-F]{4,8})(?=\s|$)")


class TraceError(ValueError):
    """An invalid trace or runtime image placement."""


def _runtime_units(
    units: list[ImageUnit], root_segment: int | None, overlay_segments: dict[str, int],
) -> list[tuple[int, ImageUnit]]:
    if not units or units[0].name != "root":
        raise TraceError("the first image unit must be root")
    root = units[0]
    overlays = {unit.name.casefold(): unit for unit in units[1:]}
    placements = [(root.segment if root_segment is None else root_segment, root)]
    placed = set()
    for name, segment in overlay_segments.items():
        key = name.casefold()
        unit = overlays.get(key)
        if unit is None:
            raise TraceError(f"unknown overlay unit {name}")
        if key in placed:
            raise TraceError(f"runtime segment specified twice for {unit.name}")
        placed.add(key)
        placements.append((segment, unit))

    ranges = []
    for segment, unit in placements:
        if type(segment) is not int or not 0 <= segment <= 0xFFFF or segment * 16 + unit.size > 0x100000:
            raise TraceError(f"runtime placement for {unit.name} is outside the first MiB")
        if unit.size:
            ranges.append((segment * 16, unit))
    ranges.sort(key=lambda item: item[0])
    for (left_start, left), (right_start, right) in zip(ranges, ranges[1:]):
        if left_start + left.size > right_start:
            raise TraceError(f"runtime ranges overlap for {left.name} and {right.name}")
    return ranges


def import_trace(
    trace: Path, export: Path, *, runtime_base: int | None = None,
    overlay_segments: dict[str, int] | None = None, project: Path | None = None,
) -> dict:
    image = export / "image.bin"
    units = read_units(export, image.stat().st_size)
    if units[0].segment is None:
        raise TraceError("DOSBox-X traces require a DOS MZ image")
    ranges = _runtime_units(units, runtime_base, overlay_segments or {})
    starts = [start for start, _ in ranges]
    counts: Counter[int] = Counter()
    addresses: dict[int, str] = {}
    ignored = 0
    with trace.open(encoding="utf-8-sig", errors="replace") as source:
        for line in source:
            match = _TRACE_LINE.match(line)
            if match is None or (offset := int(match[2], 16)) > 0xFFFF:
                ignored += bool(line.strip())
                continue
            address = Address(int(match[1], 16), offset)
            linear = address.linear
            counts[linear] += 1
            if linear not in addresses:
                addresses[linear] = str(address)
    if not counts:
        raise TraceError("trace contains no 16-bit DOSBox-X instruction addresses")

    mapped, unmapped = [], []
    for linear, count in sorted(counts.items()):
        hit = {"runtime_address": addresses[linear], "count": count}
        index = bisect_right(starts, linear) - 1
        if index >= 0:
            start, unit = ranges[index]
            offset = linear - start
            if offset < unit.size:
                mapped.append({**hit, **unit.location(offset)})
                continue
        unmapped.append(hit)
    analysis = None
    if project is not None:
        analysis = trace_coverage(project, {
            "sha256": sha256(image.read_bytes()).hexdigest(),
            "units": [asdict(unit) for unit in units],
            "hits": mapped,
        })
    return {
        "instructions": counts.total(), "ignored_lines": ignored,
        "mapped": mapped, "unmapped": unmapped, "analysis": analysis,
    }
