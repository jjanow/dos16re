"""Map DOSBox-X debugger instruction logs onto an exported DOS image."""

import re
from bisect import bisect_right
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from .evidence import EvidenceError, ExportEvidence
from .ghidra import QUERY_TIMEOUT, trace_coverage
from .mz import Address

_TRACE_LINE = re.compile(r"^\s*(?:\d+\.\d+\s+)?([0-9a-fA-F]{4}):([0-9a-fA-F]{4,8})(?=\s|$)")


class TraceError(ValueError):
    """An invalid trace or runtime image placement."""


def import_trace(
    trace: Path, export: Path, *, runtime_base: int | None = None,
    overlay_segments: dict[str, int] | None = None, project: Path | None = None,
    timeout: float | None = QUERY_TIMEOUT, classify_gaps: bool = False, evidence: bool = False,
) -> dict:
    if classify_gaps and project is None:
        raise TraceError("classifying gaps requires a Ghidra project")
    try:
        image = ExportEvidence(export, runtime_base, overlay_segments)
    except EvidenceError as error:
        raise TraceError(str(error)) from error
    if image.format != "MZ":
        raise TraceError("DOSBox-X traces require a DOS MZ image")
    ranges = [(image.runtime[unit.name], unit) for unit in image.units if unit.name in image.runtime]
    ranges.sort(key=lambda placement: placement[0])
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
    anchors = {}
    for linear, count in sorted(counts.items()):
        hit = {"runtime_address": addresses[linear], "count": count}
        index = bisect_right(starts, linear) - 1
        if index >= 0:
            start, unit = ranges[index]
            offset = linear - start
            if offset < unit.size:
                location = unit.location(offset)
                mapped.append({**hit, **location})
                if evidence:
                    position = unit.image_offset + offset
                    original, _ = image.original
                    anchors[location["linear"]] = {
                        "address": image.location(unit, offset),
                        "loaded": image.image[position:position + 1].hex(),
                        "original": original[position:position + 1].hex(),
                    }
                continue
        unmapped.append(hit)
    identity = image.identity() if project is not None or evidence else None
    analysis = None
    if project is not None:
        analysis = trace_coverage(project, {
            "sha256": identity["image_sha256"],
            "units": [asdict(unit) for unit in image.units],
            "hits": mapped,
            "classify_gaps": classify_gaps,
        }, timeout=timeout)
    report = {
        "instructions": counts.total(), "ignored_lines": ignored,
        "mapped": mapped, "unmapped": unmapped, "analysis": analysis,
    }
    # Keep loader evidence out of the Ghidra coverage request.
    if evidence:
        report["export"] = identity
        for hit in mapped:
            hit["export_evidence"] = anchors[hit["linear"]]
        if analysis is not None:
            for hit in analysis["missed"]:
                hit["export_evidence"] = anchors[hit["linear"]]
            for gap in analysis.get("observed_gaps", ()):
                for hit in gap["trace_evidence"]["examples"]:
                    hit["export_evidence"] = anchors[hit["linear"]]
    return report
