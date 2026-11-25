"""Map DOSBox-X debugger logs and versioned emulator traces onto exported images."""

import json
import re
from bisect import bisect_right
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import TextIO

from .dynamic import TraceAddressBackend
from .evidence import EvidenceError, ExportEvidence
from .ghidra import QUERY_TIMEOUT, trace_coverage
from .image import ImageUnit, RuntimePlacementError, RuntimeSpan, explicit_runtime_units, runtime_spans
from .load_manifest import LoadManifestError, state_loads, state_spans
from .mz import Address

_TRACE_LINE = re.compile(r"^\s*(?:\d+\.\d+\s+)?([0-9a-fA-F]{4}):([0-9a-fA-F]{4,8})(?=\s|$)")
_TRACE_VERSION = 1
_MAX_INSTRUCTION_BYTES = 32


class TraceError(ValueError):
    """An invalid trace or runtime image placement."""


def import_trace(
    trace: Path, export: Path, *, runtime_base: int | None = None,
    overlay_segments: dict[str, int] | None = None, project: Path | None = None,
    timeout: float | None = QUERY_TIMEOUT, classify_gaps: bool = False, evidence: bool = False,
    runtime_loads: dict[str, int | None] | None = None, apply: bool = False, program: str | None = None,
    state: str | None = None,
) -> dict:
    if project is None:
        if classify_gaps:
            raise TraceError("classifying gaps requires a Ghidra project")
        if apply or program is not None:
            raise TraceError("applying trace additions or selecting a program requires a Ghidra project")
    try:
        image = ExportEvidence(export, runtime_base, overlay_segments, runtime_loads=runtime_loads, state=state)
    except (EvidenceError, LoadManifestError) as error:
        raise TraceError(str(error)) from error
    with trace.open(encoding="utf-8-sig", errors="replace") as source:
        first = source.read(1)
        while first and first.isspace():
            first = source.read(1)
        source.seek(0)
        if first == "{" or trace.suffix.casefold() == ".json":
            try:
                document = json.loads(source.buffer.read().decode("utf-8-sig"))
            except ValueError as error:
                raise TraceError(f"invalid trace JSON: {error}") from error
            report = _structured_trace(image, _object(document, "trace document"), evidence)
        else:
            report = _dosbox_trace(image, source, evidence)

    if evidence:
        report["export"] = image.identity()
    if project is not None:
        report["analysis"] = _analyze(
            report, image, project, timeout=timeout, classify_gaps=classify_gaps, apply=apply, program=program,
        )
    return report


def _dosbox_trace(image: ExportEvidence, source: TextIO, evidence: bool) -> dict:
    if image.format != "MZ":
        raise TraceError("DOSBox-X traces require a DOS MZ image")
    backend = TraceAddressBackend(image)
    counts: Counter[int] = Counter()
    addresses: dict[int, str] = {}
    ignored = 0
    for line in source:
        match = _TRACE_LINE.match(line)
        if match is None or (offset := int(match[2], 16)) > 0xFFFF:
            ignored += bool(line.strip())
            continue
        address = Address(int(match[1], 16), offset)
        linear = address.linear
        counts[linear] += 1
        addresses.setdefault(linear, str(address))
    if not counts:
        raise TraceError("trace contains no 16-bit DOSBox-X instruction addresses")

    mapped, unmapped = [], []
    for linear, count in sorted(counts.items()):
        hit = {"runtime_address": addresses[linear], "count": count}
        match = backend.location(linear)
        if match is None:
            unmapped.append(hit)
        else:
            unit, offset = match
            if evidence:
                hit["export_evidence"] = _proof(image, unit, offset)
            mapped.append({**hit, **unit.location(offset)})
    return {
        "instructions": counts.total(), "ignored_lines": ignored,
        "mapped": mapped, "unmapped": unmapped, "analysis": None,
    }


def _proof(image: ExportEvidence, unit: ImageUnit, offset: int, runtime: dict | None = None) -> dict:
    position = unit.image_offset + offset
    original, _ = image.original
    location = image.location(unit, offset)
    if runtime is not None:
        location["runtime"] = {"address": runtime["runtime_address"], "linear": runtime["runtime_linear"]}
    return {"address": location, "loaded": image.image[position:position + 1].hex(),
            "original": original[position:position + 1].hex()}


def _array(value: object, label: str) -> list:
    if not isinstance(value, list):
        raise TraceError(f"{label} must be an array")
    return value


def _object(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise TraceError(f"{label} must be an object")
    return value


def _number(value: object, label: str, minimum: int = 0, maximum: int = 0xFFFFFFFF) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise TraceError(f"{label} must be an integer between {minimum} and {maximum}")
    return value


def _bytes(value: object) -> str:
    if not isinstance(value, str) or len(value) % 2 or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        raise TraceError("bytes must be a nonempty hexadecimal byte string")
    return value.lower()


def _name(event: dict) -> dict:
    if "name" not in event:
        return {}
    if not isinstance(event["name"], str) or not event["name"].strip():
        raise TraceError("name must be a nonempty string")
    return {"name": event["name"]}


class _Runtime:
    """Track the active placements while reading the ordered event stream."""

    def __init__(self, image: ExportEvidence, evidence: bool):
        self.image = image
        self.evidence = evidence
        self.backend = TraceAddressBackend(image)
        self.units = {unit.name.casefold(): unit for unit in image.units}
        self.active = image.runtime
        self.state = image.state
        self.history: dict[int, tuple[list[RuntimeSpan], list[int]]] = {}
        self._set_ranges(image.runtime_spans)

    def change(self, placements: dict) -> dict:
        changes = {}
        for name, address in placements.items():
            unit = self.units.get(name.casefold())
            if unit is None:
                raise TraceError(f"unknown runtime unit {name}")
            if unit.name in changes:
                raise TraceError(f"runtime placement specified twice for {unit.name}")
            changes[unit.name] = None if address is None else self.backend.linear(address)
        if all(self.active.get(unit) == at for unit, at in changes.items()):
            return changes
        proposed = {unit.name: self.active.get(unit.name) for unit in self.image.units}
        proposed.update(changes)
        try:
            active = explicit_runtime_units(self.image.units, proposed, self.image.format)
        except RuntimePlacementError as error:
            raise TraceError(str(error)) from error
        self.state = None
        self.active = active
        self._set_ranges(runtime_spans(self.image.units, self.active))
        return changes

    def transition(self, event: dict) -> dict:
        if "state" not in event:
            return self.change(_object(event.get("placements"), "transition placements"))
        state = event["state"]
        if "placements" in event or self.image.manifest is None or self.state is None:
            raise TraceError("a named transition requires an active manifest state and excludes explicit placements")
        if not any((row["from"], row["to"], row["kind"]) == (self.state, state, event["kind"])
                   for row in self.image.manifest["transitions"]):
            raise TraceError(f"no {event['kind']} transition from {self.state!r} to {state!r} in the load manifest")
        placements = state_loads(self.image.manifest, state)
        changes = {unit: placements.get(unit) for unit in self.active.keys() | placements.keys()
                   if placements.get(unit) != self.active.get(unit)}
        self.active = placements
        self._set_ranges(state_spans(self.image.manifest, state, self.image.units))
        self.state = state
        return dict(sorted(changes.items()))

    def _set_ranges(self, spans: list[RuntimeSpan]) -> None:
        self.ranges = spans
        self.starts = [span.linear for span in spans]

    def remember(self, event: int) -> None:
        self.history[event] = self.ranges, self.starts

    def _display(self, linear: int) -> str:
        width = 4 if self.backend.limit == 0x10000 else 8
        return f"{linear:0{width}x}"

    def _point(self, linear: int, display: str, unit: ImageUnit | None, offset: int = 0) -> dict:
        where = {"runtime_address": display, "runtime_linear": linear,
                 "location": None if unit is None else unit.location(offset)}
        if unit is not None and self.evidence:
            where["export_evidence"] = _proof(self.image, unit, offset, where)
        return where

    def point(self, address: object, state: int | None = None) -> dict:
        linear = self.backend.linear(address)
        display = address.lower() if isinstance(address, str) else self._display(linear)
        ranges, starts = (self.ranges, self.starts) if state is None else self.history[state]
        index = bisect_right(starts, linear) - 1
        if index >= 0:
            span = ranges[index]
            if linear < span.end:
                return self._point(linear, display, span.unit, span.offset + linear - span.linear)
        return self._point(linear, display, None)

    def span(self, address: object, size: int) -> dict:
        first = self.point(address)
        start = first["runtime_linear"]
        end = start + size
        if end > self.backend.limit:
            raise TraceError("memory range exceeds the runtime address space")
        spans = []
        at = start
        index = max(0, bisect_right(self.starts, at) - 1)
        for span in self.ranges[index:]:
            base = span.linear
            if base >= end:
                break
            unit_end = span.end
            if unit_end <= at:
                continue
            if at < base:
                spans.append({**self._point(at, self._display(at), None), "size": base - at})
                at = base
            stop = min(end, unit_end)
            spans.append({**self._point(at, self._display(at), span.unit, span.offset + at - base), "size": stop - at})
            at = stop
        if at < end:
            spans.append({**self._point(at, self._display(at), None), "size": end - at})
        return {**first, "size": size, "spans": spans}

    def endpoint(self, event: dict, field: str) -> dict:
        key = f"{field}_state"
        state = event.get(key)
        if key in event and (type(state) is not int or state not in self.history):
            raise TraceError(f"{key} must identify an earlier transition or the initial state (0)")
        return self.point(event.get(field), state)


def _snapshot(event: dict, runtime: _Runtime) -> dict:
    registers = _object(event.get("registers", {}), "snapshot registers")
    for name, value in registers.items():
        if not name.strip():
            raise TraceError("register names must be nonempty strings")
        _number(value, f"register {name}")
    memory = []
    for value in _array(event.get("memory", []), "snapshot memory"):
        region = _object(value, "snapshot memory region")
        data = _bytes(region.get("bytes"))
        memory.append({**runtime.span(region.get("address"), len(data) // 2), "bytes": data})
    result = {**_name(event), "registers": registers, "memory": memory}
    if "pc" in event:
        result["pc"] = runtime.point(event["pc"])
    if "state" in event:
        result["state"] = _object(event["state"], "snapshot state")
    return result


def _access(event: dict, runtime: _Runtime) -> dict:
    access = event.get("access")
    if access not in ("read", "write"):
        raise TraceError("memory access must be read or write")
    size = _number(event.get("size"), "memory size", 1, runtime.backend.limit)
    result = {"access": access, **runtime.span(event.get("address"), size)}
    if "bytes" in event:
        data = _bytes(event["bytes"])
        if len(data) != 2 * size:
            raise TraceError("memory bytes do not match the recorded access size")
        result["bytes"] = data
    if "pc" in event:
        result["pc"] = runtime.point(event["pc"])
    return result


def _structured_trace(image: ExportEvidence, document: dict, evidence: bool) -> dict:
    if type(document.get("version")) is not int or document["version"] != _TRACE_VERSION:
        raise TraceError(f"expected trace JSON version {_TRACE_VERSION}")
    runtime = _Runtime(image, evidence)
    try:
        runtime.change(_object(document.get("placements", {}), "initial placements"))
    except ValueError as error:
        raise TraceError(f"initial placements: {error}") from error
    runtime.remember(0)
    initial = runtime.active.copy()
    initial_state = runtime.state
    events = _array(document.get("events"), "trace events")
    if not events:
        raise TraceError("trace contains no events")

    explicit, departures, arrivals = Counter(), Counter(), Counter()
    resume_departures, resume_arrivals = Counter(), Counter()
    locations = {}
    observed_bytes: dict[tuple[int, str], set[str]] = {}
    edges, memory, snapshots, transitions = [], [], [], []

    def observe(where: dict, counts: Counter, count: int, data: str | None = None) -> None:
        location = where["location"]
        key = where["runtime_linear"], location["unit_address"] if location is not None else ""
        locations.setdefault(key, where)
        counts[key] += count
        if data is not None:
            observed_bytes.setdefault(key, set()).add(data)

    for index, value in enumerate(events, 1):
        try:
            event = _object(value, "event")
            kind = event.get("kind")
            if kind in ("instruction", "edge"):
                count = _number(event.get("count", 1), "count", 1, 0x7FFFFFFF)
                if kind == "instruction":
                    data = _bytes(event["bytes"]) if "bytes" in event else None
                    if data is not None and len(data) > 2 * _MAX_INSTRUCTION_BYTES:
                        raise TraceError(f"instruction bytes exceed {_MAX_INSTRUCTION_BYTES} bytes")
                    observe(runtime.point(event.get("address")), explicit, count, data)
                    continue
                flow = event.get("flow")
                if flow not in (None, "call", "jump", "return", "fallthrough", "interrupt", "interrupt_resume"):
                    raise TraceError("edge flow must be call, jump, return, fallthrough, interrupt, or interrupt_resume")
                source = runtime.endpoint(event, "from")
                destination = runtime.endpoint(event, "to")
                observe(source, resume_departures if flow == "interrupt_resume" else departures, count)
                observe(destination, resume_arrivals if flow == "interrupt_resume" else arrivals, count)
                states = {key: event[key] for key in ("from_state", "to_state") if key in event}
                edges.append({"event": index, "from": source, "to": destination, "count": count, "flow": flow, **states})
            elif kind == "memory":
                memory.append({"event": index, **_access(event, runtime)})
            elif kind == "snapshot":
                snapshots.append({"event": index, **_snapshot(event, runtime)})
            elif kind in ("bank", "overlay"):
                previous = runtime.active
                previous_state = runtime.state
                placements = runtime.transition(event)
                runtime.remember(index)
                transitions.append({"event": index, "kind": kind, **_name(event), "placements": placements,
                                    **({"from": previous_state, "to": runtime.state} if "state" in event else {}),
                                    "previous": {unit: previous.get(unit) for unit in placements}})
            else:
                raise TraceError(f"unknown event kind {kind!r}")
        except ValueError as error:
            raise TraceError(f"trace event {index}: {error}") from error

    # An edge-only trace establishes a lower bound on visits. Explicit records
    # and interrupt continuations can describe the same visits as CPU edges.
    mapped, unmapped = [], []
    visits = 0
    for key, where in sorted(locations.items()):
        location = where["location"]
        hit = {name: value for name, value in where.items() if name != "location"}
        hit["count"] = max(explicit[key], departures[key], arrivals[key], resume_departures[key], resume_arrivals[key])
        visits += hit["count"]
        if key in observed_bytes:
            hit["observed_bytes"] = sorted(observed_bytes[key])
        if location is None:
            unmapped.append(hit)
        else:
            mapped.append({**hit, **location})
    return {"trace_version": _TRACE_VERSION, "initial_placements": initial, "instructions": visits,
            **({"initial_state": initial_state} if initial_state is not None else {}),
            "instruction_records": explicit.total(), "ignored_lines": 0,
            "mapped": mapped, "unmapped": unmapped, "analysis": None,
            "edges": edges, "memory": memory, "snapshots": snapshots, "transitions": transitions}


def _analyze(report: dict, image: ExportEvidence, project: Path, *, timeout: float | None,
             classify_gaps: bool, apply: bool, program: str | None) -> dict:
    anchors, expected, observations = {}, {}, {}
    ranges = {unit.name: unit for unit in image.units}
    hits = []
    for row in report["mapped"]:
        hit = row.copy()
        proof = hit.pop("export_evidence", None)
        if proof is not None:
            anchors[(hit["runtime_address"], hit["linear"])] = proof
        hits.append(hit)
        if "observed_bytes" in hit:
            observations.setdefault(str(hit["linear"]), set()).update(hit["observed_bytes"])
        name, _, offset = hit["unit_address"].rpartition(":")
        unit = ranges[name]
        offset = int(offset, 16)
        length = min(unit.file_size - offset, _MAX_INSTRUCTION_BYTES)
        if length > 0:
            position = unit.image_offset + offset
            expected[str(hit["linear"])] = image.image[position:position + length].hex()
    identity = report.get("export") or image.identity()
    coverage = {"sha256": identity["image_sha256"], "units": [asdict(unit) for unit in image.units],
                "hits": hits, "expected_bytes": expected, "classify_gaps": classify_gaps,
                "observed_bytes": {linear: sorted(values) for linear, values in observations.items()}}
    if apply and image.format in ("MZ", "PC98"):
        coverage["segment_map"] = {key: image.program[key] for key in (
            "format", "units", "entry", "entries", "stack", "initial_segments", "image_origin", "relocations", "jump_tables",
            "microsoft_pascal_dgroup", "microsoft_pascal_capture",
        ) if key in image.program}
    if "edges" in report:
        coverage["edges"] = [
            {**{key: edge[key] for key in ("event", "flow", "count")},
             **{key: edge[key]["location"] for key in ("from", "to")}}
            for edge in report["edges"]
        ]
    analysis = trace_coverage(project, coverage, timeout=timeout, apply=apply, program=program)
    if anchors:
        evidence_rows = [analysis["missed"]]
        evidence_rows.extend(gap["trace_evidence"]["examples"] for gap in analysis.get("observed_gaps", ()))
        for rows in evidence_rows:
            for hit in rows:
                hit["export_evidence"] = anchors[hit["runtime_address"], hit["linear"]]
    return analysis
