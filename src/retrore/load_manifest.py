"""Validate and apply reusable load states to a static program export."""

import json
import re
from hashlib import sha256
from pathlib import Path

from .errors import CodedError
from .image import FLAT16_FORMATS, ImageUnit, RuntimeSpan, image_units, read_map, runtime_limit


class LoadManifestError(CodedError):
    """An invalid load manifest or state selection."""

    default_code = "load_manifest_invalid"


_STATE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*\Z")


def _object(value: object, label: str, fields: set[str]) -> dict:
    if not isinstance(value, dict) or value.keys() - fields:
        raise LoadManifestError(f"{label} must be an object with fields {', '.join(sorted(fields))}")
    return value


def _list(value: object, label: str) -> list:
    if not isinstance(value, list):
        raise LoadManifestError(f"{label} must be an array")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LoadManifestError(f"{label} must be a nonempty string")
    return value


def _linear(value: object, label: str) -> int:
    if isinstance(value, str) and re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,8}", value):
        return int(value, 16)
    if type(value) is int and value >= 0:
        return value
    raise LoadManifestError(f"{label} must be a nonnegative linear address or hexadecimal string")


def _states(document: dict, units: list[ImageUnit], image_format: str) -> dict:
    all_units = {unit.name.casefold(): unit for unit in units}
    limit = runtime_limit(image_format)
    states = {}
    for state in _list(document.get("states"), "states"):
        row = _object(state, "state", {"name", "loads", "spans"})
        name = _text(row.get("name"), "state name")
        if not _STATE_NAME.fullmatch(name) or name in states:
            raise LoadManifestError(f"invalid or duplicate load state {name!r}")
        loads, spans, seen_units = [], [], set()
        for load in _list(row.get("loads"), f"state {name} loads"):
            record = _object(load, "load", {"unit", "linear", "replace"})
            unit_name = _text(record.get("unit"), "load unit")
            unit = all_units.get(unit_name.casefold())
            if unit is None or unit.name in seen_units or not unit.size:
                raise LoadManifestError(f"state {name} refers to an unknown or duplicate unit {unit_name!r}")
            seen_units.add(unit.name)
            start = _linear(record.get("linear", unit.linear), "load linear address")
            replace = record.get("replace", False)
            if type(replace) is not bool:
                raise LoadManifestError(f"state {name} load {unit.name} replace must be a boolean")
            if start + unit.size > limit:
                raise LoadManifestError(f"state {name} load {unit.name} exceeds the platform address space")
            spans = _place(spans, RuntimeSpan(start, unit, 0, unit.size), replace, name)
            loads.append({"unit": unit.name, "linear": start, **({"replace": True} if replace else {})})
        if not loads:
            raise LoadManifestError(f"state {name} must load at least one unit")
        records = [{"unit": span.unit.name, "linear": span.linear, "offset": span.offset, "size": span.size}
                   for span in spans]
        if "spans" in row and row["spans"] != records:
            raise LoadManifestError(f"state {name} has inconsistent runtime spans")
        states[name] = {"name": name, "loads": loads, "spans": records}
    initial = _text(document.get("initial"), "initial state")
    if initial not in states:
        raise LoadManifestError(f"unknown initial load state {initial!r}")
    transitions = []
    seen = set()
    for transition in _list(document.get("transitions", []), "transitions"):
        row = _object(transition, "transition", {"from", "to", "kind", "trigger"})
        source, target, kind = (_text(row.get(key), f"transition {key}") for key in ("from", "to", "kind"))
        key = source, target, kind
        if source not in states or target not in states or source == target or kind not in ("bank", "overlay") or key in seen:
            raise LoadManifestError(f"invalid or duplicate {kind} transition from {source!r} to {target!r}")
        seen.add(key)
        transitions.append({"from": source, "to": target, "kind": kind,
                            **({"trigger": _text(row["trigger"], "transition trigger")} if "trigger" in row else {})})
    return {"version": 1, "initial": initial, "states": list(states.values()), "transitions": transitions}


def _place(spans: list[RuntimeSpan], new: RuntimeSpan, replace: bool, state: str) -> list[RuntimeSpan]:
    placed = []
    for span in spans:
        if span.end <= new.linear or span.linear >= new.end:
            placed.append(span)
            continue
        if not replace:
            raise LoadManifestError(f"state {state}: runtime ranges overlap for {span.unit.name} and {new.unit.name}")
        if span.linear < new.linear:
            placed.append(RuntimeSpan(span.linear, span.unit, span.offset, new.linear - span.linear))
        if span.end > new.end:
            placed.append(RuntimeSpan(new.end, span.unit, span.offset + new.end - span.linear, span.end - new.end))
    return sorted([*placed, new], key=lambda span: span.linear)


def _add_variants(path: Path, variants: list, image: bytes, program: dict) -> bytes:
    """Use separately selected flat 8-bit bank bytes as additional analysis units."""
    image_format = program["format"]
    if image_format not in FLAT16_FORMATS:
        raise LoadManifestError("extra bank exports require a flat 8-bit image")
    units = program["units"]
    names = {unit["name"].casefold() for unit in units}
    origin = units[0]["linear"]
    payloads = []
    for variant in variants:
        row = _object(variant, "variant", {"export", "unit", "name", "linear"})
        name = _text(row.get("name"), "variant name")
        if not _STATE_NAME.fullmatch(name) or name.casefold() in names:
            raise LoadManifestError(f"invalid or duplicate variant name {name!r}")
        at = _linear(row.get("linear"), "variant analysis address")
        export = path.parent / _text(row.get("export"), "variant export")
        source_map = read_map(export)
        source_image = (export / "image.bin").read_bytes()
        if source_map.get("format") != image_format:
            raise LoadManifestError(f"bank export {export} has a different platform format")
        source_name = _text(row.get("unit"), "variant source unit").casefold()
        source = next((unit for unit in image_units(source_map, len(source_image))
                       if unit.name.casefold() == source_name), None)
        if source is None or not source.size:
            raise LoadManifestError(f"no nonempty unit {source_name!r} in bank export {export}")
        if at + source.size > 0x10000:
            raise LoadManifestError(f"variant {name} exceeds the 64 KiB analysis address space")
        original = next(unit for unit in source_map["units"] if unit["name"] == source.name)
        record = {key: original[key] for key in ("kind", "writable", "file_offset", "file_spans", "disk_file", "member_id",
                                                "container_spans", "file_offset_kind") if key in original}
        if image_format == "ATARI8" and not any(key in record for key in ("file_offset", "file_spans")):
            from .evidence import ExportEvidence
            record["file_spans"] = ExportEvidence(export).file_spans(source)
        record.update(name=name, linear=at, size=source.size, file_size=source.file_size,
                      source=original.get("source", source_map.get("program")),
                      variant_source={"program": source_map.get("program"), "unit": source.name,
                                      "image_sha256": sha256(source_image).hexdigest()})
        units.append(record)
        names.add(name.casefold())
        payloads.append((at, source_image[source.image_offset:source.image_offset + source.size]))
    new_origin = min(unit["linear"] for unit in units)
    result = bytearray(max(origin + len(image), *(at + len(data) for at, data in payloads)) - new_origin)
    result[origin - new_origin:origin - new_origin + len(image)] = image
    for at, data in payloads:
        result[at - new_origin:at - new_origin + len(data)] = data
    for unit in units:
        unit["image_offset"] = unit["linear"] - new_origin
    units.sort(key=lambda unit: (unit["linear"], unit["size"]))
    return bytes(result)


def apply_load_manifest(path: Path, image: bytes, program: dict) -> bytes:
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeError, ValueError) as error:
        raise LoadManifestError(f"invalid load manifest JSON: {error}") from error
    document = _object(document, "load manifest", {"version", "initial", "states", "transitions", "variants"})
    if type(document.get("version")) is not int or document["version"] != 1:
        raise LoadManifestError("expected load manifest version 1")
    variants = _list(document.get("variants", []), "variants")
    if variants:
        image = _add_variants(path, variants, image, program)
    units = image_units(program, len(image))
    program["load_manifest"] = _states(document, units, program["format"])
    return image


def add_native_load_manifest(program: dict, image_size: int) -> None:
    """Describe states known from a native overlay directory."""
    states, transitions = [], []
    if tree := program.get("overlay_tree"):
        by_id = {}
        nonempty = {unit["name"] for unit in program["units"] if unit["size"]}
        for node in tree["nodes"]:
            name = node["id"]
            parent = node["parent"]
            loads = list(by_id.get(parent, ()))
            loads.extend({"unit": unit} for unit in node["units"] if unit in nonempty)
            by_id[name] = loads
            states.append({"name": name, "loads": loads})
            if parent is not None:
                transitions.extend(({"from": parent, "to": name, "kind": "overlay"},
                                    {"from": name, "to": parent, "kind": "overlay"}))
    elif overlays := [unit for unit in program["units"] if unit.get("overlay_format") == "MS_LINK"
                     and "runtime_linear" in unit]:
        states.append({"name": "root", "loads": [{"unit": "root"}]})
        for unit in overlays:
            name = unit["name"]
            states.append({"name": name, "loads": [{"unit": "root"},
                                                   {"unit": name, "linear": unit["runtime_linear"], "replace": True}]})
        transitions.extend({"from": source["name"], "to": target["name"], "kind": "overlay"}
                           for source in states for target in states[1:] if source is not target)
    if states:
        document = {"initial": states[0]["name"], "states": states, "transitions": transitions}
        program["load_manifest"] = _states(document, image_units(program, image_size), program["format"])


def manifest_states(program: dict, units: list[ImageUnit]) -> dict | None:
    if "load_manifest" not in program:
        return None
    document = _object(program["load_manifest"], "export load manifest", {"version", "initial", "states", "transitions"})
    if type(document.get("version")) is not int or document["version"] != 1:
        raise LoadManifestError("expected export load manifest version 1")
    return _states(document, units, program.get("format", "MZ"))


def state_loads(manifest: dict, state: str) -> dict[str, int]:
    return {row["unit"]: row["linear"] for row in _state(manifest, state)["loads"]}


def state_spans(manifest: dict, state: str, units: list[ImageUnit]) -> list[RuntimeSpan]:
    by_name = {unit.name: unit for unit in units}
    return [RuntimeSpan(row["linear"], by_name[row["unit"]], row["offset"], row["size"])
            for row in _state(manifest, state)["spans"]]


def _state(manifest: dict, state: str) -> dict:
    for row in manifest["states"]:
        if row["name"] == state:
            return row
    raise LoadManifestError(f"unknown load state {state!r}")
