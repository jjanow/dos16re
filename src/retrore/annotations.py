"""Export and replay Ghidra annotations through a versioned JSON document."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from . import ghidra, worker
from .evidence import ExportEvidence, compare_project_range


def _read_json(path: Path) -> dict:
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as error:
        raise ghidra.GhidraError(f"invalid JSON in {path.name}: {error}") from error
    if not isinstance(content, dict):
        raise ghidra.GhidraError(f"expected a JSON object in {path.name}")
    return content


def _read_annotations(path: Path) -> dict:
    content = _read_json(path)
    if (type(content.get("version")) is not int or not 1 <= content["version"] <= 5
            or not isinstance(content.get("annotations"), list)
            or ("data_types" in content) != (content["version"] >= 2)
            or (content["version"] >= 2 and not isinstance(content["data_types"], dict))
            or ("storage_blocks" in content) != (content["version"] == 5)
            or (content["version"] == 5 and not isinstance(content["storage_blocks"], list))):
        raise ghidra.GhidraError("expected a version 1 through 5 annotation document")
    return content


def export_annotations(project: Path, *, program: str = "image.bin", export: Path | None = None,
                       timeout: float | None = ghidra.QUERY_TIMEOUT) -> dict:
    ghidra._check_program_name(program)
    if export is not None:
        image = ExportEvidence(export)
        request = {"mode": "export", "_anchor_bytes": True}
        report = (ghidra._report(project, "annotations", request, timeout) if program == "image.bin" else
                  ghidra._oneshot(project, "annotations", request, timeout, program=program))
        report["export"] = image.identity()
        for item in report["annotations"]:
            region = item.pop("_anchor_bytes", None)
            item["export_evidence"] = (compare_project_range(image, region) if region is not None else
                                       {"status": "unavailable", "reason": "Ghidra did not return an anchor byte"})
        return report
    if program == "image.bin":
        return ghidra._report(project, "annotations", {"mode": "export"}, timeout)
    return ghidra._query(project, "RetroreAnnotations.java", "export", timeout=timeout, program=program)


def import_annotations(project: Path, document: Path, *, apply: bool = False, program: str = "image.bin",
                       timeout: float | None = ghidra.QUERY_TIMEOUT) -> dict:
    ghidra._check_program_name(program)
    ghidra._require_project(project)
    content = _read_annotations(document)
    if not apply and program == "image.bin":
        return ghidra._report(project, "annotations", {"mode": "preview", "document": content}, timeout)
    # Serialize the validated snapshot so the preview and transaction read the same data even if the input changes.
    with TemporaryDirectory() as temp:
        path = Path(temp) / "annotations.json"
        path.write_text(json.dumps(content), encoding="utf-8")
        arguments = ("RetroreAnnotations.java", "apply" if apply else "preview", str(path))
        if not apply:
            return ghidra._query(project, *arguments, timeout=timeout, program=program)
        worker.stop(project)
        return ghidra._run(project, ["-process", program, "-noanalysis"], *arguments, timeout=timeout)


def _transfer_storage(storage: dict, offsets: dict) -> dict | None:
    if offsets.get("same") is True:
        return storage
    before, after = offsets["before"], offsets["after"]
    if (len(before) != len(after) or any(type(offset) is not int for offset in before + after)
            or len(set(before)) != len(before) or len(set(after)) != len(after)):
        raise ghidra.GhidraError("invalid comparison instruction offsets")
    locations = dict(zip(before, after, strict=True))
    if locations.get(0) != 0:
        raise ghidra.GhidraError("comparison instruction offsets must align the entries")
    locals_ = []
    for variable in storage["locals"]:
        offset = locations.get(variable["first_use"])
        if offset is None:
            return None
        locals_.append({**variable, "first_use": offset})
    return {**storage, "locals": locals_}


def _site(record: dict) -> tuple[str, int]:
    unit, offset = record["unit"], record["offset"]
    if not isinstance(unit, str) or not unit or type(offset) is not int or offset < 0:
        raise ghidra.GhidraError("invalid comparison instruction location")
    return unit, offset


def _instruction_matches(matches: dict) -> dict:
    locations = {}
    destinations = set()
    for entry, match in matches.items():
        if match["status"] != "same_body" or "instruction_map" not in match:
            continue
        destination_entry = _site(match["after"])
        entry_aligned = False
        for pair in match["instruction_map"]:
            old, new = _site(pair["before"]), _site(pair["after"])
            if old in locations or new in destinations:
                raise ghidra.GhidraError("comparison contains duplicate instruction matches")
            if old == entry and new == destination_entry:
                entry_aligned = True
            locations[old] = (entry, match, pair["after"])
            destinations.add(new)
        if not entry_aligned:
            raise ghidra.GhidraError("comparison instruction map must align the entries")
    return locations


def transfer_annotations(document: Path, comparison: Path) -> dict:
    """Make a replay document for same-body function entries and mapped instructions."""
    source = _read_annotations(document)
    comparison = _read_json(comparison)
    if type(comparison.get("comparison_version")) is not int or comparison["comparison_version"] != 1:
        raise ghidra.GhidraError("expected a version 1 comparison report")
    try:
        before, after = comparison["before"], comparison["after"]
        if (before["language"] != source.get("language") or not before["sha256"]
                or before["sha256"] != source.get("sha256") or not after["sha256"]):
            raise ghidra.GhidraError("annotation document must identify the comparison's before executable")
        matches = {}
        destinations = set()
        for match in comparison["matches"]:
            entry = match["before"]
            key = entry["unit"], entry["offset"]
            destination = match["after"]["unit"], match["after"]["offset"]
            if key in matches or destination[0] is not None and destination in destinations:
                raise ghidra.GhidraError("comparison contains duplicate function entry matches")
            matches[key] = match
            destinations.add(destination)
        same_language = before["language"] == after["language"]
        instructions = _instruction_matches(matches) if same_language else {}
        annotations, skipped = [], []
        for item in source["annotations"]:
            key = item["unit"], item["offset"]
            kind = item["kind"]
            match = matches.get(key)
            scoped = "function" in item
            needs_instruction = kind in ("label", "local_label") or (
                kind == "comment" and (scoped or (match is None and bool(instructions))))
            site = instructions.get(key) if needs_instruction else None
            entry = None
            if site is not None:
                entry, match, destination = site
            else:
                destination = match["after"] if match is not None else None
            custom_storage = "custom_storage" in item
            mapped_storage = None
            if custom_storage and "storage_blocks" not in comparison:
                reason = "custom_variable_storage_requires_original_layout"
            elif kind == "data_layout":
                reason = "data_layout_requires_original_layout"
            elif kind not in ("function_name", "signature", "comment", "label", "local_label"):
                reason = "unsupported_annotation_kind"
            elif needs_instruction and site is None:
                reason = ("no_instruction_match_on_page" if instructions or kind == "local_label"
                          or scoped else "unsupported_annotation_kind")
            elif entry is not None and scoped and _site(item["function"]) != entry:
                reason = "instruction_function_mismatch"
            elif match is None:
                reason = "no_function_entry_match_on_page"
            elif match["status"] != "same_body" or not same_language:
                reason = "function_match_requires_review"
            elif destination["unit"] is None or type(destination["offset"]) is not int:
                reason = "destination_has_no_unit"
            elif custom_storage and source["version"] == 5:
                reason = "custom_storage_requires_fresh_export"
            elif custom_storage and ("storage_offsets" not in match or
                    (mapped_storage := _transfer_storage(item["custom_storage"], match["storage_offsets"])) is None):
                reason = "custom_storage_first_use_unmapped"
            else:
                transferred = {**item, "unit": destination["unit"], "offset": destination["offset"]}
                if mapped_storage is not None:
                    transferred["custom_storage"] = mapped_storage
                provenance = {"sha256": before["sha256"], "unit": key[0], "offset": key[1],
                              "matched_by": match["matched_by"]}
                if entry is not None:
                    transferred["function"] = {name: match["after"][name] for name in ("unit", "offset")}
                    provenance["function"] = {"unit": entry[0], "offset": entry[1]}
                if "export_evidence" in transferred:
                    provenance["export_evidence"] = transferred.pop("export_evidence")
                    if "export" in source:
                        provenance["export"] = source["export"]
                if "provenance" in item:
                    provenance["previous"] = item["provenance"]
                transferred["provenance"] = provenance
                annotations.append(transferred)
                continue
            skipped.append({"unit": key[0], "offset": key[1], "kind": kind, "reason": reason})
        report = {"version": 1, "language": after["language"], "sha256": after["sha256"],
                  "annotations": annotations, "transfer": {"skipped": skipped}}
        if any("custom_storage" in item for item in annotations):
            report.update(version=5, data_types=source["data_types"], storage_blocks=comparison["storage_blocks"])
        elif any(item["kind"] == "signature" and "prototype" in item for item in annotations):
            report.update(version=2, data_types=source["data_types"])
        return report
    except (KeyError, TypeError) as error:
        raise ghidra.GhidraError(f"invalid annotation or comparison record: {error}") from error
