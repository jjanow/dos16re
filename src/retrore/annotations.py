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
    if (type(content.get("version")) is not int or content["version"] not in (1, 2)
            or not isinstance(content.get("annotations"), list)
            or ("data_types" in content) != (content["version"] == 2)
            or (content["version"] == 2 and not isinstance(content["data_types"], dict))):
        raise ghidra.GhidraError("expected a version 1 or 2 annotation document")
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


def transfer_annotations(document: Path, comparison: Path) -> dict:
    """Make a replay document for same-body function entries on a page of comparison results."""
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
        annotations, skipped = [], []
        for item in source["annotations"]:
            key = item["unit"], item["offset"]
            match = matches.get(key)
            if item["kind"] not in ("function_name", "signature", "comment"):
                reason = "unsupported_annotation_kind"
            elif match is None:
                reason = "no_function_entry_match_on_page"
            elif match["status"] != "same_body" or before["language"] != after["language"]:
                reason = "function_match_requires_review"
            elif match["after"]["unit"] is None or type(match["after"]["offset"]) is not int:
                reason = "destination_has_no_unit"
            else:
                transferred = {**item, "unit": match["after"]["unit"], "offset": match["after"]["offset"]}
                provenance = {"sha256": before["sha256"], "unit": key[0], "offset": key[1],
                              "matched_by": match["matched_by"]}
                if "export_evidence" in transferred:
                    provenance["export_evidence"] = transferred.pop("export_evidence")
                    if "export" in source:
                        provenance["export"] = source["export"]
                if "provenance" in item:
                    provenance["previous"] = item["provenance"]
                transferred["provenance"] = provenance
                annotations.append(transferred)
                continue
            skipped.append({"unit": key[0], "offset": key[1], "kind": item["kind"], "reason": reason})
        report = {"version": 1, "language": after["language"], "sha256": after["sha256"],
                  "annotations": annotations, "transfer": {"skipped": skipped}}
        if any(item["kind"] == "signature" and "prototype" in item for item in annotations):
            report.update(version=2, data_types=source["data_types"])
        return report
    except (KeyError, TypeError) as error:
        raise ghidra.GhidraError(f"invalid annotation or comparison record: {error}") from error
