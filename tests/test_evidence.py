import json
import os
from pathlib import Path

import pytest

from retrore import evidence, ghidra
from retrore.annotations import export_annotations, import_annotations
from retrore.cli import main
from retrore.evidence import inspect_bytes, map_address
from retrore.mcp import call_tool

FIXTURES = Path(__file__).parent / "fixtures" / "maps"


def test_dos_bytes_and_runtime_mapping(capsys):
    export = FIXTURES / "mz"
    proof = inspect_bytes(export, "root:1", size=2)
    assert proof["loaded"] == "ff0f" and proof["original"] == "ffff"
    assert proof["evidence"] == [
        {"kind": "relocation", "image_offset": 1, "size": 2, "before": "ffff", "after": "ff0f"},
    ]
    assert main(["address-map", "2000:0001", "--from", "runtime", "--runtime-base", "2000",
                 "--export", str(export), "--json"]) == 0
    match, = json.loads(capsys.readouterr().out)["matches"]
    assert match["unit_address"] == "root:0001" and match["linear"] == 0x10001
    assert match["runtime"] == {"address": "2000:0001", "linear": 0x20001}
    assert map_address(export, "root:20")["count"] == 0


def test_hunk_file_mapping_and_bss():
    export = FIXTURES / "hunk"
    matches = map_address(export, "36", space="file", source="demo")["matches"]
    match, = matches
    assert match["unit_address"] == "h0:0002"
    assert match["file"] == {"source": "demo", "member": None, "offset_kind": "file", "offset": 54}
    proof = inspect_bytes(export, "h0:2", size=4)
    assert proof["original"] == "00000000" and proof["loaded"] == "00010020"
    assert proof["file_spans"] == [
        {"source": "demo", "member": None, "offset_kind": "file", "unit_offset": 2, "file_offset": 54, "size": 4},
    ]
    bss = inspect_bytes(export, "h3:1", size=4)
    assert bss["truncated"] and not bss["address"]["initialized"] and bss["loaded"] == ""


def test_bundle_reports_byte_comparison_status_and_conflicts(monkeypatch):
    export = FIXTURES / "hunk"
    addresses = ["h3:1", "h0:2", "h3:1", "h0:2", "h0:2", "h0:2", "h0:6"]
    rows = [
        {"kind": "uninitialized"},
        {"kind": "data", "bytes": "ffffffff"},
        {"kind": "data", "bytes": "00000000"},
        {"kind": "uninitialized"},
        {"kind": "data", "bytes": "00010020"},
        {"kind": "data", "bytes": "00010020"},
        {"kind": "data", "bytes": inspect_bytes(export, "h0:6", size=2)["loaded"]},
    ]
    results = [{"result": {"program": "demo"}}]
    for index, (address, row) in enumerate(zip(addresses, rows, strict=True)):
        start, = map_address(export, address)["matches"]
        if index == 5:
            start["linear"] += 0x10
        results.append({"result": {"start": start, "size": 4, "rows": [row]}})
    monkeypatch.setattr(evidence, "query_batch", lambda *args, **kwargs: {"results": results})

    requests = [{"command": "disasm", "address": address} for address in addresses]
    bundle = evidence.evidence_bundle(Path("demo.gpr"), requests, export=export)

    comparisons = [row["export_evidence"] for row in bundle["results"]]
    assert [item["status"] for item in comparisons] == [
        "unavailable", "conflict", "conflict", "conflict", "consistent", "conflict", "conflict",
    ]
    assert [item.get("conflicts") for item in comparisons] == [
        None, ["byte_mismatch"], ["initialized_size_mismatch"], ["initialized_size_mismatch"],
        None, ["address_mismatch"], ["incomplete_range"],
    ]
    assert comparisons[0]["reason"] == "range is uninitialized"
    assert comparisons[0]["bytes"]["loaded"] == ""


@pytest.mark.parametrize("address, project_bytes, truncated, status, instruction_status", [
    ("h0:2", "ffffffff", True, "conflict", "conflict"),
    ("h0:2", "00010020", True, "unavailable", "consistent"),
    ("h0:8", "1234", False, "unavailable", "unavailable"),
])
def test_bundle_reports_decomp_instruction_coverage(monkeypatch, address, project_bytes, truncated, status,
                                                     instruction_status):
    export = FIXTURES / "hunk"
    location = {"address": "00010002", "unit_address": address, "linear": 0x10002}
    result = {"name": "demo", "_instruction_bytes": {
        "instructions": [{"address": location, "bytes": project_bytes}], "truncated": truncated,
    }}
    rows = [{"result": {"program": "demo"}}, {"result": result}]
    monkeypatch.setattr(evidence, "query_batch", lambda *args, **kwargs: {"results": rows})

    bundle = evidence.evidence_bundle(Path("demo.gpr"), [{"command": "decomp", "address": "h0:2"}], export=export)

    row, = bundle["results"]
    assert row["result"] == {"name": "demo"}
    comparison = row["export_evidence"]
    assert comparison["status"] == status
    assert comparison["truncated"] == truncated
    instruction, = comparison["instructions"]
    assert instruction["status"] == instruction_status
    if instruction_status == "conflict":
        assert instruction["conflicts"] == ["byte_mismatch"]


def test_fragmented_file_mapping_and_mcp(tmp_path):
    program = {"format": "C64_PRG", "program": "disk", "units": [
        {"name": "code", "linear": 0x1000, "image_offset": 0, "size": 4, "file_size": 4,
         "source": "disk", "disk_file": "code", "file_spans": [
             {"offset": 0, "file_offset": 0x10, "size": 2},
             {"offset": 2, "file_offset": 0x20, "size": 2},
         ]},
    ]}
    (tmp_path / "map.json").write_text(json.dumps(program), encoding="utf-8")
    (tmp_path / "image.bin").write_bytes(b"abcd")
    result = call_tool("address_map", {"export": str(tmp_path), "space": "file", "address": "21",
                                       "source": "disk", "member": "code"})["structuredContent"]
    assert [row["unit_offset"] for row in result["matches"]] == [3]
    assert map_address(tmp_path, "12", space="file")["count"] == 0
    proof = call_tool("bytes", {"export": str(tmp_path), "address": "code:1", "size": 10})["structuredContent"]
    assert proof["original"] == b"bcd".hex() and proof["truncated"]
    assert [(span["file_offset"], span["size"]) for span in proof["file_spans"]] == [(0x11, 1), (0x20, 2)]


def test_annotation_transfer_preserves_anchors_and_skips_changed_bodies(tmp_path, capsys):
    annotations = tmp_path / "notes.json"
    comparison = tmp_path / "comparison.json"
    source = {"version": 1, "language": "6502", "sha256": "before", "annotations": [
        {"kind": "function_name", "unit": "root", "offset": 16, "value": "worker"},
        {"kind": "comment", "unit": "root", "offset": 32, "comment_type": "PRE", "value": "changed"},
    ]}
    annotations.write_text(json.dumps(source), encoding="utf-8")
    comparison.write_text(json.dumps({
        "comparison_version": 1, "before": {"language": "6502", "sha256": "before"},
        "after": {"language": "6502", "sha256": "after"},
        "matches": [
            {"before": {"unit": "root", "offset": 16}, "after": {"unit": "text", "offset": 20},
             "status": "same_body", "matched_by": "normalized_instructions"},
            {"before": {"unit": "root", "offset": 32}, "after": {"unit": "text", "offset": 40},
             "status": "changed_candidate", "matched_by": "symbol"},
        ],
    }), encoding="utf-8")
    assert main(["annotations", "transfer", str(annotations), str(comparison), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["sha256"] == "after"
    match, = report["annotations"]
    assert (match["unit"], match["offset"], match["value"]) == ("text", 20, "worker")
    assert match["provenance"] == {
        "sha256": "before", "unit": "root", "offset": 16, "matched_by": "normalized_instructions",
    }
    assert report["transfer"]["skipped"] == [
        {"unit": "root", "offset": 32, "kind": "comment", "reason": "function_match_requires_review"},
    ]
    proof = {"status": "consistent", "project_bytes": "ea"}
    source["export"] = {"image_sha256": "loader-image"}
    source["annotations"][0]["export_evidence"] = proof
    annotations.write_text(json.dumps(source), encoding="utf-8")
    assert main(["annotations", "transfer", str(annotations), str(comparison), "--json"]) == 0
    match, = json.loads(capsys.readouterr().out)["annotations"]
    assert "export_evidence" not in match
    assert match["provenance"]["export_evidence"] == proof
    assert match["provenance"]["export"] == source["export"]

    source["version"] = 2
    source["data_types"] = {"format": "ghidra-gdt", "types": [{"category": "/", "name": "Mode"}], "archive": "AA=="}
    signature = {"kind": "signature", "unit": "root", "offset": 16, "value": "Mode worker(void)",
                 "prototype": {"return_type": {"category": "/", "name": "Mode"}, "parameters": []}}
    source["annotations"].append(signature)
    annotations.write_text(json.dumps(source), encoding="utf-8")
    assert main(["annotations", "transfer", str(annotations), str(comparison), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["version"] == 2 and report["data_types"] == source["data_types"]
    assert report["annotations"][-1]["prototype"] == signature["prototype"]

    source["version"] = 3
    signature.pop("prototype")
    signature["custom_storage"] = {}
    annotations.write_text(json.dumps(source), encoding="utf-8")
    assert main(["annotations", "transfer", str(annotations), str(comparison), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["version"] == 1
    assert report["transfer"]["skipped"][-1]["reason"] == "custom_variable_storage_requires_original_layout"

    source["version"] = 4
    source["annotations"].append({
        "kind": "data_layout", "unit": "root", "offset": 16,
        "data_layout": {"type": {"category": "/", "name": "Mode[4]"}, "length": 4},
    })
    annotations.write_text(json.dumps(source), encoding="utf-8")
    assert main(["annotations", "transfer", str(annotations), str(comparison), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["version"] == 1 and [row["kind"] for row in report["annotations"]] == ["function_name"]
    assert report["transfer"]["skipped"][-1]["reason"] == "data_layout_requires_original_layout"


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test")
def test_non_retrore_project_can_be_queried_read_only(tmp_path):
    member = tmp_path / "native test.bin"
    member.write_bytes(bytes.fromhex("ea 60"))
    project = tmp_path / "project"
    returncode, log = ghidra._launch([
        str(ghidra._headless()), str(tmp_path), project.name, "-import", str(member),
        "-loader", "BinaryLoader", "-processor", "6502:LE:16:default", "-noanalysis",
    ], 60, "import synthetic native Ghidra program")
    assert not returncode, log
    queries = ghidra.query_batch(project, [{"command": "project-summary"}, {"command": "disasm", "address": "0"}],
                                 program=member.name)["results"]
    for row in queries:
        assert "error" not in row, row
    summary, disasm = (row["result"] for row in queries)
    assert summary["program"] == member.name and summary["language"].startswith("6502")
    first = disasm["rows"][0]
    assert first["bytes"] == "ea" and first["kind"] == "undefined"
    assert first["ghidra_file"] == {"name": member.name, "offset": 0, "original": "ea"}


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test")
def test_annotations_preview_conflict_and_round_trip(tmp_path, capsys):
    source, export, project = (tmp_path / name for name in ("example.prg", "export", "project"))
    source.write_bytes(bytes.fromhex("00 c0 a9 07 60"))
    assert main(["load", str(source), "-o", str(export), "--entry", "c000"]) == 0
    assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    capsys.readouterr()
    document = export_annotations(project)
    assert document["version"] == 1
    summary = ghidra.query(project, {"command": "project-summary"})
    unit = next(row["name"] for row in summary["units"] if row["start"]["linear"] == 0xC000)
    document["annotations"] += [
        {"unit": unit, "offset": 0, "kind": "function_name", "value": "read_border_mode"},
        {"unit": unit, "offset": 0, "kind": "signature", "value": "byte read_border_mode(void)",
         "calling_convention": "default"},
        {"unit": unit, "offset": 0, "kind": "comment", "comment_type": "PRE", "value": "Read ☃ mode"},
        {"unit": unit, "offset": 2, "kind": "label", "value": "return_mode"},
    ]
    path = tmp_path / "annotations.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    preview = import_annotations(project, path)
    assert preview["additions"] == 4 and not preview["applied"]
    assert export_annotations(project)["annotations"] != document["annotations"]
    assert main(["annotations", "import", str(path), "--project", str(project), "--apply", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["applied"]
    after = export_annotations(project)
    assert {row["kind"] for row in after["annotations"]} >= {"function_name", "label", "signature", "comment"}
    assert main(["annotations", "export", "--project", str(project), "--export", str(export), "--json"]) == 0
    sourced = json.loads(capsys.readouterr().out)
    comment = next(row for row in sourced["annotations"] if row.get("value") == "Read ☃ mode")
    proof = comment["export_evidence"]
    assert proof["status"] == "consistent"
    assert proof["project_bytes"] == "a9"
    assert proof["bytes"]["file_spans"][0]["file_offset"] == 2
    assert sourced["export"]["format"] == "C64_PRG"

    image = export / "image.bin"
    image.write_bytes(b"\x00" + image.read_bytes()[1:])
    sourced = export_annotations(project, export=export)
    comment = next(row for row in sourced["annotations"] if row.get("value") == "Read ☃ mode")
    assert comment["export_evidence"]["conflicts"] == ["byte_mismatch"]
    path.write_text(json.dumps(sourced), encoding="utf-8")
    assert import_annotations(project, path)["conflicts"] == 0

    path.write_text(json.dumps(document), encoding="utf-8")
    again = import_annotations(project, path)
    assert again["additions"] == again["conflicts"] == 0

    document["annotations"] = [
        {"unit": unit, "offset": 1, "kind": "comment", "comment_type": "EOL", "value": "would be added"},
        {"unit": unit, "offset": 0, "kind": "comment", "comment_type": "PRE", "value": "would overwrite"},
    ]
    path.write_text(json.dumps(document), encoding="utf-8")
    assert main(["annotations", "import", str(path), "--project", str(project), "--apply", "--json"]) == 1
    conflicts = json.loads(capsys.readouterr().out)
    assert not conflicts["applied"] and conflicts["conflicts"] == conflicts["additions"] == 1
    assert export_annotations(project) == after


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test")
def test_annotation_data_types_round_trip(tmp_path, capsys):
    source, export, original, fresh = (tmp_path / name for name in ("demo.prg", "export", "original", "fresh"))
    source.write_bytes(bytes.fromhex("00 c0 a9 07 60"))
    assert main(["load", str(source), "-o", str(export), "--entry", "c000"]) == 0
    for project in (original, fresh):
        assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    capsys.readouterr()

    def edit_types(project, mode):
        returncode, log = ghidra._launch([
            str(ghidra._headless()), *ghidra._project_parts(project),
            "-process", "image.bin", "-noanalysis", "-scriptPath", str(Path(__file__).parent / "ghidra"),
            "-postScript", "AnnotationDataTypes.java", mode,
        ], 60, "synthetic annotation data types")
        assert not returncode and "Annotation data types checked" in log, log

    edit_types(original, "seed")
    document = export_annotations(original, export=export)
    assert document["version"] == 2
    assert document["data_types"]["format"] == "ghidra-gdt"
    assert [(row["category"], row["name"]) for row in document["data_types"]["types"]] == [
        ("/other", "Mode"), ("/records", "Mode"), ("/records", "Node"), ("/records", "NodeRef"),
        ("/records", "OnSelected"), ("/records", "Selection"),
    ]
    signature, = [row for row in document["annotations"] if row["kind"] == "signature"]
    assert signature["prototype"]["return_type"] == {"category": "/records", "name": "Mode"}
    assert signature["export_evidence"]["status"] == "consistent"
    path = tmp_path / "annotations.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    preview = import_annotations(fresh, path)
    assert not preview["applied"] and preview["conflicts"] == 0
    assert [row["status"] for row in preview["data_type_changes"]] == ["add"] * 6
    assert "data_types" not in export_annotations(fresh)
    assert main(["annotations", "import", str(path), "--project", str(fresh), "--apply", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["applied"]
    again = import_annotations(fresh, path)
    assert again["additions"] == again["conflicts"] == 0
    assert [row["status"] for row in again["data_type_changes"]] == ["unchanged"] * 6

    edit_types(fresh, "conflict")
    document["annotations"].append({
        "unit": signature["unit"], "offset": 1, "kind": "comment", "comment_type": "EOL", "value": "unapplied",
    })
    path.write_text(json.dumps(document), encoding="utf-8")
    assert main(["annotations", "import", str(path), "--project", str(fresh), "--apply", "--json"]) == 1
    conflict = json.loads(capsys.readouterr().out)
    assert not conflict["applied"] and conflict["additions"] == 2 and conflict["conflicts"] > 0
    assert conflict["data_type_changes"][0]["status"] == "add"
    assert conflict["data_type_changes"][1]["status"] == "conflict"
    remaining = export_annotations(fresh)
    assert {"category": "/other", "name": "Mode"} not in remaining["data_types"]["types"]
    assert all(row.get("value") != "unapplied" for row in remaining["annotations"])


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test")
def test_annotation_custom_storage_round_trip(tmp_path, capsys):
    source, export, original, fresh, conflict = (
        tmp_path / name for name in ("storage.prg", "export", "original", "fresh", "conflict")
    )
    source.write_bytes(bytes.fromhex("00 c0 a9 07 60"))
    assert main(["load", str(source), "-o", str(export), "--entry", "c000"]) == 0
    for project in (original, fresh, conflict):
        assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    capsys.readouterr()

    def edit_storage(project, mode):
        returncode, log = ghidra._launch([
            str(ghidra._headless()), *ghidra._project_parts(project),
            "-process", "image.bin", "-noanalysis", "-scriptPath", str(Path(__file__).parent / "ghidra"),
            "-postScript", "AnnotationStorage.java", mode,
        ], 60, "synthetic annotation storage")
        assert not returncode and "Annotation storage checked" in log, log

    edit_storage(original, "seed")
    document = export_annotations(original, export=export)
    assert document["version"] == 3 and document["data_types"]["types"] == []
    signature, = [row for row in document["annotations"] if row["kind"] == "signature"]
    assert signature["export_evidence"]["status"] == "consistent"
    path = tmp_path / "annotations.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    preview = import_annotations(fresh, path)
    assert not preview["applied"] and preview["additions"] == 1 and preview["conflicts"] == 0
    assert export_annotations(fresh)["version"] == 1
    assert main(["annotations", "import", str(path), "--project", str(fresh), "--apply", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["applied"]
    edit_storage(fresh, "check")
    again = import_annotations(fresh, path)
    assert again["additions"] == again["conflicts"] == 0

    document["annotations"].append({
        "unit": signature["unit"], "offset": 1, "kind": "comment", "comment_type": "EOL", "value": "unapplied",
    })
    path.write_text(json.dumps(document), encoding="utf-8")
    edit_storage(conflict, "conflict")
    before = export_annotations(conflict)
    preview = import_annotations(conflict, path)
    assert preview["additions"] == preview["conflicts"] == 1
    reason, = [row["reason"] for row in preview["changes"] if row["status"] == "conflict"]
    assert "manual_cache" in reason
    assert main(["annotations", "import", str(path), "--project", str(conflict), "--apply", "--json"]) == 1
    assert not json.loads(capsys.readouterr().out)["applied"]
    assert export_annotations(conflict) == before
