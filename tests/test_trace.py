import json
import os
from hashlib import sha256
from struct import pack_into

import pytest

from retrore.cli import main
from retrore.trace import TraceError, import_trace


def test_imports_dosbox_x_log_and_rebases_runtime_units(tmp_path, capsys):
    root = b"\xc3" + bytes(31)
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(root), 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
    pack_into("<HH", header, 28, 30, 0)
    exe = tmp_path / "sample.exe"
    exe.write_bytes(header + root)
    overlay = tmp_path / "OV1.ovr"
    overlay.write_bytes(b"\xcb" + bytes(15))
    export = tmp_path / "image"
    assert main(["load", str(exe), "-o", str(export), "--overlay", f"{overlay}@1200"]) == 0
    capsys.readouterr()

    trace = tmp_path / "LOGCPU.TXT"
    trace.write_text(
        "CPU log\n"
        "2000:0000  ret                            EAX:00000000\n"
        "2001:000F  nop                            EAX:00000000\n"
        "2000:0000001F\n"
        "2.500000 3000:00000000  retf              CB         EAX:00000000\n"
        "3000:00000010\n"
        "1200:00000000\n"
        "f000:fffe\n"
        "2000:00010000\n",
        encoding="utf-8-sig",
    )
    command = ["trace", str(trace), "--export", str(export), "--runtime-base", "2000"]
    assert main([*command, "--overlay-segment", "ov1=3000", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report == {
        "instructions": 7, "ignored_lines": 2, "analysis": None,
        "mapped": [
            {"runtime_address": "2000:0000", "address": "1000:0000", "unit_address": "root:0000", "linear": 0x10000, "count": 1},
            {"runtime_address": "2001:000f", "address": "1000:001f", "unit_address": "root:001f", "linear": 0x1001F, "count": 2},
            {"runtime_address": "3000:0000", "address": "1200:0000", "unit_address": "OV1:0000", "linear": 0x12000, "count": 1},
        ],
        "unmapped": [
            {"runtime_address": "1200:0000", "count": 1},
            {"runtime_address": "3000:0010", "count": 1},
            {"runtime_address": "f000:fffe", "count": 1},
        ],
    }

    assert main([*command, "--overlay-segment", "ov1=3000", "--evidence", "--json"]) == 0
    sourced = json.loads(capsys.readouterr().out)
    assert sourced["export"]["image_sha256"] == sha256((export / "image.bin").read_bytes()).hexdigest()
    assert sourced["unmapped"] == report["unmapped"]
    for hit, loaded, original, source, file_offset in zip(
        sourced["mapped"], ("c3", "10", "cb"), ("c3", "00", "cb"), (exe, exe, overlay), (32, 63, 0), strict=True,
    ):
        proof = hit["export_evidence"]
        assert (proof["loaded"], proof["original"]) == (loaded, original)
        assert proof["address"]["unit_address"] == hit["unit_address"]
        assert proof["address"]["file"] == {
            "source": source.name, "offset": file_offset, "offset_kind": "file", "member": None,
        }
    assert sourced["mapped"][1]["runtime_address"] == "2001:000f"
    assert sourced["mapped"][1]["export_evidence"]["address"]["runtime"] == {
        "address": "2000:001f", "linear": 0x2001F,
    }

    assert main([*command, "--overlay-segment", "OV1=2001", "--json"]) == 1
    assert "runtime ranges overlap" in json.loads(capsys.readouterr().err)["error"]["message"]

    trace.write_text("2000:00010000\n", encoding="ascii")
    assert main([*command, "--json"]) == 1
    assert "no 16-bit DOSBox-X instruction addresses" in json.loads(capsys.readouterr().err)["error"]["message"]


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test")
def test_trace_attaches_execution_evidence_to_static_gaps(tmp_path, capsys):
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", 64, 1, 0, 2, 0, 0, 0, 32, 0, 0, 0, 28, 0)
    source = tmp_path / "test.exe"
    source.write_bytes(header + b"\xc3" + b"\0" * 31)
    export, project = tmp_path / "export", tmp_path / "project"
    assert main(["load", str(source), "-o", str(export)]) == 0
    assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    capsys.readouterr()
    trace = tmp_path / "logcpu.txt"
    trace.write_text("2000:0000\n2000:000e\n2000:000e\n2000:000f\n", encoding="utf-8")
    assert main(["trace", str(trace), "--project", str(project), "--export", str(export), "--classify-gaps",
                 "--runtime-base", "2000", "--evidence", "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    gap, = report["analysis"]["observed_gaps"]
    assert gap["class"] == "padding"
    evidence = gap["trace_evidence"]
    assert (evidence["kind"], evidence["addresses"], evidence["hits"]) == ("executed", 2, 3)
    assert [row["unit_address"] for row in evidence["examples"]] == ["root:000e", "root:000f"]
    assert evidence["examples"] == report["analysis"]["missed"]
    for index, example in enumerate(evidence["examples"], 1):
        proof = example["export_evidence"]
        assert proof == report["mapped"][index]["export_evidence"]
        assert proof["loaded"] == proof["original"] == "00"
        assert proof["address"]["file"]["offset"] == 45 + index


def test_structured_trace_maps_snapshots_and_bank_changes(tmp_path):
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", 64, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
    exe = tmp_path / "sample.exe"
    exe.write_bytes(header + b"\xc3" + bytes(31))
    first, second = tmp_path / "OV1.ovr", tmp_path / "OV2.ovr"
    first.write_bytes(b"\xcb" + bytes(15))
    second.write_bytes(b"\xc3" + bytes(15))
    export = tmp_path / "export"
    assert main(["load", str(exe), "-o", str(export), "--overlay", f"{first}@1200",
                 "--overlay", f"{second}@1400"]) == 0
    trace = tmp_path / "emulator.json"
    events = [
        {"kind": "instruction", "address": "3000:0000", "count": 2},
        {"kind": "memory", "access": "read", "pc": "3000:0000", "address": "3000:000f", "size": 2,
         "bytes": "00ff"},
        {"kind": "bank", "name": "slot", "placements": {"OV1": None, "ov2": "3000:0000"}},
        {"kind": "edge", "from": "3000:0000", "from_state": 0, "to": 0x30000, "flow": "jump"},
        {"kind": "snapshot", "name": "loaded", "pc": 0x30000, "registers": {"ax": 7},
         "memory": [{"address": 0x30000, "bytes": "C300"}]},
        {"kind": "overlay", "placements": {"OV2": None}},
        {"kind": "instruction", "address": "3000:0000"},
    ]
    document = {"version": 1, "placements": {"ov1": "3000:0000"}, "events": events}
    trace.write_text(json.dumps(document), encoding="utf-8")
    report = import_trace(trace, export, evidence=True)
    assert (report["instruction_records"], report["instructions"]) == (3, 4)
    assert [(hit["unit_address"], hit["count"]) for hit in report["mapped"]] == [("OV1:0000", 2), ("OV2:0000", 1)]
    assert report["unmapped"] == [{"runtime_linear": 0x30000, "runtime_address": "3000:0000", "count": 1}]
    edge, = report["edges"]
    assert edge["from"]["location"]["unit_address"] == "OV1:0000"
    assert edge["to"]["location"]["unit_address"] == "OV2:0000"
    assert edge["to"]["export_evidence"]["loaded"] == "c3"
    assert edge["to"]["export_evidence"]["address"]["runtime"]["linear"] == 0x30000
    assert report["transitions"][0]["previous"] == {"OV1": 0x30000, "OV2": None}
    access, = report["memory"]
    assert access["pc"]["location"]["unit_address"] == "OV1:0000"
    left, right = access["spans"]
    assert (left["location"]["unit_address"], left["size"]) == ("OV1:000f", 1)
    assert (right["location"], right["runtime_linear"], right["size"]) == (None, 0x30010, 1)
    snapshot, = report["snapshots"]
    assert snapshot["registers"] == {"ax": 7}
    assert snapshot["memory"][0]["bytes"] == "c300"
    assert snapshot["memory"][0]["location"]["unit_address"] == "OV2:0000"

    events[2]["placements"].pop("OV1")
    trace.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(TraceError, match="event 3: runtime ranges overlap"):
        import_trace(trace, export)


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test")
def test_structured_flat_trace_previews_and_applies_only_observed_additions(tmp_path, capsys):
    source = tmp_path / "demo.prg"
    code = bytes.fromhex("d0046c0003ea60") + b"\xea" * 9 + bytes.fromhex("e860")
    source.write_bytes(b"\x00\x08" + code)
    export, project = tmp_path / "export", tmp_path / "project"
    assert main(["load", str(source), "-o", str(export), "--c64", "--entry", "0800"]) == 0
    assert main(["ghidra", "import", str(export), str(project)]) == 0
    capsys.readouterr()
    trace = tmp_path / "emulator.json"
    events = [
        {"kind": "edge", "from": "0800", "to": "0802", "flow": "fallthrough"},
        {"kind": "edge", "from": "0802", "to": "0810", "flow": "jump"},
        {"kind": "edge", "from": "0802", "to": "0810", "flow": "jump"},
    ]
    command = ["trace", str(trace), "--export", str(export), "--project", str(project), "--json"]

    def write_events(rows):
        trace.write_text(json.dumps({"version": 1, "events": rows}), encoding="utf-8")

    def analyze(*options):
        assert main([*command, *options]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)["analysis"]

    write_events([*events, {"kind": "instruction", "address": "0810", "bytes": "ea"}])
    incompatible = analyze()
    assert incompatible["additions"] == []
    assert incompatible["missed"][0]["proposal_blocked"] == "runtime_bytes_differ"

    write_events([*events, {"kind": "instruction", "address": "0810", "bytes": "e8"}])
    preview = analyze()
    assert [entry["reason"] for entry in preview["edge_gaps"]] == ["target_not_disassembled"] * 2
    branch, = preview["unobserved_flows"]
    assert (branch["from"]["linear"], branch["to"]["linear"], branch["kind"]) == (0x0800, 0x0806, "branch")
    instruction, flow = preview["additions"]
    assert (instruction["address"]["linear"], instruction["bytes"]) == (0x0810, "e8")
    assert (flow["from"]["linear"], flow["to"]["linear"], flow["events"]) == (0x0802, 0x0810, [2, 3])

    assert analyze() == preview
    applied = analyze("--apply")
    assert applied["applied"] == preview["additions"]
    assert analyze("--apply")["applied"] == []
    write_events([*events[:2], {"kind": "instruction", "address": "0811"}])
    after = analyze()
    assert after["edge_gaps"] == []
    assert [hit["linear"] for hit in after["missed"]] == [0x0811]
    assert [entry["address"]["linear"] for entry in after["additions"]] == [0x0811]


def test_trace_recovers_a_real_mode_software_interrupt_entry(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    image = bytes.fromhex("cd60 ffe3 c3") + bytes(11) + b"\xcf"
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(image), 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
    exe, export, project = tmp_path / "test.exe", tmp_path / "export", tmp_path / "interrupt"
    exe.write_bytes(header + image)
    assert main(["load", str(exe), "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    capsys.readouterr()

    trace = tmp_path / "interrupt.json"
    trace.write_text(json.dumps({"version": 1, "events": [
        {"kind": "edge", "from": 0x10000, "to": 0x10010, "flow": "interrupt"},
        {"kind": "edge", "from": 0x10002, "to": 0x10010, "flow": "interrupt"},
    ]}), encoding="utf-8")
    command = ["trace", str(trace), "--export", str(export), "--project", str(project), "--json"]
    assert main([*command, "--apply"]) == 0, capsys.readouterr().err
    applied = json.loads(capsys.readouterr().out)["analysis"]["applied"]
    flow, = (row for row in applied if row["kind"] == "flow")
    assert (flow["from"]["unit_address"], flow["to"]["unit_address"], flow["type"], flow["events"]) == (
        "root:0000", "root:0010", "COMPUTED_CALL", [1],
    )
    assert main(command) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)["analysis"]
    assert report["additions"] == []
    assert [edge["event"] for edge in report["edge_gaps"]] == [2]


def test_interrupt_resume_repairs_only_unobserved_inline_operand_disassembly(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    image = bytes.fromhex("b8 20 10 8e d8 bf 20 01 cd 60 d9 cd 39 7e fe c3")
    image = image.ljust(0x20, b"\0") + bytes.fromhex("c6 05 7f cf")
    image = (image.ljust(0x30, b"\0") + b"\xcf").ljust(0x321, b"\0")
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", (len(header) + len(image)) % 512, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
    exe, export, project = (tmp_path / name for name in ("test.exe", "export", "interrupt"))
    exe.write_bytes(header + image)
    assert main(["load", str(exe), "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    capsys.readouterr()

    trace = tmp_path / "interrupt.json"
    events = [
        {"kind": "instruction", "address": 0x10008, "bytes": "cd60"},
        {"kind": "edge", "from": 0x10008, "to": 0x10020, "flow": "interrupt"},
        {"kind": "edge", "from": 0x10008, "to": 0x1000b, "flow": "interrupt_resume"},
        {"kind": "instruction", "address": 0x1000b, "bytes": "cd39"},
        {"kind": "edge", "from": 0x1000b, "to": 0x10030, "flow": "interrupt"},
        {"kind": "edge", "from": 0x1000b, "to": 0x1000f, "flow": "interrupt_resume"},
    ]
    command = ["trace", str(trace), "--export", str(export), "--project", str(project), "--json"]

    def replay(events, *options):
        trace.write_text(json.dumps({"version": 1, "events": events}), encoding="utf-8")
        assert main([*command, *options]) == 0, capsys.readouterr().err
        report = json.loads(capsys.readouterr().out)
        assert all(hit["count"] == 1 for hit in report["mapped"])
        return report["analysis"]

    competing = replay([*events, {"kind": "instruction", "address": 0x1000a, "bytes": "d9cd"}])
    assert not ({"clear_instruction", "interrupt_resume"} & {row["kind"] for row in competing["additions"]})
    applied = replay(events, "--apply")["applied"]
    assert [row["address"]["linear"] for row in applied if row["kind"] == "clear_instruction"] == [0x1000a, 0x1000c]
    assert [row["from"]["linear"] for row in applied if row["kind"] == "interrupt_resume"] == [0x10008, 0x1000b]
    after = replay(events, "--apply")
    assert after["applied"] == after["edge_gaps"] == after["missed"] == []
    assert main(["record-writes", "root:320", "--code-start", "root:20", "--code-end", "root:20",
                 "--project", str(project), "--compact", "--json"]) == 0, capsys.readouterr().err
    write, = json.loads(capsys.readouterr().out)["writes"]
    assert write["status"] == "overlap" and write["hits"] == [{"address": "root:0320", "value": 0x7f}]
