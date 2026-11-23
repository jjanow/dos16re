import json
import os
from struct import pack_into

import pytest

from retrore.cli import main


def test_imports_dosbox_x_log_and_rebases_runtime_units(tmp_path, capsys):
    root = b"\xc3" + bytes(31)
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(root), 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
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
        "2000:0000001F\n"
        "2001:000F  nop                            EAX:00000000\n"
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
            {"runtime_address": "2000:001f", "address": "1000:001f", "unit_address": "root:001f", "linear": 0x1001F, "count": 2},
            {"runtime_address": "3000:0000", "address": "1200:0000", "unit_address": "OV1:0000", "linear": 0x12000, "count": 1},
        ],
        "unmapped": [
            {"runtime_address": "1200:0000", "count": 1},
            {"runtime_address": "3000:0010", "count": 1},
            {"runtime_address": "f000:fffe", "count": 1},
        ],
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
    trace.write_text("1000:0000\n1000:000e\n1000:000e\n1000:000f\n", encoding="utf-8")
    assert main(["trace", str(trace), "--project", str(project), "--export", str(export), "--classify-gaps",
                 "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    gap, = report["analysis"]["observed_gaps"]
    assert gap["class"] == "padding"
    evidence = gap["trace_evidence"]
    assert (evidence["kind"], evidence["addresses"], evidence["hits"]) == ("executed", 2, 3)
    assert [row["unit_address"] for row in evidence["examples"]] == ["root:000e", "root:000f"]
