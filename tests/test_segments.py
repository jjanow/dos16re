import json
import os
import subprocess
from io import StringIO
from pathlib import Path
from struct import pack_into

import pytest

from retrore import ghidra
from retrore.cli import main
from retrore.ghidra import _headless


@pytest.fixture(autouse=True)
def require_ghidra():
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")


def _import_program(tmp_path, capsys, exe, *options):
    export = tmp_path / "export"
    project = tmp_path / "segments"
    assert main(["load", str(exe), "-o", str(export), "--json", *options]) == 0
    program = json.loads(capsys.readouterr().out)
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["units"] == 1
    return project, program


def _check_references(project, *checks):
    script_path = Path(__file__).parent / "ghidra"
    result = subprocess.run(
        [
            str(_headless()), str(project.parent), project.name,
            "-process", "image.bin", "-noanalysis", "-readOnly",
            "-scriptPath", str(script_path), "-postScript", "CheckSegmentReferences.java", *checks,
        ],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout
    assert "All segment references checked" in result.stdout, result.stdout


def test_tracks_segment_values_and_drops_conflicting_or_mutable_values(tmp_path, capsys):
    image = bytearray(0x540)
    code = bytes.fromhex(
        "b8 20 00 8e d8"       # mov ax, DGROUP; mov ds, ax
        " e8 01 00 c3"         # call helper; ret
        " 8e 06 10 00"         # helper: mov es, [0x10]
        " 26 a1 30 00"         # mov ax, es:[0x30]
        " 36 a3 32 00"         # mov ss:[0x32], ax
        " 1e 07 26 a3 34 00"   # push ds; pop es; mov es:[0x34], ax
        " 85 db 74 05"         # test bx, bx; je join
        " b8 50 00 8e c0"      # mov ax, OTHER; mov es, ax
        " 26 a3 36 00"         # join: mov es:[0x36], ax
        " c6 06 13 00 00"      # overwrite the high byte of the word at DS:0x12
        " 8e 06 12 00"         # mov es, [0x12]
        " 26 a3 38 00 c3"      # mov es:[0x38], ax; ret
    )
    image[:len(code)] = code
    pack_into("<HH", image, 0x210, 0x30, 0x30)
    header = bytearray(48)
    file_size = len(header) + len(image)
    pack_into(
        "<2s13H", header, 0,
        b"MZ", file_size % 512, (file_size + 511) // 512, 4, 3, 0, 0,
        0x40, 0x3E, 0, 0, 0, 0x1C, 0,
    )
    pack_into("<8H", header, 0x1C, 1, 0, 0x20, 0, 0x10, 0x20, 0x12, 0x20)
    exe = tmp_path / "sample.exe"
    exe.write_bytes(header + image)
    project, program = _import_program(tmp_path, capsys, exe, "--base-segment", "2000")

    assert program["relocations"] == [1, 0x20, 0x210, 0x212]
    _check_references(
        project,
        "2000:0009,DS,2020,1,2020:0010,word,DGROUP_0010",
        "2000:000d,ES,2030,1,2030:0030,word,FAR2030_0030",
        "2000:0011,SS,2040,0,2040:0032,word,FAR2040_0032",
        "2000:0017,ES,2020,0,2020:0034,word,DGROUP_0034",
        "2000:0024,ES,?",
        "2000:0031,ES,?",
    )

    assert main(["xrefs", "2020:0010", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    refs = json.loads(capsys.readouterr().out)
    assert refs["address"]["unit_address"] == "root:0210"
    assert refs["outgoing"] == []
    assert [(ref["from"]["unit_address"], ref["type"]) for ref in refs["incoming"]] == [("root:0009", "READ")]

    assert main(["func", "root:0d", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["function"]["entry"]["unit_address"] == "root:0009"
    assert report["address"]["unit_address"] == "root:000d"
    assert report["segments"] == {"DS": 0x2020, "ES": 0x2030, "SS": 0x2040}
    assert report["callers"][0]["from_function"]["entry"]["unit_address"] == "root:0000"

    assert main(["func", "root:24", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["segments"]["ES"] is None


def test_ghidra_types_phantasie_iii_far_globals(tmp_path, capsys):
    directory = os.environ.get("RETRORE_PH3_DIR")
    if not directory:
        pytest.skip("set RETRORE_PH3_DIR to run the real-game test")
    exe = next(path for path in Path(directory).iterdir() if path.name.upper() == "MAIN.EXE")
    project, _ = _import_program(tmp_path, capsys, exe)

    # The save-game code reads and writes a word through the relocated FAR segment.
    _check_references(
        project,
        "13b2:452a,ES,2820,1,2820:97f0,word,FAR2820_97f0",
        "13b2:467d,ES,2820,0,2820:97f0,word,FAR2820_97f0",
    )


def test_recovers_far_prototype_and_reports_undefined_bytes(tmp_path, capsys, monkeypatch):
    image = bytes.fromhex(
        "b8 34 12 50 0e e8 08 00"  # push argument and CS, then call the far routine
        " 0e e8 10 00 5b c3"       # push CS as an argument to an ordinary near call
        " 9d d7"                   # 0x0e, no incoming flow
        " 55 8b ec 8b 46 06 5d ca 02 00"  # 0x10, far routine returns its argument
        " 9e d7"                   # 0x1a, no incoming flow
        " 9a 00 00 00 11 c3"       # 0x1c, near routine calls a raw overlay
    )
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(image), 1, 0, 2, 32, 32, 2, 0x200, 0, 0, 0, 28, 0)
    exe = tmp_path / "sample.exe"
    exe.write_bytes(header + image)
    overlay = tmp_path / "OV1.ovr"
    overlay.write_bytes(b"\xcb")
    export = tmp_path / "export"
    project = tmp_path / "recovery"
    assert main(["load", str(exe), "-o", str(export), "--overlay", f"{overlay}@1100"]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["far_procedures"] == 1

    assert main(["decomp", "root:10", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    result = json.loads(capsys.readouterr().out)
    assert "__stdcall16far" in result["decompilation"]

    requests = [
        {"command": "decomp", "address": "root:10"},
        {"command": "func", "address": "root:e"},
        {"command": "decomp", "address": "OV1:0"},
        {"command": "callers", "address": "1000:0013"},
        {"command": "callees", "address": "root:0"},
        {"command": "xrefs", "address": "root:5"},
        {"command": "func", "address": "root:10"},
    ]
    real_run = ghidra._run
    launches = []

    def count_launch(*args, **kwargs):
        launches.append(args)
        return real_run(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr("sys.stdin", StringIO(json.dumps(requests)))
        patch.setattr(ghidra, "_run", count_launch)
        assert main(["batch", "--project", str(project), "--json"]) == 1
    captured = capsys.readouterr()
    assert not captured.err
    assert len(launches) == 1
    batch = json.loads(captured.out)["results"]
    assert [{name: row[name] for name in ("command", "address")} for row in batch] == requests
    assert "no analyzed function" in batch[1]["error"]
    assert batch[0]["result"] == result
    assert batch[2]["result"]["unit_address"] == "OV1:0000"

    assert main(["callers", "1000:0013", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    callers = json.loads(capsys.readouterr().out)
    assert batch[3]["result"] == callers
    assert callers["function"]["entry"]["unit_address"] == "root:0010"
    call, = callers["callers"]
    assert call["from"]["unit_address"] == "root:0005"
    assert call["to_function"] == callers["function"]

    assert main(["callees", "root:0", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    callees = json.loads(capsys.readouterr().out)
    assert batch[4]["result"] == callees
    assert callees["callees"][0] == call
    assert [edge["to"]["unit_address"] for edge in callees["callees"]] == ["root:0010", "root:001c"]

    assert main(["callees", "root:1c", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    overlay_call, = json.loads(capsys.readouterr().out)["callees"]
    entry = overlay_call["to_function"]["entry"]
    assert entry["unit_address"] == "OV1:0000"
    assert entry["linear"] == 0x11000

    assert main(["xrefs", "root:5", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    xrefs = json.loads(capsys.readouterr().out)
    assert batch[5]["result"] == xrefs
    assert call in xrefs["outgoing"]

    assert main(["func", "root:10", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    function = json.loads(capsys.readouterr().out)
    assert batch[6]["result"] == function
    assert function["size"] == 10
    assert [(span["start"]["unit_address"], span["end"]["unit_address"]) for span in function["ranges"]] == [
        ("root:0010", "root:0019"),
    ]
    assert function["callers"] == callers["callers"]

    assert main(["func", "root:e", "--project", str(project), "--json"]) == 1
    assert "no analyzed function" in json.loads(capsys.readouterr().err)["error"]

    assert main(["gaps", "--project", str(project) + ".gpr", "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["undefined_bytes"] == 4
    assert report["ranges"] == [
        {"unit": "root", "size": 2, "linear": 0x1000E, "start": "root:000e", "end": "root:000f"},
        {"unit": "root", "size": 2, "linear": 0x1001A, "start": "root:001a", "end": "root:001b"},
    ]

    trace = tmp_path / "LOGCPU.TXT"
    trace.write_text("1000:0000\n1000:0001\n1000:0013\n1001:0003\n1000:000e\n3000:0000\n")
    assert main([
        "trace", str(trace), "--export", str(export), "--project", str(project),
        "--overlay-segment", "OV1=3000", "--json",
    ]) == 0, capsys.readouterr().err
    analysis = json.loads(capsys.readouterr().out)["analysis"]
    assert [(row["function"]["entry"]["unit_address"], row["count"]) for row in analysis["functions"]] == [
        ("root:0000", 1), ("root:0010", 2), ("OV1:0000", 1),
    ]
    assert [(row["unit_address"], row["reason"]) for row in analysis["missed"]] == [
        ("root:0001", "instruction_offcut"), ("root:000e", "undefined"),
    ]
