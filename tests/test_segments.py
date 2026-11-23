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
    report = json.loads(capsys.readouterr().out)
    assert report["units"] == 1
    program["import"] = report
    return project, program


def _single(capsys):
    report = json.loads(capsys.readouterr().out)
    assert report.pop("contract") == 1
    return report


def _check_references(project, *checks):
    script_path = Path(__file__).parent / "ghidra"
    result = subprocess.run(
        [
            str(_headless()), str(project.parent), project.name,
            "-process", "image.bin", "-noanalysis", "-readOnly",
            "-scriptPath", str(script_path), "-postScript", "CheckSegmentReferences.java",
            # cmd.exe splits arguments at commas, so analyzeHeadless.bat would break up comma-separated checks.
            *(check.replace(",", "/") for check in checks),
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


class _Code:
    """Assemble 16-bit code from hex chunks with near-call labels and relocated segment immediates."""

    def __init__(self):
        self.data = bytearray()
        self.labels = {}
        self.calls = []
        self.relocations = []

    def emit(self, text):
        self.data += bytes.fromhex(text)

    def label(self, name):
        self.labels[name] = len(self.data)

    def call(self, name, opcode=b"\xe8"):
        self.data += opcode + b"\0\0"
        self.calls.append((len(self.data) - 2, name))

    def jump(self, name):
        self.call(name, b"\xe9")

    def segment(self, opcode, paragraph):
        self.emit(opcode)
        self.relocations.append(len(self.data))
        self.data += paragraph.to_bytes(2, "little")

    def finish(self):
        for position, name in self.calls:
            pack_into("<h", self.data, position, self.labels[name] - position - 2)
        return bytes(self.data)


def test_carries_segments_across_calls_far_pointers_and_frames(tmp_path, capsys):
    code = _Code()
    code.segment("b8", 0x20)
    code.emit("8e d8")                              # DS = DGROUP
    code.call("set_es")
    code.label("after_set")
    code.emit("26 a1 10 00")                        # the callee set ES = FAR
    code.call("keep_es")
    code.label("after_keep")
    code.emit("26 a3 12 00")                        # the callee saved and restored ES
    code.emit("8c db 8e c3")                        # mov bx, ds; mov es, bx
    code.label("alias")
    code.emit("26 a3 14 00")
    code.emit("c4 3e 40 00")                        # les di, [0x40]: relocated far pointer in DGROUP
    code.label("far_pointer")
    code.emit("26 8b 45 02")                        # mov ax, es:[di+2]
    code.segment("b8", 0x30)
    code.emit("50 b8 30 00 50")                     # push FAR; push 0x30
    code.call("pointer_argument")
    code.segment("b8", 0x30)
    code.emit("8e c0")                              # ES = FAR
    code.call("frame")
    code.label("after_frame")
    code.emit("26 a3 20 00")                        # the callee restored ES from its frame
    code.call("clobber")
    code.label("after_clobber")
    code.emit("26 a3 16 00")
    code.emit("1e 07 ff d6")                        # push ds; pop es; call si
    code.label("after_unknown_call")
    code.emit("26 a3 18 00")
    code.emit("1e 07 85 db 74 05")                  # ES = DGROUP, or FAR on one path
    code.segment("b8", 0x30)
    code.emit("8e c0")
    code.label("join")
    code.emit("26 a3 1a 00")
    code.emit("8e 06 46 00")                        # mov es, [0x46]: not a relocated word
    code.label("after_load")
    code.emit("26 a3 1c 00")
    code.emit("b8 00 4c cd 21 eb fe")
    code.label("set_es")
    code.segment("b8", 0x30)
    code.emit("8e c0 c3")
    code.label("keep_es")
    code.emit("06")
    code.segment("b8", 0x40)
    code.emit("8e c0 26 a3 00 00 07 c3")
    code.label("pointer_argument")
    code.emit("55 8b ec c4 5e 04")                  # les bx, [bp+4]
    code.label("argument_use")
    code.emit("26 8b 07 5d c2 04 00")               # mov ax, es:[bx]; pop bp; ret 4
    code.label("clobber")
    code.emit("8e 06 44 00 c3")
    code.label("frame")
    code.emit("55 8b ec 83 ec 02 8c 46 fe")         # save ES in a local
    code.call("clobber")
    code.emit("8e 46 fe")                           # restore ES from the local
    code.label("frame_use")
    code.emit("26 a1 1e 00 8b e5 5d c3")
    image = bytearray(0x480)
    image[:len(code.data)] = code.finish()
    pack_into("<4H", image, 0x240, 0x20, 0x40, 0x1234, 0x5678)
    relocations = [(position, 0) for position in code.relocations] + [(0x42, 0x20)]
    header = bytearray(0x1C + 4 * len(relocations))
    header += bytes(-len(header) % 16)
    file_size = len(header) + len(image)
    pack_into(
        "<2s13H", header, 0,
        b"MZ", file_size % 512, (file_size + 511) // 512, len(relocations), len(header) // 16, 0, 0,
        0x46, 0x3E, 0, 0, 0, 0x1C, 0,
    )
    for index, (offset, segment) in enumerate(relocations):
        pack_into("<2H", header, 0x1C + 4 * index, offset, segment)
    exe = tmp_path / "calls.exe"
    exe.write_bytes(header + image)
    project, program = _import_program(tmp_path, capsys, exe, "--base-segment", "2000")
    assert program["relocations"] == sorted([*code.relocations, 0x242])

    def at(name):
        return f"2000:{code.labels[name]:04x}"

    _check_references(
        project,
        f"{at('after_set')},ES,2030,1,2030:0010,word,FAR2030_0010",
        f"{at('after_keep')},ES,2030,0,2030:0012,word,FAR2030_0012",
        f"{at('alias')},ES,2020,0,2020:0014,word,DGROUP_0014",
        f"{at('far_pointer')},ES,2040,1,2040:0022,word,FAR2040_0022",
        f"{at('argument_use')},ES,2030,1,2030:0030,word,FAR2030_0030",
        f"{at('frame_use')},ES,2030,1,2030:001e,word,FAR2030_001e",
        f"{at('after_frame')},ES,2030,0,2030:0020,word,FAR2030_0020",
        f"{at('after_clobber')},ES,?",
        f"{at('after_unknown_call')},ES,?",
        f"{at('join')},ES,?",
        f"{at('after_load')},ES,?",
    )

    # Each unknown ES names the instruction that lost it: the call, the join, or the load.
    expected = {
        "after_clobber": ("call", 3),
        "after_unknown_call": ("unknown_call", 2),
        "join": ("join", 0),
        "after_load": ("load", 4),
    }
    for name, (reason, back) in expected.items():
        assert main(["func", at(name), "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        report = json.loads(capsys.readouterr().out)
        assert report["segments"]["ES"] is None
        loss = report["segment_losses"]["ES"]
        assert (loss["reason"], loss["address"]["linear"]) == (reason, 0x20000 + code.labels[name] - back), loss
    assert main(["func", at("after_load"), "--project", str(project)]) == 0
    assert "ES lost at root:" in capsys.readouterr().out


def _mz(code, data):
    """Wrap code at paragraph 0 and DGROUP words at paragraph 0x20 in an MZ file."""
    image = bytearray(0x480)
    image[:len(code.data)] = code.finish()
    pack_into(f"<{len(data)}H", image, 0x200, *data)
    relocations = code.relocations
    header = bytearray(0x1C + 4 * len(relocations))
    header += bytes(-len(header) % 16)
    file_size = len(header) + len(image)
    pack_into(
        "<2s13H", header, 0,
        b"MZ", file_size % 512, (file_size + 511) // 512, len(relocations), len(header) // 16, 0, 0,
        0x46, 0x3E, 0, 0, 0, 0x1C, 0,
    )
    for index, offset in enumerate(relocations):
        pack_into("<2H", header, 0x1C + 4 * index, offset, 0)
    return bytes(header + image)


def test_jumps_into_another_function_keep_its_context(tmp_path, capsys):
    code = _Code()
    code.segment("b8", 0x20)
    code.emit("8e d8")                              # DS = DGROUP
    code.call("shared")
    code.call("tail")
    code.call("error")
    code.call("entry_jump")
    code.emit("b8 00 4c cd 21 eb fe")
    code.label("shared")
    code.emit("90")
    code.label("middle")
    code.emit("a1 10 00 c3")                        # mov ax, [0x10]; ret
    code.label("tail")
    code.emit("a1 12 00 c3")
    code.label("error")
    code.segment("b8", 0x30)
    code.emit("8e d8")                              # DS = FAR
    code.jump("middle")
    code.label("entry_jump")
    code.segment("b8", 0x30)
    code.emit("8e d8")                              # DS = FAR
    code.jump("tail")
    exe = tmp_path / "jumps.exe"
    exe.write_bytes(_mz(code, [0x1111, 0x2222, 0x3333]))
    project, program = _import_program(tmp_path, capsys, exe, "--base-segment", "2000")
    assert program["import"]["segment_analysis"]["skipped_jumps"] >= 1

    # The error path's jump into the middle of `shared` does not erase the DGROUP that `shared`
    # receives from its caller, while the jump to `tail`'s entry still joins its context.
    _check_references(
        project,
        f"2000:{code.labels['middle']:04x},DS,2020,1,2020:0010,word,DGROUP_0010",
        f"2000:{code.labels['tail']:04x},DS,?",
    )
    assert main(["func", f"2000:{code.labels['tail']:04x}", "--project", str(project), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["segment_losses"]["DS"]["reason"] == "join"


def test_ghidra_types_phantasie_iii_far_globals(tmp_path, capsys):
    directory = os.environ.get("RETRORE_PH3_DIR")
    if not directory:
        pytest.skip("set RETRORE_PH3_DIR to run the real-game test")
    exe = next(path for path in Path(directory).iterdir() if path.name.upper() == "MAIN.EXE")
    project, program = _import_program(tmp_path, capsys, exe)

    # The save-game code reads and writes a word through the relocated FAR segment.
    # 1000:125d, called from main, keeps DGROUP now that a misread jump table no longer joins
    # main's context. int86 at 1000:5276 and 1000:2840 receive far pointers that every caller
    # pushes as relocated FAR segment and offset.
    _check_references(
        project,
        "13b2:452a,ES,2820,1,2820:97f0,word,FAR2820_97f0",
        "13b2:467d,ES,2820,0,2820:97f0,word,FAR2820_97f0",
        "1000:1274,ES,2820,0,2820:aa30,word,FAR2820_aa30",
        "1000:52af,DS,2820,1,2820:b7f6,word,FAR2820_b7f6",
        "1000:2851,ES,2820,0,2820:09fa,byte,FAR2820_09fa",
    )
    # Before summaries and loss tracking, 247 of 380 functions entered with a known DS and the
    # import added 1,903 data references.
    analysis = program["import"]["segment_analysis"]
    assert analysis["entry_known"]["DS"] >= 360
    assert analysis["data_references"] >= 2500


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
    result = _single(capsys)
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
    assert "no analyzed function" in batch[1]["error"]["message"]
    assert batch[1]["error"]["code"] == "no_function"
    assert batch[0]["result"] == result
    assert batch[2]["result"]["unit_address"] == "OV1:0000"

    assert main(["callers", "1000:0013", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    callers = _single(capsys)
    assert batch[3]["result"] == callers
    assert callers["function"]["entry"]["unit_address"] == "root:0010"
    call, = callers["callers"]
    assert call["from"]["unit_address"] == "root:0005"
    assert call["to_function"] == callers["function"]

    assert main(["callees", "root:0", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    callees = _single(capsys)
    assert batch[4]["result"] == callees
    assert callees["callees"][0] == call
    assert [edge["to"]["unit_address"] for edge in callees["callees"]] == ["root:0010", "root:001c"]

    assert main(["callees", "root:1c", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    overlay_call, = _single(capsys)["callees"]
    entry = overlay_call["to_function"]["entry"]
    assert entry["unit_address"] == "OV1:0000"
    assert entry["linear"] == 0x11000

    assert main(["xrefs", "root:5", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    xrefs = _single(capsys)
    assert batch[5]["result"] == xrefs
    assert call in xrefs["outgoing"]

    assert main(["func", "root:10", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    function = _single(capsys)
    assert batch[6]["result"] == function
    assert function["size"] == 10
    assert [(span["start"]["unit_address"], span["end"]["unit_address"]) for span in function["ranges"]] == [
        ("root:0010", "root:0019"),
    ]
    assert function["callers"] == callers["callers"]

    narrow = [
        {"command": "callees", "address": "root:0", "compact": True, "limit": 1, "fields": ["callees"]},
        {"command": "callees", "address": "root:0", "compact": True, "limit": 1, "offset": 1},
        {"command": "callees", "address": "root:0", "limit": 1, "offset": 20},
        {"command": "xrefs", "address": "root:5", "direction": "outgoing", "ref_types": ["READ"], "limit": 1},
        {"command": "decomp", "address": "root:10", "fields": ["unit_address", "name"]},
    ]
    pages = [row["result"] for row in ghidra.query_batch(project, narrow)["results"]]
    assert set(pages[0]) == {"callees", "pagination"}
    assert pages[0]["callees"][0]["to"] == "root:0010"
    assert pages[0]["pagination"]["callees"] == {"offset": 0, "total": 2, "returned": 1, "next_offset": 1}
    assert pages[1]["callees"][0]["to"] == "root:001c"
    assert pages[1]["pagination"]["callees"]["next_offset"] is None
    assert pages[2]["callees"] == []
    assert pages[2]["pagination"]["callees"] == {"offset": 20, "total": 2, "returned": 0, "next_offset": None}
    assert "incoming" not in pages[3]
    assert pages[3]["outgoing"] == []
    assert pages[3]["pagination"]["outgoing"]["total"] == 0
    assert pages[4] == {key: result[key] for key in ("unit_address", "name")}
    assert main(["callees", "root:0", "--project", str(project), "--limit", "1", "--compact",
                 "--fields", "callees", "--json"]) == 0
    assert _single(capsys) == pages[0]

    assert main(["func", "root:e", "--project", str(project), "--json"]) == 1
    error = json.loads(capsys.readouterr().err)["error"]
    assert error["code"] == "no_function" and "no analyzed function" in error["message"]
    assert main(["func", "nosuchunit:0", "--project", str(project), "--json"]) == 1
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "address_not_found"

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
