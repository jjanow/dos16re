import json
import os
from struct import pack, unpack_from

import pytest

from retrore.amiga import HunkError, build_hunk_image
from retrore.cli import main


def _words(*values):
    return pack(f">{len(values)}I", *values)


def _program():
    return b"".join((
        _words(0x3F3, 0, 5, 0, 4, 2, 0x40000004, 1, 0xC0000002, 4, 0),
        _words(0x3E9, 2), bytes.fromhex("4eb9 00000000 4e75"),
        _words(0x3EC, 1, 2, 2, 0, 0x3F2),
        _words(0x3E8, 1), b"vars",
        _words(0x3EA, 3, 4, 0), bytes.fromhex("1234 e921"),
        _words(0x3FC), pack(">6H", 2, 3, 0, 4, 0, 0),
        _words(0x3F1, 1, 0, 0x3F2),
        _words(0x3E9, 1), bytes.fromhex("7007 4e75"),
        _words(0x3F0, 2), b"worker\0\0", _words(0, 0, 0x3F2),
        _words(0x3EB, 2, 0x3F2),
        _words(0x3EA, 0, 0x3F2),
    ))


def test_amiga_export_and_search(tmp_path, capsys):
    source = tmp_path / "demo"
    source.write_bytes(_program())
    out = tmp_path / "out"
    assert main(["load", str(source), "--base-address", "200000", "-o", str(out), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    assert json.loads((out / "map.json").read_text()) == program
    assert program["entry"] == {"unit_address": "h0:0000", "linear": 0x200000}
    code, data, worker, bss, empty = program["units"]
    assert [unit["linear"] for unit in program["units"]] == list(range(0x200000, 0x200050, 16))
    assert [unit["kind"] for unit in program["units"]] == ["code", "data", "code", "bss", "data"]
    assert (data["size"], data["file_size"], data["memory_flags"]) == (16, 12, 2)
    assert (bss["size"], bss["file_offset"], bss["memory_flags"]) == (8, None, 4)
    assert empty["size"] == 0
    assert worker["symbols"] == [{"name": "worker", "offset": 0}]
    assert code["relocations"] == [{"offset": 2, "target": "h2", "original": 0, "value": 0x200020}]

    image = (out / "image.bin").read_bytes()
    assert unpack_from(">I", image, 2) == (0x200020,)
    assert unpack_from(">2I", image, 16) == (0x200034, 0x200030)
    assert image[28:32] == bytes(4)
    assert image[48:56] == bytes(8)
    assert main(["info", str(source), "--base-address", "200000", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == program

    for flag, pattern, position in (
        ("--constant", "0x1234", 8), ("--string", "é!", 10),
    ):
        assert main(["where-is", "--export", str(out), flag, pattern, "--json"]) == 0
        match, = json.loads(capsys.readouterr().out)["matches"]
        assert match == {
            "address": f"{0x200010 + position:08x}",
            "unit_address": f"h1:{position:04x}", "linear": 0x200010 + position,
        }
    assert main(["where-is", "--export", str(out), "--bytes", "00 00 00 00", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["count"] == 0

    assert main(["call", "h0:0", "--export", str(out), "--json"]) == 1
    assert "requires a DOS MZ image" in json.loads(capsys.readouterr().err)["error"]
    assert main(["trace", str(tmp_path / "log"), "--export", str(out), "--json"]) == 1
    assert "require a DOS MZ image" in json.loads(capsys.readouterr().err)["error"]


@pytest.mark.parametrize("record", [0x3F7, 0x3FC])
def test_unpadded_short_relocations(record):
    source = _words(0x3F3, 0, 1, 0, 0, 1, 0x3E9, 1, 0, record)
    source += pack(">4H", 1, 0, 0, 0) + _words(0x3F2)
    image, _ = build_hunk_image(source, "demo")
    assert image == _words(0x10000)


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda data: data[:-1], "truncated"),
        (lambda data: data + _words(0x3F5), "HUNK_OVERLAY"),
        (lambda data: data[:16] + _words(3) + data[20:], "HUNK_OVERLAY"),
        (lambda data: data[:20] + _words(0x3FFFFFFF) + data[24:], "24-bit address space"),
        (lambda data: data.replace(_words(0x3EC, 1, 2, 2), _words(0x3EC, 1, 5, 2)), "target"),
        (lambda data: data.replace(_words(0x3EC, 1, 2, 2), _words(0x3EC, 1, 2, 6)), "offset"),
    ],
)
def test_malformed_and_unsupported_hunks(edit, message):
    with pytest.raises(HunkError, match=message):
        build_hunk_image(edit(_program()), "demo")


def test_amiga_ghidra_import_and_queries(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    source, out, project = (tmp_path / name for name in ("demo", "out", "project"))
    source.write_bytes(_program())
    assert main(["load", str(source), "-o", str(out)]) == 0
    capsys.readouterr()

    def query(*args):
        assert main([*args, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)

    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert (report["format"], report["units"], report["relocations"]) == ("HUNK", 5, 3)

    call, = query("callees", "00010000")["callees"]
    assert call["from"]["unit_address"] == "h0:0000"
    assert call["to"]["unit_address"] == "h2:0000"
    assert call["to_function"]["name"] == "worker"
    assert query("func", "h2:0000")["segments"] == {}
    assert "return 7;" in query("decomp", "h2:0000")["decompilation"]
    assert any(ref["to"]["unit_address"] == "h3:0004" for ref in query("xrefs", "h1:0000")["outgoing"])
    assert {gap["unit"] for gap in query("gaps")["ranges"]} <= {"h0", "h2"}
