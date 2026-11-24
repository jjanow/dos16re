import json
import os
from struct import pack, unpack_from

import pytest

from retrore.atari_st import PrgError, build_prg_image
from retrore.cli import main


def _prg(text, data=b"", bss_size=0, symbols=b"", fixups=b"\0" * 4, absolute=0):
    header = pack(">H6IH", 0x601A, len(text), len(data), bss_size, len(symbols), 0, 1, absolute)
    return header + text + data + symbols + fixups


def _program():
    text = bytes.fromhex("4eb9 00000008 4e75 7007 4e75").ljust(0x100, b"\0")
    data = b"ST!\0" + pack(">2I", 0x10E, 8)
    symbols = b"".join((
        pack(">8sHI", b"worker", 0xA200, 8),
        pack(">8sHI", b"message_", 0xA448, 0x100), b"long_name\0".ljust(14, b"\0"),
        pack(">8sHI", b"buffer", 0xA100, 0x10E),
        pack(">8sHI", b"constant", 0xE200, 2),
    ))
    fixups = pack(">I", 2) + bytes([1, 4, 4, 0]) + b"tail"
    return _prg(text, data, 8, symbols, fixups)


def test_atari_st_export_and_search(tmp_path, capsys):
    source = tmp_path / "demo.tos"
    source.write_bytes(_program())
    out = tmp_path / "out"
    assert main(["load", str(source), "--base-address", "10002", "-o", str(out), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    assert json.loads((out / "map.json").read_text()) == program
    assert program["format"] == "PRG"
    assert program["header"] == {"reserved": 0, "flags": 1, "absolute": False, "symbol_table_size": 70}
    assert program["entry"] == {"unit_address": "text:0000", "linear": 0x10002}
    text, data, bss = program["units"]
    assert [(unit["name"], unit["linear"], unit["size"], unit["file_offset"], unit["file_size"])
            for unit in (text, data, bss)] == [
        ("text", 0x10002, 0x100, 0x1C, 0x100),
        ("data", 0x10102, 12, 0x11C, 12),
        ("bss", 0x1010E, 8, None, 0),
    ]
    assert text["symbols"] == [{"name": "worker", "offset": 8}]
    assert data["symbols"] == [{"name": "message_long_name", "offset": 0}]
    assert bss["symbols"] == [{"name": "buffer", "offset": 2}]
    assert text["relocations"] == [{"offset": 2, "original": 8, "value": 0x1000A}]
    assert data["relocations"] == [
        {"offset": 4, "original": 0x10E, "value": 0x10110},
        {"offset": 8, "original": 8, "value": 0x1000A},
    ]
    image = (out / "image.bin").read_bytes()
    assert unpack_from(">I", image, 2) == (0x1000A,)
    assert unpack_from(">2I", image, 0x104) == (0x10110, 0x1000A)
    assert image[0x10C:] == bytes(8)
    assert main(["info", str(source), "--base-address", "10002", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == program

    for pattern, offset in ((["--constant", "0x10110", "--width", "4"], 4), (["--string", "ST!"], 0)):
        assert main(["where-is", "--export", str(out), *pattern, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["matches"] == [{
            "address": f"{0x10102 + offset:08x}", "unit_address": f"data:{offset:04x}", "linear": 0x10102 + offset,
        }]
    assert main(["where-is", "--export", str(out), "--bytes", "00 00 00 00", "--json"]) == 0
    matches = json.loads(capsys.readouterr().out)["matches"]
    assert matches and all(match["unit_address"].startswith("text:") for match in matches)
    assert main(["call", "text:0", "--export", str(out), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["registers"]["d0"] == 7
    log = tmp_path / "log"
    log.write_text("2000:0000\n", encoding="ascii")
    assert main(["trace", str(log), "--export", str(out), "--json"]) == 1
    assert "require a DOS MZ image" in json.loads(capsys.readouterr().err)["error"]["message"]


@pytest.mark.parametrize("absolute", [0, 1])
def test_atari_st_without_fixups(absolute):
    text = bytes.fromhex("4efa 0004 4e75")
    fixups = b"" if absolute else bytes(4)
    image, program = build_prg_image(_prg(text, fixups=fixups, absolute=absolute), "demo", base=0)
    assert program["header"]["absolute"] is bool(absolute)
    assert program["entry"]["linear"] == 0
    assert [unit["size"] for unit in program["units"]] == [len(text), 0, 0]
    assert all(not unit["relocations"] for unit in program["units"])
    assert image == text


def test_atari_st_recovers_a_relocated_switch_table_in_data():
    text = bytes.fromhex("b47c0001 620e e542 3642 d7fc00000020 2653 4ed3 4e75 7001 4e75 7002 4e75 0000")
    data = pack(">2I", 22, 26)
    fixups = pack(">I3B", 12, 20, 4, 0)
    _, export = build_prg_image(_prg(text, data, fixups=fixups), "switch")
    switch, = export["jump_tables"]
    assert switch["table"]["unit_address"] == "data:0000"
    assert switch["address"]["unit_address"] == "text:0012"
    assert [target["unit_address"] for target in switch["targets"]] == ["text:0016", "text:001a"]

    _, incomplete = build_prg_image(_prg(text, data, fixups=pack(">I2B", 12, 20, 0)), "switch")
    assert "jump_tables" not in incomplete


@pytest.mark.parametrize(("source", "base", "message"), [
    (b"\x60\x1a", 0, "truncated GEMDOS program header"),
    (_prg(bytes(8))[:30], 0, "truncated GEMDOS TEXT"),
    (_prg(bytes(8), fixups=b""), 0, "truncated GEMDOS relocation table"),
    (_prg(bytes(8), fixups=pack(">I", 2)), 0, "unterminated GEMDOS relocation table"),
    (_prg(bytes(8), fixups=pack(">IB", 3, 0)), 0, "relocation offset 0x3"),
    (_prg(bytes(8), bss_size=8, fixups=pack(">IB", 6, 0)), 0, "relocation offset 0x6"),
    (_prg(bytes(8), fixups=pack(">IBB", 2, 1, 2)), 0, "relocation offset 0x102"),
    (_prg(bytes(8)), 1, "base address must be even"),
    (_prg(bytes(8), bss_size=0x1000000), 0, "layout exceeds the 24-bit address space"),
])
def test_atari_st_rejects_invalid_layout_or_fixups(source, base, message):
    with pytest.raises(PrgError, match=message):
        build_prg_image(source, "demo", base)


def test_atari_st_ghidra_import_and_queries(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    source, out, project = (tmp_path / name for name in ("demo.prg", "out", "project"))
    source.write_bytes(_program())
    assert main(["load", str(source), "-o", str(out)]) == 0
    capsys.readouterr()

    def query(*args):
        assert main([*args, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)

    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert (report["format"], report["units"], report["relocations"]) == ("PRG", 3, 3)
    call, = query("callees", "00010000")["callees"]
    assert call["from"]["unit_address"] == "text:0000"
    assert call["to_function"]["name"] == "worker"
    assert "return 7;" in query("decomp", "text:0008")["decompilation"]
    focused = query("decomp", "00010000", "--context", "0", "--slice", "1")
    assert focused["focus"]["address"]["unit_address"] == "text:0000"
    assert "worker(" in focused["excerpt"][0]["text"]
    assert focused["slice"]["operations"][0]["opcode"] == "CALL"
    assert any(ref["to"]["unit_address"] == "bss:0002" for ref in query("xrefs", "data:0004")["outgoing"])
    assert {gap["unit"] for gap in query("gaps")["ranges"]} == {"text"}
