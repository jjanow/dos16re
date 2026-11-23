import json
import os
from struct import pack, unpack_from

import pytest

from retrore.cli import main
from retrore.x68k import XError, build_x_image, line_f_name

TEXT = bytes.fromhex(
    # worker: XC-style entry through a trailing link.
    "6006"          # 0000 bra.b 0008
    "7007"          # 0002 moveq #7,d0
    "4e5e"          # 0004 unlk a6
    "4e75"          # 0006 rts
    "4e560000"      # 0008 link.w a6,#0
    "60f4"          # 000c bra.b 0002
    # start
    "4eb900000000"  # 000e jsr worker
    "2f00"          # 0014 move.l d0,-(sp)
    "ff09"          # 0016 DOS _PRINT
    "588f"          # 0018 addq.l #4,sp
    "7006"          # 001a moveq #6,d0
    "7203"          # 001c moveq #3,d1
    "48e7c000"      # 001e movem.l d0/d1,-(sp)
    "fee0"          # 0022 FPACK __CLMUL
    "4cdf0003"      # 0024 movem.l (sp)+,d0/d1
    "23c00000003e"  # 0028 move.l d0,result
    "ff00"          # 002e DOS _EXIT
    "ffff"          # 0030 table: data that must stay unpatched
)
DATA = b"X68!" + bytes(2) + pack(">I", 0) + pack(">H", 2)


def _symbol(kind, value, name):
    record = pack(">HI", kind, value) + name + b"\0"
    return record + b"\0" * (len(record) % 2)


def _x(text=TEXT, data=DATA, bss_size=8, relocations=None, symbols=None, entry=0x0E, link_base=0):
    if relocations is None:
        # 0010 and 002a in TEXT, a long pointer at data:0006, and a word at data:000a (odd delta).
        relocations = pack(">4H", 0x10, 0x1A, 0x0E, 0x05)
    if symbols is None:
        symbols = b"".join((
            _symbol(0x0201, 0x00, b"worker"), _symbol(0x0201, 0x0E, b"start"), _symbol(0x0201, 0x30, b"table"),
            _symbol(0x0202, 0x32, b"message"), _symbol(0x0203, 0x3E, b"result"), _symbol(0x0003, 0x42, b"shared"),
            _symbol(0x0200, 0x1234, b"absolute"),
        ))
    header = pack(">2sBBIIIIIII", b"HU", 0, 0, link_base, entry + link_base, len(text), len(data), bss_size,
                  len(relocations), len(symbols)).ljust(0x40, b"\0")
    return header + text + data + relocations + symbols


def test_x68k_export_and_search(tmp_path, capsys):
    source = tmp_path / "DEMO.X"
    source.write_bytes(_x())
    out = tmp_path / "out"
    assert main(["load", str(source), "--base-address", "12344", "-o", str(out), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    assert json.loads((out / "map.json").read_text()) == program
    assert program["format"] == "X68K"
    assert program["header"] == {
        "load_mode": "normal", "link_base": 0, "relocation_table_size": 8, "symbol_table_size": 96,
        "word_relocations": 1, "symbols": {"text": 3, "data": 1, "bss": 1, "common": 1, "other": 1},
    }
    assert program["entry"] == {"unit_address": "text:000e", "linear": 0x12352}
    text, data, bss = program["units"]
    assert [(unit["name"], unit["linear"], unit["size"], unit["file_offset"], unit["file_size"])
            for unit in (text, data, bss)] == [
        ("text", 0x12344, 0x32, 0x40, 0x32),
        ("data", 0x12376, 12, 0x72, 12),
        ("bss", 0x12382, 8, None, 0),
    ]
    assert text["symbols"] == [
        {"name": "worker", "offset": 0}, {"name": "start", "offset": 0x0E}, {"name": "table", "offset": 0x30},
    ]
    assert data["symbols"] == [{"name": "message", "offset": 0}]
    assert bss["symbols"] == [{"name": "result", "offset": 0}, {"name": "shared", "offset": 4}]
    assert text["relocations"] == [
        {"offset": 0x10, "original": 0, "value": 0x12344},
        {"offset": 0x2A, "original": 0x3E, "value": 0x12382},
    ]
    assert data["relocations"] == [
        {"offset": 6, "original": 0, "value": 0x12344},
        {"offset": 10, "original": 2, "value": 0x2346, "width": 2},
    ]
    image = (out / "image.bin").read_bytes()
    assert unpack_from(">I", image, 0x10) == (0x12344,)
    assert unpack_from(">IH", image, 0x38) == (0x12344, 0x2346)
    assert image[0x3E:] == bytes(8)
    regions = {region["name"]: region for region in program["memory_map"]}
    assert regions["main_ram"] == {"name": "main_ram", "linear": 0, "size": 0xC00000, "read": "ram", "write": "ram"}
    assert regions["opm"]["linear"] == 0xE90000 and regions["cgrom"]["write"] == "none"
    assert {"name": "OPM_DATA", "linear": 0xE90003} in program["hardware_labels"]
    assert program["line_f_calls"]["dos"]["FF3D"] == "_OPEN"
    assert program["line_f_calls"]["fpack"]["FEE0"] == "__CLMUL"
    assert program["line_f_calls"]["no_return"] == ["FF00", "FF31", "FF4C"]
    assert main(["info", str(source), "--base-address", "12344", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == program
    assert main(["info", str(source)]) == 0
    assert capsys.readouterr().out.startswith("X68000 Human68k  entry text:000e (01000e)  6 symbols")

    for pattern, offset in ((["--constant", "0x2346", "--width", "2"], 10), (["--string", "X68!"], 0)):
        assert main(["where-is", "--export", str(out), *pattern, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["matches"] == [{
            "address": f"{0x12376 + offset:08x}", "unit_address": f"data:{offset:04x}", "linear": 0x12376 + offset,
        }]


def test_x68k_shift_jis_search(tmp_path, capsys):
    message = "ドライブ".encode("cp932")
    source = tmp_path / "SJIS.X"
    source.write_bytes(_x(data=message, relocations=pack(">2H", 0x10, 0x1A), symbols=b""))
    out = tmp_path / "out"
    assert main(["load", str(source), "-o", str(out)]) == 0
    capsys.readouterr()
    assert main(["where-is", "--export", str(out), "--string", "ドライブ", "--json"]) == 0
    match, = json.loads(capsys.readouterr().out)["matches"]
    assert match["unit_address"] == "data:0000"


def test_x68k_link_base_and_long_relocation_delta():
    # A long delta escape (0x0001) reaches a site past 64 KiB; the link base shifts the entry and the fixup.
    text = bytes.fromhex("4e75").ljust(0x10010, b"\0")
    text = text[:0x1000C] + pack(">I", 0x100 + 2) + text[0x10010:]
    relocations = pack(">HI", 1, 0x1000C)
    image, program = build_x_image(_x(text=text, data=b"", bss_size=0, relocations=relocations, symbols=b"",
                                      entry=0, link_base=0x100), "demo", base=0x20000)
    assert program["entry"] == {"unit_address": "text:0000", "linear": 0x20000}
    relocation, = program["units"][0]["relocations"]
    assert relocation == {"offset": 0x1000C, "original": 0x102, "value": 0x20002}
    assert unpack_from(">I", image, 0x1000C) == (0x20002,)


def test_x68k_line_f_names():
    assert (line_f_name(0xFF00), line_f_name(0xFF3D), line_f_name(0xFF53), line_f_name(0xFF83)) == (
        "_EXIT", "_OPEN", "_GETENV", "_GETENV")
    assert (line_f_name(0xFEE0), line_f_name(0xFE00)) == ("__CLMUL", "__LMUL")
    assert line_f_name(0xFF14) is None and line_f_name(0x4E75) is None


@pytest.mark.parametrize(("source", "base", "message"), [
    (b"HU", 0, "truncated Human68k executable header"),
    (b"MZ".ljust(0x40, b"\0"), 0, "missing Human68k HU magic"),
    (_x()[:0x60], 0, "truncated Human68k TEXT"),
    (_x(entry=0x40), 0, "entry 0x40 is outside TEXT"),
    (_x(relocations=pack(">H", 0x3F)), 0, "relocation offset 0x3e"),
    (_x(relocations=pack(">H", 0x3E)), 0, "relocation offset 0x3e"),
    (_x(relocations=b"\0\1\0"), 0, "truncated Human68k relocation table"),
    (_x(symbols=pack(">HI", 0x0201, 0) + b"name"), 0, "unterminated Human68k symbol name"),
    (_x(), 1, "base address must be even"),
    (_x(bss_size=0x1000000), 0, "layout exceeds the 24-bit address space"),
])
def test_x68k_rejects_invalid_layout(source, base, message):
    with pytest.raises(XError, match=message):
        build_x_image(source, "demo", base)


def test_x68k_ghidra_import_patches_line_f_calls(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    source, out, project = (tmp_path / name for name in ("DEMO.X", "out", "project"))
    source.write_bytes(_x())
    assert main(["load", str(source), "-o", str(out)]) == 0
    capsys.readouterr()

    def query(*args):
        assert main([*args, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)

    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert (report["format"], report["units"], report["relocations"]) == ("X68K", 3, 4)
    line_f = report["line_f"]
    assert (line_f["call_sites"], line_f["arithmetic_rewrites"]) == (2, 1)
    assert line_f["calls"] == {"_EXIT": 1, "_PRINT": 1, "__CLMUL": 1}

    printing, = query("callers", "01000012")["callers"]
    assert printing["from"]["unit_address"] == "text:0016"
    assert printing["to_function"]["name"] == "_PRINT"
    assert printing["type"] == "CALL_OVERRIDE_UNCONDITIONAL"
    start = query("decomp", "text:000e")["decompilation"]
    assert "DOS::_PRINT(" in start and "DOS::_EXIT(" in start
    assert "result = 0x12;" in start
    assert "return 7;" in query("decomp", "text:0000")["decompilation"]
    assert query("func", "text:0008")["function"]["entry"]["unit_address"] == "text:0000"
    assert any(ref["to"]["unit_address"] == "bss:0000" for ref in query("xrefs", "text:0028")["outgoing"])
    assert any(ref["to"]["unit_address"] == "text:0000" for ref in query("xrefs", "data:0006")["outgoing"])
    gap, = query("gaps")["ranges"]
    assert (gap["start"], gap["size"]) == ("text:0030", 2)
