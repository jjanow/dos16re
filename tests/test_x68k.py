import json
import os
import re
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


DOS_TEXT = bytes.fromhex(
    "3f3c0001"      # 0000 move.w #1,-(sp)             mode
    "487900000030"  # 0004 pea name
    "ff3d"          # 000a DOS _OPEN
    "5c8f"          # 000c addq.l #6,sp
    "2f3c00000010"  # 000e move.l #16,-(sp)            length
    "48790000003a"  # 0014 pea buffer
    "3f00"          # 001a move.w d0,-(sp)             handle
    "ff40"          # 001c DOS _WRITE
    "4fef000a"      # 001e lea 10(sp),sp
    "23c00000004a"  # 0022 move.l d0,result
    "7210"          # 0028 moveq #16,d1
    "7010"          # 002a moveq #$10,d0
    "4e4f"          # 002c IOCS _CRTMOD
    "ff00"          # 002e DOS _EXIT
)


def _dos_x(symbols=b""):
    return _x(text=DOS_TEXT, data=b"SAVE.DAT".ljust(10, b"\0") + bytes(16), bss_size=4,
              relocations=pack(">3H", 0x06, 0x10, 0x0E), symbols=symbols, entry=0)


def test_x68k_dos_prototypes_in_map():
    _, program = build_x_image(_dos_x(), "demo")
    prototypes = program["line_f_calls"]["dos_prototypes"]
    assert prototypes["FF3D"] == {"parameters": [
        {"name": "name", "type": "char*", "size": 4}, {"name": "mode", "type": "short", "size": 2},
    ], "result": "int", "variadic": False}
    assert [parameter["size"] for parameter in prototypes["FF40"]["parameters"]] == [2, 4, 4]
    assert [parameter["size"] for parameter in prototypes["FF42"]["parameters"]] == [2, 4, 2]
    assert prototypes["FF83"] == prototypes["FF53"]
    assert prototypes["FF44"]["variadic"]
    iocs = program["line_f_calls"]["iocs_prototypes"]
    assert iocs["10"] == {
        "parameters": [{"name": "mode", "type": "short", "register": "D1w"}],
        "result": "int",
    }
    assert iocs["21"]["parameters"] == [{"name": "text", "type": "char*", "register": "A1"}]
    assert [parameter["register"] for parameter in iocs["45"]["parameters"]] == ["D1", "D2", "D3", "A1"]
    assert [parameter["register"] for parameter in iocs["77"]["parameters"]] == ["D1u", "D1w", "D2u", "D2w"]
    subcalls = program["line_f_calls"]["iocs_subcalls"]
    assert subcalls["F000"]["parameters"] == []
    assert [parameter["register"] for parameter in subcalls["F003"]["parameters"]] == ["D2", "A1"]


def test_x68k_ghidra_dos_call_arguments(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    source, out, project = (tmp_path / name for name in ("DOS.X", "out", "project"))
    source.write_bytes(_dos_x(_symbol(0x0201, 0, b"start") + _symbol(0x0202, 0x3a, b"buffer")))
    assert main(["load", str(source), "-o", str(out)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["line_f"]["iocs_calls"] == 1
    assert main(["decomp", "text:0000", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    decompiled = json.loads(capsys.readouterr().out)["decompilation"]
    assert "DOS::_OPEN(" in decompiled and ",1);" in decompiled
    assert "DOS::_WRITE(" in decompiled and "&buffer,0x10);" in decompiled
    assert re.search(r"IOCS::_CRTMOD\((?:0x10|16)\);", decompiled)
    assert main(["callers", "01000420", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    calling, = json.loads(capsys.readouterr().out)["callers"]
    assert calling["from"]["unit_address"] == "text:002c"


def test_x68k_ghidra_iocs_subcalls_require_an_unambiguous_selector(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    code = bytes.fromhex(
        " 742a 227c 0001 0200 7203 70f0 4e4f"  # OPMDRV subcall 3 with D2 and A1.
        " 4a80 6702 720c 70f0 4e4f 4e75"      # A branch can bypass the next subcall selector.
    )
    source, export, project = (tmp_path / name for name in ("OPM.X", "out", "project"))
    source.write_bytes(_x(code, b"", relocations=b"", symbols=b"", entry=0))
    assert main(["load", str(source), "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["line_f"]["iocs_calls"] == 2
    assert main(["decomp", "text:0", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    code = json.loads(capsys.readouterr().out)["decompilation"]
    assert re.search(r"IOCS::_OPMDRV_03\((?:0x2a|42),", code)
    assert "IOCS::_OPMDRV(" in code
    assert "IOCS::_OPMDRV_0C(" not in code


def test_x68k_recovers_arguments_of_rejoined_xc_routine(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    code = bytes.fromhex(
        "2f3c0000002a"  # 0000 move.l #42,-(sp)
        "4eb900000010"  # 0006 jsr worker
        "588f4e75"      # 000c addq.l #4,sp; rts
        "6008"          # 0010 worker: bra.b 001a
        "202e0008"      # 0012 move.l 8(a6),d0
        "4e5e4e75"      # 0016 unlk a6; rts
        "4e56000060f2"  # 001a link.w a6,#0; bra.b 0012
    )
    source, out, project = (tmp_path / name for name in ("ARGS.X", "out", "project"))
    source.write_bytes(_x(text=code, data=b"", bss_size=0, entry=0, relocations=pack(">H", 8),
                          symbols=_symbol(0x0201, 0x10, b"worker")))
    assert main(["load", str(source), "-o", str(out)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["line_f"]["recovered_stack_parameters"] == 1
    assert main(["decomp", "text:0000", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    assert re.search(r"worker\((?:0x2a|42)\)", json.loads(capsys.readouterr().out)["decompilation"])


FPACK_TEXT = bytes.fromhex(
    # modulo(a, b)
    "202f0004"          # 0000 move.l 4(sp),d0
    "222f0008"          # 0004 move.l 8(sp),d1
    "48e7c000"          # 0008 movem.l d0/d1,-(sp)
    "fee2"              # 000c FPACK __CLMOD
    "4cdf0003"          # 000e movem.l (sp)+,d0/d1
    "4e75"              # 0012 rts
    # halve(double sum): XC pushes the right operand first.
    "4cf900030000005a"  # 0014 movem.l two,d0/d1
    "48e7c000"          # 001c movem.l d0/d1,-(sp)
    "4cef0003000c"      # 0020 movem.l 12(sp),d0/d1
    "48e7c000"          # 0026 movem.l d0/d1,-(sp)
    "fef0"              # 002a FPACK __CDDIV
    "4cdf0003"          # 002c movem.l (sp)+,d0/d1
    "4fef0008"          # 0030 lea 8(sp),sp
    "4e75"              # 0034 rts
    # greater(double a, double b)
    "4cef0003000c"      # 0036 movem.l 12(sp),d0/d1   b
    "48e7c000"          # 003c movem.l d0/d1,-(sp)
    "4cef0003000c"      # 0040 movem.l 12(sp),d0/d1   a
    "48e7c000"          # 0046 movem.l d0/d1,-(sp)
    "feec"              # 004a FPACK __CDCMP
    "4fef0010"          # 004c lea 16(sp),sp
    "6e04"              # 0050 bgt.b 0056
    "7000"              # 0052 moveq #0,d0
    "4e75"              # 0054 rts
    "7001"              # 0056 moveq #1,d0
    "4e75"              # 0058 rts
)


def test_x68k_ghidra_stacked_fpack_results(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    source, out, project = (tmp_path / name for name in ("FPACK.X", "out", "project"))
    symbols = b"".join(_symbol(0x0201, offset, name) for offset, name in (
        (0, b"modulo"), (0x14, b"halve"), (0x36, b"greater")))
    source.write_bytes(_x(text=FPACK_TEXT, data=bytes.fromhex("4000000000000000"), bss_size=0,
                          relocations=pack(">H", 0x18), symbols=symbols, entry=0))
    assert main(["load", str(source), "-o", str(out)]) == 0
    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    capsys.readouterr()

    def decompile(address):
        assert main(["decomp", address, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)["decompilation"]

    modulo, halve, greater = (decompile(address) for address in ("text:0000", "text:0014", "text:0036"))
    assert "replaced with injection: retrore_fpack_fee2" in modulo and "param_1 % param_2" in modulo
    assert "return local_10 / (double)CONCAT44(DAT_0001005a,DAT_0001005e);" in halve  # sum / 2.0
    assert "if ((double)CONCAT44(param_1,param_2) <= (double)CONCAT44(param_3,param_4)) {" in greater


def test_ghidra_phantasie_iv_dos_and_fpack_calls(tmp_path, capsys):
    directory = os.environ.get("RETRORE_PH4_X68K_DIR")
    if not directory or not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set RETRORE_PH4_X68K_DIR and GHIDRA_HOME to run the real-game test")
    out, project = tmp_path / "out", tmp_path / "project"
    assert main(["load", os.path.join(directory, "P4.X"), "-o", str(out)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["line_f"]["iocs_calls"] == 38

    def decompile(address):
        assert main(["decomp", address, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)["decompilation"]

    # _save writes each file through _xwrite, which calls XC's _open, _write, and _close.
    assert "_xwrite(1,s_goods_0_0004f670,&_item,0x13a);" in decompile("text:1714")
    assert "_open(acStack_1c,0x4402,1);" in decompile("text:31924")
    assert "DOS::_OPEN(unaff_A2,0);" in decompile("text:3c086")  # XC's open helper, path in A2
    writing = decompile("text:3c2dc")
    assert "DOS::_WRITE(handle,buffer,length);" in writing and "DOS::_WRITE(handle,&DAT_0004c3de,2);" in writing
    assert "DOS::_SEEK(handle,0,1);" in decompile("text:3bd3c")
    # Stacked FPACK doubles: _avg_attr is (anc1 + anc2) / 2.0, _frand is rand(100) / 100.0.
    assert "return (dVar2 + dVar1) / local_24;" in decompile("text:ba90")
    random = decompile("text:30996")
    assert re.search(r"_rand\((?:0x64|100)\)", random)
    assert "return (double)iVar1 / 100.0;" in random
    crt_mode = decompile("text:3b676")
    assert "void _CRTMOD(short param_1)" in crt_mode and "IOCS::_CRTMOD(param_1);" in crt_mode
    assert "IOCS::_OPMDRV_03(" in decompile("text:3b57c")
