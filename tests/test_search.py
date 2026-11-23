import json
import os
from pathlib import Path
from struct import pack_into

import pytest

from retrore.cli import main
from retrore.mcp import call_tool


def test_searches_each_exported_unit_without_crossing_its_boundary(tmp_path, capsys):
    root = bytes.fromhex("c3 41 41 41 34 12 82") + bytes(8) + b"\xde"
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(root), 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
    exe = tmp_path / "sample.exe"
    exe.write_bytes(header + root)
    near = tmp_path / "Near.ovr"
    near.write_bytes(bytes.fromhex("ad 41 41 34 12 82") + bytes(12))
    extra = tmp_path / "Extra.ovr"
    extra.write_bytes(bytes.fromhex("de ad ff ff"))
    export = tmp_path / "image"
    assert main([
        "load", str(exe), "-o", str(export), "--overlay", f"{extra}@2000", "--overlay", f"{near}@1001",
    ]) == 0
    capsys.readouterr()

    search = ["where-is", "--export", str(export)]
    for options, pattern, locations in (
        (["--bytes", "41 41"], "4141", ["root:0001", "root:0002", "Near:0001"]),
        (["--string", "é"], "82", ["root:0006", "Near:0005"]),
        (["--constant", "0x1234"], "3412", ["root:0004", "Near:0003"]),
        (["--constant", "-1", "--width", "1"], "ff", ["Extra:0002", "Extra:0003"]),
        (["--bytes", "00 de"], "00de", ["root:000e"]),
        (["--bytes", "12 12"], "1212", []),
    ):
        assert main([*search, *options, "--json"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["pattern"] == pattern
        assert report["count"] == len(locations)
        assert [match["unit_address"] for match in report["matches"]] == locations

    assert main([*search, "--bytes", "dead", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["matches"] == [
        {"address": "2000:0000", "unit_address": "Extra:0000", "linear": 0x20000},
    ]
    assert main([*search, "--bytes", "00"]) == 0
    output = capsys.readouterr().out.splitlines()
    assert output[0] == "20 matches"
    assert len(output) == 12
    assert output[-1] == "Use --json for all matches."

    assert main([*search, "--bytes", "", "--json"]) == 1
    assert "at least one byte" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_reports_matches_past_the_first_64_kib_of_the_root_unit(tmp_path, capsys):
    root = b"\xc3" + bytes(0xFFFF) + b"\x34\x12"
    header = bytearray(32)
    size = len(header) + len(root)
    pack_into("<2s13H", header, 0, b"MZ", size % 512, (size + 511) // 512, 0, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
    exe = tmp_path / "large.exe"
    exe.write_bytes(header + root)
    export = tmp_path / "image"
    assert main(["load", str(exe), "-o", str(export)]) == 0
    capsys.readouterr()

    assert main(["where-is", "--export", str(export), "--bytes", "3412", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["matches"] == [
        {"address": "2000:0000", "unit_address": "root:10000", "linear": 0x20000},
    ]


def _export(tmp_path, image_format, units, image, **extra):
    """Write a minimal export: image.bin and a map.json with the given units."""
    export = tmp_path / image_format.lower()
    export.mkdir()
    (export / "image.bin").write_bytes(image)
    flat = image_format not in ("MZ", "PC98")
    rows = []
    for name, linear, image_offset, size, *rest in units:
        row = {"name": name, "linear": linear, "image_offset": image_offset, "size": size}
        if flat:
            row["file_size"] = size
        else:
            row["segment"] = linear >> 4
        if rest:
            row.update(rest[0])
        rows.append(row)
    (export / "map.json").write_text(json.dumps({"version": 1, "format": image_format, "units": rows, **extra}))
    return export


def _run(capsys, *argv):
    assert main([*argv, "--json"]) == 0, capsys.readouterr().err
    return json.loads(capsys.readouterr().out)


def test_platform_string_encodings(tmp_path, capsys):
    # C64: unshifted PETSCII, shifted PETSCII with a capital at $C1, and both screen-code sets.
    c64 = bytes.fromhex("00 48 49 54 00 c8 49 54 00 08 09 14 00 48 09 14 00")
    export = _export(tmp_path, "C64_PRG", [("root", 0x1000, 0, len(c64))], c64)
    report = _run(capsys, "where-is", "--export", str(export), "--string", "Hit")
    assert report["encodings"] == ["petscii", "petscii-shifted", "c64-screen", "c64-screen-shifted"]
    assert [(row["unit_address"], row["encoding"]) for row in report["matches"]] == [
        ("root:0001", "petscii"), ("root:0005", "petscii-shifted"), ("root:0009", "c64-screen"),
        ("root:000d", "c64-screen-shifted"),
    ]
    only = _run(capsys, "where-is", "--export", str(export), "--string", "Hit", "--encoding", "c64-screen")
    assert [row["unit_address"] for row in only["matches"]] == ["root:0009"]
    assert only["pattern"] == "080914" and "encoding" not in only["matches"][0]

    # Apple II: bit 7 set; plain ASCII is the fallback. Ignoring case matches either.
    apple = b"\x00" + bytes(c | 0x80 for c in b"HELLO") + b"\x00hello"
    export = _export(tmp_path, "APPLE2", [("root", 0x800, 0, len(apple))], apple)
    report = _run(capsys, "where-is", "--export", str(export), "--string", "HELLO")
    assert [(row["unit_address"], row["encoding"]) for row in report["matches"]] == [("root:0001", "apple2")]
    report = _run(capsys, "where-is", "--export", str(export), "--string", "hello", "--ignore-case")
    assert [(row["unit_address"], row["encoding"]) for row in report["matches"]] == [
        ("root:0001", "apple2"), ("root:0007", "ascii")]

    # Atari 8-bit: ATASCII and internal screen codes (space is $00, A is $21).
    atari = b"GO WEST\x00" + bytes.fromhex("27 2f 00 37 25 33 34")
    export = _export(tmp_path, "ATARI8", [("root", 0x2000, 0, len(atari))], atari)
    report = _run(capsys, "where-is", "--export", str(export), "--string", "GO WEST")
    assert [(row["address"], row["encoding"]) for row in report["matches"]] == [
        ("2000", "atascii"), ("2008", "atari-screen")]

    # Japanese text on the X68000 is Shift-JIS; a character outside an encoding skips it.
    text = "勇者".encode("cp932")
    export = _export(tmp_path, "X68K", [("text", 0x10000, 0, len(text) + 2)], b"\0" + text + b"\0")
    report = _run(capsys, "where-is", "--export", str(export), "--string", "勇者")
    assert report["pattern"] == text.hex() and report["matches"][0]["unit_address"] == "text:0001"
    assert main(["where-is", "--export", str(export), "--string", "勇", "--encoding", "petscii", "--json"]) == 1
    assert "cannot be encoded" in json.loads(capsys.readouterr().err)["error"]["message"]
    assert main(["where-is", "--export", str(export), "--bytes", "00", "--encoding", "ascii", "--json"]) == 1
    capsys.readouterr()


def test_pointer_search_marks_relocated_far_pointers(tmp_path, capsys):
    # Root at 1000:0000. A relocated far pointer to 1000:0020 at root:0004, an unrelocated alias
    # 1001:0010 at root:0008, and a near pointer word 0020 at root:000c. The overlay holds another far pointer.
    root = bytearray(0x30)
    pack_into("<HH", root, 4, 0x0020, 0x1000)
    pack_into("<HH", root, 8, 0x0010, 0x1001)
    pack_into("<H", root, 12, 0x0020)
    overlay = bytearray(0x10)
    pack_into("<HH", overlay, 2, 0x0020, 0x1000)
    export = _export(tmp_path, "MZ", [("root", 0x10000, 0, 0x30), ("OV1", 0x10030, 0x30, 0x10)],
                     bytes(root) + bytes(overlay), relocations=[6, 0x34])
    report = _run(capsys, "where-is", "--export", str(export), "--pointer", "root:0020")
    assert report["target"] == {"address": "1000:0020", "unit_address": "root:0020", "linear": 0x10020}
    assert report["counts"] == {"far": 3, "near": 3} and report["relocated"] == 2
    far = [(row["unit_address"], row["value"], row["relocated"]) for row in report["matches"] if row["kind"] == "far"]
    assert far == [("root:0004", "1000:0020", True), ("root:0008", "1001:0010", False), ("OV1:0002", "1000:0020", True)]
    near = [(row["unit_address"], row["relocated"]) for row in report["matches"] if row["kind"] == "near"]
    assert near == [("root:0004", None), ("root:000c", None), ("OV1:0002", None)]
    only_far = _run(capsys, "where-is", "--export", str(export), "--pointer", "1001:0010", "--pointer-kind", "far")
    assert only_far["count"] == 3 and only_far["kinds"] == ["far"]
    assert main(["where-is", "--export", str(export), "--pointer", "10020", "--pointer-kind", "absolute",
                 "--json"]) == 1
    assert "far, near" in json.loads(capsys.readouterr().err)["error"]["message"]
    assert main(["where-is", "--export", str(export), "--pointer", "root:0020"]) == 0
    assert capsys.readouterr().out.splitlines()[:2] == [
        "6 pointers to 1000:0020 (3 far, 3 near; 2 relocated)", "root:0004  1000:0004  far 1000:0020  relocated"]

    relocs = _run(capsys, "relocs", "--export", str(export))
    assert [(row["unit_address"], row["value"], row["segment_unit"]) for row in relocs["relocations"]] == [
        ("root:0006", "1000", "root"), ("OV1:0004", "1000", "root")]
    assert _run(capsys, "relocs", "--export", str(export), "--unit", "ov1")["count"] == 1
    assert _run(capsys, "relocs", "--export", str(export), "--at", "root:0000", "--size", "16")["count"] == 1
    assert _run(capsys, "relocs", "--export", str(export), "--target", "OV1:0000")["count"] == 0
    page = _run(capsys, "relocs", "--export", str(export), "--limit", "1", "--offset", "1")
    assert page["pagination"] == {"offset": 1, "total": 2, "returned": 1, "next_offset": None}


def test_pointer_and_relocation_search_on_flat_images(tmp_path, capsys):
    # 68k: longs at text:0002 (relocated), text:0007 (odd, ignored), and data:0000 (not relocated).
    text = bytearray(16)
    pack_into(">I", text, 2, 0x10014)
    pack_into(">I", text, 7, 0x10014)
    data = (0x10014).to_bytes(4, "big") + bytes(4)
    units = [("text", 0x10000, 0, 16, {"relocations": [{"offset": 2, "original": 0x14, "value": 0x10014}]}),
             ("data", 0x10010, 16, 8, {"relocations": []})]
    export = _export(tmp_path, "X68K", units, bytes(text) + data)
    report = _run(capsys, "where-is", "--export", str(export), "--pointer", "data:0004")
    assert [(row["unit_address"], row["relocated"]) for row in report["matches"]] == [
        ("text:0002", True), ("data:0000", False)]
    relocs = _run(capsys, "relocs", "--export", str(export), "--target", "10014")
    assert [(row["unit_address"], row["target"]["unit_address"]) for row in relocs["relocations"]] == [
        ("text:0002", "data:0004")]
    assert _run(capsys, "relocs", "--export", str(export), "--target", "10000", "--size", "4")["count"] == 0

    # 6502: little-endian words anywhere, and no relocations to back them.
    code = bytes.fromhex("ad 34 12 8d 35 12 60 34 12")
    export = _export(tmp_path, "C64_PRG", [("root", 0x1200, 0, len(code))], code)
    report = _run(capsys, "where-is", "--export", str(export), "--pointer", "1234")
    assert [(row["address"], row["relocated"]) for row in report["matches"]] == [("1201", None), ("1207", None)]
    assert report["has_relocations"] is False
    assert _run(capsys, "relocs", "--export", str(export))["has_relocations"] is False


def test_68k_short_pointers_are_aligned_sign_extended_and_width_checked(tmp_path, capsys):
    code = b"\x12\x34\x80\x12\x80\x12\x12\x34\x00\x00\x12\x34\xff\xee\xff\xff"
    fixups = [{"offset": 0, "original": 0x1234, "value": 0x1234, "width": 2},
              {"offset": 6, "original": 0x12340000, "value": 0x12340000}]
    export = _export(tmp_path, "X68K", [("text", 0x10000, 0, len(code), {"relocations": fixups})], code)
    common = ("where-is", "--export", str(export), "--pointer-kind", "absolute-short", "--pointer")
    report = _run(capsys, *common, "1234")
    assert [(row["unit_address"], row["relocated"], row["value"]) for row in report["matches"]] == [
        ("text:0000", True, "1234"), ("text:0006", False, "1234"), ("text:000a", False, "1234")]
    assert _run(capsys, *common, "8012")["count"] == 0
    assert [row["unit_address"] for row in _run(capsys, *common, "ff8012")["matches"]] == [
        "text:0002", "text:0004"]
    assert _run(capsys, *common, "ffffff")["count"] == 1


def test_6502_split_pointer_search_reports_both_bytes_and_load_evidence(tmp_path, capsys):
    code = bytes.fromhex("bd 20 20 85 02 bd 23 20 85 03 b9 23 20 8d 03 00 b9 20 20 85 02")
    image = code.ljust(0x20, b"\x00") + bytes.fromhex("44 34 50 11 12 13")
    export = _export(tmp_path, "APPLE2", [("root", 0x2000, 0, len(image))], image)
    arguments = ("where-is", "--export", str(export), "--pointer", "1234")
    assert _run(capsys, *arguments)["count"] == 0
    report = _run(capsys, *arguments, "--pointer-kind", "split")
    match, = report["matches"]
    assert report["counts"] == {"split": 1}
    assert (match["address"], match["high"]["address"], match["value"], match["relocated"]) == (
        "2021", "2024", "1234", None)
    assert [(item["instruction"]["address"], item["index_register"], item["index"]) for item in match["evidence"]] == [
        ("2000", "x", 1), ("200a", "y", 1)]
    assert match["evidence"][0]["low_table"]["address"] == "2020"
    assert match["evidence"][0]["high_table"]["address"] == "2023"


def test_symbol_lookup_from_the_map(tmp_path, capsys):
    units = [("text", 0x10000, 0, 16, {"symbols": [{"name": "_main", "offset": 0}, {"name": "_Save", "offset": 8}]})]
    export = _export(tmp_path, "X68K", units, bytes(16), entry={"unit_address": "text:0004", "linear": 0x10004},
                     memory_map=[{"name": "main_ram", "linear": 0, "size": 0xC00000}],
                     hardware_labels=[{"name": "CRTC_R00", "linear": 0xE80000}])
    report = _run(capsys, "lookup", "--export", str(export), "--address", "text:000a")
    assert report["nearest"]["name"] == "_Save" and report["nearest"]["distance"] == 2
    assert report["containing"] == ["text", "main_ram"] and report["next"]["name"] == "CRTC_R00"
    assert _run(capsys, "lookup", "--export", str(export), "--address", "e80000")["nearest"]["name"] == "CRTC_R00"
    assert _run(capsys, "lookup", "--export", str(export), "--name", "_s*")["symbols"] == []
    found = _run(capsys, "lookup", "--export", str(export), "--name", "_s*", "--ignore-case")["symbols"]
    assert [(row["name"], row["unit_address"]) for row in found] == [("_Save", "text:0008")]
    assert _run(capsys, "lookup", "--export", str(export), "--name", "entry")["symbols"][0]["linear"] == 0x10004
    assert main(["lookup", "--export", str(export), "--address", "nowhere:1"]) == 1
    assert "unknown unit" in capsys.readouterr().err

    # DOS overlay entries and stubs use the names the Ghidra importer gives them.
    units = [("root", 0x10000, 0, 0x20), ("tpov_0016", 0x10020, 0x20, 0x20, {"entries": [4]})]
    export = _export(tmp_path, "MZ", units, bytes(0x40), entry={"segment": 0x1000, "offset": 0, "linear": 0x10000},
                     stubs=[{"address": {"segment": 0x1001, "offset": 0, "linear": 0x10010},
                             "target": {"segment": 0x1002, "offset": 4, "linear": 0x10024}, "unit": "tpov_0016"}])
    rows = _run(capsys, "lookup", "--export", str(export), "--name", "*")["symbols"]
    assert {row["name"]: row["unit_address"] for row in rows} == {
        "root": "root:0000", "tpov_0016": "tpov_0016:0000", "tpov_0016_0004": "tpov_0016:0004",
        "entry": "root:0000", "stub_tpov_0016_0000": "root:0010"}
    assert main(["lookup", "--export", str(export), "--address", "1002:0006"]) == 0
    assert capsys.readouterr().out.splitlines()[0] == "tpov_0016:0006  tpov_0016_0004+0x2  (overlay_entry)"


def test_mcp_search_tools(tmp_path):
    code = bytes.fromhex("ad 34 12 60") + b"HI"
    export = _export(tmp_path, "C64_PRG", [("root", 0x1230, 0, len(code))], code)

    def call(tool, **arguments):
        result = call_tool(tool, {"export": str(export), **arguments})
        return result["isError"], result["structuredContent"]

    failed, report = call("where_is", pointer="1234")
    assert not failed and report["matches"][0]["address"] == "1231"
    failed, report = call("where_is", string="hi", ignore_case=True)
    assert not failed and report["matches"][0]["encoding"] == "petscii"
    assert call("where_is", pointer="1234", bytes="00")[1]["error"]["message"].startswith("specify exactly one")
    assert call("where_is", bytes="00", encoding="ascii")[0]
    failed, report = call("lookup", address="1233")
    assert not failed and report["nearest"] is None and report["containing"] == ["root"]
    assert not call("relocations")[1]["has_relocations"]
    assert call("lookup", name=3)[1]["error"]["message"] == "name must be a nonempty string"


def _game_file(variable, name):
    directory = os.environ.get(variable)
    if not directory:
        pytest.skip(f"set {variable} to run the real-game test")
    return next(path for path in Path(directory).iterdir() if path.name.upper() == name)


def test_phantasie_text_in_8_bit_encodings(tmp_path, capsys):
    disk = _game_file("RETRORE_PH1_ATARI8_DIR", "PHANTASIE1-SIDE-A.ATR")
    atari = tmp_path / "atari"
    assert main(["load", str(disk), "--disk-file", "DNG.COM", "-o", str(atari)]) == 0
    capsys.readouterr()
    # The copy-protection quiz in DNG.COM is stored in Atari screen codes, not ATASCII.
    for text, address in (("WHAT IS THE ITEM NUMBER OF", "9f5c"), ("DISPELL UNDEAD", "aa42")):
        match, = _run(capsys, "where-is", "--export", str(atari), "--string", text)["matches"]
        assert (match["address"], match["encoding"]) == (address, "atari-screen")


def test_phantasie_c64_text_and_pointers(tmp_path, capsys):
    disk = _game_file("RETRORE_PH1_C64_DIR", "PHANTASIE_I_1986_SSI_SIDE_A.D64")
    c64 = tmp_path / "c64"
    assert main(["load", str(disk), "--disk-file", "RTL-64", "--base-address", "a000", "--c64-bank", "6",
                 "--disk-file", "TOWNR", "--entry", "a090", "-o", str(c64)]) == 0
    capsys.readouterr()
    match, = _run(capsys, "where-is", "--export", str(c64), "--string", "Minotaur")["matches"]
    assert (match["unit_address"], match["encoding"]) == ("TOWNR:0187", "petscii")
    assert _run(capsys, "lookup", "--export", str(c64), "--address", "a095")["nearest"]["name"] == "entry"


def test_phantasie_iii_apple2_high_bit_text(tmp_path, capsys):
    disk = _game_file("RETRORE_PH3_APPLE2_DIR", "PHANTASIE_III_1987_SSI_CR_DISK_1_OF_3_SIDE_A.DSK")
    export = tmp_path / "apple2"
    assert main(["load", str(disk), "--disk-file", "SSI.INIT3", "-o", str(export)]) == 0
    capsys.readouterr()
    report = _run(capsys, "where-is", "--export", str(export), "--string", "INSERT ANOTHER DISK")
    match, = report["matches"]
    assert (match["address"], match["encoding"]) == ("0a8c", "apple2")


def test_phantasie_iv_x68k_pointers_relocations_and_symbols(tmp_path, capsys):
    program = _game_file("RETRORE_PH4_X68K_DIR", "P4.X")
    assert main(["load", str(program), "-o", str(tmp_path / "p4")]) == 0
    capsys.readouterr()
    export = str(tmp_path / "p4")
    # The character records at 88fbe (190 bytes each) are addressed by relocated longs in _load, _save,
    # and _mkdetail.
    report = _run(capsys, "where-is", "--export", export, "--pointer", "88fbe")
    assert [(row["unit_address"], row["relocated"]) for row in report["matches"]] == [
        ("text:13f6", True), ("text:1760", True), ("text:12b80", True), ("text:12c16", True)]
    relocs = _run(capsys, "relocs", "--export", export, "--target", "88fbe", "--size", str(6 * 190))
    assert relocs["count"] == 50 and relocs["relocations"][0]["unit_address"] == "text:13f6"
    owner = _run(capsys, "lookup", "--export", export, "--address", "text:1760")["nearest"]
    assert (owner["name"], owner["distance"]) == ("_save", 0x4C)
    assert _run(capsys, "lookup", "--export", export, "--name", "_save")["symbols"][0]["unit_address"] == "text:1714"


def test_pool_of_radiance_stub_lookup(tmp_path, capsys):
    root = _game_file("RETRORE_POR_DIR", "START.EXE")
    bank = _game_file("RETRORE_POR_DIR", "GAME.OVR")
    assert main(["load", str(root), "--overlay", str(bank), "-o", str(tmp_path / "por")]) == 0
    capsys.readouterr()
    # The documented overlay stub 0085:0039 sits at 1085:0039 once the root loads at 1000.
    stub = _run(capsys, "lookup", "--export", str(tmp_path / "por"), "--address", "1085:0039")["nearest"]
    assert (stub["name"], stub["distance"], stub["unit_address"]) == ("stub_tpov_0085_0039", 0, "root:0889")
