import json
import os
from pathlib import Path
from struct import unpack_from

import pytest

from retrore.cli import main


def _game_files(variable):
    directory = os.environ.get(variable)
    if not directory:
        pytest.skip(f"set {variable} to run the real-game test")
    return {path.name.upper(): path for path in Path(directory).iterdir() if path.is_file()}


@pytest.fixture
def por_export(tmp_path, capsys):
    files = _game_files("RETRORE_POR_DIR")
    root = files.get("START.EXE") or files["GAME.EXE"]
    bank = files["GAME.OVR"]
    assert main(["load", str(root), "--overlay", str(bank), "-o", str(tmp_path), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    assert json.loads((tmp_path / "map.json").read_text()) == program
    return tmp_path, program


def test_pool_of_radiance_overlay_directory_and_view_call(por_export):
    output, program = por_export
    units = program["units"]
    assert program["packer"] == "EXEPACK"
    assert program["compiler"]["family"] == "Turbo Pascal"
    assert program["compiler"]["version"] == "6.0"
    assert len(units) == len({unit["segment"] for unit in units}) == 36
    assert len(program["stubs"]) == 406

    origin = units[0]["linear"]
    image = (output / "image.bin").read_bytes()
    for stub in program["stubs"]:
        position = stub["address"]["linear"] - origin
        target = stub["target"]
        assert unpack_from("<BHH", image, position) == (
            0xEA, target["offset"], target["segment"],
        )

    view = next(
        stub for stub in program["stubs"]
        if (stub["address"]["segment"], stub["address"]["offset"]) == (0x1085, 0x39)
    )
    assert view["file_offset"] == 0x21AED
    caller = next(unit for unit in units[1:] if unit["name"] == "tpov_0025")
    loot_call = caller["linear"] + (0x65B4 - caller["file_offset"])
    call = next(item for item in program["calls"] if item["linear"] == loot_call)
    assert call["target"] == view["target"]
    assert unpack_from("<BHH", image, loot_call - origin) == (
        0x9A, view["target"]["offset"], view["target"]["segment"],
    )


@pytest.fixture
def phantasie_export(tmp_path, capsys):
    files = _game_files("RETRORE_PH1_DIR")
    main_program, ov1, ov2 = (files[name] for name in ("PHANTASI.EXE", "OV1.OVR", "OV2.OVR"))
    assert main([
        "load", str(main_program), "--overlay", str(ov1), "--overlay", str(ov2),
        "-o", str(tmp_path), "--json",
    ]) == 0
    program = json.loads(capsys.readouterr().out)
    return tmp_path, program, (ov1, ov2)


def test_phantasie_i_raw_overlays(phantasie_export):
    output, program, sources = phantasie_export
    image = (output / "image.bin").read_bytes()
    assert program["packer"] == "LZEXE 0.90"
    assert len({unit["segment"] for unit in program["units"]}) == 3
    for name, unit, source in zip(("OV1", "OV2"), program["units"][1:], sources, strict=True):
        assert unit["name"] == name
        offset = unit["image_offset"]
        assert image[offset:offset + unit["size"]] == source.read_bytes()

    mystic = next(table for table in program["jump_tables"]
                  if table["unit"] == "OV1" and table["address"]["offset"] == 0x20A5)
    assert mystic["table"]["offset"] == 0x208F
    assert len(mystic["targets"]) == 7
    assert mystic["targets"][2]["offset"] == 0x1F5A


def test_calls_phantasie_i_revive_routine(phantasie_export, capsys):
    output, _, _ = phantasie_export
    assert main([
        "call", "OV1:016b", "--export", str(output), "--regs", "ds=3000,ss=4000,sp=1000",
        "--mem", "4000:1000=0020", "--mem", "3000:2014=7d0001000000", "--read", "3000:2016=4", "--json",
    ]) == 0, capsys.readouterr().err
    result = json.loads(capsys.readouterr().out)
    # The near routine updates current HP and status in a caller-provided character record.
    assert result["memory"][0]["data"] == "7d000100"
    assert result["registers"]["sp"] == 0x1000


def test_ghidra_recovers_mystic_score(phantasie_export, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    output, program, _ = phantasie_export
    project = output / "phantasie"
    assert main(["ghidra", "import", str(output), str(project), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["units"] == len(program["units"])
    assert main(["decomp", "OV1:20bb", "--project", str(project), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["unit_address"] == "OV1:20bb"
    assert "0x5bf6" in result["decompilation"]


def test_ghidra_decompiles_cross_overlay_call(por_export, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    output, program = por_export
    project = output / "pool"
    assert main(["ghidra", "import", str(output), str(project), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["units"] == len(program["units"])
    assert report["runtime_signatures"] > 0
    assert main(["decomp", "tpov_0025:1036", "--project", str(project), "--json"]) == 0
    by_unit = json.loads(capsys.readouterr().out)
    assert "tpov_0085_0ab3(" in by_unit["decompilation"]
    assert by_unit["unit_address"].startswith("tpov_0025:")

    caller = next(unit for unit in program["units"] if unit["name"] == "tpov_0025")
    address = f"{caller['segment']:04x}:1036"
    assert main(["decomp", address, "--project", str(project) + ".gpr", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == by_unit

    assert main(["decomp", "tpov_001f:0c74", "--project", str(project), "--json"]) == 0
    loadpieces = json.loads(capsys.readouterr().out)["decompilation"]
    assert "DGROUP_4433" in loadpieces
    assert "DGROUP_4434" in loadpieces
    assert "tpov_03d5_0e08(" in loadpieces


@pytest.fixture(params=[
    ("RETRORE_PH1_AMIGA_DIR", "GAME"),
    ("RETRORE_PH3_AMIGA_DIR", "PHANTASIEIII"),
], ids=["phantasie-i", "phantasie-iii"])
def amiga_export(request, tmp_path, capsys):
    variable, filename = request.param
    source = _game_files(variable)[filename]
    assert main(["load", str(source), "--base-address", "0", "-o", str(tmp_path), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    return tmp_path, program


def test_phantasie_amiga_hunk_layout(amiga_export):
    output, program = amiga_export
    units = program["units"]
    image = (output / "image.bin").read_bytes()
    assert program["entry"] == {"unit_address": "h0:0000", "linear": 0}
    assert len(units) == len({unit["linear"] for unit in units})

    if program["program"].upper() == "GAME":
        assert len(units) == 240
        assert units[69]["file_offset"] == 0x19428
        caller, target = units[20], units[77]
        fixup = next(item for item in caller["relocations"] if item["offset"] == 0x18E)
        assert fixup["target"] == "h77"
        assert unpack_from(">I", image, caller["image_offset"] + 0x18E) == (target["linear"] + 0x466,)
    else:
        assert [unit["kind"] for unit in units] == ["code", "data", "bss"]
        code, data, bss = units
        assert (data["linear"], bss["linear"]) == (0x21890, 0x283A0)
        assert image[data["linear"] + data["file_size"]:data["linear"] + data["size"]] == bytes(0x4390)
        assert image[bss["linear"]:bss["linear"] + bss["size"]] == bytes(4)
        assert unpack_from(">I", image, code["image_offset"] + 0x7372) == (0x240FC,)


def test_ghidra_analyzes_phantasie_amiga(amiga_export, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    output, program = amiga_export
    project = output / "amiga"
    assert main(["ghidra", "import", str(output), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["units"] == len(program["units"])
    assert report["relocations"] == sum(len(unit["relocations"]) for unit in program["units"])

    def query(command, address):
        assert main([command, address, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)

    if program["program"].upper() == "GAME":
        routine = "h77:0466"
        calls = query("callers", routine)["callers"]
        assert any(call["from"]["unit_address"] == "h20:018c" for call in calls)
    else:
        routine = "h0:736c"
        writes = query("xrefs", "h0:7370")["outgoing"]
        assert any(ref["to"]["unit_address"] == "h1:286c" and ref["type"] == "WRITE" for ref in writes)
    result = query("decomp", routine)
    assert result["unit_address"] == routine
    assert result["decompilation"].strip()


@pytest.fixture
def phantasie_ii_atari_export(tmp_path, capsys):
    files = _game_files("RETRORE_PH2_ST_DIR")
    assert main(["load", str(files["PHANT.PRG"]), "-o", str(tmp_path), "--json"]) == 0
    return tmp_path, json.loads(capsys.readouterr().out)


def test_phantasie_ii_atari_st_layout(phantasie_ii_atari_export):
    output, program = phantasie_ii_atari_export
    text, data, bss = program["units"]
    assert program["entry"] == {"unit_address": "text:0000", "linear": 0x10000}
    assert (text["size"], data["linear"], bss["linear"]) == (0x1E298, 0x2E298, 0x3468C)
    assert bss["size"] == 0x3CBC
    assert sum(len(unit["relocations"]) for unit in (text, data, bss)) == 6485
    image = (output / "image.bin").read_bytes()
    assert unpack_from(">I", image, 8) == (bss["linear"],)
    assert unpack_from(">I", image, data["image_offset"] + 0x2EC) == (data["linear"] + 0x718,)
    assert image[bss["image_offset"]:] == bytes(bss["size"])


def test_phantasie_ii_atari_st_utility_symbols(capsys):
    utility = _game_files("RETRORE_PH2_ST_DIR")["UTILIT2.PRG"]
    assert main(["info", str(utility), "--json"]) == 0
    text, data, bss = json.loads(capsys.readouterr().out)["units"]
    assert {"name": "_main", "offset": 0x116} in text["symbols"]
    assert {"name": "_ctrl_cn", "offset": 0} in data["symbols"]
    assert {"name": "__base", "offset": 0} in bss["symbols"]


def test_ghidra_analyzes_phantasie_ii_atari_st(phantasie_ii_atari_export, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    output, _ = phantasie_ii_atari_export
    project = output / "phantasie-ii"
    assert main(["ghidra", "import", str(output), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["relocations"] == 6485

    def query(command, address):
        assert main([command, address, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)

    call, = query("xrefs", "text:ec8e")["outgoing"]
    assert call["from_function"]["entry"]["unit_address"] == "text:ec36"
    assert call["to"]["unit_address"] == "text:b8f2"
    assert call["type"] == "UNCONDITIONAL_CALL"
    assert any(ref["to"]["unit_address"] == "data:0718" for ref in query("xrefs", "data:02ec")["outgoing"])
    result = query("decomp", "text:ec36")
    assert result["unit_address"] == "text:ec36"
    assert "FUN_0001b8f2()" in result["decompilation"]
