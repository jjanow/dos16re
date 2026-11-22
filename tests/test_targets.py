import json
import os
from pathlib import Path
from struct import unpack_from

import pytest

from dos16re.cli import main


def _game_files(variable):
    directory = os.environ.get(variable)
    if not directory:
        pytest.skip(f"set {variable} to run the real-game test")
    return {path.name.upper(): path for path in Path(directory).iterdir() if path.is_file()}


@pytest.fixture
def por_export(tmp_path, capsys):
    files = _game_files("DOS16RE_POR_DIR")
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
    files = _game_files("DOS16RE_PH1_DIR")
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
    assert json.loads(capsys.readouterr().out)["units"] == len(program["units"])
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
