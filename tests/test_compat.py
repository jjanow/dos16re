"""Exports written before map versioning (no "version" field) stay readable.

The MZ fixture also predates runtime signatures, so it has no "compiler" or "runtime_signatures".
"""

import json
import os
import shutil
from pathlib import Path

import pytest

from retrore.cli import main
from retrore.emulator import Emulator
from retrore.image import MAP_VERSION, ImageError, check_map_version, read_map, read_units

FIXTURES = Path(__file__).parent / "fixtures" / "maps"
FAMILIES = {"mz": "MZ", "hunk": "HUNK", "c64": "C64_PRG", "msx2": "MSX2", "pc98": "PC98"}


@pytest.mark.parametrize(("family", "image_format"), FAMILIES.items())
def test_unversioned_fixture_reads_as_version_1(family, image_format, capsys):
    export = FIXTURES / family
    program = read_map(export)
    assert "version" not in program
    assert check_map_version(program) == 1
    assert program.get("format", "MZ") == image_format
    units = read_units(export, (export / "image.bin").stat().st_size)
    assert units and units[0].image_offset == 0

    image = (export / "image.bin").read_bytes()
    assert main(["where-is", "--export", str(export), "--bytes", image[:2].hex(), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["matches"]


def test_unversioned_mz_fixture_runs_in_the_emulator():
    result = Emulator.from_export(FIXTURES / "mz").call("root:0013")
    assert result.registers["ax"] == 0x1007


def _versioned_copy(tmp_path, version):
    export = tmp_path / "export"
    shutil.copytree(FIXTURES / "mz", export)
    program = json.loads((export / "map.json").read_text(encoding="utf-8"))
    (export / "map.json").write_text(json.dumps({"version": version, **program}), encoding="utf-8")
    return export


def test_current_and_future_map_versions(tmp_path, capsys):
    assert read_map(_versioned_copy(tmp_path / "current", MAP_VERSION))["version"] == MAP_VERSION

    export = _versioned_copy(tmp_path / "future", MAP_VERSION + 1)
    with pytest.raises(ImageError) as caught:
        read_map(export)
    assert caught.value.code == "unsupported_map_version"
    for command in (["where-is", "--export", str(export), "--bytes", "c3"], ["call", "root:0013", "--export", str(export)]):
        assert main([*command, "--json"]) == 1
        report = json.loads(capsys.readouterr().err)
        assert report["contract"] == 1
        assert report["error"]["code"] == "unsupported_map_version"
        assert "newer" in report["error"]["message"] and report["error"]["hint"]

    for version in (0, "1", None):
        with pytest.raises(ImageError) as caught:
            read_map(_versioned_copy(tmp_path / f"bad{version}", version))
        assert caught.value.code == "export_invalid"


def test_missing_map_is_export_invalid(tmp_path, capsys):
    (tmp_path / "image.bin").write_bytes(b"\xc3")
    assert main(["where-is", "--export", str(tmp_path), "--bytes", "c3", "--json"]) == 1
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "export_invalid"


def test_ghidra_imports_unversioned_mz_fixture(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    export = tmp_path / "export"
    shutil.copytree(FIXTURES / "mz", export)
    project = tmp_path / "project"
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["units"] == 1
    assert main(["func", "root:0013", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["contract"] == 1
    assert report["function"]["entry"]["unit_address"] == "root:0013"
