import json
import os
import subprocess
from pathlib import Path
from struct import pack_into

import pytest

from dos16re.cli import main
from dos16re.ghidra import _headless


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


def test_ghidra_types_phantasie_iii_far_globals(tmp_path, capsys):
    directory = os.environ.get("DOS16RE_PH3_DIR")
    if not directory:
        pytest.skip("set DOS16RE_PH3_DIR to run the real-game test")
    exe = next(path for path in Path(directory).iterdir() if path.name.upper() == "MAIN.EXE")
    project, _ = _import_program(tmp_path, capsys, exe)

    # The save-game code reads and writes a word through the relocated FAR segment.
    _check_references(
        project,
        "13b2:452a,ES,2820,1,2820:97f0,word,FAR2820_97f0",
        "13b2:467d,ES,2820,0,2820:97f0,word,FAR2820_97f0",
    )
