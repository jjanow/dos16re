"""The catalog, input selector, and exported source identity agree across loaders."""

import json
import os
from pathlib import Path
from struct import pack_into

import pytest

from retrore.cli import main
from test_apple2 import _dos_disk
from test_atari8 import _disk as _atr
from test_c64 import _disk as _d64, _prg
from test_macintosh import _hfs, _macbinary, _resource_fork
from test_msx2 import _disk as _fat12
from test_pc88 import _boot_disk


def _boot_atr():
    disk = _atr(5)
    pack_into("<BBHH", disk, 16, 0, 1, 0x2000, 0x2006)
    return disk


@pytest.mark.parametrize(("name", "data", "format_name", "selected", "options"), [
    ("c64.d64", lambda: _d64(_prg(0x2000, b"\x60" + bytes(256))), "d64", 0, ()),
    ("apple.dsk", lambda: _dos_disk(b"\x60"), "apple2", 0, ()),
    ("atari.atr", _boot_atr, "atr", 0, ()),
    ("msx.dsk", _fat12, "fat12", 0, ("--msx2",)),
    ("multi.d88", lambda: _boot_disk() * 2, "d88", 1, ("--pc88",)),
    ("pc98.hdm", lambda: bytes(77 * 2 * 8 * 1024), "hdm", 0, ("--pc98",)),
    ("mac.dc42", lambda: _hfs(_resource_fork(), dc42=True), "dc42", 0, ()),
    ("mac.macbin", lambda: _macbinary(_resource_fork()), "macbinary", 0, ()),
])
def test_catalog_selects_the_exported_member(tmp_path, capsys, name, data, format_name, selected, options):
    source = tmp_path / name
    source.write_bytes(data())
    assert main(["members", str(source), "--json"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert (catalog["format"], catalog["source"], catalog["count"]) == (format_name, name, len(catalog["members"]))
    member = catalog["members"][selected]
    assert member["selectable"]
    assert len({item["selector"] for item in catalog["members"]}) == catalog["count"]
    if format_name == "d88":
        assert member["container_offset"] == len(_boot_disk())
    if format_name == "macbinary":
        assert member["container_offset"] == 384
        assert [item["details"]["resource_id"] for item in catalog["members"][1:]] == [0, 1, 2]
        assert all(not item["selectable"] for item in catalog["members"][1:])
    out = tmp_path / "out"
    assert main(["load", str(source), *options, "--member", member["selector"], "-o", str(out), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report == json.loads((out / "map.json").read_text())
    assert report["container_layout"]["format"] == format_name
    assert report["container_layout"]["members"] == [member]
    assert report["container_layout"]["decisions"]["selection"] == "explicit"
    assert any(unit.get("member_id") == member["id"] for unit in report["units"])
    if format_name == "d88":
        unit = report["units"][0]
        assert main(["address-map", f"{unit['file_offset']:x}", "--from", "file", "--offset-kind", "container",
                     "--member", member["selector"], "--export", str(out), "--json"]) == 0
        match, = json.loads(capsys.readouterr().out)["matches"]
        assert match["container"]["member_id"] == member["id"]
        assert match["linear"] == unit["linear"]


def test_duplicate_names_require_a_member_id(tmp_path, capsys):
    source = tmp_path / "dup.dsk"
    media = _fat12()
    media[1056:1067] = b"DEMO    COM"
    source.write_bytes(media)
    assert main(["members", str(source), "--json"]) == 0
    members = json.loads(capsys.readouterr().out)["members"]
    assert [member["name"] for member in members] == ["DEMO.COM", "DEMO.COM"]
    assert main(["info", str(source), "--msx2", "--member", "DEMO.COM", "--json"]) == 1
    error = json.loads(capsys.readouterr().err)["error"]
    assert "ambiguous" in error["message"] and all(member["selector"] in error["message"] for member in members)

    first, second = (member["selector"] for member in members)
    out = tmp_path / "out"
    assert main(["load", str(source), "--msx2", "--member", first, "--member", f"{second}@130",
                 "-o", str(out), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["container_layout"]["members"] == members
    assert [unit["member_id"] for unit in report["units"]] == ["file:1", "file:2", "file:1"]
    assert (out / "image.bin").read_bytes()[0x30:0x35] == bytes.fromhex("3e 07 d3 99 c9")
    for selector, expected in ((first, 0x100), (second, 0x130)):
        assert main(["address-map", "0", "--from", "file", "--member", selector, "--export", str(out), "--json"]) == 0
        match, = json.loads(capsys.readouterr().out)["matches"]
        assert match["linear"] == expected
        assert f"id:{match['file']['member_id']}" == selector


def test_ambiguous_dsk_format_requires_an_override(tmp_path, capsys):
    source = tmp_path / "ambiguous.dsk"
    disk = _dos_disk(b"\x60")
    fat = _fat12()
    disk[:len(fat)] = fat
    source.write_bytes(disk)
    assert main(["members", str(source), "--json"]) == 1
    assert "ambiguous .dsk container" in json.loads(capsys.readouterr().err)["error"]["message"]
    for format_name in ("apple2", "fat12"):
        assert main(["members", str(source), "--format", format_name, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["format"] == format_name


def test_original_msx2_catalog(tmp_path, capsys):
    media = os.environ.get("RETRORE_PH3_MSX2_DIR")
    if not media:
        pytest.skip("set RETRORE_PH3_MSX2_DIR to validate the Phantasie III catalog")
    disks = list(Path(media).glob("*Scenario Disk*.dsk"))
    assert len(disks) == 1, "expected one Phantasie III Scenario Disk .dsk image"
    assert main(["members", str(disks[0]), "--format", "fat12", "--json"]) == 0
    members = json.loads(capsys.readouterr().out)["members"]
    main_program, = (member for member in members if member["name"] == "PM3.COM")
    assert main(["load", str(disks[0]), "--msx2", "--member", main_program["selector"],
                 "-o", str(tmp_path / "out"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["container_layout"]["members"] == [main_program]
