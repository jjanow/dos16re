import json
import os
from pathlib import Path
from struct import pack_into

import pytest

from retrore.cli import main
from retrore.ghidra import query_batch
from retrore.msx2 import Msx2Error, MsxDosDisk


def _disk():
    image = bytearray(512 * 9)
    pack_into("<HBHBHHBH", image, 11, 512, 1, 1, 1, 16, 9, 0xF9, 1)
    image[512:521] = bytes.fromhex("f9 ff ff 05 f0 ff 00 f0 ff")  # 2 -> 5, 3 and 5 end
    for i, name, cluster, size in ((0, b"DEMO    COM", 2, 0x220), (1, b"HELPER  OVR", 3, 5)):
        offset = 1024 + 32 * i
        image[offset:offset + 11] = name
        pack_into("<HI", image, offset + 26, cluster, size)
    image[1536:1543] = bytes.fromhex("cd 30 01 cd 05 00 c9")
    image[2048:2053] = bytes.fromhex("3e 07 d3 99 c9")
    image[3072:3077] = b"HELLO"
    return image


def test_disk_chain_and_runtime_view(tmp_path, capsys):
    disk = tmp_path / "sample.dsk"
    data = _disk()
    filesystem = MsxDosDisk(data)
    assert filesystem.read_file("demo.com")[512:517] == b"HELLO"
    broken = bytearray(data)
    broken[515] = 2  # A self-loop at the first cluster.
    with pytest.raises(Msx2Error, match="cluster chain"):
        MsxDosDisk(broken).read_file("DEMO.COM")
    disk.write_bytes(data)

    export = tmp_path / "image"
    status = main(["load", str(disk), "--msx2", "--disk-file", "DEMO.COM", "--disk-file", "helper.ovr@130",
                   "--msx2-copy", "300:20@c000", "-o", str(export), "--json"])
    assert status == 0, capsys.readouterr().err
    program = json.loads(capsys.readouterr().out)
    assert program["entry"] == {"linear": 0x100, "unit_address": "root_0100:0000"}
    assert [(unit["name"], unit["linear"], unit["file_offset"]) for unit in program["units"]] == [
        ("root_0100", 0x100, 0), ("HELPER.OVR", 0x130, 0), ("root_0135", 0x135, 0x35), ("copy_c000", 0xC000, 0x200),
    ]
    assert (export / "image.bin").read_bytes()[0x30:0x35] == filesystem.read_file("HELPER.OVR")
    assert main(["where-is", "--export", str(export), "--string", "HELLO", "--json"]) == 0
    assert [row["address"] for row in json.loads(capsys.readouterr().out)["matches"]] == ["0300", "c000"]


def test_standalone_msx_com_and_raw(tmp_path, capsys):
    com = tmp_path / "demo.com"
    com.write_bytes(b"\xc9")
    assert main(["info", str(com), "--msx2", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["entry"]["linear"] == 0x100
    raw = com.with_suffix(".bin")
    raw.write_bytes(com.read_bytes())
    assert main(["info", str(raw), "--msx2", "--base-address", "ffff", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["entry"] is None
    assert main(["info", str(raw), "--msx2", "--base-address", "10000", "--json"]) == 1
    assert "16-bit address space" in json.loads(capsys.readouterr().err)["error"]


def test_ghidra_msx2_cross_unit_call(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    disk = tmp_path / "sample.dsk"
    disk.write_bytes(_disk())
    export, project = tmp_path / "image", tmp_path / "msx2"
    assert main(["load", str(disk), "--msx2", "--disk-file", "DEMO.COM", "--disk-file", "HELPER.OVR@130",
                 "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["format"] == "MSX2"
    requests = [{"command": "decomp", "address": "HELPER.OVR:0000"},
                {"command": "xrefs", "address": "0130", "direction": "incoming", "ref_types": ["unconditional_call"],
                 "compact": True, "limit": 1}]
    overlay, refs = query_batch(project, requests)["results"]
    assert overlay["result"]["unit_address"] == "HELPER.OVR:0000"
    assert overlay["result"]["decompilation"]
    call, = refs["result"]["incoming"]
    assert (call["from"], call["to"]) == ("root_0100:0000", "HELPER.OVR:0000")
    assert refs["result"]["pagination"]["incoming"] == {"offset": 0, "total": 1, "returned": 1, "next_offset": None}


@pytest.mark.parametrize(("member", "entry"), [("INIT1.OVR", "0103"), ("INIT2.OVR", "01a5")])
def test_phantasie_iii_msx2_resident_and_overlay(tmp_path, capsys, member, entry):
    media = os.environ.get("RETRORE_PH3_MSX2_DIR")
    if not media or not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set RETRORE_PH3_MSX2_DIR and GHIDRA_HOME to validate the Phantasie III release")
    disks = list(Path(media).glob("*Scenario Disk*.dsk"))
    assert len(disks) == 1, "expected one Phantasie III Scenario Disk .dsk image"
    export, project = tmp_path / "image", tmp_path / "msx2"
    assert main(["load", str(disks[0]), "--msx2", "--disk-file", "PM3.COM", "--disk-file", f"{member}@100",
                 "--msx2-copy", "100:5f13@7000", "--entry", "0100", "--entry", "cdc3", "--entry", "b646",
                 "-o", str(export)]) == 0, capsys.readouterr().err
    assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    requests = [{"command": "decomp", "address": entry},
                {"command": "xrefs", "address": "b684", "direction": "outgoing", "compact": True}]
    function, refs = query_batch(project, requests)["results"]
    assert function["result"]["unit_address"] == f"{member}:{int(entry, 16) - 0x100:04x}"
    assert function["result"]["decompilation"]
    cross_unit, = refs["result"]["outgoing"]
    assert cross_unit["from"] == "copy_7000:4684"
    assert cross_unit["to"] == f"{member}:0000"
