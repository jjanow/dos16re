import json
import os
from pathlib import Path
from struct import pack, pack_into

import pytest

from retrore.cli import main
from retrore.d88 import D88Disk, D88Error
from retrore.ghidra import query_batch


def _disk(tracks, *, header_size=0x2B0, media=0):
    data = bytearray(header_size)
    data[:4] = b"DEMO"
    data[0x1B] = media
    heads = 1 if media == 0x30 else 2
    for (cylinder, head), sectors in tracks.items():
        pack_into("<I", data, 0x20 + (cylinder * heads + head) * 4, len(data))
        for record, payload in sectors:
            data += pack("<BBBBH8xH", cylinder, head, record, len(payload).bit_length() - 8, len(sectors), len(payload))
            data += payload
    pack_into("<I", data, 0x1C, len(data))
    return data


def _boot_disk():
    boot = bytes.fromhex("cd 00 c1 c9").ljust(256, b"\0")
    helper = bytes.fromhex("3e 01 d3 5c c9").ljust(256, b"\0")
    return _disk({(0, 0): [(2, helper), (1, boot)], (0, 1): [(1, b"NEXT".ljust(128, b"\0"))]})


def test_d88_selection_uses_ids_and_member_offsets():
    data = _boot_disk()
    disk = D88Disk(data + data, 2)
    assert disk.metadata["image_count"] == 2
    assert disk.metadata["index"] == 2
    spans = disk.read_sectors(0, 0, 1, 3)
    assert [(sector.record, len(sector.data), sector.file_offset - len(data)) for sector in spans] == [
        (1, 256, 0x3D0), (2, 256, 0x2C0), (1, 128, 0x4E0),
    ]
    assert spans[-1].data[:4] == b"NEXT"
    with pytest.raises(D88Error, match="not found"):
        disk.read_sectors(0, 0, 3)
    with pytest.raises(D88Error, match="unformatted"):
        disk.read_sectors(0, 0, 1, 4)
    with pytest.raises(D88Error, match="disk size"):
        D88Disk(data[:-1])
    with pytest.raises(D88Error, match="ambiguous"):
        D88Disk(_disk({(0, 0): [(1, bytes(256)), (1, bytes(256))]})).read_sectors(0, 0, 1)
    pack_into("<H", data, 0x2BE, 0xFFFF)
    with pytest.raises(D88Error, match="sector length or count"):
        D88Disk(data).read_sectors(0, 0, 1)


def test_short_single_sided_disk_with_end_sentinels():
    data = _disk({(0, 0): [(1, bytes(256))], (1, 0): [(2, bytes(128))]}, header_size=0x2A0, media=0x30)
    data[0x1A] = 1
    data[0x28:0x30] = pack("<II", len(data), len(data))
    disk = D88Disk(data)
    assert disk.metadata["write_protected"]
    assert disk.metadata["track_count"] == 2
    assert [sector.record for sector in disk.read_sectors(0, 0, 1, 2)] == [1, 2]


def test_pc88_boot_banks_and_overlay_provenance(tmp_path, capsys):
    disk = tmp_path / "sample.d88"
    disk.write_bytes(_boot_disk())
    assert main(["info", str(disk), "--pc88", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["entry"] == {"linear": 0xC000, "unit_address": "root:0000"}
    assert report["memory_view"] == "n88-rom/ram"
    assert report["units"][0]["file_offset"] == 0x3D0

    overlay = tmp_path / "replacement.bin"
    overlay.write_bytes(b"CODE")
    export = tmp_path / "image"
    assert main(["load", str(disk), "--pc88", "--pc88-sector", "0:0:1+3@c000", "--pc88-copy", "c0fe:5@9000",
                 "--pc88-unit", f"{overlay}@c0fe", "--pc88-high", "blue", "--entry", "c000",
                 "--entry", "9000", "-o", str(export), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["memory_view"] == "ram/blue"
    assert report["memory_map"][-1]["read"] == "vram_blue"
    copy, first, replacement, remaining = report["units"]
    assert copy["file_spans"] == [
        {"offset": 0, "file_offset": 0x4CE, "size": 2}, {"offset": 2, "file_offset": 0x2C0, "size": 3},
    ]
    assert first["size"] == 0xFE and replacement["linear"] == 0xC0FE
    assert remaining["file_spans"] == [
        {"offset": 0, "file_offset": 0x2C2, "size": 254}, {"offset": 254, "file_offset": 0x4E0, "size": 128},
    ]
    binary = (export / "image.bin").read_bytes()
    assert binary[:5] == bytes.fromhex("00 00 3e 01 d3")
    assert binary[0x30FE:0x3102] == b"CODE"
    assert main(["where-is", "--export", str(export), "--string", "CODE", "--json"]) == 0
    match, = json.loads(capsys.readouterr().out)["matches"]
    assert match["unit_address"] == "replacement:0000"


@pytest.mark.parametrize(
    ("options", "error"),
    [([], "--base-address"), (["--base-address", "10000"], "16-bit address space"),
     (["--base-address", "100", "--pc88-low", "n-rom"], "hidden by"),
     (["--base-address", "100", "--pc88-copy", "100:2@200"], "single visible load")],
)
def test_pc88_raw_load_errors(tmp_path, capsys, options, error):
    raw = tmp_path / "demo.bin"
    raw.write_bytes(b"\xc9")
    assert main(["info", str(raw), "--pc88", *options, "--json"]) == 1
    assert error in json.loads(capsys.readouterr().err)["error"]["message"]


def test_ghidra_pc88_cross_unit_call_and_io(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    disk = tmp_path / "sample.d77"
    disk.write_bytes(_boot_disk())
    export, project = tmp_path / "image", tmp_path / "pc88"
    assert main(["load", str(disk), "--pc88", "--pc88-sector", "0:0:1@c000", "--pc88-sector", "0:0:2@c100",
                 "--pc88-low", "n88-rom", "--entry", "c000", "-o", str(export)]) == 0, capsys.readouterr().err
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    imported = json.loads(capsys.readouterr().out)
    assert (imported["format"], imported["memory_view"]) == ("PC88", "n88-rom/ram")
    function, call, port = query_batch(project, [
        {"command": "decomp", "address": "c100"},
        {"command": "xrefs", "address": "root:0000", "compact": True, "direction": "outgoing"},
        {"command": "xrefs", "address": "pc88_ports:005c", "compact": True, "direction": "incoming"},
    ])["results"]
    assert "SELECT_BLUE_VRAM" in function["result"]["decompilation"]
    assert call["result"]["outgoing"][0]["to"] == "sector_0_0_2_c100:0000"
    assert port["result"]["incoming"][0]["from"] == "sector_0_0_2_c100:0002"


@pytest.mark.parametrize(
    ("disk_name", "payload", "extra", "handoff", "entry"),
    [
        ("Program", "1:0:1+174@0100", ["--pc88-sector", "0:0:10+19@ea80"], "c52e", 0x0523),
        ("Utility", "6:0:1+159@0100", [], "c497", 0x0161),
    ],
)
def test_phantasie_iii_pc88_boot_and_payload(tmp_path, capsys, disk_name, payload, extra, handoff, entry):
    media = os.environ.get("RETRORE_PH3_PC88_DIR")
    if not media or not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set RETRORE_PH3_PC88_DIR and GHIDRA_HOME to validate the Phantasie III release")
    disk, = Path(media).glob(f"*{disk_name} Disk*.d88")
    export, project = tmp_path / "image", tmp_path / "pc88"
    # The common IPL reads seven sectors. Each second stage then loads its own program at $0100.
    assert main(["load", str(disk), "--pc88", "--pc88-sector", "0:0:1@c000", "--pc88-sector", "0:0:2+7@c080",
                 "--pc88-sector", payload, *extra, "--pc88-copy", "c600:100@0", "--pc88-copy", "c053:12@0", "--entry", "c000",
                 "-o", str(export)]) == 0, capsys.readouterr().err
    assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    function, primary, transfer, port = query_batch(project, [
        {"command": "decomp", "address": f"{entry:04x}"},
        {"command": "xrefs", "address": "c050", "compact": True, "direction": "outgoing"},
        {"command": "xrefs", "address": handoff, "compact": True, "direction": "outgoing"},
        {"command": "xrefs", "address": "c013", "compact": True, "direction": "outgoing"},
    ])["results"]
    unit = f"sector_{payload[0]}_0_1_0100"
    assert function["result"]["unit_address"] == f"{unit}:{entry - 0x100:04x}"
    assert function["result"]["decompilation"]
    assert primary["result"]["outgoing"][0]["to"] == "sector_0_0_2_c080:0080"
    assert transfer["result"]["outgoing"][0]["to"] == f"{unit}:0000"
    assert port["result"]["outgoing"][0]["to"] == "pc88_ports:0031"
