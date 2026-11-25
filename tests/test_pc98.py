import json
import os
from pathlib import Path
from struct import pack, pack_into

import pytest

from retrore.cli import main
from retrore.ghidra import query_batch


def _sample_disk():
    disk = bytearray(0x2B0)
    pack_into("<I", disk, 0x20, len(disk))
    # A far jump to the next stage, whose first instruction sets DS to blue VRAM.
    stage = bytes.fromhex("b8 00 a8 8e d8 c6 06 12 00 42 cb")
    boot = bytes.fromhex("ea 00 00 00 02")
    for record, code in ((2, stage.ljust(0x40, b"\0") + b"\xcb"), (1, boot)):
        disk += pack("<BBBBH8xH", 0, 0, record, 1, 2, 256) + code.ljust(256, b"\0")
    pack_into("<I", disk, 0x1C, len(disk))
    return bytes(disk)


def _fat12_raw(sector_size=1024, total_sectors=1232):
    disk = bytearray(sector_size * total_sectors)
    pack_into("<HBHBHHBHHH", disk, 11, sector_size, 2, 1, 2, sector_size // 32, total_sectors, 0xFE, 1, 8, 2)
    for copy in (1, 2):
        start = copy * sector_size
        disk[start:start + 9] = bytes.fromhex("fe ff ff 05 f0 ff 00 f0 ff")  # 2 -> 5, 3 and 5 end
    for index, (name, cluster, size) in enumerate((
        (b"DEMO    COM", 2, 2 * sector_size + 11),
        ("補助".encode("cp932").ljust(8, b" ") + b"BIN", 3, 1),
    )):
        offset = 3 * sector_size + 32 * index
        disk[offset:offset + 11] = name
        pack_into("<HI", disk, offset + 26, cluster, size)
    disk[4 * sector_size:4 * sector_size + 4] = bytes.fromhex("b8 01 00 c3")
    disk[6 * sector_size] = 0xCB
    disk[10 * sector_size:10 * sector_size + 11] = b"lastcluster"
    return bytes(disk)


def _fat12_d88(data, sector_size):
    disk = bytearray(0x2B0)
    disk[0x1B] = 0x20
    sector_count = len(data) // sector_size
    offsets = {}
    for track, start in enumerate(range(0, sector_count, 8)):
        pack_into("<I", disk, 0x20 + 4 * track, len(disk))
        cylinder, head = divmod(track, 2)
        count = min(8, sector_count - start)
        for record in reversed(range(1, count + 1)):
            logical = start + record - 1
            disk += pack("<BBBBH8xH", cylinder, head, record, {512: 2, 1024: 3}[sector_size], count, sector_size)
            offsets[logical] = len(disk)
            offset = logical * sector_size
            disk += data[offset:offset + sector_size]
    pack_into("<I", disk, 0x1C, len(disk))
    return bytes(disk), offsets


@pytest.mark.parametrize("sector_size", [512, 1024])
def test_pc98_d88_fat12_members_use_original_sector_offsets(tmp_path, capsys, sector_size):
    disk = tmp_path / "sample.d77"
    prefix = _sample_disk()
    physical, offsets = _fat12_d88(_fat12_raw(sector_size, total_sectors=32), sector_size)
    disk.write_bytes(prefix + physical)
    assert main(["members", str(disk), "--json"]) == 0
    assert [row["id"] for row in json.loads(capsys.readouterr().out)["members"]] == ["disk:1", "disk:2"]
    assert main(["members", str(disk), "--format", "fat12", "--pc98-disk", "2", "--json"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert catalog["details"]["index"] == 2
    assert [(row["selector"], row["name"], row["container_offset"]) for row in catalog["members"]] == [
        ("id:file:1", "DEMO.COM", len(prefix) + offsets[3]),
        ("id:file:2", "補助.BIN", len(prefix) + offsets[3] + 32),
    ]

    export = tmp_path / "export"
    assert main(["load", str(disk), "--pc98", "--pc98-disk", "2", "--member", "id:file:1@1000",
                 "--member", "補助.bin@2000", "--pc98-sector", "0:0:1@1fc0", "-o", str(export), "--json"]) == 0
    layout = json.loads(capsys.readouterr().out)
    assert layout["container_layout"]["members"] == catalog["members"]
    assert layout["disk"]["filesystem"] == "FAT12"
    root, helper, boot = layout["units"]
    assert root["size"] == 2 * sector_size + 11
    assert root["container_spans"] == [
        {"offset": 0, "file_offset": len(prefix) + offsets[4], "size": sector_size},
        {"offset": sector_size, "file_offset": len(prefix) + offsets[5], "size": sector_size},
        {"offset": 2 * sector_size, "file_offset": len(prefix) + offsets[10], "size": 11},
    ]
    assert (root["member_id"], helper["member_id"], boot["member_id"]) == ("file:1", "file:2", "disk:2")
    assert (export / "image.bin").read_bytes()[2 * sector_size:2 * sector_size + 11] == b"lastcluster"
    source_offset = len(prefix) + offsets[10] + 4
    assert main(["address-map", f"{source_offset:x}", "--from", "file", "--offset-kind", "container",
                 "--member", "id:file:1", "--export", str(export), "--json"]) == 0
    match, = json.loads(capsys.readouterr().out)["matches"]
    assert match["linear"] == 0x10000 + 2 * sector_size + 4
    assert match["file"]["offset"] == 2 * sector_size + 4
    assert match["container"]["offset"] == source_offset
    assert disk.read_bytes()[source_offset:source_offset + 1] == b"c"

    broken = bytearray(physical)
    broken[offsets[4] - 16 + 2] = 6  # Duplicate a record ID on the first track.
    disk.write_bytes(prefix + broken)
    assert main(["members", str(disk), "--format", "fat12", "--pc98-disk", "2", "--json"]) == 1
    assert "geometry does not match D88 track 0:0" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_pc98_hdm_fat12_members_and_load_errors(tmp_path, capsys):
    disk = tmp_path / "sample.hdm"
    disk.write_bytes(_fat12_raw())
    assert main(["members", str(disk), "--format", "fat12", "--json"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert catalog["details"]["sector_size"] == 1024
    assert [row["container_offset"] for row in catalog["members"]] == [3072, 3104]
    options = ["info", str(disk), "--pc98", "--json"]
    assert main([*options, "--member", "demo.com", "--base-segment", "3000"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["entry"]["linear"] == 0x30000
    assert report["units"][0]["container_spans"] == [
        {"offset": 0, "file_offset": 4096, "size": 2048},
        {"offset": 2048, "file_offset": 10240, "size": 11},
    ]
    for flags, message in (
        (["--member", "demo.com"], "with @SEG"),
        (["--member", "demo.com@zz"], "invalid PC-98 member load segment"),
        (["--member", "demo.com@1000", "--base-segment", "3000"], "specify the root member segment once"),
        (["--member", "unknown.com@1000"], "not found"),
    ):
        assert main([*options, *flags]) == 1
        assert message in json.loads(capsys.readouterr().err)["error"]["message"]
    broken = bytearray(disk.read_bytes())
    broken[1027] = 2  # First cluster links to itself.
    disk.write_bytes(broken)
    assert main([*options, "--member", "demo.com@1000"]) == 1
    assert "invalid FAT12 cluster chain" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_ghidra_pc98_fat12_program(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    disk = tmp_path / "sample.hdm"
    disk.write_bytes(_fat12_raw())
    export, project = tmp_path / "export", tmp_path / "pc98fat12"
    assert main(["load", str(disk), "--pc98", "--member", "DEMO.COM@1000", "-o", str(export)]) == 0
    assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    function, = query_batch(project, [{"command": "decomp", "address": "1000:0000"}])["results"]
    assert function["result"]["unit_address"] == "root:0000"
    assert function["result"]["decompilation"]


def test_pc98_d88_preserves_root_and_sector_origins(tmp_path, capsys):
    disk = tmp_path / "sample.d88"
    media = _sample_disk()
    disk.write_bytes(media * 2)
    assert main(["info", str(disk), "--pc98", "--pc98-disk", "2", "--json"]) == 0
    boot = json.loads(capsys.readouterr().out)
    assert boot["entry"] == {"segment": 0x1FC0, "offset": 0, "linear": 0x1FC00}
    assert boot["disk"]["index"] == 2
    assert boot["units"][0]["file_offset"] == len(media) + 0x3D0

    export = tmp_path / "export"
    assert main(["load", str(disk), "--pc98", "--pc98-sector", "0:0:1@1fc0",
                 "--pc98-sector", "0:0:2@0200", "-o", str(export)]) == 0
    capsys.readouterr()
    layout = json.loads((export / "map.json").read_text())
    assert layout["image_origin"] == 0x2000
    assert [unit["image_offset"] for unit in layout["units"]] == [0x1DC00, 0]
    assert main(["where-is", "--export", str(export), "--bytes", "b8 00 a8", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["matches"] == [
        {"address": "0200:0000", "unit_address": "sector_0_0_2_0200:0000", "linear": 0x2000}
    ]


def test_pc98_hdm_sector_span_crosses_heads(tmp_path, capsys):
    disk = tmp_path / "sample.hdm"
    disk.write_bytes(bytes(77 * 2 * 8 * 1024))
    assert main(["info", str(disk), "--pc98", "--pc98-sector", "0:0:8+2@1000", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["disk"]["sector_size"] == 1024
    assert report["units"][0]["size"] == 2048
    assert report["units"][0]["file_spans"] == [
        {"offset": 0, "file_offset": 7 * 1024, "size": 1024},
        {"offset": 1024, "file_offset": 8 * 1024, "size": 1024},
    ]
    assert main(["info", str(disk), "--pc98", "--pc98-sector", "76:1:8+2@1000", "--json"]) == 1
    assert "beyond the disk" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_pc98_raw_units_entries_and_bounds(tmp_path, capsys):
    root, secondary = tmp_path / "program.bin", tmp_path / "secondary.bin"
    root.write_bytes(b"\xc3" * 16 + "日本".encode("cp932"))
    secondary.write_bytes(b"\xcb")
    export = tmp_path / "export"
    options = ["--pc98", "--base-segment", "1000"]
    assert main(["load", str(root), *options, "--pc98-unit", f"{secondary}@3000",
                 "--pc98-entry", "1001:0000", "--pc98-entry", "3000:0000", "-o", str(export), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [entry["linear"] for entry in report["entries"]] == [0x10010, 0x30000]
    assert main(["where-is", "--export", str(export), "--string", "日本", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["matches"][0]["unit_address"] == "root:0010"
    trace = tmp_path / "LOGCPU.TXT"
    trace.write_text("1000:0010\n", encoding="ascii")
    assert main(["trace", str(trace), "--export", str(export), "--json"]) == 1
    assert "require a DOS MZ image" in json.loads(capsys.readouterr().err)["error"]["message"]
    for flags, expected in (
        (["--pc98-unit", f"{secondary}@1001"], "overlap"),
        (["--pc98-unit", f"{secondary}@a000"], "conventional RAM"),
        (["--pc98-entry", "3000:0000"], "outside the loaded image"),
    ):
        assert main(["info", str(root), *options, *flags, "--json"]) == 1
        assert expected in json.loads(capsys.readouterr().err)["error"]["message"]


def test_ghidra_pc98_far_jump_and_vram(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    disk = tmp_path / "sample.d77"
    disk.write_bytes(_sample_disk())
    export, project = tmp_path / "image", tmp_path / "pc98"
    assert main(["load", str(disk), "--pc98", "--pc98-sector", "0:0:1@1fc0",
                 "--pc98-sector", "0:0:2@0200", "--pc98-entry", "1fc0:0000",
                 "--pc98-entry", "0200:0040", "-o", str(export)]) == 0, capsys.readouterr().err
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    imported = json.loads(capsys.readouterr().out)
    assert (imported["format"], imported["units"]) == ("PC98", 2)
    function, jump, video, extra = query_batch(project, [
        {"command": "decomp", "address": "0200:0000"},
        {"command": "xrefs", "address": "root:0000", "compact": True, "direction": "outgoing"},
        {"command": "xrefs", "address": "blue_vram:0012", "compact": True, "direction": "incoming"},
        {"command": "decomp", "address": "0200:0040", "fields": ["unit_address"]},
    ])["results"]
    assert function["result"]["unit_address"] == "sector_0_0_2_0200:0000"
    assert jump["result"]["outgoing"][0]["to"] == "sector_0_0_2_0200:0000"
    assert video["result"]["incoming"][0]["from"] == "sector_0_0_2_0200:0005"
    assert extra["result"]["unit_address"] == "sector_0_0_2_0200:0040"


@pytest.mark.parametrize(
    ("disk_name", "jump", "next_segment", "next_offset"),
    [("Program", "3f00:0069", "0412", "0006"), ("Utility", "3f00:0048", "03ca", "000f")],
)
def test_phantasie_iii_pc98_boot_and_payload(tmp_path, capsys, disk_name, jump, next_segment, next_offset):
    media = os.environ.get("RETRORE_PH3_PC98_DIR")
    if not media or not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set RETRORE_PH3_PC98_DIR and GHIDRA_HOME to validate the Phantasie III release")
    disk, = Path(media).glob(f"*{disk_name} disk*.d88")
    export, project = tmp_path / "image", tmp_path / "pc98"
    # The BIOS disk call uses only the first 16 sectors of each payload track.
    # The first three tracks include the entry and both release-specific startup destinations.
    assert main(["load", str(disk), "--pc98", "--pc98-sector", "0:0:1@1fc0", "--pc98-sector", "0:1:1+2@3f00",
                 "--pc98-sector", "1:0:1+16@0200", "--pc98-sector", "1:1:1+16@0300",
                 "--pc98-sector", "2:0:1+16@0400", "--pc98-entry", "1fc0:0000",
                 "--pc98-entry", "3f00:0000", "--pc98-entry", "0200:035f", "-o", str(export)]) == 0, capsys.readouterr().err
    assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    boot, loader, transfer, startup, next_transfer = query_batch(project, [
        {"command": "decomp", "address": "1fc0:0000"},
        {"command": "decomp", "address": "3f00:0000"},
        {"command": "xrefs", "address": jump, "compact": True, "direction": "outgoing"},
        {"command": "decomp", "address": "0200:035f"},
        {"command": "xrefs", "address": "0200:036d", "direction": "outgoing"},
    ])["results"]
    assert boot["result"]["unit_address"] == "root:0000"
    assert loader["result"]["unit_address"] == "sector_0_1_1_3f00:0000"
    assert transfer["result"]["outgoing"][0]["to"] == "sector_1_0_1_0200:035f"
    assert startup["result"]["decompilation"]
    destination = next_transfer["result"]["outgoing"][0]["to"]
    assert destination["linear"] == int(next_segment, 16) * 16 + int(next_offset, 16)
