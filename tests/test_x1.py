import json
import os
from pathlib import Path
from struct import pack, pack_into

import pytest

from retrore.cli import main
from retrore.ghidra import query_batch
from retrore.x1 import IplHeader, X1Error, sector_address

_HEADER_SIZE = 0x2B0


def _disk(tracks):
    data = bytearray(_HEADER_SIZE)
    data[:4] = b"DEMO"
    for (cylinder, head), sectors in tracks.items():
        pack_into("<I", data, 0x20 + (cylinder * 2 + head) * 4, len(data))
        for record, payload in sectors:
            data += pack("<BBBBH8xH", cylinder, head, record, len(payload).bit_length() - 8, len(sectors), len(payload))
            data += payload
    pack_into("<I", data, 0x1C, len(data))
    return data


def _ipl_entry(size, load, start, lsn, attribute=1, extension=b"Sys"):
    entry = bytearray(b"\xe5" * 256)
    entry[:0x20] = bytes(0x20)
    entry[0] = attribute
    entry[1:0x0E] = b"DEMO BOOT".ljust(13)
    entry[0x0E:0x11] = extension
    pack_into("<HHH", entry, 0x12, size, load, start)
    entry[0x18:0x1E] = bytes.fromhex("86a108120000")
    pack_into("<H", entry, 0x1E, lsn)
    return bytes(entry)


# LD BC,1800 / LD A,0D / OUT (C),A / LD BC,1E00 / OUT (C),A / JP 0100
_BOOT = bytes.fromhex("01 00 18 3e 0d ed 79 01 00 1e ed 79 c3 00 01")
# LD BC,0FFC / LD A,80 / OUT (C),A / RET
_STAGE2 = bytes.fromhex("01 fc 0f 3e 80 ed 79 c9")


def _boot_disk(entry=None):
    boot = _BOOT.ljust(256, b"\0")
    return _disk({
        (0, 0): [(1, entry or _ipl_entry(0x180, 0xC000, 0xC000, 0x12))],
        # LSN 10–13 are track 1, which is cylinder 0, head 1.
        (0, 1): [(1, _STAGE2.ljust(256, b"\0")), (2, bytes(256)), (3, boot), (4, b"TAIL".ljust(256, b"\xff"))],
    })


def test_logical_sectors_alternate_heads():
    assert sector_address(0) == (0, 0, 1)
    assert sector_address(0x12) == (0, 1, 3)
    assert sector_address(0x80) == (4, 0, 1)
    assert sector_address(0x370) == (27, 1, 1)
    with pytest.raises(X1Error, match="logical sector"):
        sector_address(-1)


def test_ipl_header_fields():
    header = IplHeader.parse(_ipl_entry(0x0C00, 0xBF80, 0xC000, 0x370))
    assert (header.name, header.extension, header.size, header.load_address, header.exec_address) == (
        "DEMO BOOT", "Sys", 0x0C00, 0xBF80, 0xC000,
    )
    assert header.sector_count == 12
    assert header.metadata()["start_chr"] == "27:1:1"
    for entry in (_ipl_entry(0x100, 0xC000, 0xC000, 0, attribute=0), _ipl_entry(0x100, 0xC000, 0xC000, 0, extension=b"Bin")):
        with pytest.raises(X1Error, match="no X1 IPL boot entry"):
            IplHeader.parse(entry)
    with pytest.raises(X1Error, match="16-bit address space"):
        IplHeader.parse(_ipl_entry(0x200, 0xFF00, 0xFF00, 0))


def test_x1_ipl_boot_follows_header(tmp_path, capsys):
    disk = tmp_path / "boot.d88"
    disk.write_bytes(_boot_disk())
    assert main(["info", str(disk), "--x1", "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["format"] == "X1" and report["memory_view"] == "ram"
    assert report["ipl"] == {
        "name": "DEMO BOOT", "extension": "Sys", "size": 0x180, "load_address": 0xC000, "exec_address": 0xC000,
        "start_sector": 0x12, "start_chr": "0:1:3", "sector_count": 2, "date": "86a108120000",
    }
    assert report["entry"] == {"linear": 0xC000, "unit_address": "root:0000"}
    root, = report["units"]
    assert (root["linear"], root["size"]) == (0xC000, 0x180)
    sector_3 = _HEADER_SIZE + 16 + 256 + 2 * (16 + 256) + 16
    assert root["file_spans"] == [
        {"offset": 0, "file_offset": sector_3, "size": 256},
        {"offset": 256, "file_offset": sector_3 + 256 + 16, "size": 0x80},
    ]
    assert [region["name"] for region in report["memory_map"]] == ["low_ram", "high_ram"]
    io = {region["name"]: region for region in report["io_map"]}
    assert io["ipl_rom_off"]["port"] == 0x1E00 and io["crtc"]["labels"][1] == {"name": "CRTC_DATA", "port": 0x1801}
    assert main(["info", str(disk), "--x1"]) == 0
    assert "IPL 'DEMO BOOT'" in capsys.readouterr().out


def test_x1_explicit_spans_copies_and_units(tmp_path, capsys):
    disk = tmp_path / "boot.d77"
    disk.write_bytes(_boot_disk())
    unit = tmp_path / "patch.bin"
    unit.write_bytes(b"PATCH")
    export = tmp_path / "image"
    assert main(["load", str(disk), "--x1", "--x1-ipl", "--x1-lsn", "10+2@100", "--x1-sector", "0:1:4@8000",
                 "--x1-copy", "c000:f@9000", "--x1-unit", f"{unit}@8002", "--entry", "100",
                 "-o", str(export), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    names = [unit["name"] for unit in report["units"]]
    assert names == ["lsn_0010_0100", "sector_0_1_4_8000_8000", "patch", "sector_0_1_4_8000_8007",
                     "copy_9000_from_c000_f", "root"]
    assert [entry["linear"] for entry in report["entries"]] == [0xC000, 0x100]
    binary = (export / "image.bin").read_bytes()
    assert binary[:len(_STAGE2)] == _STAGE2
    assert binary[0x7F00:0x7F07] == b"TAPATCH"
    assert binary[0x8F00:0x8F00 + len(_BOOT)] == _BOOT

    # Explicit sectors without --x1-ipl replace the boot payload, and the first becomes the root.
    assert main(["info", str(disk), "--x1", "--x1-lsn", "10@100", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [unit["name"] for unit in report["units"]] == ["root"] and "ipl" not in report


@pytest.mark.parametrize(
    ("options", "error"),
    [([], "--base-address"), (["--base-address", "100", "--x1-view", "ipl-rom"], "hidden by the IPL ROM"),
     (["--base-address", "100", "--x1-copy", "100:2@200"], "single visible load"),
     (["--base-address", "100", "--x1-lsn", "0@100"], "--x1-sector"),
     (["--base-address", "8000", "--x1-view", "ipl-rom", "--disk-file", "A"], "--x1-sector or --x1-lsn")],
)
def test_x1_load_errors(tmp_path, capsys, options, error):
    raw = tmp_path / "demo.bin"
    raw.write_bytes(b"\xc9")
    assert main(["info", str(raw), "--x1", *options, "--json"]) == 1
    assert error in json.loads(capsys.readouterr().err)["error"]


def test_x1_disk_without_ipl_and_option_guards(tmp_path, capsys):
    disk = tmp_path / "data.d88"
    disk.write_bytes(_boot_disk(entry=bytes(256)))
    assert main(["info", str(disk), "--x1", "--json"]) == 1
    assert "--x1-sector or --x1-lsn" in json.loads(capsys.readouterr().err)["error"]
    assert main(["info", str(disk), "--x1", "--x1-sector", "0:1:3@c000", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["units"][0]["size"] == 256
    assert main(["info", str(disk), "--x1-view", "ram", "--json"]) == 1
    assert "require --x1" in json.loads(capsys.readouterr().err)["error"]
    with pytest.raises(SystemExit):
        main(["info", str(disk), "--x1", "--x1-lsn", "zz@100"])
    capsys.readouterr()


def test_ghidra_x1_full_port_references(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    disk = tmp_path / "boot.d88"
    disk.write_bytes(_boot_disk())
    export, project = tmp_path / "image", tmp_path / "x1"
    assert main(["load", str(disk), "--x1", "--x1-ipl", "--x1-lsn", "10@100", "--entry", "100",
                 "-o", str(export)]) == 0, capsys.readouterr().err
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    imported = json.loads(capsys.readouterr().out)
    assert (imported["format"], imported["memory_view"]) == ("X1", "ram")
    function, transfer, crtc, rom, fdc = query_batch(project, [
        {"command": "decomp", "address": "c000"},
        {"command": "xrefs", "address": "c00c", "compact": True, "direction": "outgoing"},
        {"command": "xrefs", "address": "x1_crtc:0000", "compact": True, "direction": "incoming"},
        {"command": "xrefs", "address": "x1_ipl_rom_off:0000", "compact": True, "direction": "incoming"},
        {"command": "xrefs", "address": "x1_fdc:0004", "compact": True, "direction": "incoming"},
    ])["results"]
    # Ports use the full BC value, so 1800 and 1E00 are distinct from each other and from port 00.
    assert "CRTC_ADDRESS" in function["result"]["decompilation"]
    assert "IPL_ROM_OFF" in function["result"]["decompilation"]
    assert transfer["result"]["outgoing"][0]["to"] == "lsn_0010_0100:0000"
    assert crtc["result"]["incoming"][0]["from"] == "root:0005"
    assert rom["result"]["incoming"][0]["from"] == "root:000a"
    assert fdc["result"]["incoming"][0]["from"] == "lsn_0010_0100:0005"


def _phantasie_program_disk() -> Path:
    media = os.environ.get("RETRORE_PH1_X1_DIR")
    if not media:
        pytest.skip("set RETRORE_PH1_X1_DIR to validate the Phantasie I X1 release")
    disk, = Path(media).glob("*Program disk*.d88")
    return disk


def test_phantasie_i_x1_ipl_entry(capsys):
    disk = _phantasie_program_disk()
    assert main(["info", str(disk), "--x1", "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    ipl = report["ipl"]
    assert (ipl["name"], ipl["size"], ipl["load_address"], ipl["exec_address"]) == ("PHANTASIE 1", 0xC00, 0xBF80, 0xC000)
    assert (ipl["start_sector"], ipl["start_chr"]) == (0x370, "27:1:1")
    assert report["entry"] == {"linear": 0xC000, "unit_address": "root:0080"}
    assert report["units"][0]["file_offset"] == 0x3A9C0
    player, = disk.parent.glob("*Player disk*.d88")
    assert main(["info", str(player), "--x1", "--json"]) == 1
    assert "no X1 IPL boot entry" in json.loads(capsys.readouterr().err)["error"]


def test_phantasie_i_x1_boot_and_second_stage(tmp_path, capsys):
    disk = _phantasie_program_disk()
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to validate the Phantasie I X1 release")
    export, project = tmp_path / "image", tmp_path / "x1"
    # The IPL payload at bf80 reads 112 sectors from C4 H0 R1 (LSN 80) to 0100 and jumps there.
    assert main(["load", str(disk), "--x1", "--x1-ipl", "--x1-lsn", "80+112@100", "--entry", "100",
                 "-o", str(export)]) == 0, capsys.readouterr().err
    assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    main_loop, loader, load_call, transfer, crtc, ppi, fdc = query_batch(project, [
        {"command": "decomp", "address": "3d7f"},
        {"command": "decomp", "address": "c3d8"},
        {"command": "xrefs", "address": "c45e", "compact": True, "direction": "outgoing", "ref_types": ["UNCONDITIONAL_CALL"]},
        {"command": "xrefs", "address": "c465", "compact": True, "direction": "outgoing"},
        {"command": "xrefs", "address": "x1_crtc:0001", "compact": True, "direction": "incoming"},
        {"command": "xrefs", "address": "c05b", "compact": True, "direction": "outgoing"},
        {"command": "xrefs", "address": "011d", "compact": True, "direction": "outgoing", "ref_types": ["WRITE"]},
    ])["results"]
    assert main_loop["result"]["unit_address"] == "lsn_0080_0100:3c7f"
    assert "FUN_ram_0108" in main_loop["result"]["decompilation"]
    assert loader["result"]["unit_address"] == "root:0458"
    assert loader["result"]["decompilation"]
    assert load_call["result"]["outgoing"][0]["to"] == "root:0458"
    assert transfer["result"]["outgoing"][0]["to"] == "lsn_0080_0100:0000"
    assert "root:00cf" in [ref["from"] for ref in crtc["result"]["incoming"]]
    assert ppi["result"]["outgoing"][0]["to"] == "x1_ppi:0003"
    assert [ref["to"] for ref in fdc["result"]["outgoing"]] == ["x1_fdc:0004"]
