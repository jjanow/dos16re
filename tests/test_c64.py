import json
import os
from contextlib import nullcontext
from struct import pack

import pytest

from retrore.c64 import C64Error, PrgUnit, build_c64_image, memory_map
from retrore.cli import main


def _prg(address, payload):
    return pack("<H", address) + payload


def _sys_stub():
    return pack("<HH", 0x080B, 10) + b"\x9e2061\0\0\0"


def _disk(prg):
    # Directory link to 18/2 and file link from 1/0 to 40/0.
    disk = bytearray(768 * 257)
    directory = (17 * 21 + 1) * 256
    disk[directory:directory + 2] = bytes([18, 2])
    entry = directory + 256
    disk[entry:entry + 5] = bytes([0, 255, 0xC2, 1, 0])
    disk[entry + 5:entry + 21] = b"DEMO".ljust(16, b"\xa0")
    disk[:256] = bytes([40, 0]) + prg[:254]
    remainder = prg[254:]
    end = (768 - 17) * 256
    disk[end:end + len(remainder) + 2] = bytes([0, len(remainder) + 1]) + remainder
    return disk


def test_c64_disk_export_and_search(tmp_path, capsys):
    prg = _prg(0x0801, _sys_stub() + b"\x60" + bytes(245) + b"AB")
    disk = tmp_path / "demo.d64"
    disk.write_bytes(_disk(prg))
    addon = tmp_path / "worker.PRG"
    addon.write_bytes(_prg(0xA001, b"C\x60"))
    out = tmp_path / "out"
    assert main(["load", str(disk), "--disk-file", "demo", "--c64-unit", str(addon) + "@a000",
                 "--c64-bank", "6", "-o", str(out), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    assert json.loads((out / "map.json").read_text()) == program
    assert program["format"] == "C64_PRG"
    assert program["entry"] == {"unit_address": "root:000c", "linear": 0x080D}
    root, worker = program["units"]
    assert (root["source"], root["disk_file"], root["file_offset"]) == ("demo.d64", "DEMO", 2)
    assert (worker["load_address"], worker["linear"]) == (0xA001, 0xA000)
    image = (out / "image.bin").read_bytes()
    assert image[:root["size"]] == prg[2:]
    assert image[root["size"]:worker["image_offset"]] == bytes(worker["image_offset"] - root["size"])
    assert image[worker["image_offset"]:] == b"C\x60"

    def search(flag, value):
        assert main(["where-is", "--export", str(out), flag, value, "--json"]) == 0
        return json.loads(capsys.readouterr().out)["matches"]

    assert search("--constant", "0x6043") == [{"address": "a000", "linear": 0xA000, "unit_address": "worker:0000"}]
    match, = search("--string", "AB")
    assert match["unit_address"] == "root:0102"
    assert not search("--bytes", "414200")


@pytest.mark.parametrize(("bank", "basic", "io", "kernal"), [
    (0, "ram", "ram", "ram"), (1, "ram", "rom", "ram"), (2, "ram", "rom", "rom"),
    (3, "rom", "rom", "rom"), (4, "ram", "ram", "ram"), (5, "ram", "io", "ram"),
    (6, "ram", "io", "rom"), (7, "rom", "io", "rom"),
])
def test_c64_bank_view(bank, basic, io, kernal):
    regions = {region["linear"]: region for region in memory_map(bank)}
    assert (regions[0xA000]["read"], regions[0xD000]["read"], regions[0xE000]["read"]) == (basic, io, kernal)
    assert regions[0xA000]["write"] == regions[0xE000]["write"] == "ram"
    assert regions[0xD000]["write"] == ("io" if io == "io" else "ram")
    with pytest.raises(C64Error, match="overlaps basic_rom") if basic == "rom" else nullcontext():
        build_c64_image([PrgUnit("root", "one", _prg(0x9FFF, b"\x60\x60"))], "one", bank=bank)


@pytest.mark.parametrize(("address", "payload", "entry", "error"), [
    (0x0801, b"", [], "two-byte load address and a payload"),
    (0xFFFF, b"\x60\x60", [], "16-bit address space"),
    (0x2000, b"\x60", [0x2001], "outside the loaded PRGs"),
])
def test_c64_rejects_invalid_prg(address, payload, entry, error):
    with pytest.raises(C64Error, match=error):
        build_c64_image([PrgUnit("root", "demo", _prg(address, payload))], "demo", bank=0, entries=entry)


def test_c64_rejects_overlapping_units_and_leaves_unknown_entry_unset():
    root = PrgUnit("root", "demo", _prg(0x0801, _sys_stub() + b"\x60"))
    alternate = PrgUnit("alternate", "other", _prg(0x0801, b"\x60"))
    with pytest.raises(C64Error, match="overlaps another unit"):
        build_c64_image([root, alternate], "demo")
    _, program = build_c64_image([alternate], "other")
    assert program["entry"] is None
    assert not program["entries"]


def test_c64_override_disambiguates_gemdos_signature(tmp_path, capsys):
    source = tmp_path / "demo.prg"
    source.write_bytes(_prg(0x1A60, b"\x60"))
    assert main(["info", str(source), "--json"]) == 1
    assert "GEMDOS" in json.loads(capsys.readouterr().err)["error"]
    assert main(["info", str(source), "--c64", "--entry", "1a60", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["entry"]["linear"] == 0x1A60


@pytest.mark.parametrize(("block", "link", "message"), [
    (0, [1, 0], "sector chain loops"),
    (0, [40, 17], "invalid D64 track/sector"),
    ((768 - 17) * 256, [0, 0], "invalid final D64 file sector length"),
])
def test_c64_rejects_corrupt_sector_chains(block, link, message, tmp_path, capsys):
    image = _disk(_prg(0x2000, bytes(256)))
    image[block:block + 2] = bytes(link)
    source = tmp_path / "disk.d64"
    source.write_bytes(image)
    out = tmp_path / "out"
    assert main(["load", str(source), "--disk-file", "demo", "-o", str(out), "--json"]) == 1
    assert message in json.loads(capsys.readouterr().err)["error"]
    assert not out.exists()


def test_c64_ghidra_import_and_queries(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    source, addon, out, project = (tmp_path / name for name in ("demo.prg", "worker.prg", "out", "project"))
    source.write_bytes(_prg(0x0801, _sys_stub() + bytes.fromhex("2000a0 60")))
    addon.write_bytes(_prg(0xA000, bytes.fromhex("a907 8d20d0 60")))
    assert main(["load", str(source), "-o", str(out), "--c64-unit", str(addon), "--c64-bank", "6"]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert (report["format"], report["units"], report["entries"], report["bank"]) == ("C64_PRG", 2, 1, 6)

    def query(*args):
        assert main([*args, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)

    call, = query("callees", "080d")["callees"]
    assert call["to_function"]["entry"]["unit_address"] == "worker:0000"
    write, = query("xrefs", "worker:0002")["outgoing"]
    assert write["to"]["unit_address"] == "c64_vic:0020"
    assert write["type"] == "WRITE"
    assert "FUN_a000" in query("decomp", "worker:0000")["decompilation"]
