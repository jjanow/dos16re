import json
import os
from struct import pack, pack_into

import pytest

from retrore.atari8 import Atari8Binary, Atari8Error, AtrImage, memory_map
from retrore.cli import main


def _record(address, data):
    return pack("<HH", address, address + len(data) - 1) + data


def _xex(*records):
    return b"\xff\xff" + b"".join(_record(address, data) for address, data in records)


def _disk(count=720, sector_size=128):
    size = 384 + (count - 3) * sector_size
    paragraphs = size // 16
    disk = bytearray(16 + size)
    pack_into("<HHHH", disk, 0, 0x0296, paragraphs & 0xFFFF, sector_size, paragraphs >> 16)
    return disk


def _sector(disk, number, sector_size=128):
    size = 128 if number <= 3 else sector_size
    start = 16 + (number - 1) * 128 if number <= 3 else 16 + 384 + (number - 4) * size
    return memoryview(disk)[start:start + size]


@pytest.mark.parametrize(("sector_size", "count", "flag"), [(128, 720, 0x62), (256, 720, 0x42), (128, 1040, 0x03)])
def test_atr_reads_linked_dos_binary(sector_size, count, flag):
    disk = _disk(count, sector_size)
    _sector(disk, 360, sector_size)[0] = 2
    for slot in range(8):
        _sector(disk, 361, sector_size)[slot * 16] = 0x80
    directory = _sector(disk, 362, sector_size)
    # A deleted entry with the same name is ignored, and the active entry uses file index 9.
    directory[0] = 0x80
    directory[5:16] = b"DEMO    COM"
    last_number = 1000 if count == 1040 else 700
    pack_into("<BHH11s", directory, 16, flag, 2, 20, b"DEMO    COM")
    executable = _xex((0x2000, bytes(range(150))), (0x02E0, pack("<H", 0x2000)))
    first = _sector(disk, 20, sector_size)
    first[:100] = executable[:100]
    first[-3:] = bytes((9 << 2 | (last_number >> 8), last_number & 0xFF, 100))
    last = _sector(disk, last_number, sector_size)
    last[:len(executable) - 100] = executable[100:]
    last[-3:] = bytes((9 << 2, 0, len(executable) - 100))
    assert AtrImage(disk).read_file("demo.com") == executable

    last[-3:] = bytes((9 << 2, 20, len(executable) - 100))
    with pytest.raises(Atari8Error, match="sector loop"):
        AtrImage(disk).read_file("DEMO.COM")


def test_atr_boot_view(tmp_path, capsys):
    source = tmp_path / "boot.atr"
    disk = _disk(5, 256)
    pack_into("<BBHH", disk, 16, 0, 4, 0x2000, 0x2181)
    _sector(disk, 4, 256)[:] = bytes(range(256))
    source.write_bytes(disk)
    out = tmp_path / "out"
    assert main(["load", str(source), "-o", str(out), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    assert program["disk"] == {"sector_size": 256, "sector_count": 5}
    assert program["entries"] == [
        {"linear": 0x2006, "unit_address": "root:0006"},
        {"linear": 0x2181, "unit_address": "root:0181"},
    ]
    assert program["sources"][0]["segments"][-1] == {"linear": 0x2180, "size": 128, "file_offset": 400}
    assert (out / "image.bin").read_bytes() == disk[16:16 + 4 * 128]
    with pytest.raises(Atari8Error, match="header size"):
        AtrImage(disk[:-1])


@pytest.mark.parametrize("data", [
    b"\xff\xff", b"\xff\xff\x00", b"\xff\xff" + pack("<HH", 0x1000, 0x0FFF),
    b"\xff\xff" + pack("<HH", 0x1000, 0x1000),
])
def test_malformed_xex(data):
    with pytest.raises(Atari8Error):
        Atari8Binary.from_xex(data, "bad.xex")


def test_xex_patch_vectors_and_overlay_export(tmp_path, capsys):
    source, helper, out = (tmp_path / name for name in ("demo.bin", "patch.xex", "out"))
    source.write_bytes(
        _xex((0x2000, b"ABC"), (0x02E2, b"\x00"), (0x02E3, b"\x20"))
        + b"\xff\xff" + _record(0x02E2, pack("<H", 0x2100))
        + _record(0x2001, b"D") + _record(0x2100, b"EF")
        + _record(0x02E0, pack("<H", 0x2001)) + _record(0xD301, b"\xfe")
    )
    helper.write_bytes(_xex((0x2002, b"X"), (0x2200, b"YZ"), (0x02E0, pack("<H", 0x2200))))
    assert main(["load", str(source), "--atari8-unit", str(helper), "-o", str(out), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    assert program["format"] == "ATARI8"
    assert program["sources"][0]["init_addresses"] == [0x2000, 0x2100]
    assert program["sources"][0]["run_address"] == 0x2001
    assert program["sources"][0]["unmapped_writes"][0]["linear"] == 0xD301
    assert [entry["linear"] for entry in program["entries"]] == [0x2001, 0x2000, 0x2100, 0x2200]
    assert [unit["linear"] for unit in program["units"]] == [0x02E0, 0x02E2, 0x2000, 0x2002, 0x2100, 0x2200]
    image = (out / "image.bin").read_bytes()
    i = 0x2000 - program["base_address"]
    assert image[:4] == pack("<HH", 0x2200, 0x2100)
    assert image[i:i + 3] == b"ADX"
    assert image[i + 3:i + 0x100] == bytes(0xFD)
    assert main(["where-is", "--export", str(out), "--string", "EF", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["matches"][0]["address"] == "2100"


def test_portb_maps_rom_and_xe_ram(tmp_path, capsys):
    source = tmp_path / "code.bin"
    source.write_bytes(b"\x60")
    assert main(["info", str(source), "--atari8-raw", "--base-address", "e000",
                 "--entry", "e000", "--json"]) == 1
    assert "os_rom_high" in json.loads(capsys.readouterr().err)["error"]["message"]
    assert main(["info", str(source), "--atari8-raw", "--base-address", "e000", "--atari8-portb", "fe",
                 "--entry", "e000", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["entry"]["linear"] == 0xE000
    regions = {region["linear"]: (region["name"], region["read"]) for region in memory_map(0x69)}
    assert regions[0x4000] == ("xe_bank2", "ram")
    assert regions[0x5000] == ("self_test", "rom")
    assert regions[0xA000] == ("basic_rom", "rom")
    assert regions[0xD300] == ("pia", "io")


def test_c64_prg_with_atr_magic_as_its_load_address(tmp_path, capsys):
    source = tmp_path / "code.prg"
    source.write_bytes(pack("<H", 0x0296) + b"\x60")
    assert main(["info", str(source), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    assert (program["format"], program["units"][0]["linear"]) == ("C64_PRG", 0x0296)


def test_atari8_ghidra_import_and_queries(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    source, helper, out, project = (tmp_path / name for name in ("root.xex", "helper.xex", "out", "project"))
    source.write_bytes(_xex((0x2000, bytes.fromhex("200030 60")), (0x02E0, pack("<H", 0x2000))))
    helper.write_bytes(_xex((0x3000, bytes.fromhex("8d1ad0 60"))))
    assert main(["load", str(source), "--atari8-unit", str(helper), "-o", str(out)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert (report["format"], report["entries"], report["portb"]) == ("ATARI8", 2, 0xFF)

    def query(command, address):
        assert main([command, address, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)

    call, = query("callees", "root_2000:0000")["callees"]
    assert call["to_function"]["entry"]["unit_address"] == "helper:0000"
    write, = query("xrefs", "3000")["outgoing"]
    assert (write["type"], write["to"]["unit_address"]) == ("WRITE", "atari8_gtia:001a")
    assert "COLBK" in query("decomp", "helper:0000")["decompilation"]
