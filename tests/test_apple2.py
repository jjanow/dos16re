import json
import os
from pathlib import Path
from struct import pack, pack_into

import pytest

from retrore.apple2 import Apple2Error, SectorImage, memory_map
from retrore.cli import main
from retrore.dynamic import RoutineBackend, RoutineRequest


def _high_ascii(name, width):
    return bytes(value | 0x80 for value in name.encode("ascii").ljust(width))


def _sector(disk, track, slot, stride=16):
    offset = (track * stride + slot) * 256
    return memoryview(disk)[offset:offset + 256]


def _dos_disk(payload, slots=range(16)):
    def block(track, logical_sector):
        return _sector(disk, track, slots[logical_sector])

    disk = bytearray(35 * 16 * 256)
    vtoc = block(17, 0)
    vtoc[1:3] = b"\x11\x0f"
    vtoc[0x34:0x38] = bytes((35, 16, 0, 1))
    block(17, 15)[1:3] = b"\x11\x0e"
    entry = block(17, 14)[11:46]
    entry[:3] = bytes((2, 1, 0x84))
    entry[3:33] = _high_ascii("DEMO", 30)
    first_list = block(2, 1)
    first_list[1:3] = bytes((2, 2))
    pack_into("<H", first_list, 5, 1)
    first_list[12:14] = bytes((3, 3))
    block(2, 2)[12:14] = bytes((3, 9))
    contents = (pack("<HH", 0x2000, len(payload)) + payload).ljust(512, b"\xff")
    block(3, 9)[:] = contents[:256]
    block(3, 3)[:] = contents[256:]
    return disk


@pytest.mark.parametrize(("suffix", "options", "slots", "order"), [
    (".dsk", [], range(16), "dos"),
    (".po", [], (0, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 15), "prodos"),
    (".img", ["--apple2-disk-order", "physical"], (0, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 15),
     "physical"),
])
def test_dos_disk_export_and_search(tmp_path, capsys, suffix, options, slots, order):
    payload = bytes(256) + b"AB"
    disk = tmp_path / f"demo{suffix}"
    disk.write_bytes(_dos_disk(payload, slots))
    worker = tmp_path / "worker.bin"
    worker.write_bytes(pack("<HH", 0x2102, 1) + b"C")
    out = tmp_path / "out"
    assert main(["load", str(disk), "--disk-file", "demo", "--apple2-unit", str(worker),
                 "--entry", "2001", "--entry", "2001", "-o", str(out), "--json", *options]) == 0
    program = json.loads(capsys.readouterr().out)
    assert program == json.loads((out / "map.json").read_text())
    assert program["disk"] == {"filesystem": "DOS 3.3", "sector_order": order}
    assert program["entries"] == [{"unit_address": "root:0001", "linear": 0x2001}]
    root, helper = program["units"]
    assert (root["disk_file"], root["file_offset"], root["size"]) == ("DEMO", 4, len(payload))
    assert (helper["linear"], helper["source"]) == (0x2102, worker.name)
    assert (out / "image.bin").read_bytes() == payload + b"C"
    offset = (3 * 16 + slots[3]) * 256 + 4
    assert main(["address-map", f"{offset:x}", "--from", "file", "--offset-kind", "container",
                 "--member", "DEMO", "--export", str(out), "--json"]) == 0
    match, = json.loads(capsys.readouterr().out)["matches"]
    assert match["unit_address"] == "root:0100"
    assert match["container"]["offset"] == offset and match["file"]["offset"] == 260

    for flag, value, expected in [("--string", "ABC", []), ("--constant", "0x4241", [
        {"address": "2100", "unit_address": "root:0100", "linear": 0x2100},
    ])]:
        assert main(["where-is", "--export", str(out), flag, value, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["matches"] == expected


@pytest.mark.parametrize(("track", "slot", "offset", "value", "message"), [
    (17, 14, 1, bytes((17, 15)), "chain loops"),
    (2, 2, 1, bytes((2, 1)), "chain loops"),
    (2, 2, 12, bytes((35, 0)), "invalid Apple II track/sector"),
    (2, 1, 12, bytes((0, 0)), "missing data sector 1"),
    (17, 14, 13, bytes((2,)), "is not a binary"),
])
def test_dos_rejects_invalid_disk_members(track, slot, offset, value, message):
    disk = _dos_disk(bytes(258))
    _sector(disk, track, slot)[offset:offset + len(value)] = value
    with pytest.raises(Apple2Error, match=message):
        SectorImage(disk).read_binary("DEMO")


@pytest.mark.parametrize(("version", "stride", "logical_count", "last_slot", "catalog_slot", "order"), [
    ("2.1", 13, 13, 12, 1, "physical"),
    ("2.1", 16, 13, 12, 1, "physical"),
    ("2.1", 16, 13, 9, 7, "dos"),
    ("3.3", 16, 16, 15, 14, "dos"),
])
def test_rdos_reads_catalog_addresses_and_contiguous_sectors(version, stride, logical_count, last_slot, catalog_slot, order):
    disk = bytearray(35 * stride * 256)
    catalog = _sector(disk, 1, 0, stride)
    catalog[:24] = _high_ascii(f"RDOS {version}", 24)
    for offset in range(32, 256, 32):
        catalog[offset] = 0x80  # Deleted entries do not end the catalog.
    entry = _sector(disk, 1, catalog_slot, stride)[:32]
    entry[:24] = _high_ascii("DEMO", 24)
    pack_into("<BBHHH", entry, 24, 0xC2, 2, 0x0300, 257, 3 * logical_count - 1)
    if version == "2.1":
        _sector(disk, 1, last_slot, stride)[0xA2:0xA8] = _high_ascii("<NAME>", 6)
    _sector(disk, 2, last_slot, stride)[:] = b"X" * 256
    _sector(disk, 3, 0, stride)[:2] = b"YZ"
    image = SectorImage(disk)
    assert (image.filesystem, image.order) == (f"RDOS {version}", order)
    binary = image.read_binary("Demo")
    assert (binary.load_address, binary.file_offset, binary.payload) == (0x0300, 0, b"X" * 256 + b"Y")
    pack_into("<H", entry, 30, 35 * logical_count - 1)
    with pytest.raises(Apple2Error, match="invalid sector range"):
        image.read_binary("DEMO")


@pytest.mark.parametrize(("switch", "low_region", "read", "write"), [
    (0xC080, "lc_bank2", "ram", "none"), (0xC081, "system_rom_low", "rom", "ram"),
    (0xC082, "system_rom_low", "rom", "none"), (0xC083, "lc_bank2", "ram", "ram"),
    (0xC088, "lc_bank1", "ram", "none"), (0xC08F, "lc_bank1", "ram", "ram"),
])
def test_apple2_language_card(switch, low_region, read, write):
    regions = {region["linear"]: region for region in memory_map(switch)}
    assert (regions[0xD000]["name"], regions[0xD000]["read"], regions[0xD000]["write"]) == (low_region, read, write)
    assert regions[0xE000]["size"] == 0x2000
    assert (regions[0xE000]["read"], regions[0xE000]["write"]) == (read, write)


def test_apple2_raw_and_language_card_placement(tmp_path, capsys):
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x60")
    helper = tmp_path / "helper.bin"
    helper.write_bytes(b"\x60")
    command = ["info", str(raw), "--apple2-raw", "--base-address", "d000", "--json"]
    assert main(command) == 1
    assert "outside visible RAM" in json.loads(capsys.readouterr().err)["error"]["message"]
    command += ["--apple2-lc", "c088", "--apple2-unit", str(helper) + "@e000"]
    assert main(command) == 0
    program = json.loads(capsys.readouterr().out)
    assert program["entry"] is None
    assert [(unit["linear"], unit["writable"], unit["load_address"]) for unit in program["units"]] == [
        (0xD000, False, None), (0xE000, False, None),
    ]
    assert main([*command, "--apple2-unit", str(raw) + "@d000"]) == 1
    assert "overlaps another unit" in json.loads(capsys.readouterr().err)["error"]["message"]
    assert main([*command, "--entry", "ffff"]) == 1
    assert "outside the loaded binaries" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_apple2_ghidra_import_and_queries(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    source, worker, out, project = (tmp_path / name for name in ("app.bin", "worker.bin", "out", "project"))
    source.write_bytes(pack("<HH", 0x0800, 4) + bytes.fromhex("2000d0 60"))
    worker.write_bytes(bytes.fromhex("ad30c0 60"))
    assert main(["load", str(source), "--apple2", "--apple2-lc", "c08b", "--apple2-unit", str(worker) + "@d000",
                 "--entry", "0800", "-o", str(out)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert (report["format"], report["units"], report["entries"], report["language_card"]) == ("APPLE2", 2, 1, 0xC08B)

    def query(command, address):
        assert main([command, address, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)

    call, = query("callees", "root:0000")["callees"]
    assert call["to_function"]["entry"]["unit_address"] == "worker:0000"
    read, = query("xrefs", "d000")["outgoing"]
    assert (read["type"], read["to"]["unit_address"]) == ("READ", "apple2_soft_switches:0030")
    assert "SPKR" in query("decomp", "worker:0000")["decompilation"]


def test_phantasie_iii_picplot_rebuilds_the_screen_pointer(tmp_path, capsys):
    directory = os.environ.get("RETRORE_PH3_APPLE2_DIR")
    if not directory:
        pytest.skip("set RETRORE_PH3_APPLE2_DIR to the Phantasie III disk directory")
    disk, = Path(directory).glob("*Disk_1_of_3_Side_A.dsk")
    export = tmp_path / "picplot"
    assert main(["load", str(disk), "--apple2", "--disk-file", "PICPLOT", "--entry", "6e8c", "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["where-is", "--export", str(export), "--pointer", "2228", "--pointer-kind", "split", "--json"]) == 0
    match, = json.loads(capsys.readouterr().out)["matches"]
    evidence, = match["evidence"]
    assert (match["address"], match["high"]["address"], evidence["index_register"], evidence["index"]) == (
        "6e24", "6dc0", "y", 0x60,
    )
    assert evidence["high_table"]["unit_address"] is None
    assert (evidence["instruction"]["linear"], evidence["destination"]["linear"]) == (0x6e8e, 0x6ea0)

    panel = bytes(range(12)) + bytes(range(12, 24)) + bytes(94 * 12)
    result = RoutineBackend.from_export(export).run(RoutineRequest(
        "6e8c", writes=((0x7530, panel),), reads=((0x2228, 12), (0x2628, 12), (0x6e9d, 2)),
    ))
    assert dict(result.after.memory) == {0x2228: panel[:12], 0x2628: panel[12:24], 0x6e9d: pack("<H", 0x79b0)}
