import json
import os
from pathlib import Path
from struct import pack, unpack

import pytest

from retrore.cli import main
from retrore.evidence import inspect_bytes, map_address
from retrore.ghidra import import_program, query_batch
from retrore.nes import NesError, build_nes_image


def _rom(prg, *, flags6=0, flags7=0, extra=bytes(8), chr_rom=b"", trainer=b""):
    return (b"NES\x1a" + bytes((len(prg) // 0x4000, len(chr_rom) // 0x2000, flags6, flags7))
            + extra + trainer + prg + chr_rom)


def _prg(count, vectors=(0xE010, 0xE000, 0xE010)):
    prg = bytearray(b"".join(bytes((bank,)) * 0x2000 for bank in range(count)))
    prg[-6:] = pack("<3H", *vectors)
    return prg


def test_nrom_mirror_trainer_and_cli_provenance(tmp_path, capsys):
    source, out = tmp_path / "cart.bin", tmp_path / "out"
    prg = _prg(2, vectors=(0x7000, 0xC010, 0xC010))
    prg[0x10:0x13] = b"NES"
    trainer = b"\x60" + bytes(511)
    rom = _rom(prg, flags6=5, trainer=trainer, chr_rom=b"\x99" * 0x2000)
    source.write_bytes(rom)
    assert main(["load", str(source), "-o", str(out), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["format"] == "NES"
    assert report["memory_view"] == "NROM"
    assert report["cartridge"]["mirroring"] == "vertical"
    assert report["cartridge"]["chr_rom"] == {"file_offset": 16 + 512 + 0x4000, "size": 0x2000}
    assert report["units"][0]["linear"] == 0x7000
    assert report["entries"] == [
        {"linear": 0xC010, "unit_address": "prg_c000:0010"},
        {"linear": 0x7000, "unit_address": "trainer:0000"},
    ]
    image = (out / "image.bin").read_bytes()
    assert image == trainer + bytes(0x1000 - len(trainer)) + prg * 2
    locations = map_address(out, "220", space="file")["matches"]
    assert [item["address"] for item in locations] == ["8010", "c010"]
    assert inspect_bytes(out, "trainer:0000", size=1)["address"]["file"]["offset"] == 16
    assert main(["where-is", "--export", str(out), "--string", "NES", "--json"]) == 0
    assert [item["address"] for item in json.loads(capsys.readouterr().out)["matches"]] == ["8010", "c010"]


@pytest.mark.parametrize(("mode", "expected"), [(0, [4, 5, 6, 7]), (1, [6, 5, 4, 7])])
def test_nes2_mmc3_selects_banks_and_reports_ram(mode, expected):
    prg = _prg(8)
    rom = _rom(prg, flags6=0x42, flags7=8, extra=bytes.fromhex("00 00 70 06 00 00 00 00"))
    image, report = build_nes_image(rom, "cart.nes", mode=mode, r6=4, r7=5)
    assert report["prg_registers"] == {"mode": mode, "r6": 4, "r7": 5}
    assert report["cartridge"]["header"] == "NES 2.0"
    assert report["cartridge"]["prg_nvram_size"] == 8192
    assert report["cartridge"]["chr_ram_size"] == 4096
    assert [unit["bank"] for unit in report["units"]] == expected
    assert [unit["file_offset"] for unit in report["units"]] == [16 + 0x2000 * bank for bank in expected]
    assert image == b"".join(prg[0x2000 * bank:0x2000 * (bank + 1)] for bank in expected)
    assert [entry["linear"] for entry in report["entries"]] == [0xE000, 0xE010]
    regions = report["memory_map"]
    assert all(left["linear"] + left["size"] == right["linear"] for left, right in zip(regions, regions[1:]))
    assert [region["write"] for region in regions if region["linear"] >= 0x6000] == ["ram", "mapper"]


def test_nes2_exponent_multiplier_and_explicit_entries():
    prg = _prg(4, vectors=(1, 0xC000, 0xFFFF))
    # Use the exponent encoding for an odd-sized CHR ROM.
    chr_size = 3 * 2048
    rom = bytearray(_rom(prg, flags7=8, extra=bytes.fromhex("00 f0 00 00 00 00 00 00")))
    rom[5] = 11 << 2 | 1
    rom.extend(bytes(chr_size))
    image, report = build_nes_image(rom, "cart.nes")
    assert image == prg
    assert report["cartridge"]["chr_rom"]["size"] == chr_size
    assert [item["linear"] for item in report["entries"]] == [0xC000]
    _, report = build_nes_image(rom, "cart.nes", entries=[0x8001, 0x8001, 0xC002])
    assert [item["unit_address"] for item in report["entries"]] == ["prg_8000:0001", "prg_c000:0002"]


@pytest.mark.parametrize(("rom", "options", "message"), [
    (b"NES\x1a", {}, "complete"),
    (_rom(_prg(4), flags6=4)[:16], {}, "trainer"),
    (_rom(_prg(4))[:-1], {}, "PRG ROM"),
    (_rom(_prg(4), chr_rom=bytes(0x2000))[:-1], {}, "CHR ROM"),
    (_rom(_prg(4), flags6=0x10), {}, "mapper 1"),
    (_rom(_prg(4), flags6=0x40, flags7=8, extra=b"\x10" + bytes(7)), {}, "submapper 1"),
    (_rom(_prg(4), flags6=0x40, flags7=8, extra=b"\x01" + bytes(7)), {}, "mapper 260"),
    (_rom(_prg(4)), {"r6": 0}, "require mapper 4"),
    (_rom(_prg(4), flags6=0x40), {"r7": 4}, "R7 bank 4"),
    (_rom(_prg(4), flags6=0x40), {"mode": 2}, "mode must be 0 or 1"),
    (_rom(_prg(4)), {"entries": [0x6000]}, "outside the loaded program"),
])
def test_invalid_cartridge_or_view(rom, options, message):
    with pytest.raises(NesError, match=message):
        build_nes_image(rom, "invalid.nes", **options)


def test_nes_cli_options_report_json_errors(tmp_path, capsys):
    source = tmp_path / "cart.nes"
    source.write_bytes(_rom(_prg(4), flags6=0x40))
    assert main(["info", str(source), "--nes", "--nes-r6", "02", "--nes-r7", "03",
                 "--nes-prg-mode", "1", "--json"]) == 0
    assert [unit["bank"] for unit in json.loads(capsys.readouterr().out)["units"]] == [2, 3, 2, 3]
    assert main(["info", str(source), "--base-address", "8000", "--json"]) == 1
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "input_invalid"


def test_nes_ghidra_vectors_cross_bank_calls_and_io(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the NES Ghidra integration test")
    source, out, project = (tmp_path / name for name in ("cart.nes", "out", "project"))
    prg = _prg(8, vectors=(0xE010, 0xE000, 0xE010))
    prg[4 * 0x2000:4 * 0x2000 + 6] = bytes.fromhex("a9 07 8d 00 20 60")
    prg[-0x2000:-0x2000 + 6] = bytes.fromhex("20 00 c0 4c 03 e0")
    prg[-0x1FF0] = 0x40
    source.write_bytes(_rom(prg, flags6=0x40))
    assert main(["load", str(source), "--nes-prg-mode", "1", "--nes-r6", "04", "-o", str(out)]) == 0
    capsys.readouterr()
    report = import_program(out, project)
    assert (report["format"], report["entries"], report["memory_view"]) == ("NES", 2, "MMC3")
    calls, writes, vector, decomp = query_batch(project, [
        {"command": "callees", "address": "e000"},
        {"command": "xrefs", "address": "c002", "direction": "outgoing"},
        {"command": "xrefs", "address": "fffc", "direction": "outgoing"},
        {"command": "decomp", "address": "c000"},
    ])["results"]
    call, = calls["result"]["callees"]
    assert call["to_function"]["entry"]["unit_address"] == "prg_c000:0000"
    write, = writes["result"]["outgoing"]
    assert (write["type"], write["to"]["unit_address"]) == ("WRITE", "nes_ppu:0000")
    assert any(ref["to"]["linear"] == 0xE000 for ref in vector["result"]["outgoing"])
    assert "PPUCTRL" in decomp["result"]["decompilation"]


@pytest.mark.parametrize("env", ["RETRORE_POR_NES_DIR", "RETRORE_POR_FAMICOM_DIR"])
def test_pool_of_radiance_cartridge(env, tmp_path, capsys):
    directory = os.environ.get(env)
    if not directory:
        pytest.skip(f"set {env} to validate the original cartridge")
    source, = Path(directory).glob("*.nes")
    out, swapped, project = (tmp_path / name for name in ("out", "swapped", "project"))
    data = source.read_bytes()
    assert main(["load", str(source), "-o", str(out), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    banks = 64
    assert report["cartridge"]["header"] == "NES 2.0"
    assert report["cartridge"]["prg_nvram_size"] == 0x2000
    assert report["cartridge"]["prg_rom"] == {"file_offset": 16, "size": banks * 0x2000}
    assert report["cartridge"]["chr_rom"]["size"] == 0x20000
    assert [unit["bank"] for unit in report["units"]] == [0, 1, banks - 2, banks - 1]
    nmi, reset, irq = unpack("<3H", data[16 + banks * 0x2000 - 6:16 + banks * 0x2000])
    assert [entry["linear"] for entry in report["entries"]] == [reset, nmi, irq]
    assert main(["load", str(source), "--nes-prg-mode", "1", "--nes-r6", "2a", "--nes-r7", "12",
                 "-o", str(swapped), "--json"]) == 0, capsys.readouterr().err
    assert [unit["bank"] for unit in json.loads(capsys.readouterr().out)["units"]] == [62, 18, 42, 63]
    assert map_address(swapped, "c000")["matches"][0]["file"]["offset"] == 16 + 42 * 0x2000
    assert (swapped / "image.bin").read_bytes()[0x4000:0x6000] == data[16 + 42 * 0x2000:16 + 43 * 0x2000]
    if os.environ.get("GHIDRA_HOME"):
        assert import_program(out, project)["entries"] == 3
        function, calls, decomp = query_batch(project, [
            {"command": "func", "address": f"{reset:04x}"},
            {"command": "callees", "address": f"{reset:04x}"},
            {"command": "decomp", "address": f"{irq:04x}"},
        ])["results"]
        assert function["result"]["function"]["entry"]["linear"] == reset
        assert any(call["to_function"] is not None for call in calls["result"]["callees"])
        assert decomp["result"]["decompilation"]
