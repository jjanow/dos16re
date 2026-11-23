import json
import os
from pathlib import Path
from struct import pack_into

import pytest

from retrore.cli import main
from retrore.evidence import inspect_bytes, map_address
from retrore.genesis import GenesisError, build_genesis_image
from retrore.ghidra import import_program, query_batch
from retrore.search import find_pointers, find_relocations, find_text


def _rom(*, sram=True):
    data = bytearray(0x280)
    data[0x100:0x110] = b"SEGA MEGA DRIVE "
    data[0x150:0x159] = b"TEST CART"
    data[0x1F0:0x1F3] = b"JUE"
    pack_into(">2I", data, 0, 0x00FFFFFC, 0x200)
    pack_into(">I", data, 8, 0x221)  # Odd addresses cannot be execution entries.
    pack_into(">I", data, 0x70, 0xFF000240)  # The bus ignores the top byte.
    pack_into(">I", data, 0x78, 0x240)
    pack_into(">4I", data, 0x1A0, 0, len(data) - 1, 0xFF0000, 0xFFFFFF)
    if sram:
        pack_into(">2sBBII", data, 0x1B0, b"RA", 0xF8, 0x20, 0x200001, 0x203FFF)
    data[0x200:0x20A] = bytes.fromhex("4eb9 0000 0220 60fe 4e71")  # jsr, bra.s, nop
    data[0x220:0x22A] = bytes.fromhex("33fc 1234 00c0 0004 4e75")  # move.w to VDP, rts
    data[0x240:0x24A] = bytes.fromhex("13fc 0001 0020 0001 4e73")  # move.b to SRAM, rte
    return data


def test_genesis_export_and_shared_queries(tmp_path, capsys):
    source, out = tmp_path / "test.bin", tmp_path / "out"
    rom = _rom()
    source.write_bytes(rom)
    assert main(["load", str(source), "--entry", "220", "--entry", "240", "-o", str(out), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["format"] == "GENESIS"
    assert (out / "image.bin").read_bytes() == rom
    assert report["initial_ssp"] == 0xFFFFFC
    assert report["entry"] == {"linear": 0x200, "unit_address": "rom:0000"}
    assert [entry["linear"] for entry in report["entries"]] == [0x200, 0x240, 0x220]
    assert report["vectors"][28]["value"] == 0xFF000240
    assert report["vectors"][28]["target"] == 0x240
    assert "target" not in report["vectors"][2]
    sram, = [region for region in report["memory_map"] if region["name"] == "cart_sram"]
    assert (sram["linear"], sram["size"], sram["capacity"], sram["bus"], sram["source"]) == (
        0x200000, 0x4000, 0x2000, "odd", "header",
    )
    assert find_text(out, "TEST CART")["matches"][0]["unit_address"] == "header:0050"
    assert any(row["unit_address"] == "vectors:0004" for row in find_pointers(out, "rom:0000")["matches"])
    assert not find_relocations(out)["has_relocations"]
    assert map_address(out, "220", space="file")["matches"][0]["unit_address"] == "rom:0020"
    assert inspect_bytes(out, "rom:0020", size=2)["address"]["file"]["offset"] == 0x220
    assert main(["info", str(source), "--genesis", "--genesis-sram", "300000:3000ff", "--json"]) == 0
    override = json.loads(capsys.readouterr().out)
    sram, = [region for region in override["memory_map"] if region["name"] == "cart_sram"]
    assert (sram["capacity"], sram["bus"], sram["source"]) == (0x100, "word", "override")
    assert override["cartridge"]["external_ram"]["start"] == 0x200001
    assert main(["info", str(source), "--genesis", "--base-address", "100", "--json"]) == 1
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "input_invalid"


def test_genesis_validates_input_and_keeps_overlapping_ram_in_header_only():
    rom = _rom()
    with pytest.raises(GenesisError, match="Sega header"):
        build_genesis_image(b"\0" * len(rom), "test.bin")
    with pytest.raises(GenesisError, match="truncated"):
        build_genesis_image(rom[:-2], "test.bin")
    with pytest.raises(GenesisError, match="must be even"):
        build_genesis_image(rom[:-1], "test.bin")
    with pytest.raises(GenesisError, match="must be even and within"):
        build_genesis_image(rom, "test.bin", entries=[0x221])
    with pytest.raises(GenesisError, match="byte lanes"):
        build_genesis_image(rom, "test.bin", sram=(0x200001, 0x203FFE))
    with pytest.raises(GenesisError, match="overlaps"):
        build_genesis_image(rom, "test.bin", sram=(0x201, 0x229))
    pack_into(">2I", rom, 0x1B4, 0x201, 0x229)
    _, report = build_genesis_image(rom, "test.bin")
    assert report["cartridge"]["external_ram"]["start"] == 0x201
    assert all(region["name"] != "cart_sram" for region in report["memory_map"])


def test_genesis_headless_vectors_calls_and_io(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Genesis Ghidra integration test")
    source, out, project = (tmp_path / name for name in ("test.md", "out", "project"))
    source.write_bytes(_rom())
    assert main(["load", str(source), "-o", str(out)]) == 0
    capsys.readouterr()
    report = import_program(out, project)
    assert (report["format"], report["entries"], report["memory_view"]) == ("GENESIS", 2, "linear")
    calls, vdp, sram, vector = query_batch(project, [
        {"command": "callees", "address": "rom:0000"},
        {"command": "decomp", "address": "rom:0020"},
        {"command": "xrefs", "address": "rom:0040", "direction": "outgoing"},
        {"command": "xrefs", "address": "vectors:0070", "direction": "outgoing"},
    ])["results"]
    assert calls["result"]["callees"][0]["to_function"]["entry"]["linear"] == 0x220
    assert "VDP_CONTROL" in vdp["result"]["decompilation"]
    assert any(ref["type"] == "WRITE" and ref["to"]["unit_address"] == "cart_sram:0001"
               for ref in sram["result"]["outgoing"])
    assert any(ref["to"]["linear"] == 0x240 for ref in vector["result"]["outgoing"])


def test_countdown_to_doomsday_cartridge(tmp_path, capsys):
    directory = os.environ.get("RETRORE_CTD_GENESIS_DIR")
    if not directory:
        pytest.skip("set RETRORE_CTD_GENESIS_DIR to validate the original Genesis cartridge")
    source, = (file for file in Path(directory).iterdir() if file.suffix.lower() in (".md", ".bin", ".gen"))
    out, project = tmp_path / "out", tmp_path / "project"
    assert main(["load", str(source), "--genesis-sram", "200001:203fff", "-o", str(out), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    cartridge = report["cartridge"]
    assert cartridge["rom"] == {"start": 0, "end": 0xFFFFF, "file_offset": 0, "size": 0x100000}
    assert cartridge["external_ram"] is None
    assert cartridge["checksum"] == cartridge["computed_checksum"] == 0xD7B6
    assert [entry["linear"] for entry in report["entries"]] == [0x200, 0xF1B64, 0xDE8C]
    assert (out / "image.bin").read_bytes() == source.read_bytes()
    assert map_address(out, "rom:dc8c")["matches"][0]["file"]["offset"] == 0xDE8C
    if os.environ.get("GHIDRA_HOME"):
        assert import_program(out, project)["entries"] == 3
        startup, vblank, vdp, sram = query_batch(project, [
            {"command": "callees", "address": "200"},
            {"command": "decomp", "address": "de8c"},
            {"command": "xrefs", "address": "c00004", "direction": "incoming", "limit": 5},
            {"command": "xrefs", "address": "200001", "direction": "incoming"},
        ])["results"]
        assert any(call["to"]["linear"] == 0x19CCA for call in startup["result"]["callees"])
        assert vblank["result"]["decompilation"]
        assert any(ref["type"] == "WRITE" for ref in vdp["result"]["incoming"])
        assert any(ref["type"] == "READ" and ref["from"]["linear"] == 0x19CFA
                   and ref["to"]["unit_address"] == "cart_sram:0001" for ref in sram["result"]["incoming"])
