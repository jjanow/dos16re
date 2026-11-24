import json
import os
from pathlib import Path
from struct import pack, pack_into

import pytest

from retrore.cli import main
from retrore.dos import load_dos_flat, load_dos_mz
from retrore.mz import Address, MZError


def _mz(image, *, relocations=(), member=0, cs=0, ip=0, extra=b""):
    header_size = (28 + len(extra) + 4 * len(relocations) + 15) & -16
    size = header_size + len(image)
    header = pack("<2s13H", b"MZ", size % 512, (size + 511) // 512, len(relocations),
                  header_size // 16, 0, 0xFFFF, 0, 0x100, 0, ip, cs, 28 + len(extra), member)
    table = b"".join(pack("<HH", offset, segment) for offset, segment in relocations)
    return (header + extra + table).ljust(header_size, b"\0") + image


def _align(data):
    return data.ljust((len(data) + 511) & -512, b"\0")


def _link_program(directory=True):
    root = bytearray(0x80)
    root[:4] = bytes.fromhex("b80000c3")
    root[0x50:0x5d] = pack("<5H3B", 3, 3, 0, 2, 2, 0, 1, 2)
    offsets = [(0x54, 0), (0x56, 0), (0x58, 0)] if directory else []
    first = _mz(bytes.fromhex("b80200cb"), relocations=[(1, 2)], member=1)
    second = _mz(bytes.fromhex("b80400cb"), member=2)
    return _align(_mz(root, relocations=offsets)) + _align(first) + second


def _vroomm():
    root = bytearray(0x80)
    root[:6] = bytes.fromhex("9a20000200c3")
    pack_into("<BBHI3H", root, 0x20, 0xCD, 0x3F, 0, 0, 4, 2, 1)
    root[0x40:0x45] = bytes.fromhex("cd3f000000")
    pack_into("<8H", root, 0x60, 0, 0x20, 0, 0, 2, 0x25, 2, 0)
    resident = _mz(root, relocations=[(3, 0)])
    directory = len(resident) - 0x80 + 0x60
    return resident + pack("<4sIII", b"FBOV", 6, directory, 2) + bytes.fromhex("b80000cb0100")


def _command(capsys, *arguments):
    assert main([*map(str, arguments), "--json"]) == 0, capsys.readouterr().err
    return json.loads(capsys.readouterr().out)


def test_com_and_raw_startup_and_provenance(tmp_path, capsys):
    com = tmp_path / "demo.com"
    com.write_bytes(bytes.fromhex("8cd8c3"))
    out = tmp_path / "com"
    report = _command(capsys, "load", com, "-o", out, "--base-segment", "2800")
    assert (report["dos_format"], report["load_offset"], report["initial_segments"]) == (
        "COM", 0x100, {"ds": 0x2800, "es": 0x2800},
    )
    assert report["stack"]["offset"] == 0xfffe
    assert (out / "image.bin").read_bytes()[:4] == bytes.fromhex("cd200038")
    result = _command(capsys, "address-map", "100", "--from", "image", "--export", out, "--source-file", com)
    assert result["matches"][0]["file"]["offset"] == 0
    assert _command(capsys, "address-map", "root:20", "--export", out)["matches"][0]["file"] is None
    result = _command(capsys, "call", "root:0100", "--export", out)
    assert result["registers"]["ax"] == 0x2800
    raw = tmp_path / "demo.bin"
    raw.write_bytes(bytes.fromhex("90 8c d8 c3"))
    result = _command(capsys, "info", raw, "--dos-raw", "--dos-offset", "80", "--dos-entry", "81")
    assert (result["dos_format"], result["entry"]["offset"]) == ("RAW", 0x81)
    assert result["units"][0]["file_spans"] == [{"offset": 0x80, "file_offset": 0, "size": 4}]


def test_link_native_states_relocate_and_keep_member_bytes(tmp_path, capsys):
    source, out = tmp_path / "demo.exe", tmp_path / "out"
    source.write_bytes(_link_program())
    report = _command(capsys, "load", source, "-o", out)
    _, first, second = report["units"]
    assert first["runtime_linear"] == second["runtime_linear"] == 0x10020
    assert [row["name"] for row in report["load_manifest"]["states"]] == ["root", "link_0001", "link_0002"]
    matches = _command(capsys, "address-map", "10020", "--from", "runtime", "--all-states", "--export", out)["matches"]
    assert [(row["unit"], row["file"]["offset"]) for row in matches] == [
        (unit["name"], unit["file_offset"] + (0x20 if unit["name"] == "root" else 0))
        for unit in report["units"]
    ]
    proof = _command(capsys, "bytes", "link_0001:0", "--export", out, "--size", 4)
    assert proof["original"] == "b80200cb"
    assert proof["loaded"] == (b"\xb8" + pack("<H", first["segment"]) + b"\xcb").hex()
    loaded, embedded = load_dos_mz(_link_program(directory=False) + b"trailing bytes", 0x1000, "demo.exe")
    assert [row["code"] for row in loaded.diagnostics] == ["overlay_layout_partial", "unmapped_trailer"]
    assert [overlay.runtime_segment for overlay in embedded] == [None, None]
    with pytest.raises(MZError, match="Microsoft LINK member.*truncated"):
        load_dos_mz(_link_program()[:-1], 0x1000, "bad.exe")


def test_vroomm_restores_stub_call_fixup_and_source(tmp_path, capsys):
    source, out = tmp_path / "demo.exe", tmp_path / "out"
    source.write_bytes(_vroomm())
    report = _command(capsys, "load", source, "-o", out)
    _, overlay = report["units"]
    assert (overlay["name"], overlay["overlay_format"], overlay["relocation_count"]) == ("vroomm_0002", "VROOMM", 1)
    assert report["stubs"][0]["original"] == "cd3f000000"
    assert report["calls"][0]["target"]["linear"] == overlay["linear"]
    proof = _command(capsys, "bytes", "vroomm_0002:0", "--export", out, "--size", 4)
    assert (proof["original"], proof["loaded"]) == ("b80000cb", "b80010cb")
    with pytest.raises(MZError, match="truncated Borland FBOV section"):
        load_dos_mz(_vroomm()[:-1], 0x1000, "bad.exe")


def _packed_stream(number, *, extra=False, large=False):
    body = bytes.fromhex("b80200c3")
    if extra:
        body = bytes(byte ^ (15 - index) for index, byte in enumerate(body))
    end = {0x114: ("010011" if large else "0110")}.get(number, "011100" if large else "011")
    control = int(("00001" + end)[::-1], 2)
    return pack("<H", control) + body + b"\xff"


@pytest.mark.parametrize(("number", "extra", "large"), [(0x201, False, False), (0x10e, True, True), (0x114, False, True)])
def test_pklite_exe_literals_relocation_and_footer(number, extra, large, tmp_path, capsys):
    flags = (0x1000 if extra else 0) | (0x2000 if large else 0)
    decoder = bytes.fromhex("fd8cdb5383c314").ljust(64, b"\0")
    reloc = pack("<3H", 1, 1, 0xffff) if extra else bytes.fromhex("010000010000")
    footer = pack("<4H", 1, 0x10, 0, 0)
    data = _mz(decoder + _packed_stream(number, extra=extra, large=large) + reloc + footer,
               cs=0xfff0, ip=0x100, extra=pack("<H", number | flags) + b"PKLITE")
    source, out = tmp_path / "pklite.exe", tmp_path / "out"
    source.write_bytes(data)
    report = _command(capsys, "load", source, "-o", out)
    assert report["packer"] == f"PKLITE {(number >> 8)}.{number & 0xff:02d}"
    assert report["relocations"] == [1]
    assert report["stack"]["segment"] == 0x1001
    assert (out / "image.bin").read_bytes() == bytes.fromhex("b80210c3")


def test_pklite_com_does_not_claim_source_offsets(tmp_path, capsys):
    decoder = bytearray(bytes.fromhex("ba0000a102002d20068ccb").ljust(500, b"\0"))
    decoder[36:40] = bytes.fromhex("0e01") + b"PK"
    source = tmp_path / "packed.com"
    source.write_bytes(decoder + _packed_stream(0x10e))
    out = tmp_path / "image"
    catalog = tmp_path / "catalog.json"
    catalog.write_text('{"version":1,"signatures":[{"name":"routine","pattern":"b8 02 00 c3"}]}')
    report = _command(capsys, "load", source, "-o", out, "--signatures", catalog)
    assert report["packer"] == "PKLITE 1.14"
    assert report["toolchain_signatures"][0]["status"] == "matched"
    assert (out / "image.bin").read_bytes()[0x100:] == bytes.fromhex("b80200c3")
    assert report["units"][0]["file_spans"] == []


def test_original_dos_tool_outputs_when_available():
    if not (directory := os.environ.get("RETRORE_DOS_LOADER_DIR")):
        pytest.skip("set RETRORE_DOS_LOADER_DIR to LINK 3.65 and PKLITE 2.01 validation outputs")
    probe = Path(directory)
    resident, overlays = load_dos_mz((probe / "TEST2.EXE").read_bytes(), 0x1000, "TEST2.EXE")
    assert resident.diagnostics == ()
    assert [(overlay.runtime_segment, len(overlay.fixups)) for overlay in overlays] == [(0x1006, 5), (0x1006, 1)]

    original, _ = load_dos_mz((probe / "PACK.EXE").read_bytes(), 0x1000, "PACK.EXE")
    packed, _ = load_dos_mz((probe / "PACK201.EXE").read_bytes(), 0x1000, "PACK201.EXE")
    assert packed.packer == "PKLITE 2.01"
    assert (packed.image, packed.entry, packed.stack, packed.relocations) == (
        original.image, original.entry, original.stack, original.relocations,
    )
    packed_com = load_dos_flat((probe / "COM201.COM").read_bytes(), com=True)
    assert (packed_com.packer, packed_com.entry, packed_com.image[0x100:]) == (
        "PKLITE 2.01", Address(0x1000, 0x100), (probe / "testcom.com").read_bytes(),
    )


def test_original_tlink_vroomm_output_when_available():
    if not (directory := os.environ.get("RETRORE_VROOMM_DIR")):
        pytest.skip("set RETRORE_VROOMM_DIR to a directory containing a TLINK output named VROOMM.EXE")
    source = Path(directory) / "VROOMM.EXE"
    resident, overlays = load_dos_mz(source.read_bytes(), 0x1000, source.name)
    assert resident.toolchain["family"] == "Borland TLINK"
    assert overlays and all(overlay.format == "VROOMM" and overlay.entries for overlay in overlays)
