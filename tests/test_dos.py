import json
import os
from pathlib import Path
from struct import pack, pack_into, unpack_from

import pytest

from retrore.cli import main
from retrore.dos import load_dos_flat, load_dos_mz
from retrore.mz import Address, MZError, read_mz_header


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


def _split_link_directory(*, counted=False, duplicate=False, outside_window=False):
    root = bytearray(0xC0)
    root[0] = 0xC3
    offsets = []
    for start in (0x60, 0x80) if duplicate else (0x60,):
        if counted:
            pack_into("<2H", root, start - 4, 5, 8)
        pack_into("<5H5B", root, start, 0, 4, 2, 3, 5, 0, 7, 1, 1, 7)
        offsets.extend((position, 0) for position in range(start, start + 10, 2))
    resident = _align(_mz(root, relocations=offsets))
    first_code = bytes.fromhex("b80300cb").ljust(16, b"\0") + b"\xcb"
    first = _mz(first_code, relocations=[(1, 2)], member=1)
    second_code = bytes(0x20) + bytes.fromhex("b80400cb").ljust(16, b"\0") + bytes.fromhex("b80100cb")
    second = _mz(second_code, relocations=[(1, 6 if outside_window else 4), (1, 5)], member=7)
    return resident + _align(first) + second


def _vroomm(code=bytes.fromhex("b80000cb"), *, fixups=(1,), entries=(0,)):
    root = bytearray(0x80)
    root[:6] = bytes.fromhex("9a20000200c3")
    fixup_table = pack(f"<{len(fixups)}H", *fixups)
    pack_into("<BBHI3H", root, 0x20, 0xCD, 0x3F, 0, 0, len(code), len(fixup_table), len(entries))
    for index, entry in enumerate(entries):
        pack_into("<BBHB", root, 0x40 + index * 5, 0xCD, 0x3F, entry, 0)
    pack_into("<8H", root, 0x60, 0, 0x20, 0, 0, 2, 0x20 + len(entries) * 5, 2, 0)
    resident = _mz(root, relocations=[(3, 0)])
    directory = len(resident) - 0x80 + 0x60
    return resident + pack("<4sIII", b"FBOV", len(code) + len(fixup_table), directory, 2) + code + fixup_table


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


@pytest.mark.parametrize("counted", [True, False])
def test_link_directory_keeps_member_padding_in_shared_runtime_window(counted, tmp_path, capsys):
    source, out = tmp_path / "link.exe", tmp_path / "out"
    source.write_bytes(_split_link_directory(counted=counted))
    report = _command(capsys, "load", source, "-o", out)
    _, first, second = report["units"]
    assert "diagnostics" not in report
    assert first["runtime_linear"] == second["runtime_linear"] == 0x10020
    assert first["segment_offsets"] == [0, 0x10]
    assert second["segment_offsets"] == [0x20, 0x30]
    internal = _command(capsys, "bytes", "link_0007:20", "--export", out, "--size", 4)
    assert internal["original"] == "b80400cb"
    assert internal["loaded"] == pack("<BHB", 0xB8, second["segment"] + 2, 0xCB).hex()
    resident = _command(capsys, "bytes", "link_0007:30", "--export", out, "--size", 4)
    assert resident["loaded"] == "b80110cb"
    mapping = _command(capsys, "address-map", "10040", "--from", "runtime", "--state", "link_0007", "--export", out)
    match, = mapping["matches"]
    assert match["unit"] == "link_0007" and match["file"]["offset"] == second["file_offset"] + 0x20
    if os.environ.get("GHIDRA_HOME") and not counted:
        imported = _command(capsys, "ghidra", "import", out, tmp_path / "project", "--load-views")
        blocks = imported["load_views"]["link_0007"]["blocks"]
        block, = (block for block in blocks if block["unit"] == "link_0007")
        assert int(block["address"].rsplit(":", 1)[-1], 16) == second["runtime_linear"]
        assert block["size"] == second["size"]


@pytest.mark.parametrize(("duplicate", "outside_window", "reason"), [
    (True, False, "multiple candidates"), (False, True, "could not locate"),
])
def test_link_keeps_unproven_layouts_partial(duplicate, outside_window, reason):
    resident, overlays = load_dos_mz(_split_link_directory(duplicate=duplicate, outside_window=outside_window),
                                     0x1000, "link.exe")
    diagnostic, = resident.diagnostics
    assert diagnostic["code"] == "overlay_layout_partial"
    assert reason in diagnostic["message"]
    assert all(overlay.runtime_segment is None and not overlay.fixups for overlay in overlays)


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


@pytest.mark.parametrize(("encoded", "restored"), [
    ("b8090050b8000050", "b8021050b8250050"),
    ("bb090053bb000053", "bb021053bb250053"),
])
def test_vroomm_restores_flagged_far_pointer_pushes(encoded, restored, tmp_path, capsys):
    source, out = tmp_path / "vroomm.exe", tmp_path / "out"
    code = bytes.fromhex(encoded).ljust(8, b"\x90") + b"\xcb"
    source.write_bytes(_vroomm(code, entries=(8, 0)))
    report = _command(capsys, "load", source, "-o", out)
    assert "diagnostics" not in report
    proof = _command(capsys, "bytes", "vroomm_0002:0", "--export", out, "--size", len(encoded) // 2)
    assert (proof["original"], proof["loaded"]) == (encoded, restored)


@pytest.mark.parametrize(("code", "fixups", "entries"), [
    ("b8090050bb000050cb", (1,), (8, 0)),
    ("b8090050bb000053cb", (1,), (8, 0)),
    ("6809006800009090cb", (1,), (8, 0)),
    ("680900bb00005390cb", (1,), (8, 0)),
    ("b809005068000090cb", (1,), (8, 0)),
    ("b8090050b8120050cb", (1,), (8, 0)),
    ("b8090050b8000050cb", (1,), (0, 0)),
    ("b8090050b8000050cb", (1, 5), (8, 0)),
])
def test_vroomm_reports_function_offsets_without_a_unique_valid_rewrite(code, fixups, entries):
    resident, (overlay,) = load_dos_mz(_vroomm(bytes.fromhex(code), fixups=fixups, entries=entries),
                                      0x1000, "vroomm.exe")
    assert all(fixup.segment for fixup in overlay.fixups)
    assert resident.diagnostics[0]["code"] == "overlay_fixups_partial"
    assert "1 unresolved function-pointer offset" in resident.diagnostics[0]["message"]


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


def _scrambled_pklite(*, add):
    stub = bytearray(0x180)
    start = 0x80
    key = 0x3D9A
    stub[:6] = pack("<BHBH", 0xB8, 0, 0xBA, key)
    loop = (b"\xb9" + pack("<H", (len(stub) - start) // 2 + 1) + b"\xbe" + pack("<H", 0x27E)
            + bytes.fromhex("8bfe fd") + (b"" if add else b"\x90")
            + bytes.fromhex("49 7407 ad92") + (b"\x03" if add else b"\x33")
            + bytes.fromhex("c2abebf6"))
    stub[0x30:0x30 + len(loop)] = loop
    decoder = bytes.fromhex("fd5f4f4fbe7e0203f28bcad1e9f3" if add else "fd8cdb5383c328")
    stub[start:start + len(decoder)] = decoder
    if add:
        stub[0x150:0x154] = bytes.fromhex("ac34988a")
        control = int("000011010110"[::-1], 2)
        literals = bytes(byte ^ (15 - index) for index, byte in enumerate(bytes.fromhex("b80200c3")))
        stream = pack("<H", control) + literals + bytes([2 ^ 0x98, 0xFF])
    else:
        stream = _packed_stream(0x10F, extra=True)
    for position in range(len(stub) - 2, start - 1, -2):
        word = int.from_bytes(stub[position:position + 2], "little")
        key = (word - key) & 0xFFFF if add else word ^ key
        pack_into("<H", stub, position, key)
    relocations = b"\x01\x00" + (b"\x00\x01" if add else b"\x01\x00") + b"\xff\xff"
    footer = pack("<4H", 1, 0x10, 0, 0)
    # The small v1.20 decoder is identifiable even when the header's large flag is set.
    version = 0x310A if add else 0x110F
    return _mz(stub + stream + relocations + footer, cs=0xFFF0, ip=0x100,
               extra=pack("<H", version) + b"PKLITE")


@pytest.mark.parametrize("add", [True, False])
def test_pklite_recovers_scrambled_decoders_and_relocations(add):
    program = _scrambled_pklite(add=add)
    resident, _ = load_dos_mz(program, 0x1000, "packed.exe")
    assert resident.relocations == (Address(0, 1),)
    assert resident.stack == Address(0x1001, 0x10)
    assert resident.image == bytes.fromhex("b80210c300c3" if add else "b80210c3")
    corrupt = bytearray(program)
    header_size = int.from_bytes(program[8:10], "little") * 16
    pack_into("<H", corrupt, header_size + 0x31, 0xFFFF)
    with pytest.raises(MZError, match="scrambled decoder lies outside the stub"):
        load_dos_mz(corrupt, 0x1000, "bad.exe")


def test_pklite_standard_decoder_table_takes_precedence_over_version_word():
    decoder = bytes.fromhex("fd8cdb5383c314").ljust(40, b"\0")
    decoder += bytes.fromhex("09 01 02 00 00 03 04 05 06") + bytes(8) + bytes(range(7, 12))
    footer = b"\x00" + pack("<4H", 0, 0x10, 0, 0)
    program = _mz(decoder.ljust(64, b"\0") + _packed_stream(0x10E) + footer,
                  cs=0xFFF0, ip=0x100, extra=pack("<H", 0x2114) + b"PKLITE")
    resident, _ = load_dos_mz(program, 0x1000, "packed.exe")
    assert resident.image == bytes.fromhex("b80200c3")


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


def test_pklite_com_follows_codec_offsets_without_copyright():
    intro = bytes.fromhex("b80000ba00003bc47367")
    copier = bytes.fromhex("8bc42d000025f0ff8bf8b90000be9001")
    decoder = bytes.fromhex("fd8bf84f4fbeae02")
    stub = (intro + copier).ljust(0x90, b"\0") + decoder
    packed = stub.ljust(0x1B0, b"\0") + _packed_stream(0x10E)
    restored = load_dos_flat(packed, com=True)
    assert restored.packer == "PKLITE"
    assert restored.image[0x100:] == bytes.fromhex("b80200c3")
    ordinary = (intro + b"\x8b").ljust(len(packed), b"\0")
    assert load_dos_flat(ordinary, com=True).image[0x100:] == ordinary


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
    com = (probe / "COM201.COM").read_bytes()
    packed_com = load_dos_flat(com, com=True)
    assert (packed_com.packer, packed_com.entry, packed_com.image[0x100:]) == (
        "PKLITE 2.01", Address(0x1000, 0x100), (probe / "testcom.com").read_bytes(),
    )
    assert com[46:52] == b"\x01\x02PKLI"
    unlabelled = load_dos_flat(com[:46] + bytes(22) + com[68:], com=True)
    assert unlabelled.packer == "PKLITE"
    assert (unlabelled.image, unlabelled.entry) == (packed_com.image, packed_com.entry)


@pytest.mark.parametrize("name", ["t10fr", "h10fr"])
def test_original_pklite_xor_output_when_available(name):
    if not (directory := os.environ.get("RETRORE_PKLITE_TESTEXE_DIR")):
        pytest.skip("set RETRORE_PKLITE_TESTEXE_DIR to the testexe repository's compress directory")
    probe = Path(directory)
    packed, _ = load_dos_mz((probe / f"{name}.exe").read_bytes(), 0x1000, f"{name}.exe")
    original, _ = load_dos_mz((probe / f"{name}.unc").read_bytes(), 0x1000, f"{name}.unc")
    assert packed.packer == "PKLITE 1.15"
    assert (packed.image, packed.entry, packed.stack, packed.relocations) == (
        original.image, original.entry, original.stack, original.relocations,
    )


def test_original_pklite_add_output_when_available():
    if not (directory := os.environ.get("RETRORE_PKLITE_SFX_DIR")):
        pytest.skip("set RETRORE_PKLITE_SFX_DIR to the PKZIP 2.04g installer and Deark reference")
    probe = Path(directory)
    packed, _ = load_dos_mz((probe / "pk204g.exe").read_bytes(), 0x1000, "pk204g.exe")
    original, _ = load_dos_mz((probe / "pk204g-unpacked.000.exe").read_bytes(), 0x1000, "pk204g-unpacked.000.exe")
    assert packed.packer == "PKLITE 1.20"
    assert len(packed.relocations) == 24
    assert (packed.image, packed.entry, packed.stack, packed.relocations) == (
        original.image, original.entry, original.stack, original.relocations,
    )


@pytest.mark.parametrize("clear_counts", [False, True])
def test_original_link_member_with_leading_padding(clear_counts, tmp_path, capsys):
    if not (directory := os.environ.get("RETRORE_DOS_LINK_LAYOUT_DIR")):
        pytest.skip("set RETRORE_DOS_LINK_LAYOUT_DIR to the LINK 3.65 LIVE365.EXE probe")
    source = Path(directory) / "LIVE365.EXE"
    original = source.read_bytes()
    count_site = read_mz_header(original).header_size + 0x1260
    assert unpack_from("<2H", original, count_site) == (4, 3)
    if clear_counts:
        source = tmp_path / "WITHOUT.EXE"
        source.write_bytes(original[:count_site] + bytes(4) + original[count_site + 4:])

    out = tmp_path / "link"
    program = _command(capsys, "load", source, "-o", out)
    _, first, second = program["units"]
    assert "diagnostics" not in program
    assert first["runtime_linear"] == second["runtime_linear"] == 0x10B00
    assert second["segment_offsets"] == [0, 0x100]
    assert second["size"] == 0x107
    padding = _command(capsys, "bytes", "link_0002:0", "--export", out, "--size", "256")
    assert padding["original"] == padding["loaded"] == bytes(256).hex()
    proof = _command(capsys, "bytes", "link_0002:100", "--export", out, "--size", 7)
    assert proof["original"] == "bac000b80700cb"
    assert proof["loaded"] == (pack("<BH", 0xBA, second["segment"] + 0x10) + bytes.fromhex("b80700cb")).hex()
    mapping = _command(capsys, "address-map", "10c00", "--from", "runtime", "--state", "link_0002", "--export", out)
    match, = mapping["matches"]
    assert match["unit"] == "link_0002"
    assert match["file"]["offset"] == 0x1D00


def test_original_dos_overlay_probe_outputs_when_available(tmp_path, capsys):
    if not (directory := os.environ.get("RETRORE_DOS_OVERLAY_PROBE_DIR")):
        pytest.skip("set RETRORE_DOS_OVERLAY_PROBE_DIR to the PADDED.EXE, VROOMM.EXE and VROOM86.EXE probe outputs")
    probe = Path(directory)
    out = tmp_path / "link"
    program = _command(capsys, "load", probe / "PADDED.EXE", "-o", out)
    _, first, second = program["units"]
    assert "diagnostics" not in program
    assert first["runtime_linear"] == second["runtime_linear"] == 0x10100
    assert first["segment_offsets"] == [0, 0x30]
    proof = _command(capsys, "bytes", "link_0001:30", "--export", out, "--size", 3)
    assert proof["original"] == "b81300"
    assert proof["loaded"] == pack("<BH", 0xB8, first["segment"] + 3).hex()
    assert proof["address"]["file"]["offset"] == 0x830

    for filename, encoded, offset_site in (
        ("VROOMM.EXE", "689000682000", 4),
        ("VROOM86.EXE", "b8900050b8200050", 5),
    ):
        binary = probe / filename
        out = tmp_path / binary.stem
        program = _command(capsys, "load", binary, "-o", out)
        _, caller, target = program["units"]
        assert "diagnostics" not in program
        proof = _command(capsys, "bytes", f"{caller['name']}:3", "--export", out, "--size", len(encoded) // 2)
        assert proof["original"] == encoded
        stub = next(row["address"] for row in program["stubs"] if row["target"]["linear"] == target["linear"])
        loaded = bytearray.fromhex(encoded)
        pack_into("<H", loaded, 1, stub["segment"])
        assert unpack_from("<H", loaded, offset_site)[0] == stub["offset"]
        assert proof["loaded"] == loaded.hex()

        # Exercise the original overlay bytes with the flag set and the offset changed
        # from the resident stub to the function entry. TLINK emits the stub offset directly.
        flagged = bytearray(binary.read_bytes())
        site = proof["address"]["file"]["offset"]
        encoded_segment, = unpack_from("<H", flagged, site + 1)
        assert not encoded_segment & 7
        pack_into("<H", flagged, site + 1, encoded_segment | 1)
        pack_into("<H", flagged, site + offset_site, target["entries"][0])
        modified = tmp_path / f"flagged-{filename}"
        modified.write_bytes(flagged)
        export = tmp_path / f"flagged-{binary.stem}"
        program = _command(capsys, "load", modified, "-o", export)
        if filename == "VROOMM.EXE":
            diagnostic, = program["diagnostics"]
            assert diagnostic["code"] == "overlay_fixups_partial"
            assert "1 unresolved function-pointer offset" in diagnostic["message"]
            pack_into("<H", loaded, offset_site, target["entries"][0])
        else:
            assert "diagnostics" not in program
        proof = _command(capsys, "bytes", f"{caller['name']}:3", "--export", export, "--size", len(loaded))
        assert proof["original"] == flagged[site:site + len(loaded)].hex()
        assert proof["loaded"] == loaded.hex()


def test_original_tlink_vroomm_output_when_available():
    if not (directory := os.environ.get("RETRORE_VROOMM_DIR")):
        pytest.skip("set RETRORE_VROOMM_DIR to a directory containing a TLINK output named VROOMM.EXE")
    source = Path(directory) / "VROOMM.EXE"
    resident, overlays = load_dos_mz(source.read_bytes(), 0x1000, source.name)
    assert resident.toolchain["family"] == "Borland TLINK"
    assert overlays and all(overlay.format == "VROOMM" and overlay.entries for overlay in overlays)
