import json
from dataclasses import replace
from struct import pack

import pytest

from retrore.cli import main
from retrore.mz import Address, MZError, MZExecutable


def make_packed_mz(image, *, decoder_segment, decoder_ip, extra_header=b""):
    length = 32 + len(image)
    fields = pack(
        "<2s13H", b"MZ", length % 512, (length + 511) // 512, 0, 2, 0, 0xFFFF,
        0, 128, 0, decoder_ip, decoder_segment, 0x1C, 0,
    )
    return fields + extra_header.ljust(4, b"\0") + image


def make_exepack(header_size):
    # A plain prefix, a literal run, then a fill run, followed by alignment padding.
    compressed = b"\x00\0\x07\0" + b"hello" + pack("<HB", 5, 0xB3)
    compressed += b"A" + pack("<HB", 23, 0xB0)
    message = b"Packed file is corrupt"
    relocs = pack("<HH", 1, 2) + bytes(30)
    skip = 1 if header_size == 16 else 2
    stub = pack("<4H", 4, 0, 0, header_size + len(message) + len(relocs))
    if header_size == 20:
        stub += bytes(2)
    stub += pack("<3H", 0x400, 2, 2 + skip - 1)
    if header_size >= 18:
        stub += pack("<H", skip)
    stub += b"RB"
    return make_packed_mz(
        compressed.ljust(16, b"\xff") + bytes(16 * (skip - 1)) + stub + message + relocs,
        decoder_segment=skip, decoder_ip=header_size,
    )


@pytest.mark.parametrize("header_size", [16, 18, 20])
def test_exepack_expansion_and_relocation(header_size):
    exe = MZExecutable.parse(make_exepack(header_size))
    program = exe.load(0x2000)
    assert exe.packer == "EXEPACK"
    assert program.entry == Address(0x2000, 4)
    assert program.stack == Address(0x2002, 0x400)
    assert program.relocations == (Address(0, 2),)
    assert program.image == b"\0\0\x07\x20hello" + b"A" * 23


def test_exepack_rejects_bad_stream_and_relocation():
    raw = bytearray(make_exepack(16))
    raw[47] = 0xB4
    with pytest.raises(MZError, match="compression record"):
        MZExecutable.parse(raw).load()
    raw = bytearray(make_exepack(16))
    raw[-30] = 0xFF
    with pytest.raises(MZError, match="relocation table"):
        MZExecutable.parse(raw).load()


@pytest.mark.parametrize("version", ["0.90", "0.91", "0.91e"])
def test_lzexe_literals_overlapping_copy_and_relocation(version):
    # Control bits encode three literals, a three-byte short copy, and the end marker.
    compressed = (pack("<H", 0b101000111) + b"A\x07\x00\xfd\0\0\0").ljust(16, b"\0")
    if version == "0.90":
        reloc_offset = 0x19D
        relocs = pack("<HH", 1, 1) + bytes(30)
    else:
        reloc_offset = 0x158
        relocs = b"\x01\x00\x01\x00"
    decoder = pack("<7H", 0, 0, 0x200, 1, 1, 0, reloc_offset + len(relocs))
    raw = make_packed_mz(
        compressed + decoder.ljust(reloc_offset, b"\0") + relocs,
        decoder_ip=0x12, decoder_segment=1,
    )
    exe = replace(MZExecutable.parse(raw), packer=f"LZEXE {version}")
    program = exe.load(0x2000)
    assert program.image == b"A\x07\x20A\x07\x00"
    assert program.stack == Address(0x2001, 0x200)
    assert program.relocations == (Address(0, 1),)


def test_unsupported_packer_reports_json(tmp_path, capsys):
    program = tmp_path / "packed.exe"
    program.write_bytes(make_packed_mz(
        bytes.fromhex("b8 0000 ba 0000 8c db 03 d8 3b") + bytes(64),
        decoder_segment=0xFFF0, decoder_ip=0x100,
    ))
    assert main(["info", str(program), "--json"]) == 1
    error = json.loads(capsys.readouterr().err)
    assert error == {"packer": "PKLITE", "error": "unsupported DOS executable packer (PKLITE)"}


def test_unknown_lzexe_variant_is_not_loaded_as_plain_mz():
    raw = make_packed_mz(bytes(80), decoder_segment=1, decoder_ip=0x12, extra_header=b"LZ91")
    exe = MZExecutable.parse(raw)
    assert exe.packer == "unknown LZEXE variant"
    with pytest.raises(MZError, match="unknown LZEXE variant"):
        exe.load()
