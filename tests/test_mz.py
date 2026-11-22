import json
from struct import pack_into, unpack_from

import pytest

from dos16re.cli import main
from dos16re.mz import Address, MZError, MZExecutable


def make_mz(*, total_size=70, trailing=b""):
    header = bytearray(48)
    page_count = (total_size + 511) // 512
    pack_into(
        "<2s13H", header, 0,
        b"MZ", total_size % 512, page_count, 2, 3, 8, 16,
        0xFFFF, 0xFFFE, 0, 3, 1, 0x24, 0,
    )
    pack_into("<4H", header, 0x24, 1, 0, 4, 1)
    image = bytearray(total_size - len(header))
    pack_into("<H", image, 1, 0xFFFF)
    pack_into("<H", image, 20, 7)
    return bytes(header + image) + trailing


@pytest.mark.parametrize("total_size", [70, 512, 550, 1024])
def test_load_relocates_only_the_declared_module(total_size):
    raw = make_mz(total_size=total_size, trailing=b"appended overlay")
    executable = MZExecutable.parse(raw)
    loaded = executable.load(0x2000)

    assert executable.header.file_size == total_size
    assert executable.header.min_alloc_paragraphs == 8
    assert executable.relocations == (Address(0, 1), Address(1, 4))
    expected = bytearray(raw[48:total_size])
    pack_into("<H", expected, 1, 0x1FFF)
    pack_into("<H", expected, 20, 0x2007)
    assert loaded.image == expected
    assert loaded.entry == Address(0x2001, 3)
    assert loaded.stack == Address(0x1FFF, 0xFFFE)
    assert loaded.entry.linear == 0x20013
    assert executable.load(0).image == raw[48:total_size]


def test_relocation_free_module_can_leave_table_offset_unset():
    raw = bytearray(make_mz())
    pack_into("<H", raw, 6, 0)
    pack_into("<H", raw, 24, 0)
    assert MZExecutable.parse(raw).load().image == raw[48:]


@pytest.mark.parametrize(
    ("field_offset", "value", "message"),
    [
        (0, 0, "signature"),
        (2, 512, "page counts"),
        (4, 0, "page counts"),
        (8, 1, "header size"),
        (8, 5, "header size"),
        (24, 26, "relocation table"),
        (24, 44, "relocation table"),
        (40, 5, "relocation 1"),
    ],
)
def test_rejects_invalid_mz_fields(field_offset, value, message):
    raw = bytearray(make_mz())
    pack_into("<H", raw, field_offset, value)
    with pytest.raises(MZError, match=message):
        MZExecutable.parse(raw)


@pytest.mark.parametrize(
    ("size", "message"), [(27, "truncated MZ header"), (69, "truncated MZ executable")]
)
def test_rejects_truncated_mz(size, message):
    with pytest.raises(MZError, match=message):
        MZExecutable.parse(make_mz()[:size])


def test_rejects_invalid_load_bases():
    executable = MZExecutable.parse(make_mz())
    with pytest.raises(MZError, match="base segment"):
        executable.load(0x10000)
    with pytest.raises(MZError, match="1 MiB"):
        executable.load(0xFFFF)


def test_cli_load_and_info_share_the_map(tmp_path, capsys):
    program = tmp_path / "sample.exe"
    program.write_bytes(make_mz())
    output = tmp_path / "export"
    assert main(["load", str(program), "-o", str(output), "--json"]) == 0
    program_map = json.loads((output / "map.json").read_text())
    assert json.loads(capsys.readouterr().out) == program_map
    assert main(["info", str(program), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == program_map
    assert program_map["entry"] == {"segment": 0x1001, "offset": 3, "linear": 0x10013}
    assert program_map["units"] == [
        {"name": "root", "segment": 0x1000, "linear": 0x10000, "image_offset": 0, "size": 22}
    ]
    assert unpack_from("<H", (output / "image.bin").read_bytes(), 20) == (0x1007,)

    assert main(["info", str(program), "--base-segment", "3000"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "MZ  entry 3001:0003  stack 2fff:fffe",
        "root  3000:0000  22 bytes",
    ]


def test_cli_preserves_existing_export_and_rolls_back(tmp_path, capsys):
    program = tmp_path / "sample.exe"
    program.write_bytes(make_mz())
    map_path = tmp_path / "map.json"
    map_path.write_text("{}")

    assert main(["load", str(program), "-o", str(tmp_path), "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "map.json" in json.loads(captured.err)["error"]
    assert map_path.read_text() == "{}"
    assert not (tmp_path / "image.bin").exists()


def test_cli_rejects_invalid_program_before_creating_output(tmp_path, capsys):
    program = tmp_path / "bad.exe"
    program.write_bytes(b"MZ")
    output = tmp_path / "export"

    assert main(["load", str(program), "-o", str(output)]) == 1
    assert "truncated MZ header" in capsys.readouterr().err
    assert not output.exists()
