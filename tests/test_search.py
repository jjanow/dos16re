import json
from struct import pack_into

from retrore.cli import main


def test_searches_each_exported_unit_without_crossing_its_boundary(tmp_path, capsys):
    root = bytes.fromhex("c3 41 41 41 34 12 82") + bytes(8) + b"\xde"
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(root), 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
    exe = tmp_path / "sample.exe"
    exe.write_bytes(header + root)
    near = tmp_path / "Near.ovr"
    near.write_bytes(bytes.fromhex("ad 41 41 34 12 82") + bytes(12))
    extra = tmp_path / "Extra.ovr"
    extra.write_bytes(bytes.fromhex("de ad ff ff"))
    export = tmp_path / "image"
    assert main([
        "load", str(exe), "-o", str(export), "--overlay", f"{extra}@2000", "--overlay", f"{near}@1001",
    ]) == 0
    capsys.readouterr()

    search = ["where-is", "--export", str(export)]
    for options, pattern, locations in (
        (["--bytes", "41 41"], "4141", ["root:0001", "root:0002", "Near:0001"]),
        (["--string", "é"], "82", ["root:0006", "Near:0005"]),
        (["--constant", "0x1234"], "3412", ["root:0004", "Near:0003"]),
        (["--constant", "-1", "--width", "1"], "ff", ["Extra:0002", "Extra:0003"]),
        (["--bytes", "00 de"], "00de", ["root:000e"]),
        (["--bytes", "12 12"], "1212", []),
    ):
        assert main([*search, *options, "--json"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["pattern"] == pattern
        assert report["count"] == len(locations)
        assert [match["unit_address"] for match in report["matches"]] == locations

    assert main([*search, "--bytes", "dead", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["matches"] == [
        {"address": "2000:0000", "unit_address": "Extra:0000", "linear": 0x20000},
    ]
    assert main([*search, "--bytes", "00"]) == 0
    output = capsys.readouterr().out.splitlines()
    assert output[0] == "20 matches"
    assert len(output) == 12
    assert output[-1] == "Use --json for all matches."

    assert main([*search, "--bytes", "", "--json"]) == 1
    assert "at least one byte" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_reports_matches_past_the_first_64_kib_of_the_root_unit(tmp_path, capsys):
    root = b"\xc3" + bytes(0xFFFF) + b"\x34\x12"
    header = bytearray(32)
    size = len(header) + len(root)
    pack_into("<2s13H", header, 0, b"MZ", size % 512, (size + 511) // 512, 0, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
    exe = tmp_path / "large.exe"
    exe.write_bytes(header + root)
    export = tmp_path / "image"
    assert main(["load", str(exe), "-o", str(export)]) == 0
    capsys.readouterr()

    assert main(["where-is", "--export", str(export), "--bytes", "3412", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["matches"] == [
        {"address": "2000:0000", "unit_address": "root:10000", "linear": 0x20000},
    ]
