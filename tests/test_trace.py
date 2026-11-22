import json
from struct import pack_into

from dos16re.cli import main


def test_imports_dosbox_x_log_and_rebases_runtime_units(tmp_path, capsys):
    root = b"\xc3" + bytes(31)
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(root), 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
    exe = tmp_path / "sample.exe"
    exe.write_bytes(header + root)
    overlay = tmp_path / "OV1.ovr"
    overlay.write_bytes(b"\xcb" + bytes(15))
    export = tmp_path / "image"
    assert main(["load", str(exe), "-o", str(export), "--overlay", f"{overlay}@1200"]) == 0
    capsys.readouterr()

    trace = tmp_path / "LOGCPU.TXT"
    trace.write_text(
        "CPU log\n"
        "2000:0000  ret                            EAX:00000000\n"
        "2000:0000001F\n"
        "2001:000F  nop                            EAX:00000000\n"
        "2.500000 3000:00000000  retf              CB         EAX:00000000\n"
        "3000:00000010\n"
        "1200:00000000\n"
        "f000:fffe\n"
        "2000:00010000\n",
        encoding="utf-8-sig",
    )
    command = ["trace", str(trace), "--export", str(export), "--runtime-base", "2000"]
    assert main([*command, "--overlay-segment", "ov1=3000", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report == {
        "instructions": 7, "ignored_lines": 2, "analysis": None,
        "mapped": [
            {"runtime_address": "2000:0000", "address": "1000:0000", "unit_address": "root:0000", "linear": 0x10000, "count": 1},
            {"runtime_address": "2000:001f", "address": "1000:001f", "unit_address": "root:001f", "linear": 0x1001F, "count": 2},
            {"runtime_address": "3000:0000", "address": "1200:0000", "unit_address": "OV1:0000", "linear": 0x12000, "count": 1},
        ],
        "unmapped": [
            {"runtime_address": "1200:0000", "count": 1},
            {"runtime_address": "3000:0010", "count": 1},
            {"runtime_address": "f000:fffe", "count": 1},
        ],
    }

    assert main([*command, "--overlay-segment", "OV1=2001", "--json"]) == 1
    assert "runtime ranges overlap" in json.loads(capsys.readouterr().err)["error"]

    trace.write_text("2000:00010000\n", encoding="ascii")
    assert main([*command, "--json"]) == 1
    assert "no 16-bit DOSBox-X instruction addresses" in json.loads(capsys.readouterr().err)["error"]
