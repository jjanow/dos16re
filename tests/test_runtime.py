import json
import os
from pathlib import Path
from struct import pack, pack_into

import pytest
from unicorn import UC_ARCH_X86, UC_HOOK_INTR, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AH, UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_IP, UC_X86_REG_SP, UC_X86_REG_SS,
)

from retrore.cli import main
from retrore.mz import Address, LoadedMZ, MZExecutable
from retrore.overlays import Overlay, build_image
from retrore.toolchain import import_linker_map


@pytest.mark.parametrize("base", [0, 0x1000, 0xAA55])
def test_runtime_detection_uses_relocation_and_matches_inside_units(base):
    startup = bytes.fromhex("ba 10 00 2e 89 16 35 02 b4 30 cd 21 8b 2e 02 00 8b 1e 2c 00 8e da")
    marker = b"Turbo C++ - Copyright 1990 Borland Intl."
    strlen = bytes.fromhex("55 8b ec 57 8c d8 8e c0 8b 7e 04 33 c0 fc b9 ff ff f2 ae 91 f7 d0 48 5f 5d c3")
    image = startup + marker
    image += b"\x90" * (-(len(image) + 8) % 16) + strlen[:8]
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(image), 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
    pack_into("<HH", header, 28, 1, 0)
    executable = MZExecutable.parse(header + image)

    # Only the full pattern that starts in overlay memory should match.
    overlay = Overlay("overlay.ovr", "overlay", strlen[8:] + b"\x90" + strlen, None)
    _, report = build_image(executable.load(base), "test.exe", [overlay])
    assert report["compiler"]["family"] == "Turbo C++"
    signature, = report["runtime_signatures"]
    assert (signature["unit"], signature["unit_offset"]) == ("overlay", len(strlen) - 7)
    assert signature["name"] == "strlen"
    assert signature["result"] == "uint"

    # The same bytes with no relocation on the startup segment are insufficient evidence.
    pack_into("<H", header, 6, 0)
    loaded = MZExecutable.parse(header + image).load(base)
    _, unknown = build_image(loaded, "test.exe", [overlay])
    assert unknown["compiler"] is None
    assert unknown["runtime_signatures"] == []


def test_detects_medium_model_at_relocated_startup_target():
    base = 0x2000
    image = bytearray(b"\xcc" * 0x90)
    image[:5] = bytes.fromhex("ea 20 00 00 20")  # far jump to compiler startup
    startup = bytes.fromhex(
        "b4 30 cd 21 3c 02 73 02 cd 20 bf 00 21 8b 36 02 00 2b f7 81 fe 00 10"
        " 72 03 be 00 10 fa 8e d7 81 c4 20 01 fb 73 14 16 1f 9a 10 00 00 20"
    )
    image[0x20:0x20 + len(startup)] = startup
    lseek = bytes.fromhex("55 8b ec 83 ec 04 8b 5e 06 3b 1e 20 00 72 05 b8 00 09 eb 2a f7 46 0a 00 80 74 48")
    image[0x60:0x60 + len(lseek)] = lseek
    root = LoadedMZ(base, bytes(image), Address(base, 0), Address(0x2100, 0),
                    (Address(0, 3), Address(0, 0x2B), Address(0, 0x4B)))
    _, report = build_image(root, "test.exe", [])
    assert report["compiler"] == {
        "family": "Microsoft C", "version": "5.x", "evidence": "relocated entry jump to startup",
    }
    signature, = report["runtime_signatures"]
    assert (signature["name"], signature["far"], signature["stack_purge"]) == ("lseek", True, None)
    assert (signature["result"], signature["result_registers"]) == ("long", ("DX", "AX"))
    assert [(param["name"], param["type"]) for param in signature["parameters"]] == [
        ("handle", "int"), ("offset", "long"), ("origin", "int"),
    ]

    unknown = LoadedMZ(base, bytes(image), root.entry, root.stack, root.relocations[1:])
    assert build_image(unknown, "test.exe", [])[1]["compiler"] is None


@pytest.mark.parametrize("preloader", [False, True])
def test_microsoft_pascal_startup_requires_relocations(preloader):
    base = 0x2000
    startup = bytes.fromhex(
        "ba 89 01 b4 25 b0 00 8c c9 8e d9 cd 21 ba 10 f4 d1 ea b9 00 80 2b ca d1 ea d1 ea d1 ea 42"
        " 26 a1 02 00 8b e8 2d 5d 24 72 c4 33 db 2b c2 73 02 2b d8 2b d3"
        " b8 5d 14 8e d8 8c 06 8e fc be 49 24 2b f0 d1 e6 d1 e6 d1 e6 d1 e6"
    )
    image = bytes.fromhex("ea 20 00 00 20").ljust(0x20, b"\xcc") + startup
    entry = Address(base, 0 if preloader else 0x20)
    stack = Address(base + 0x100, 0x200)
    selectors = (Address(0, 0x45), Address(0, 0x54), Address(0, 0x5D))
    jump = (Address(0, 3),) if preloader else ()
    root = LoadedMZ(base, image, entry, stack, selectors + jump)
    _, report = build_image(root, "test.exe", [])
    assert report["compiler"] == {
        "family": "Microsoft Pascal", "version": None,
        "evidence": "relocated entry jump to ENTXQQ startup" if preloader else "ENTXQQ startup",
    }
    assert "microsoft_pascal_dgroup" not in report

    for missing in root.relocations:
        incomplete = LoadedMZ(base, image, entry, stack, tuple(r for r in root.relocations if r != missing))
        assert build_image(incomplete, "test.exe", [])[1]["compiler"] is None


def _verify_microsoft_pascal_startup(source, program, main_linear):
    origin = program["units"][0]["linear"]
    root = MZExecutable.parse(source.read_bytes()).load(origin // 16)
    dgroup = program["microsoft_pascal_dgroup"]
    assert dgroup["startup_linear"] == root.entry.linear
    assert dgroup["copy_end_segment"] - dgroup["biased_segment"] == 0x1000
    assert dgroup["copy_start_segment"] == root.stack.segment
    assert dgroup["stack_offset"] == 0xF610
    literal = root.image.index(b"VALUE ", dgroup["copy_start_segment"] * 16 - origin)

    def interrupt(uc, number, _):
        # The probe installs an interrupt vector before copying DGROUP.
        assert (number, uc.reg_read(UC_X86_REG_AH)) == (0x21, 0x25)

    psp = root.base_segment - 0x10
    maximum = dgroup["max_shift_paragraphs"]
    captures = []
    for available in (0x80, maximum + 0x80):
        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, 0x100000)
        uc.mem_write(origin, root.image)
        uc.mem_write(psp * 16 + 2, pack("<H", dgroup["copy_end_segment"] + available))
        for register, value in (
            (UC_X86_REG_CS, root.entry.segment), (UC_X86_REG_IP, root.entry.offset),
            (UC_X86_REG_DS, psp), (UC_X86_REG_ES, psp),
            (UC_X86_REG_SS, root.stack.segment), (UC_X86_REG_SP, root.stack.offset),
        ):
            uc.reg_write(register, value)
        uc.hook_add(UC_HOOK_INTR, interrupt)
        uc.emu_start(root.entry.linear, main_linear, count=100_000)
        assert uc.reg_read(UC_X86_REG_CS) * 16 + uc.reg_read(UC_X86_REG_IP) == main_linear
        shift = min(available, maximum)
        selector = (dgroup["biased_segment"] + shift) & 0xFFFF
        assert uc.reg_read(UC_X86_REG_DS) == uc.reg_read(UC_X86_REG_SS) == selector
        assert uc.reg_read(UC_X86_REG_SP) == dgroup["stack_offset"] - 4  # The far call to the main routine.
        assert uc.mem_read(origin + literal + shift * 16, 6) == b"VALUE "
        captures.append((selector, bytes(uc.mem_read((dgroup["copy_start_segment"] + shift) * 16,
                                                    (dgroup["copy_end_segment"] - dgroup["copy_start_segment"]) * 16))))
    return captures


@pytest.mark.parametrize("name", ["PROBE", "ALT"])
def test_original_microsoft_pascal_runtime(name, tmp_path, capsys):
    if not (directory := os.environ.get("RETRORE_MS_PASCAL_DIR")):
        pytest.skip("set RETRORE_MS_PASCAL_DIR to the Microsoft Pascal 3.20 runtime probes")
    directory = Path(directory)
    export, project = tmp_path / "export", tmp_path / "project"
    source = directory / f"{name}.EXE"
    assert main(["load", str(source), "-o", str(export), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    assert program["compiler"] == {
        "family": "Microsoft Pascal", "version": None, "evidence": "ENTXQQ startup",
    }
    # Use the LINK listing as independent evidence, without adding its labels to the export.
    import_linker_map(directory / f"{name}.MAP", program)
    publics = {row["name"]: row["linear"] for row in program["toolchain_symbols"]}
    signatures = {row["name"]: row for row in program["runtime_signatures"]}
    assert set(signatures) == {"INIFQQ", "GETHQQ", "WTLFQQ"}
    for symbol, signature in signatures.items():
        assert signature["address"]["linear"] == publics[symbol]
    assert signatures["GETHQQ"]["result"] == "void*"
    assert [signatures[symbol]["stack_purge"] for symbol in ("INIFQQ", "GETHQQ", "WTLFQQ")] == [0, 2, 2]
    captures = _verify_microsoft_pascal_startup(source, program, publics["ENTGQQ"])

    if not os.environ.get("GHIDRA_HOME"):
        return
    segment, data = captures[0 if name == "PROBE" else 1]
    capture = tmp_path / "capture.bin"
    capture.write_bytes(data)
    captured_export = tmp_path / "captured"
    assert main(["load", str(source), "--pascal-dgroup", f"{capture}@{segment:04x}",
                 "-o", str(captured_export), "--json"]) == 0, capsys.readouterr().err
    captured = json.loads(capsys.readouterr().out)["microsoft_pascal_capture"]
    assert (captured_export / "image.bin").read_bytes() == (export / "image.bin").read_bytes()
    export = captured_export
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["microsoft_pascal_capture"] == captured
    assert report["runtime_signatures"] == 3
    assert report["microsoft_pascal_frame_calls"] >= 3
    origin = program["units"][0]["linear"]
    requests = tmp_path / "queries.json"
    requests.write_text(json.dumps([
        {"command": "decomp", "address": f"root:{publics['ENTGQQ'] - origin:04x}"},
        {"command": "decomp", "address": f"root:{publics['GETHQQ'] - origin:04x}"},
        {"command": "func", "address": f"root:{publics['ENTGQQ'] - origin:04x}"},
        *({"command": "disasm", "address": f"root:{publics[symbol] - origin:04x}", "limit": 8}
          for symbol in ("INIFQQ", "GETHQQ", "WTLFQQ")),
    ]), encoding="utf-8")
    assert main(["batch", str(requests), "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    entry, heap, function, *frames = (row["result"] for row in json.loads(capsys.readouterr().out)["results"])
    assert function["segments"]["DS"] == function["segments"]["SS"] == segment
    decompilation = entry["decompilation"]
    assert all(call in decompilation for call in ("INIFQQ();", "GETHQQ(2);", "WTLFQQ("))
    assert "(size);" in heap["decompilation"]  # The allocator receives the recovered stack parameter.
    assert "WORD_" not in heap["decompilation"]  # The local size folds to a constant stack adjustment.
    image = (export / "image.bin").read_bytes()
    for frame, size in zip(frames, ("0000", "0200", "0000"), strict=True):
        call, word, continuation = frame["rows"]
        assert [row["kind"] for row in (call, word, continuation)] == ["instruction", "data", "instruction"]
        assert word["bytes"] == size
        assert call["bytes"] + word["bytes"] + continuation["bytes"] == image[
            call["unit_offset"]:call["unit_offset"] + 8
        ].hex()
        refs = {ref["type"]: ref["target"]["linear"] for ref in call["references"]}
        assert refs["FALL_THROUGH"] == continuation["address"]["linear"] == call["address"]["linear"] + 5
        helper = refs["UNCONDITIONAL_CALL"] - origin
        assert image[helper:helper + 4] == bytes.fromhex("5e 2e 8b 0c")


@pytest.fixture
def pascal_capture_inputs(tmp_path):
    # A recognized ENTXQQ layout in a small synthetic MZ. The analysis follows the startup into a
    # callee with direct DS and SS reads. The copied range ends eight bytes beyond the file image.
    image = bytearray.fromhex(
        "ba 89 01 b4 25 b0 00 8c c9 8e d9 cd 21 ba 10 f4 d1 ea b9 00 80 2b ca d1 ea d1 ea d1 ea 42"
        " 26 a1 02 00 8b e8 2d 00 00 72 00 33 db 2b c2 73 02 2b d8 2b d3"
        " b8 00 00 8e d8 8c 06 8e fc be 00 00 2b f0 d1 e6 d1 e6 d1 e6 d1 e6"
        " 81 fe 00 00 73 08 01 54 02 83 c6 04 eb f2"
        " b8 00 00 8b c8 81 e9 00 10 8e d9 03 ca 8e c1 2d 00 00 be fe ff 8b fe fd"
        " 2d 00 10 76 13 b9 00 80 f3 a5 8c c1 81 e9 00 10 8e c1 2b ca 8e d9 eb e8"
        " 05 00 10 8b c8 d1 e1 d1 e1 d1 e1 f3 a5 fc 81 c2 00 00 8e da fa 8e d2 bc 10 f6 fb"
    )
    assert len(image) == 0xA2
    image += bytes.fromhex("e8 0b 00 f4")
    image = image.ljust(0xB0, b"\xcc") + bytes.fromhex("a1 80 ff 36 03 06 c0 ff c3")
    image = image.ljust(0x178, b"\0")
    relocations = {0x25: 0x18, 0x34: 0xF018, 0x3D: 0x10, 0x58: 0x18, 0x67: 0x10, 0x97: 0xF018}
    for offset, value in relocations.items():
        pack_into("<H", image, offset, value)
    header = pack("<2s13H", b"MZ", 64 + len(image), 1, len(relocations), 4, 0, 0, 0x10, 0x80,
                  0, 0, 0, 28, 0) + b"".join(pack("<2H", offset, 0) for offset in relocations)
    source, capture, overlay = (tmp_path / name for name in ("sample.exe", "capture.bin", "extra.ovr"))
    source.write_bytes(header.ljust(64, b"\0") + image)
    capture.write_bytes(pack("<H", 0x1234).ljust(0x40, b"\0") + pack("<H", 0x5678).ljust(0x40, b"\0"))
    overlay.write_bytes(b"\xc3")
    return source, capture, overlay


def test_microsoft_pascal_capture_export(pascal_capture_inputs, tmp_path, capsys):
    source, capture, overlay = pascal_capture_inputs
    export = tmp_path / "export"
    assert main(["load", str(source), "--pascal-dgroup", f"{capture}@001c", "--overlay", str(overlay),
                 "-o", str(export), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    record = report["microsoft_pascal_capture"]
    assert (record["segment"], record["shift_paragraphs"], record["linear"], record["size"]) == (0x1C, 4, 0x10140, 0x80)
    assert (export / "pascal-dgroup.bin").read_bytes() == capture.read_bytes()
    assert report["units"][1]["linear"] == 0x101C0
    assert (export / "image.bin").read_bytes()[0x140:0x178] == bytes(0x38)
    assert main(["info", str(source), "--pascal-dgroup", f"{capture}@0118", "--overlay", str(overlay),
                 "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["units"][1]["linear"] == 0x10180
    for options, message in (
        (["--pascal-dgroup", f"{capture}@0017"], "outside the startup shift range"),
        (["--pascal-dgroup", f"{capture}@001c", "--overlay", f"{overlay}@1018"], "overlaps captured DGROUP"),
    ):
        assert main(["info", str(source), *options, "--json"]) == 1
        assert message in json.loads(capsys.readouterr().err)["error"]["message"]
    capture.write_bytes(b"short")
    assert main(["info", str(source), "--pascal-dgroup", f"{capture}@001c", "--json"]) == 1
    assert "must contain 128 bytes" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_ghidra_microsoft_pascal_capture(pascal_capture_inputs, tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    source, capture, overlay = pascal_capture_inputs
    export, project, requests, manifest = (tmp_path / name for name in ("export", "project", "queries.json", "states.json"))
    manifest.write_text(json.dumps({"version": 1, "initial": "pre", "states": [
        {"name": "pre", "loads": [{"unit": "root"}]},
    ]}), encoding="utf-8")
    assert main(["load", str(source), "--pascal-dgroup", f"{capture}@001c", "--overlay", str(overlay),
                 "--load-manifest", str(manifest), "-o", str(export), "--json"]) == 0, capsys.readouterr().err
    program = json.loads(capsys.readouterr().out)
    assert main(["ghidra", "import", str(export), str(project), "--load-views", "--json"]) == 0, capsys.readouterr().err
    imported = json.loads(capsys.readouterr().out)
    assert imported["microsoft_pascal_capture"] == program["microsoft_pascal_capture"]
    static, = imported["load_views"]["pre"]["blocks"]
    requests.write_text(json.dumps([
        {"command": "func", "address": "root:00b0"},
        {"command": "decomp", "address": "root:00b0"},
        {"command": "disasm", "address": "001c:ff80", "limit": 2},
        {"command": "disasm", "address": "001c:ffc0", "limit": 2},
        {"command": "disasm", "address": f"{static['block']}:0140", "limit": 2},
    ]), encoding="utf-8")
    assert main(["batch", str(requests), "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    function, routine, data, tail, prior = (row["result"] for row in json.loads(capsys.readouterr().out)["results"])
    assert function["segments"]["DS"] == function["segments"]["SS"] == 0x1C
    assert "DGROUP_ff80" in routine["decompilation"] and "DGROUP_ffc0" in routine["decompilation"]
    assert [data["rows"][0]["bytes"], tail["rows"][0]["bytes"]] == ["3412", "7856"]
    assert "".join(row["bytes"] for row in prior["rows"]) == "0000"

    (export / "pascal-dgroup.bin").write_bytes(bytes(0x80))
    assert main(["ghidra", "import", str(export), str(tmp_path / "tampered"), "--json"]) == 1
    assert "DGROUP does not match map.json" in json.loads(capsys.readouterr().err)["error"]["message"]


def test_ghidra_microsoft_pascal_frame_uses_each_inline_size(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    caller = bytes.fromhex("0e 1f b8 34 12 50 e8 17 00 a3 80 01 e8 31 00 a3 82 01 c3")
    # The first frame reads a parameter. The second stores at BP-0x104 and pops from SS:SP.
    zero_frame = bytes.fromhex("e8 3d 00 00 00 8b 46 04 5d c2 02 00")
    large_frame = bytes.fromhex("e8 1d 00 04 01 c7 86 fc fe 67 45 58 8b e5 5d c3")
    helper = bytes.fromhex("5e 2e 8b 0c 46 46 55 8b ec 2b e9 72 06 3b 2e 90 01 77 06 56"
                           " 9a 7f 00 45 23 8b e5 03 e9 ff e6")
    image = caller.ljust(0x20, b"\xcc") + zero_frame
    image = image.ljust(0x40, b"\xcc") + large_frame
    image = image.ljust(0x60, b"\xcc") + helper + b"\xf4"
    image = image.ljust(0x190, b"\0") + pack("<H", 0x100)
    origin, stack_segment = 0x23450, 0x2365
    header = pack("<2s13H", b"MZ", 32 + len(image), 1, 0, 2, 0x40, 0x40, 0x20, 0x400,
                  0, 0, 0, 28, 0).ljust(32, b"\0")
    source, export, project = (tmp_path / name for name in ("sample.exe", "export", "project"))
    source.write_bytes(header + image)
    assert main(["load", str(source), "--base-segment", "0x2345", "-o", str(export), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    # Compiler detection is tested separately. Start this fixture directly at the caller.
    program["compiler"] = {"family": "Microsoft Pascal"}
    (export / "map.json").write_text(json.dumps(program), encoding="utf-8")

    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["microsoft_pascal_frame_calls"] == 2
    requests = tmp_path / "queries.json"
    requests.write_text(json.dumps([
        {"command": "decomp", "address": address} for address in ("root:0020", "root:0040")
    ]), encoding="utf-8")
    assert main(["batch", str(requests), "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    zero, large = (row["result"]["decompilation"] for row in json.loads(capsys.readouterr().out)["results"])
    assert "return param_1;" in zero
    assert "return 0x4567;" in large

    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x100000)
    uc.mem_write(origin, image)
    for register, value in ((UC_X86_REG_CS, 0x2345), (UC_X86_REG_SS, stack_segment), (UC_X86_REG_SP, 0x400)):
        uc.reg_write(register, value)
    uc.emu_start(origin, origin + 0x12, count=100)  # Stop at the caller's final RET.
    assert uc.reg_read(UC_X86_REG_IP) == 0x12
    assert uc.reg_read(UC_X86_REG_SP) == 0x400
    assert uc.mem_read(origin + 0x180, 4) == pack("<HH", 0x1234, 0x4567)


CONVENTIONS = bytes.fromhex(
    "0e 1f"            # 0000 push cs; pop ds
    " b8 00 3d"        # 0002 mov ax,3d00h
    " ba 60 00"        # 0005 mov dx,offset name
    " cd 21"           # 0008 int 21h             open
    " 72 23"           # 000a jc 002f
    " a3 70 00"        # 000c mov [handle],ax
    " b8 07 00 50"     # 000f push 7
    " 1e b8 60 00 50"  # 0013 push ds; push offset name
    " e8 19 00"        # 0018 call first_plus       Pascal: ret 6
    " a3 72 00"        # 001b mov [sum],ax
    " b8 05 00 50"     # 001e push 5
    " b8 03 00 50"     # 0022 push 3
    " e8 1d 00"        # 0026 call difference       C: caller cleanup
    " 83 c4 04"        # 0029 add sp,4
    " e8 22 00"        # 002c call unknown_interrupts
    " b4 4c cd 21"     # 002f mov ah,4ch; int 21h   exit
    " 90"
    " 55 8b ec"        # 0034 first_plus(value, far name)
    " c4 5e 04"        # 0037 les bx,[bp+4]
    " 26 8a 07 32 e4"  # 003a mov al,es:[bx]; xor ah,ah
    " 03 46 08"        # 003f add ax,[bp+8]
    " 5d c2 06 00"     # 0042 pop bp; ret 6
    " 55 8b ec"        # 0046 difference(a, b)
    " 8b 46 04"        # 0049 mov ax,[bp+4]
    " 2b 46 06"        # 004c sub ax,[bp+6]
    " 5d c3"           # 004f pop bp; ret
    " b4 ff cd 21"     # 0051 an unrecognized DOS service
    " cd 16 c3"        # 0055 a BIOS interrupt
).ljust(0x60, b"\x90") + b"A.DAT\0"


def test_ghidra_dos_conventions_and_services(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    image = CONVENTIONS.ljust(0x104, b"\0")
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(image), 1, 0, 2, 32, 32, 2, 0x200, 0, 0, 0, 28, 0)
    source, export, project = (tmp_path / name for name in ("sample.exe", "export", "project"))
    source.write_bytes(header + image)
    assert main(["load", str(source), "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["dos_services"] == 2
    assert report["calling_conventions"] == {"callee_cleanup": 1, "caller_cleanup": 1, "far_pointer_arguments": 1}

    def decompile(address):
        assert main(["decomp", address, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)["decompilation"]

    entry = decompile("root:0000")
    assert "DOS::OpenFile(0,(char *)0x60);" in entry and "if (!extraout_CF) {" in entry
    assert "DOS::Exit((byte)" in entry
    assert "swi(0x21)" not in entry
    # The far pointer argument is one parameter, and the C routine takes the two words its caller removes.
    assert "FUN_1000_0034((void *)CONCAT22(unaff_CS,(void *)0x60),7);" in entry
    assert "FUN_1000_0046(3,5);" in entry
    assert "int FUN_1000_0034(void *param_1,int param_2)" in decompile("root:0034")
    unknown = decompile("root:0051")
    assert "swi(0x21)" in unknown and "swi(0x16)" in unknown
    assert main(["callees", "root:0000", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    calls = json.loads(capsys.readouterr().out)["callees"]
    assert [row["to"]["unit_address"] for row in calls if row["type"] == "CALL_OVERRIDE_UNCONDITIONAL"] == [
        "dos_services:003d", "dos_services:004c",
    ]
    assert all(row["type"] != "CALLOTHER_OVERRIDE_CALL" for row in calls)
    assert main(["callers", "dos_services:003d", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    site, = json.loads(capsys.readouterr().out)["callers"]
    assert site["from"]["unit_address"] == "root:0008"


def test_ghidra_dos_recovers_caller_verified_register_storage(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    image = bytes.fromhex(
        "b9 03 00 be 04 00 e8 1b 00 a3 80 00 89 1e 82 00 89 16 84 00"
        " e8 1b 00 a3 86 00 89 16 88 00 c3"
    ).ljust(0x24, b"\xcc") + bytes.fromhex("89 c8 89 f3 ba 34 12 c3")
    image = image.ljust(0x32, b"\xcc") + bytes.fromhex("b8 11 00 ba 22 00 c3")
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(image), 1, 0, 2, 32, 32, 2, 0x200, 0, 0, 0, 28, 0)
    source, export, project = (tmp_path / name for name in ("registers.exe", "export", "project"))
    source.write_bytes(header + image)
    assert main(["load", str(source), "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)["calling_conventions"]
    assert report["register_arguments"] == 1 and report["joined_returns"] == 2
    requests = tmp_path / "queries.json"
    requests.write_text(json.dumps([
        {"command": "context", "address": "root:0024"}, {"command": "context", "address": "root:0032"},
    ]), encoding="utf-8")
    assert main(["batch", str(requests), "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    wide, pair = (row["result"] for row in json.loads(capsys.readouterr().out)["results"])
    assert (wide["return_type"], pair["return_type"]) == ("undefined6", "undefined4")
    assert [parameter["storage"] for parameter in wide["parameters"]] == ["CX:2", "SI:2"]
    assert pair["parameters"] == []


def test_ghidra_dos_conventions_bound_inferred_stack_arguments(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    entry = bytes.fromhex(
        "b8 07 00 50 e8 19 00 83 c4 02"  # Push one argument, call 0120h, remove the argument.
        " e8 33 00 cd 20"               # Call 0140h, then exit.
    )
    c_function = bytes.fromhex(
        "55 8b ec 81 ec 04 01"  # Frame with 260 local bytes.
        " c7 86 fc fe 34 12"    # MOV word ptr [BP-104h],1234h, rendered by Ghidra with 0xfefc.
        " 8b 46 04 8b e5 5d c3"
    )
    large_purge = bytes.fromhex("55 8b ec 8b 46 04 5d c2 02 c4")  # RET 0xc402
    image = (entry.ljust(0x20, b"\x90") + c_function).ljust(0x40, b"\x90") + large_purge
    source, export, project = (tmp_path / name for name in ("sample.com", "export", "project"))
    source.write_bytes(image)
    assert main(["load", str(source), "-o", str(export)]) == 0, capsys.readouterr().err
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--timeout", "120", "--json"]) == 0, (
        capsys.readouterr().err)
    assert json.loads(capsys.readouterr().out)["calling_conventions"] == {
        "caller_cleanup": 1, "far_pointer_arguments": 0,
    }


def test_ghidra_pool_of_radiance_conventions_and_services(tmp_path, capsys):
    directory = os.environ.get("RETRORE_POR_DIR")
    if not directory or not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set RETRORE_POR_DIR and GHIDRA_HOME to run the real-game test")
    files = {name.upper(): os.path.join(directory, name) for name in os.listdir(directory)}
    export, project = tmp_path / "export", tmp_path / "project"
    root = files.get("START.EXE") or files["GAME.EXE"]
    assert main(["load", root, "--overlay", files["GAME.OVR"], "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["dos_services"] == 35
    assert report["calling_conventions"] == {
        "accessed_arguments": 1, "callee_cleanup": 564, "far_pointer_arguments": 445, "no_stack_arguments": 270}

    def decompile(address):
        assert main(["decomp", address, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)["decompilation"]

    # Turbo Pascal's Seek: the file record is one far pointer, and the carry flag comes from INT 21h AH=42h.
    seek = decompile("root:c4e3")
    assert "void __stdcall16far FUN_1000_c4e3(uint param_1,int param_2,void *param_3)" in seek
    assert "DOS::SeekFile(0,*(undefined2 *)param_3," in seek and "extraout_CF" in seek
    assert "swi(0x21)" not in seek
    # GetTime(var Hour, Minute, Second, Sec100) stores the CX and DX results of AH=2Ch.
    timing = decompile("root:a3c2")
    assert "DOS::GetTime();" in timing and "*(uint *)param_4 = (uint)extraout_CH;" in timing
    # The string store helper (retf 0Ah) takes a length and two far pointers; the source is one constant.
    assert "(void *)0x4c1f0e2e);" in decompile("tpov_0025:1036")
