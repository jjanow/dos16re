import json
import os
from pathlib import Path
from struct import pack_into

import pytest

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

    for missing in root.relocations:
        incomplete = LoadedMZ(base, image, entry, stack, tuple(r for r in root.relocations if r != missing))
        assert build_image(incomplete, "test.exe", [])[1]["compiler"] is None


@pytest.mark.parametrize("name", ["PROBE", "ALT"])
def test_original_microsoft_pascal_runtime(name, tmp_path, capsys):
    if not (directory := os.environ.get("RETRORE_MS_PASCAL_DIR")):
        pytest.skip("set RETRORE_MS_PASCAL_DIR to the Microsoft Pascal 3.20 runtime probes")
    directory = Path(directory)
    export, project = tmp_path / "export", tmp_path / "project"
    assert main(["load", str(directory / f"{name}.EXE"), "-o", str(export), "--json"]) == 0
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

    if not os.environ.get("GHIDRA_HOME"):
        return
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["runtime_signatures"] == 3
    address = f"root:{publics['ENTGQQ'] - program['units'][0]['linear']:04x}"
    assert main(["decomp", address, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    decompilation = json.loads(capsys.readouterr().out)["decompilation"]
    assert all(call in decompilation for call in ("INIFQQ();", "GETHQQ(2);", "WTLFQQ("))


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
