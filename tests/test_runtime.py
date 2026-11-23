import json
import os
from struct import pack_into

import pytest

from retrore.cli import main
from retrore.mz import MZExecutable
from retrore.overlays import Overlay, build_image


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
    " a3 74 00"        # 002c mov [result],ax
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
    # The far pointer argument is one parameter, and the C routine takes the two words its caller removes.
    assert "FUN_1000_0034((void *)CONCAT22(unaff_CS,(void *)0x60),7);" in entry
    assert "FUN_1000_0046(3,5);" in entry
    assert "int FUN_1000_0034(void *param_1,int param_2)" in decompile("root:0034")
    assert main(["callers", "dos_services:003d", "--project", str(project),
                 "--json"]) == 0, capsys.readouterr().err
    site, = json.loads(capsys.readouterr().out)["callers"]
    assert site["from"]["unit_address"] == "root:0008"
