import json
import os
from pathlib import Path
from struct import pack_into

import pytest

from retrore.cli import main
from retrore.jump_tables import JumpTable, M68kJumpTable, recover_jump_tables, recover_m68k_jump_tables
from retrore.mz import Address, LoadedMZ
from retrore.overlays import Overlay, build_image


def _separate_table():
    code = bytearray(b"\xcc" * 0x24)
    # cmp bx,1; ja default; shl bx,1; jmp word ptr cs:[bx+0x20]
    code[:12] = bytes.fromhex("83 fb 01 77 09 d1 e3 2e ff a7 20 00")
    for offset in (0x0E, 0x10, 0x14):
        code[offset] = 0xC3
    pack_into("<HH", code, 0x20, 0x10, 0x14)
    return bytes(code)


def test_recovers_separate_table_relative_to_the_initial_code_segment():
    code = _separate_table()
    image = bytes(16) + code
    loaded = LoadedMZ(0x1000, image, Address(0x1001, 0), Address(0x1000, 0x100))
    exported, program = build_image(loaded, "test.exe", [])

    assert exported == image
    switch, = program["jump_tables"]
    assert switch["unit"] == "root"
    assert switch["address"] == {"segment": 0x1001, "offset": 7, "linear": 0x10017}
    assert switch["table"]["linear"] == 0x10030
    assert switch["default"]["offset"] == 0x0E
    assert [target["offset"] for target in switch["targets"]] == [0x10, 0x14]


def test_recovers_biased_inline_table_with_duplicate_targets():
    code = bytes.fromhex(
        "cc cc c3 cc cc cc c3 cc"  # Cases at 2 and 6.
        " 02 40 02 40 06 40"       # Three words with a runtime IP bias of 0x4000.
        " 2d 05 00"                # sub ax,5
        " 3d 03 00 73 08"          # cmp ax,3; jae default
        " 93 d1 e3"                # xchg ax,bx; shl bx,1
        " 2e ff a7 08 40 c3"       # jmp word ptr cs:[bx+0x4008]; default: ret
    )
    assert recover_jump_tables(code) == []
    root = LoadedMZ(0x1000, b"\xc3", Address(0x1000, 0), Address(0x1000, 1))
    exported, program = build_image(root, "test.exe", [Overlay("test.ovr", "test", code)])

    assert exported[0x10:] == code
    switch, = program["jump_tables"]
    assert switch["unit"] == "test"
    assert switch["table"] == {"segment": 0x1001, "offset": 8, "linear": 0x10018}
    assert [target["offset"] for target in switch["targets"]] == [2, 2, 6]
    assert recover_jump_tables(code, flat_overlay=True) == [
        JumpTable(0x11, 0x19, 8, 0x1E, (2, 2, 6)),
    ]


@pytest.mark.parametrize(("offset", "replacement"), [
    (3, b"\x7f"),      # Signed comparison supplies no unsigned upper bound.
    (6, b"\xe6"),      # Scaling SI does not constrain BX.
    (7, b"\x3e"),      # DS-relative table.
    (10, b"\x21"),     # Truncated table.
    (0x20, b"\xff\xff"),  # Target outside the segment.
    (0x20, b"\x22\x00"),  # Target inside the table.
])
def test_rejects_unproven_or_invalid_tables(offset, replacement):
    code = bytearray(_separate_table())
    code[offset:offset + len(replacement)] = replacement
    assert recover_jump_tables(bytes(code)) == []


def _returns(code, *offsets):
    for offset in offsets:
        code[offset] = 0xC3


def test_recovers_compare_that_branches_over_the_default_jump():
    code = bytearray(b"\xcc" * 0x40)
    # cmp ax,2; jbe 8; jmp 0x28; add ax,ax; xchg bx,ax; jmp word ptr cs:[bx+0x30]
    code[:0x10] = bytes.fromhex("3d 02 00 76 03 e9 20 00 01 c0 93 2e ff a7 30 00")
    _returns(code, 0x14, 0x18, 0x1C)
    pack_into("<3H", code, 0x30, 0x14, 0x18, 0x1C)
    assert recover_jump_tables(bytes(code)) == [JumpTable(0, 0x0B, 0x30, 0x28, (0x14, 0x18, 0x1C))]


def test_recovers_scale_before_copy_after_a_biased_compare():
    code = bytearray(b"\xcc" * 0x40)
    # sub ax,5; cmp ax,1; ja 0x14; add ax,ax; xchg bx,ax; jmp word ptr cs:[bx+0x30]
    code[:0x10] = bytes.fromhex("2d 05 00 3d 01 00 77 0c 01 c0 93 2e ff a7 30 00")
    _returns(code, 0x14, 0x18)
    pack_into("<2H", code, 0x30, 0x18, 0x14)
    assert recover_jump_tables(bytes(code)) == [JumpTable(3, 0x0B, 0x30, 0x14, (0x18, 0x14))]


def _masked_tables():
    code = bytearray(b"\xcc" * 0x60)
    # mov bx,cx; and bx,3; rol bx,1; jmp word ptr cs:[bx+0x40]
    code[:0x0C] = bytes.fromhex("8b d9 83 e3 03 d1 c3 2e ff a7 40 00")
    # mov bl,ch; and bx,6; test cl,1; je 0x1b; call word ptr cs:[bx+0x50]; ret
    code[0x0C:0x1C] = bytes.fromhex("8a dd 83 e3 06 f6 c1 01 74 05 2e ff 97 50 00 c3")
    _returns(code, 0x20, 0x22, 0x24, 0x26)
    pack_into("<4H", code, 0x40, 0x20, 0x22, 0x24, 0x26)
    pack_into("<4H", code, 0x50, 0x26, 0x24, 0x22, 0x20)
    return code


def test_recovers_masked_jump_and_call_tables():
    jump, call = recover_jump_tables(bytes(_masked_tables()))
    assert jump == JumpTable(2, 7, 0x40, None, (0x20, 0x22, 0x24, 0x26), "jump", "mask")
    assert call == JumpTable(0x0E, 0x16, 0x50, None, (0x26, 0x24, 0x22, 0x20), "call", "mask")


@pytest.mark.parametrize(("offset", "replacement"), [
    (2, b"\x83\xcb\x03"),  # or bx,3 leaves the index unbounded.
    (5, b"\xd3"),          # rol bx,cl: unknown scale.
    (5, b"\x90\x90"),      # An unscaled mask can produce odd offsets into a word table.
])
def test_rejects_unbounded_or_misaligned_masks(offset, replacement):
    code = _masked_tables()
    code[offset:offset + len(replacement)] = replacement
    assert [table.kind for table in recover_jump_tables(bytes(code))] == ["call"]


def test_recovers_zero_extended_byte_index():
    code = bytearray(b"\xcc" * 0x240)
    # xor bx,bx; mov bl,[si+0xb]; shl bx,1; jmp word ptr cs:[bx+0x40]
    code[:0x0C] = bytes.fromhex("31 db 8a 5c 0b d1 e3 2e ff a7 40 00")
    _returns(code, 0x20)
    pack_into("<256H", code, 0x40, *([0x20] * 256))
    switch, = recover_jump_tables(bytes(code))
    assert (switch.guard, switch.bound, len(switch.targets)) == (0, "byte", 256)


def test_rejects_cases_scattered_across_the_segment():
    code = bytearray(b"\xcc" * 0x3000)
    code[:0x0C] = bytes.fromhex("83 fb 01 77 09 d1 e3 2e ff a7 20 00")
    _returns(code, 0x0E, 0x10, 0x2F00)
    pack_into("<2H", code, 0x20, 0x10, 0x2F00)
    assert recover_jump_tables(bytes(code)) == []


def test_assigns_root_switches_to_the_nearest_relocated_code_segment():
    # A relocated far call names a second code segment, 0x1010, above the entry segment 0x1000.
    code = bytearray(b"\x90" * 0x140)
    code[:6] = bytes.fromhex("9a 00 00 10 10 cb")  # call far 1010:0000; retf
    code[0x100:0x140] = _separate_table() + bytes(0x40 - 0x24)
    loaded = LoadedMZ(0x1000, bytes(code), Address(0x1000, 0), Address(0x1000, 0x200), (Address(0, 3),))
    _, program = build_image(loaded, "test.exe", [])

    record, = program["jump_tables"]
    assert record["address"] == {"segment": 0x1010, "offset": 7, "linear": 0x10107}
    assert record["table"]["offset"] == 0x20
    assert [target["offset"] for target in record["targets"]] == [0x10, 0x14]
    assert (record["kind"], record["bound"], record["default"]["offset"]) == ("jump", "compare", 0x0E)


@pytest.mark.parametrize(("branch", "expected"), [
    ("62 12", M68kJumpTable(0, 18, 28, 26, (20, 22, 24))),          # bhi.b
    ("62 00 00 14", M68kJumpTable(0, 20, 30, 28, (22, 24, 26))),    # bhi.w
])
def test_recovers_m68k_switch_through_relocated_pointers(branch, expected):
    code = bytearray.fromhex(
        f"0c 80 00 00 00 02 {branch}"  # cmpi.l #2,d0; bhi default
        " e5 80 41 fa 00 10"           # asl.l #2,d0; lea table(pc),a0
        " 20 70 08 00 4e d0"           # movea.l (a0,d0.l),a0; jmp (a0)
        " 4e 75 4e 75 4e 75 4e 75"     # three cases and the default
    )
    for target in expected.targets:
        code += (0x10000 + target).to_bytes(4, "big")
    relocations = [expected.table + 4 * case for case in range(3)]
    assert recover_m68k_jump_tables(bytes(code), 0x10000, relocations) == [expected]
    # Without a relocation on every entry the table is not proved.
    assert recover_m68k_jump_tables(bytes(code), 0x10000, relocations[:2]) == []


def _mz(image, relocations):
    header = bytearray(48)
    file_size = len(header) + len(image)
    pack_into(
        "<2s13H", header, 0,
        b"MZ", file_size % 512, (file_size + 511) // 512, len(relocations), 3, 0, 0,
        0x40, 0x3E, 0, 0, 0, 0x1C, 0,
    )
    for index, offset in enumerate(relocations):
        pack_into("<2H", header, 0x1C + 4 * index, offset, 0)
    return bytes(header) + bytes(image)


def test_ghidra_keeps_candidates_for_far_pointer_tables_and_variables(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    image = bytearray(0x210)
    code = bytes.fromhex(
        "b8 20 00 8e d8"         # mov ax, DGROUP; mov ds, ax
        " e8 38 00"              # call setup
        " ff 1e 08 00"           # call far [8]: a procedure variable that setup assigns
        " 83 e3 01 d1 e3 d1 e3"  # and bx,1; shl bx,1; shl bx,1
        " ff 9f 00 00"           # call far [bx+0]: a table of two far pointers
        " c3"
    )
    setup = bytes.fromhex(
        "b8 30 00 ba 00 00"      # mov ax, offset handler; mov dx, seg handler
        " a3 08 00 89 16 0a 00"  # mov [8], ax; mov [0xa], dx
        " c3"
    )
    image[:len(code)] = code
    image[0x40:0x40 + len(setup)] = setup
    for start in (0x24, 0x2A, 0x30):
        image[start:start + 5] = bytes.fromhex("55 8b ec 5d cb")  # push bp; mov bp,sp; pop bp; retf
    pack_into("<4H", image, 0x200, 0x24, 0, 0x2A, 0)
    exe = tmp_path / "sample.exe"
    exe.write_bytes(_mz(image, [1, 0x44, 0x202, 0x206]))
    export, project = tmp_path / "export", tmp_path / "indirect"
    assert main(["load", str(exe), "-o", str(export), "--base-segment", "2000"]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["indirect"] == {
        "sites": 2, "candidate_sites": 2, "unresolved_sites": 0, "seeded_functions": 3,
    }

    assert main(["indirect", "--project", str(project), "--json", "--compact"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["counts"] == {"resolved": 0, "candidate": 2, "unresolved": 0}
    variable, table = report["sites"]
    assert (variable["address"], variable["status"], variable["stop"]) == ("root:0008", "candidate", "variable")
    stored, = variable["candidates"]
    assert (stored["slot"], stored["target"], stored["writer"]) == ("root:0208", "root:0030", "root:0046")
    assert stored["evidence"][:2] == ["relocated", "stored"]
    assert (table["table"], table["stop"], table["segment"]) == ("root:0200", "next_variable",
                                                                 {"register": "DS", "value": 0x2020})
    assert [(entry["target"], entry["evidence"][:2]) for entry in table["candidates"]] == [
        ("root:0024", ["relocated", "initial"]), ("root:002a", ["relocated", "initial"]),
    ]
    assert all("seeded" in entry["evidence"] and "prologue" in entry["evidence"] for entry in table["candidates"])

    # Each candidate slot references its target, so xrefs on a handler shows where it can be called from.
    assert main(["xrefs", "root:0030", "--project", str(project), "--json"]) == 0
    refs = json.loads(capsys.readouterr().out)
    assert ("root:0208", "DATA") in [(ref["from"]["unit_address"], ref["type"]) for ref in refs["incoming"]]


@pytest.fixture
def phantasie_iii_export(tmp_path, capsys):
    directory = os.environ.get("RETRORE_PH3_DIR")
    if not directory:
        pytest.skip("set RETRORE_PH3_DIR to run the real-game test")
    exe = next(path for path in Path(directory).iterdir() if path.name.upper() == "MAIN.EXE")
    assert main(["load", str(exe), "-o", str(tmp_path / "export"), "--json"]) == 0
    return tmp_path, json.loads(capsys.readouterr().out)


def test_phantasie_iii_switches_in_every_code_segment(phantasie_iii_export, capsys):
    tmp_path, program = phantasie_iii_export
    tables = {(table["address"]["segment"], table["address"]["offset"]): table for table in program["jump_tables"]}
    # Microsoft C switches branch over the default jump (cmp ax,0x12; jbe; jmp default) in several segments,
    # and the sound driver at segment 0x218f dispatches through masked jump and call tables.
    assert len(tables) == 22
    switch = tables[0x1284, 0x0BA9]
    assert (switch["bound"], len(switch["targets"]), switch["default"]["offset"]) == ("compare", 19, 0x0C3E)
    driver = tables[0x218F, 0x0BCC]
    assert (driver["kind"], driver["bound"], driver["table"]["offset"]) == ("call", "mask", 0x077E)
    assert [target["offset"] for target in driver["targets"]][:4] == [0x0CB6, 0x0D97, 0x0CC1, 0x0CCC]

    if not os.environ.get("GHIDRA_HOME"):
        return
    project = tmp_path / "ph3"
    assert main(["ghidra", "import", str(tmp_path / "export"), str(project), "--json"]) == 0
    capsys.readouterr()
    assert main(["func", "218f:0ccc", "--project", str(project), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["function"]["entry"]["unit_address"] == "root:125bc"
    assert {"from": "root:124bc", "type": "COMPUTED_CALL"} in [
        {"from": caller["from"]["unit_address"], "type": caller["type"]} for caller in report["callers"]
    ]


def test_phantasie_iv_x68k_switches(tmp_path, capsys):
    directory = os.environ.get("RETRORE_PH4_X68K_DIR")
    if not directory:
        pytest.skip("set RETRORE_PH4_X68K_DIR to run the real-game test")
    program_file = next(path for path in Path(directory).iterdir() if path.name.upper() == "P4.X")
    export = tmp_path / "export"
    assert main(["load", str(program_file), "-o", str(export), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    tables = {table["address"]["unit_address"]: table for table in program["jump_tables"]}
    # Every XC switch (cmpi.l; bhi; asl.l #2; lea (pc); movea.l; jmp (a0)) has a relocated table.
    assert len(tables) == 41
    switch = tables["text:13014"]
    assert switch["table"]["unit_address"] == "text:13114"
    assert [target["unit_address"] for target in switch["targets"]][:2] == ["text:13016", "text:1305a"]

    if not os.environ.get("GHIDRA_HOME"):
        return
    project = tmp_path / "p4"
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["switches"] == 41
    # Ghidra's own switch analysis leaves this one unresolved; the recovered table adds its cases.
    assert main(["xrefs", "text:1305a", "--project", str(project), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(
        ref["from"]["unit_address"] == "text:13014" and ref["type"] == "COMPUTED_JUMP" for ref in report["incoming"]
    )
