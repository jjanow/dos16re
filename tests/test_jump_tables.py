import json
import os
from itertools import product
from pathlib import Path
from struct import pack, pack_into, unpack_from

import pytest
from unicorn import UC_HOOK_MEM_WRITE, x86_const as x86

from retrore.cli import main
from retrore.emulator import Emulator
from retrore.evidence import evidence_bundle
from retrore.jump_tables import JumpTable, M68kJumpTable, recover_jump_tables, recover_m68k_jump_tables
from retrore.load_manifest import apply_load_manifest
from retrore.mz import Address, LoadedMZ, MZExecutable
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


def _far_table(opcode):
    code = bytearray(b"\xcc" * 0x98)
    # cmp bx,1; ja 0x18; shl bx,1; shl bx,1; jmp/call far ptr cs:[bx+0x30]; ret
    code[:15] = bytes.fromhex(f"83 fb 01 77 13 d1 e3 d1 e3 2e ff {opcode} 30 00 c3")
    code[0x18] = 0xC3
    code[0x60] = 0xCB
    code[0x92:0x96] = bytes.fromhex("0e 07 90 cb")  # push cs; pop es; nop; retf
    pack_into("<4H", code, 0x30, 0x10, 5, 0x12, 8)
    return code


@pytest.mark.parametrize(("kind", "opcode"), [("jump", "af"), ("call", "9f")])
def test_recovers_far_dispatch_only_with_relocated_segments(kind, opcode):
    code = _far_table(opcode)
    unproved = MZExecutable.parse(_mz(code, (0x32,))).load(0x1000)
    assert "jump_tables" not in build_image(unproved, "test.exe", [])[1]

    proved = MZExecutable.parse(_mz(code, (0x32, 0x36))).load(0x1000)
    _, program = build_image(proved, "test.exe", [])
    table, = program["jump_tables"]
    assert table["kind"] == kind
    assert table["entry_size"] == 4
    assert table["table"]["offset"] == 0x30
    assert table["targets"] == [
        {"segment": 0x1005, "offset": 0x10, "linear": 0x10060},
        {"segment": 0x1008, "offset": 0x12, "linear": 0x10092},
    ]


def test_ghidra_adds_far_call_table_cross_references(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    exe, export, project = (tmp_path / name for name in ("calls.exe", "export", "project"))
    exe.write_bytes(_mz(_far_table("9f"), (0x32, 0x36)))
    assert main(["load", str(exe), "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    capsys.readouterr()
    assert main(["xrefs", "root:0092", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    incoming = json.loads(capsys.readouterr().out)["incoming"]
    assert {(ref["from"]["unit_address"], ref["type"]) for ref in incoming} == {
        ("root:0009", "COMPUTED_CALL"), ("root:0034", "DATA"),
    }
    assert main(["func", "root:0094", "--project", str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["segments"]["ES"] == 0x1008

    requests = [{"command": "indirect", "at": "root:9", "compact": True, "fields": ["targets"]}]
    row, = evidence_bundle(project, requests, export=export)["results"]
    returned, = row["result"]["sites"]
    assert returned.keys() == {"targets"}
    assert set(returned["targets"]) == {"root:0060", "root:0092"}
    assert "_flow_bytes" not in row["result"]
    proof = row["export_evidence"]
    assert proof["status"] == "consistent" and not proof["truncated"]
    site, = proof["sites"]
    assert site["targets"] == {"project": [0x10060, 0x10092], "export": [0x10060, 0x10092]}
    instruction, guard, table = site["ranges"]
    assert (instruction["role"], instruction["project_bytes"]) == ("site", "2eff9f3000")
    assert (guard["role"], guard["project_bytes"]) == ("guard", "83fb01")
    assert (table["role"], table["project_bytes"]) == ("table", "1000051012000810")
    assert table["bytes"]["original"] == "1000050012000800"
    assert table["bytes"]["file_spans"][0]["file_offset"] == 0x60

    image = export / "image.bin"
    data = bytearray(image.read_bytes())
    data[0x34] ^= 1
    image.write_bytes(data)
    map_path = export / "map.json"
    program = json.loads(map_path.read_bytes())
    program["jump_tables"][0]["targets"][1]["linear"] = 0x10093
    map_path.write_text(json.dumps(program), encoding="utf-8")
    row, = evidence_bundle(project, requests, export=export)["results"]
    assert row["export_evidence"]["status"] == "conflict"
    site, = row["export_evidence"]["sites"]
    assert site["conflicts"] == ["target_mismatch"]
    assert site["ranges"][-1]["conflicts"] == ["byte_mismatch"]


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

    requests = [
        {"command": "indirect", "status": "candidate", "limit": 1},
        {"command": "indirect", "status": "candidate", "offset": 1, "limit": 1},
        {"command": "indirect", "status": "resolved"},
    ]
    stored_page, initial_page, empty = evidence_bundle(project, requests, export=export)["results"]
    assert [row["export_evidence"]["status"] for row in (stored_page, initial_page, empty)] == [
        "consistent", "consistent", "unavailable",
    ]
    for row in (stored_page, initial_page):
        site, = row["export_evidence"]["sites"]
        returned, = row["result"]["sites"]
        assert site["address"] == returned["address"]
    stored_ranges = stored_page["export_evidence"]["sites"][0]["ranges"]
    assert [entry["address"]["unit_address"] for entry in stored_ranges if entry["role"] == "writer"] == [
        "root:0040", "root:0043", "root:0046", "root:0049",
    ]
    assert stored_ranges[2]["bytes"]["evidence"][0]["kind"] == "relocation"
    initial_ranges = initial_page["export_evidence"]["sites"][0]["ranges"]
    assert [entry["bytes"]["original"] for entry in initial_ranges if entry["role"] == "slot"] == [
        "24000000", "2a000000",
    ]

    # Each candidate slot references its target, so xrefs on a handler shows where it can be called from.
    assert main(["xrefs", "root:0030", "--project", str(project), "--json"]) == 0
    refs = json.loads(capsys.readouterr().out)
    assert ("root:0208", "DATA") in [(ref["from"]["unit_address"], ref["type"]) for ref in refs["incoming"]]


def test_ghidra_uses_the_explicit_segment_for_indirect_memory_operands(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    image = bytearray(0x410)
    code = bytes.fromhex(
        "ff 1e 00 00"      # call far [0], with DS still pointing at the PSP
        " 36 ff 1e 00 00"  # call far ss:[0]
        " 36 ff 1d"        # call far ss:[di], with no encoded displacement
        " ff d3 c3"       # call bx; ret
    )
    image[:len(code)] = code
    image[0x30:0x35] = bytes.fromhex("55 8b ec 5d cb")
    pack_into("<HH", image, 0x400, 0x30, 0)
    exe = tmp_path / "sample.exe"
    exe.write_bytes(_mz(image, [0x402]))
    export, project = tmp_path / "export", tmp_path / "indirect"
    assert main(["load", str(exe), "-o", str(export), "--base-segment", "2000"]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    capsys.readouterr()

    assert main(["indirect", "--project", str(project), "--json", "--compact"]) == 0, capsys.readouterr().err
    sites = {site["address"]: site for site in json.loads(capsys.readouterr().out)["sites"]}
    unknown = sites["root:0000"]
    assert (unknown["status"], unknown["reason"], unknown["segment"]) == (
        "unresolved", "segment_unknown", {"register": "DS", "value": None},
    )
    assert (unknown["segment_loss"]["address"], unknown["segment_loss"]["reason"]) == ("root:0000", "entry")
    for address in ("root:0004", "root:0009"):
        site = sites[address]
        assert (site["status"], site["segment"], site["table"]) == (
            "candidate", {"register": "SS", "value": 0x2040}, "root:0400",
        )
        candidate, = site["candidates"]
        assert (candidate["slot"], candidate["target"]) == ("root:0400", "root:0030")
    assert sites["root:000c"]["reason"] == "register"


def test_ghidra_reports_tail_jumps_as_calls(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    image = bytearray(0x40)
    image[:7] = bytes.fromhex("e8 0e 00 e8 13 00 c3")  # call 0x11; call 0x19; ret
    image[0x11:0x19] = bytes.fromhex("b8 01 00 eb 03 90 90 90")  # mov ax,1; jmp 0x19 (a tail call)
    image[0x19:0x1D] = bytes.fromhex("40 40 c3 90")          # inc ax; inc ax; ret
    exe = tmp_path / "sample.exe"
    exe.write_bytes(_mz(image, []))
    export, project = tmp_path / "export", tmp_path / "tail"
    assert main(["load", str(exe), "-o", str(export), "--base-segment", "2000"]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    capsys.readouterr()
    assert main(["callees", "root:0011", "--project", str(project), "--json"]) == 0
    callees = json.loads(capsys.readouterr().out)["callees"]
    # Ghidra's shared-return analysis already turns a jump to another function's entry into a call.
    assert [(ref["to"]["unit_address"], ref["type"]) for ref in callees] == [("root:0019", "UNCONDITIONAL_CALL")]
    assert main(["callers", "root:0019", "--project", str(project), "--json"]) == 0
    callers = {(ref["from"]["unit_address"], ref["type"]) for ref in json.loads(capsys.readouterr().out)["callers"]}
    assert callers == {("root:0003", "UNCONDITIONAL_CALL"), ("root:0014", "UNCONDITIONAL_CALL")}


def test_ghidra_classifies_gaps_and_seeds_routines_named_by_far_pointers(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    image = bytearray(0x210)
    image[:0x0B] = bytes.fromhex("b8 20 00 8e d8 9a 30 00 00 00 c3")  # set DS; call far 2000:0030; ret
    image[0x20:0x28] = bytes.fromhex("55 8b ec 8b 46 06 5d cb")  # reached only through the far pointer below
    image[0x30] = 0xCB
    image[0x40:0x200] = (b"Gap text\x01" * 50)[:0x1C0]  # Mostly printable, never a C string
    pack_into("<2H", image, 0x200, 0x20, 0)  # DGROUP:0000 holds a far pointer to 2000:0020
    exe = tmp_path / "sample.exe"
    exe.write_bytes(_mz(image, [1, 8, 0x202]))
    export, project = tmp_path / "export", tmp_path / "gaps"
    assert main(["load", str(exe), "-o", str(export), "--base-segment", "2000"]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["seeded_gaps"] == 1
    assert main(["xrefs", "root:0020", "--project", str(project), "--json"]) == 0
    refs = json.loads(capsys.readouterr().out)
    assert [(ref["from"]["unit_address"], ref["type"]) for ref in refs["incoming"]] == [("root:0200", "DATA")]

    assert main(["gaps", "--project", str(project), "--classify", "--json"]) == 0, capsys.readouterr().err
    ranges = {gap["start"]: gap for gap in json.loads(capsys.readouterr().out)["ranges"]}
    assert ranges["root:000b"]["class"] == "padding"
    text = ranges["root:0031"]  # Zero fill, then the text
    assert (text["class"], text["entry"], text["conflict"]) == ("data", None, False)
    assert "text" in [row["kind"] for row in text["evidence"]]


@pytest.fixture
def phantasie_iii_export(tmp_path, capsys):
    directory = os.environ.get("RETRORE_PH3_DIR")
    if not directory:
        pytest.skip("set RETRORE_PH3_DIR to run the real-game test")
    exe = next(path for path in Path(directory).iterdir() if path.name.upper() == "MAIN.EXE")
    assert main(["load", str(exe), "-o", str(tmp_path / "export"), "--json"]) == 0
    return tmp_path, json.loads(capsys.readouterr().out)


def _phantasie_iii_town_dispatch(tmp_path, program):
    export = tmp_path / "export"
    emulator = Emulator.from_export(export)
    image = (export / "image.bin").read_bytes()
    units = {unit["name"]: unit for unit in program["units"]}
    base = units["root"]["segment"]
    code, dgroup = base + 0x3b2, base + 0x28c0
    selection = Address(base + 0x1820, 0xb5a8)
    menu_site = Address(code, 0x724f - 0x3b20)
    window = units["link_0002"]["runtime_linear"]
    overlays = []
    loads = [{"unit": "root"}]
    for name in ("link_0002", "link_0003"):
        unit = units[name]
        assert unit["runtime_linear"] == window
        start = unit["image_offset"]
        overlays.append((Address(window // 16, 0), image[start:start + unit["size"]]))
        loads.append({"unit": name, "linear": window, "replace": True})

    # An original boot loaded member 2, then members 1 and 3 over its prefix. Member 3
    # covers member 1, and five handlers remain in the tail of member 2. Start at the
    # menu's selection lookup and stop at each entry before executing overlay code.
    class HandlerReached(Exception):
        pass

    def observe(cpu):
        ss, sp = (cpu.reg_read(register) for register in (x86.UC_X86_REG_SS, x86.UC_X86_REG_SP))
        assert cpu.mem_read(Address(ss, sp).linear, 4) == pack("<HH", 0x7253 - 0x3b20, code)
        assert cpu.mem_read(target.linear, 8) == overlays[0][1][target.offset:target.offset + 8]
        raise HandlerReached

    targets = (0x4112, 0x4152, 0x4192, 0x4259, 0x4308)  # Bank, Mystic, Exit, Armor, Inn.
    events = [{"kind": "overlay", "state": "town"}]
    for selected, handler in zip(range(0x83e, 0x867, 10), targets, strict=True):
        target = Address(window // 16, handler)
        assert len(overlays[1][1]) <= handler < len(overlays[0][1]) - 7
        with pytest.raises(HandlerReached):
            emulator.call(
                Address(code, 0x7242 - 0x3b20), regs={"ds": dgroup, "ss": dgroup, "sp": 0x7600},
                writes=[*overlays, (selection, pack("<HH", selected, dgroup))],
                hooks={target: observe}, limit=20,
            )
        events.append({"kind": "edge", "from": menu_site.linear, "to": target.linear, "flow": "call"})

    manifest = tmp_path / "town-loads.json"
    manifest.write_text(json.dumps({
        "version": 1, "initial": "root",
        "states": [{"name": "root", "loads": [{"unit": "root"}]}, {"name": "town", "loads": loads}],
        "transitions": [{"from": "root", "to": "town", "kind": "overlay"}],
    }), encoding="utf-8")
    map_path = export / "map.json"
    program_map = json.loads(map_path.read_text(encoding="utf-8"))
    apply_load_manifest(manifest, image, program_map)
    map_path.write_text(json.dumps(program_map), encoding="utf-8")
    return events, {f"link_0002:{handler:04x}" for handler in targets}


def test_phantasie_iii_root_switches(phantasie_iii_export, phantasie_iii_float_startup, capsys):
    tmp_path, program = phantasie_iii_export
    export = tmp_path / "export"
    tables = {(table["address"]["segment"], table["address"]["offset"]): table
              for table in program["jump_tables"] if table["unit"] == "root"}
    # Microsoft C switches branch over the default jump (cmp ax,0x12; jbe; jmp default).
    # The floating-point emulator at segment 0x218f dispatches through masked jump and call tables.
    assert len(tables) == 22
    switch = tables[0x1284, 0x0BA9]
    assert (switch["bound"], len(switch["targets"]), switch["default"]["offset"]) == ("compare", 19, 0x0C3E)
    emulator = tables[0x218F, 0x0BCC]
    assert (emulator["kind"], emulator["bound"], emulator["table"]["offset"]) == ("call", "mask", 0x077E)
    assert [target["offset"] for target in emulator["targets"]][:4] == [0x0CB6, 0x0D97, 0x0CC1, 0x0CCC]

    # Check initialized far-pointer sources across the root and all four LINK members.
    for target, sources in (
        ("root:6017", ["root:2b230"]), ("root:6a12", ["root:2b0d4"]),
        ("root:6383", []), ("root:68a4", []),
    ):
        assert main(["where-is", "--export", str(export), "--pointer", target, "--pointer-kind", "far", "--json"]) == 0
        matches = json.loads(capsys.readouterr().out)["matches"]
        assert [match["unit_address"] for match in matches] == sources
        assert all(match["relocated"] for match in matches)
    for target in ("13b2:2863", "13b2:2d84"):  # Runtime CS:IP for root:6383 and root:68a4.
        assert main(["where-is", "--export", str(export), "--pointer", target, "--pointer-kind", "near", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["matches"] == []

    town_events, town_targets = _phantasie_iii_town_dispatch(tmp_path, program)
    town_trace = tmp_path / "town-dispatch.json"
    town_trace.write_text(json.dumps({"version": 1, "events": town_events}), encoding="utf-8")
    assert main(["trace", str(town_trace), "--export", str(export), "--json"]) == 0, capsys.readouterr().err
    town_edges = json.loads(capsys.readouterr().out)["edges"]
    assert {(edge["from"]["location"]["unit_address"], edge["to"]["location"]["unit_address"])
            for edge in town_edges} == {("root:724f", target) for target in town_targets}

    if not os.environ.get("GHIDRA_HOME"):
        return
    project = tmp_path / "ph3"
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["units"] == 5
    # With the LINK overlays loaded, Ghidra reaches this function through a direct call.
    assert main(["xrefs", "root:532c", "--project", str(project), "--json"]) == 0
    refs = json.loads(capsys.readouterr().out)
    assert ("root:a9bf", "UNCONDITIONAL_CALL") in [
        (ref["from"]["unit_address"], ref["type"]) for ref in refs["incoming"]
    ]
    assert main(["gaps", "--project", str(project), "--classify", "--unit", "root", "--json", "--limit", "1000"]) == 0
    gaps = {gap["start"]: gap for gap in json.loads(capsys.readouterr().out)["ranges"]}
    assert (gaps["root:3a33"]["class"], gaps["root:3a33"]["entry"]) == ("code", "root:3a33")
    assert {"prologue", "valid_subroutine"} <= set(gaps["root:3a33"]["counts"])
    assert main(["func", "218f:0ccc", "--project", str(project), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["function"]["entry"]["unit_address"] == "root:125bc"
    assert {"from": "root:124bc", "type": "COMPUTED_CALL"} in [
        {"from": caller["from"]["unit_address"], "type": caller["type"]} for caller in report["callers"]
    ]

    requests = [
        {"command": "indirect", "at": address, "compact": True} for address in ("root:42df", "root:13721")
    ]
    requests.append({"command": "indirect", "limit": 1000, "compact": True})
    requests.append({
        "command": "record-writes", "address": "280a:00ab", "stride": 12, "count": 15, "compact": True,
        "code_start": "root:1241c", "code_end": "root:13721", "limit": 1000,
    })
    requests.extend({"command": "xrefs", "address": address, "direction": "incoming"} for address in (
        "38c0:1dd6", "root:6a12", "root:6383", "root:68a4", "root:6349",
    ))
    batch = tmp_path / "queries.json"
    batch.write_text(json.dumps(requests), encoding="utf-8")
    assert main(["batch", str(batch), "--project", str(project), "--evidence", "--json"]) == 0
    callback_result, dispatch_result, inventory, writes_result, *references = [
        row["result"] for row in json.loads(capsys.readouterr().out)["results"]
    ]
    callback, = callback_result["sites"]
    dispatch, = dispatch_result["sites"]
    assert (callback["status"], callback["segment"], callback["table"]) == (
        "candidate", {"register": "SS", "value": 0x38C0}, "root:2b224",
    )
    candidate, = callback["candidates"]
    assert candidate["target"] == "root:11914" and "relocated" in candidate["evidence"]
    assert dispatch["status"] == "unresolved" and dispatch["reason"] == "no_valid_entries"
    # Audit Ghidra's targets and candidates across the root and all four LINK members.
    assert inventory["pagination"]["sites"]["next_offset"] is None
    detached = {"root:6383", "root:68a4", "root:6a12"}
    observed_targets = {
        target for site in inventory["sites"]
        for target in (*site["targets"], *(row["target"] for row in site.get("candidates", ())))
    }
    assert detached.isdisjoint(observed_targets)
    # The listing shows the integer-parser call but has no incoming reference for these paths.
    assert [report["incoming"] for report in references[:-1]] == [[], [], [], []]
    parser_call, = references[-1]["incoming"]
    assert parser_call["from"]["unit_address"] == "root:60e4"

    # FST's ordinary output store can reach the record through an external segment and offset.
    # Record copies read either a CS template or another DS record.
    writes = {row["address"]: row for row in writes_result["writes"]}
    assert writes_result["undefined_bytes"] > 0 and writes_result["unresolved_transfers"] > 0
    fst = writes["root:12e40"]
    assert fst["status"] == "possible" and fst["width"] == 2 and fst["context"]
    assert fst["destination"] == {"register": "ES", "segment": None, "offset": None, "linear": None}
    assert writes["root:1271c"]["source"]["register"] == "CS"
    assert writes["root:1273c"]["source"]["register"] == "DS"

    # Replay the observed initializer and dispatcher calls and the validated FCOM/FCOMP and FTST successors.
    root_linear = program["units"][0]["linear"]
    startup_edges, _ = phantasie_iii_float_startup
    dispatch_targets = {
        0x1366D: (0x13672, 0x13699, 0x136AE, 0x136B5, 0x136BC, 0x136C2, 0x136C9, 0x136D0),
        0x13721: (0x136BC, 0x13699, 0x136AE, 0x136B5),
    }
    trace = tmp_path / "float_dispatch.json"
    events = [
        {"kind": "edge", "from": caller.linear, "to": target.linear, "flow": "call"}
        for caller, target in startup_edges
    ] + [
        {"kind": "edge", "from": root_linear + site, "to": root_linear + target, "flow": "jump"}
        for site, targets in dispatch_targets.items() for target in targets
    ] + town_events
    trace.write_text(json.dumps({"version": 1, "events": events}), encoding="utf-8")
    assert main(["trace", str(trace), "--export", str(export),
                 "--project", str(project), "--apply", "--json"]) == 0, capsys.readouterr().err
    applied = json.loads(capsys.readouterr().out)["analysis"]["applied"]
    assert any(row["address"]["unit_address"] == "root:1366d" for row in applied if row["kind"] == "instruction")
    assert {(row["from"]["unit_address"], row["to"]["unit_address"]) for row in applied if row["kind"] == "flow"} == {
        (f"root:{site:x}", f"root:{target:x}") for site, targets in dispatch_targets.items() for target in targets
    } | {(f"root:{caller.linear - root_linear:04x}", f"root:{target.linear - root_linear:04x}")
         for caller, target in startup_edges} | {("root:724f", target) for target in town_targets}
    expected = {
        "root:42df": {"root:11914"}, "root:42f5": {"root:11914"}, "root:4405": {"root:6017"},
        "root:1191c": {"root:1192a", "root:11a2a"}, "root:724f": town_targets,
        **{f"root:{site:x}": {f"root:{target:x}" for target in targets} for site, targets in dispatch_targets.items()},
    }
    batch.write_text(json.dumps([
        {"command": "indirect", "at": site, "compact": True} for site in expected
    ]), encoding="utf-8")
    assert main(["batch", str(batch), "--project", str(project), "--json"]) == 0
    reports = json.loads(capsys.readouterr().out)["results"]
    for report, (site, targets) in zip(reports, expected.items(), strict=True):
        recovered, = report["result"]["sites"]
        assert recovered["address"] == site
        assert recovered["status"] == "resolved"
        assert set(recovered["targets"]) == targets


def _dos_vector(cpu, _number):
    ax = cpu.reg_read(x86.UC_X86_REG_AX)
    vector = 4 * (ax & 0xff)
    if ax >> 8 == 0x35:
        offset, segment = unpack_from("<HH", cpu.mem_read(vector, 4))
        cpu.reg_write(x86.UC_X86_REG_BX, offset)
        cpu.reg_write(x86.UC_X86_REG_ES, segment)
    else:
        assert ax >> 8 == 0x25
        cpu.mem_write(vector, pack("<HH", cpu.reg_read(x86.UC_X86_REG_DX), cpu.reg_read(x86.UC_X86_REG_DS)))


@pytest.fixture
def phantasie_iii_float_startup(phantasie_iii_export):
    tmp_path, program = phantasie_iii_export
    emulator = Emulator.from_export(tmp_path / "export")
    base = program["units"][0]["segment"]
    psp, environment = base - 0x10, base - 0x11
    dgroup = base + 0x28c0
    code = base + 0x3b2

    def root(offset):
        return Address(code, offset - 0x3b20)

    def dos(cpu, number):
        ax = cpu.reg_read(x86.UC_X86_REG_AX)
        service = ax >> 8
        if service == 0x30:
            cpu.reg_write(x86.UC_X86_REG_AX, 6)  # DOS 6.0
        elif service in (0x25, 0x35):
            _dos_vector(cpu, number)
        else:
            assert ax == 0x4400  # IOCTL device information for the standard handles.
            cpu.reg_write(x86.UC_X86_REG_DX, 0x80)
        cpu.reg_write(x86.UC_X86_REG_EFLAGS, cpu.reg_read(x86.UC_X86_REG_EFLAGS) & ~1)

    site, installer = root(0x4405), root(0x6017)
    emu_code = base + 0x118f
    dispatcher = Address(emu_code, 0x24)
    table_call = Address(emu_code, 0x2c)
    edges = []

    def stack_bytes(cpu, size):
        ss, sp = (cpu.reg_read(register) for register in (x86.UC_X86_REG_SS, x86.UC_X86_REG_SP))
        return cpu.mem_read(Address(ss, sp).linear, size)

    def observe_dispatcher(cpu):
        service = cpu.reg_read(x86.UC_X86_REG_BX)
        caller = root({0: 0x42df, 3: 0x42f5}[service])
        assert stack_bytes(cpu, 4) == pack("<HH", caller.offset + 5, caller.segment)
        edges.append((caller, dispatcher))

    def observe_service(cpu, service, target):
        assert cpu.reg_read(x86.UC_X86_REG_BX) == service * 2
        assert stack_bytes(cpu, 2) == pack("<H", 0x31)  # Near return from the table call.
        edges.append((table_call, target))

    def observe_installer(cpu):
        assert stack_bytes(cpu, 4) == pack("<HH", root(0x4407).offset, code)
        assert cpu.mem_read(site.linear, 2) == bytes.fromhex("ff1d")  # CALL FAR [DI]
        ds, di = (cpu.reg_read(register) for register in (x86.UC_X86_REG_DS, x86.UC_X86_REG_DI))
        assert (ds, di) == (dgroup, 0x2630)
        offset, segment = unpack_from("<HH", cpu.mem_read(Address(ds, di).linear, 4))
        assert Address(segment, offset) == installer
        edges.append((site, installer))

    # Enter the shipped C initialization subroutine with the PSP and software-FPU setting.
    callback = Address(dgroup, 0x1dd6)
    initialize, register = Address(emu_code, 0x3a), Address(emu_code, 0x13a)
    installed = emulator.call(
        root(0x42a8), far=True, regs={"ds": dgroup, "ss": dgroup, "sp": 0x7600},
        writes=[(Address(dgroup, 0x1d5f), pack("<H", psp)), (Address(psp, 0x2c), pack("<H", environment)),
                (Address(environment, 0), b"NO87=\0\0")],
        reads=[(callback, 4)], interrupts={0x21: dos}, hooks={
            dispatcher: observe_dispatcher,
            initialize: lambda cpu: observe_service(cpu, 0, initialize),
            register: lambda cpu: observe_service(cpu, 3, register),
            installer: observe_installer,
        },
    )
    assert edges == [
        (root(0x42df), dispatcher), (table_call, initialize),
        (root(0x42f5), dispatcher), (table_call, register), (site, installer),
    ]
    offset, segment = unpack_from("<HH", dict(installed.memory)[callback])
    assert Address(segment, offset) == root(0x6a12)
    return edges, installed.memory


@pytest.fixture
def phantasie_iii_float_runtime(phantasie_iii_export):
    tmp_path, program = phantasie_iii_export
    export = tmp_path / "export"
    image = (export / "image.bin").read_bytes()
    emulator = Emulator.from_export(export)
    code_base = 0x118F0
    code_segment = program["units"][0]["segment"] + code_base // 16
    data_segment, = unpack_from("<H", image, 0x1249F)

    def runtime_address(offset):
        return Address(code_segment, offset - code_base)

    vectors = range(0x34, 0x3e)
    ivt = Address(0, 4 * vectors.start)
    installed = emulator.call(
        runtime_address(0x11a32), regs={"ds": data_segment},
        writes=[(Address(data_segment, 4), b"\0")],  # Select the software path.
        reads=[(ivt, 4 * len(vectors))], interrupts={0x21: _dos_vector},
    )
    assert installed.memory[0][1] == b"".join(
        pack("<HH", runtime_address(entry).offset, code_segment)
        for entry in (0x1241c,) * 8 + (0x123db, 0x123be)
    )
    initialized = emulator.call(
        runtime_address(0x11a09), regs={"ds": data_segment}, reads=[(Address(data_segment, 0x0e), 6)],
    )
    return emulator, runtime_address, data_segment, vectors, (*installed.memory, *initialized.memory)


def test_phantasie_iii_arithmetic_and_stack_record_classes(phantasie_iii_float_runtime):
    emulator, runtime_address, data_segment, vectors, setup = phantasie_iii_float_runtime
    stack_top = Address(data_segment, 0x10)
    bottom, empty_stack, last_record = unpack_from("<3H", dict(setup)[Address(data_segment, 0x0e)])
    records = Address(data_segment, bottom)
    fields = set(range(records.linear + 11, Address(data_segment, last_record + 12).linear, 12))
    written_classes = set()
    arithmetic_pairs = set()
    arithmetic_tables = dict.fromkeys((0xc1, 0xe1, 0xe9), 0x816) | {0xc9: 0x836, 0xf1: 0x856, 0xf9: 0x856}
    scratch = Address(0x7000, 0)

    def audit_classes(cpu):
        def record_write(_cpu, _access, address, size, value, _data):
            for byte in range(address, address + size):
                if byte in fields:
                    field = (value >> (8 * (byte - address))) & 0xff
                    assert 0 <= field <= 3
                    written_classes.add(field)

        hook = cpu.hook_add(UC_HOOK_MEM_WRITE, record_write, begin=records.linear, end=max(fields))
        return lambda: cpu.hook_del(hook)

    def probe(load, operands, operation):
        dispatches = []

        def observe(cpu, comparison):
            segment = cpu.reg_read(x86.UC_X86_REG_DS) * 16
            registers = (x86.UC_X86_REG_SI, x86.UC_X86_REG_DI) if comparison else (x86.UC_X86_REG_SI,)
            classes = tuple(cpu.mem_read(segment + cpu.reg_read(register) + 11, 1)[0] for register in registers)
            assert all(0 <= value <= 3 for value in classes)
            slot = 4 * classes[0] + classes[1] if comparison else classes[0]
            assert cpu.reg_read(x86.UC_X86_REG_BX) == 2 * slot
            dispatches.append(classes)

        def observe_arithmetic(cpu):
            segment = cpu.reg_read(x86.UC_X86_REG_DS) * 16
            si, di = (cpu.reg_read(register) for register in (x86.UC_X86_REG_SI, x86.UC_X86_REG_DI))
            left, right = (cpu.mem_read(segment + index + 11, 1)[0] for index in (di, si))
            assert left < 4 and right < 4
            assert cpu.reg_read(x86.UC_X86_REG_BX) == arithmetic_tables[operation] + 2 * (4 * left + right)
            arithmetic_pairs.add((left, right))

        # FLDCW masks numeric exceptions. The trailing probes test, duplicate, exchange,
        # copy, and pop the result using the runtime's software interrupt encoding.
        code = bytes.fromhex(
            f"cd352e2002 {load} cd34{operation:02x} "
            "cd35e4 cd35c0 cd35e4 cd34d9 cd35c9 cd35e4 cd34d1 "
            "cd39d1 cd34d1 cd39d9 cd35e4 c3"
        )
        final = emulator.call(
            scratch, regs={"ds": scratch.segment, "es": scratch.segment, "ss": scratch.segment, "sp": 0xFF00},
            writes=[
                *setup,
                (scratch, code),
                (Address(scratch.segment, 0x200), operands),
                (Address(scratch.segment, 0x220), pack("<H", 0x037F)),
            ],
            reads=[(stack_top, 2)],
            ivt_interrupts=vectors,
            hooks={
                runtime_address(0x13721): lambda cpu: observe(cpu, False),
                runtime_address(0x1366d): lambda cpu: observe(cpu, True),
                runtime_address(0x126cf): observe_arithmetic,
            },
            limit=4000, _setup=audit_classes,
        )
        result, duplicate, compared_copy, exchanged, compared_exchange, stored, popped = dispatches
        assert duplicate == result and compared_copy == result * 2
        assert compared_exchange == (*exchanged, *result)
        assert stored == exchanged * 2 and popped == exchanged
        assert int.from_bytes(final.memory[0][1], "little") == empty_stack + 12
        return result[0]

    samples = (
        0x3F800000, 0xBF800000, 0x00000001, 0x00000000, 0x80000000, 0x7FC00001,
        0x7F800001, 0x7F800000, 0xFF800000, 0x7F7FFFFF, 0x00800000,
    )
    # FADD, FMUL, FSUB, FSUBR, FDIV, FDIVR ST,ST(1).
    for operation in arithmetic_tables:
        arithmetic_pairs.clear()
        classes = {
            probe("cd35060002 cd35060402", pack("<II", a, b), operation)
            for a, b in product(samples, repeat=2)
        }
        assert classes == {0, 1, 2, 3}
        assert arithmetic_pairs == set(product(range(4), repeat=2))

    # Extended inputs reach result paths outside the exponent range of single-precision inputs.
    for exponent, operation, expected in ((0x7FFE, 0xC9, 3), (1, 0xC9, 1), (0, 0xF1, 2)):
        significand = 0x8000000000000000 if exponent else 0
        operands = pack("<QHQH", significand, exponent, significand, exponent)
        assert probe("cd372e0002 cd372e0a02", operands, operation) == expected
    assert written_classes == {0, 1, 2, 3}


def test_phantasie_iii_float_exception_record_classes(phantasie_iii_export, phantasie_iii_float_runtime):
    emulator, runtime_address, data_segment, vectors, setup = phantasie_iii_float_runtime
    tmp_path, program = phantasie_iii_export
    image = (tmp_path / "export" / "image.bin").read_bytes()
    # The arithmetic substitutions and FLD constants copy complete CS records.
    templates = (0x1216e, 0x1217a, 0x12186, 0x12192, 0x121b6, 0x121c2,
                 0x1220a, 0x12216, 0x12222, 0x1222e, 0x1223a)
    assert [image[offset + 11] for offset in templates] == [1, 3, 2, 0, 1, 0, 0, 0, 0, 0, 0]

    bottom, empty_top, limit = unpack_from("<3H", dict(setup)[Address(data_segment, 0x0e)])
    scratch = Address(0x7000, 0)
    operands_address = Address(scratch.segment, 0x200)
    control_word = Address(scratch.segment, 0x218)
    report = Address(scratch.segment, 0x300)
    handler_pointer = Address(data_segment, 0)
    stack_top = Address(data_segment, 0x10)
    first_field = Address(data_segment, bottom - 1).linear
    last_field = Address(data_segment, limit + 23).linear  # Include the slot past the stack limit.

    # Run the startup's BX=3 indirect call to register the game's exception callback.
    base = program["units"][0]["segment"]
    dgroup = base + 0x28c0
    c_segment = base + 0x3b2
    sp = program["stack"]["offset"] + 0x6c4e - 0x100
    registered = emulator.call(
        Address(c_segment, 0x42eb - 0x3b20), regs={"ds": dgroup, "ss": dgroup, "sp": sp},
        writes=[(Address(c_segment, 0x42fa - 0x3b20), b"\xc3")], reads=[(handler_pointer, 4)],
    )
    assert registered.memory == ((handler_pointer, pack("<HH", 0x602b - 0x3b20, c_segment)),)

    class ProgramExit(Exception):
        pass

    def dos(cpu, _number):
        ax = cpu.reg_read(x86.UC_X86_REG_AX)
        service = ax >> 8
        if service == 0x4c:
            raise ProgramExit(ax & 0xff)
        if service == 0x40:
            cpu.reg_write(x86.UC_X86_REG_AX, cpu.reg_read(x86.UC_X86_REG_CX))
        else:
            assert service == 0x25  # Restore interrupt vectors during shutdown.
        cpu.reg_write(x86.UC_X86_REG_EFLAGS, cpu.reg_read(x86.UC_X86_REG_EFLAGS) & ~1)

    def probe(code, operands, mask, *, game_handler=False):
        errors, classes = [], []
        writes = {}

        def audit(cpu):
            def record_write(_cpu, _access, address, size, value, _data):
                for byte in range(address, address + size):
                    if first_field <= byte <= last_field and (byte - first_field) % 12 == 0:
                        field = (value >> (8 * (byte - address))) & 0xff
                        assert field <= 3
                        writes.setdefault(byte - data_segment * 16, []).append(field)

            hook = cpu.hook_add(UC_HOOK_MEM_WRITE, record_write, begin=first_field - 11, end=last_field)
            return lambda: cpu.hook_del(hook)

        def exception(cpu):
            errors.append(cpu.reg_read(x86.UC_X86_REG_AL))

        def observe_test(cpu):
            assert cpu.reg_read(x86.UC_X86_REG_DS) == data_segment
            record = cpu.reg_read(x86.UC_X86_REG_SI)
            value = cpu.mem_read(Address(data_segment, record + 11).linear, 1)[0]
            assert value <= 3 and cpu.reg_read(x86.UC_X86_REG_BX) == 2 * value
            classes.append((record, value))

        operand_writes = [(operands_address, operands)] if operands else []
        # The supplied callback returns so FTST observes the state after the exception.
        handler = registered.memory if game_handler else (
            (handler_pointer, pack("<HH", report.offset, report.segment)), (report, b"\xcb"),
        )
        result = emulator.call(
            scratch, regs={"ds": scratch.segment, "ss": dgroup if game_handler else scratch.segment,
                           "sp": sp if game_handler else 0xff00},
            writes=[
                *setup,
                (scratch, bytes.fromhex(f"cd352e1802 {code} cd35e4 c3")),  # FLDCW; probe; FTST.
                *operand_writes,
                (control_word, pack("<H", mask)),
                *handler,
            ],
            reads=[(stack_top, 2)], ivt_interrupts=vectors, interrupts={0x21: dos} if game_handler else {},
            hooks={report: exception, runtime_address(0x13721): observe_test}, _setup=audit,
        )
        final_top, = unpack_from("<H", result.memory[0][1])
        return errors, classes, final_top, writes

    divide_by_zero = ("cd35060002 cd35060402 cd34f9", pack("<2f", 1, 0), 0x037b)
    empty_store = ("cd351e0802", b"", 0x037e)
    pushes = (limit - empty_top) // 12 + 1
    stack_overflow = ("cd35e8 " * pushes, b"", 0x037e)

    # Unmasked divide by zero substitutes the infinity template before returning to FTST.
    errors, classes, top, writes = probe(*divide_by_zero)
    assert errors == [0x83] and top == empty_top + 24 and classes == [(top, 3)]
    assert writes[top + 11] == [1, 3]

    # An invalid store on an empty stack leaves FTST reading the slot below the initial top.
    errors, classes, top, writes = probe(*empty_store)
    assert errors == [0x8b] and top == empty_top - 12 and classes == [(top, 0)]
    assert writes == {}

    # A returning exception callback lets the FLD1 copy write the slot past the limit.
    errors, classes, top, writes = probe(*stack_overflow)
    assert errors == [0x8a] and top == limit + 12 and classes == [(top, 0)]
    assert writes == {record + 11: [0] for record in range(empty_top + 12, top + 1, 12)}

    # Memory division stages a double zero in the next record. The register form then underflows.
    errors, classes, top, writes = probe("cd35e8 cd383e0002 cd34f9", pack("<d", 0), 0x037b)
    assert errors == [0x8b] and top == empty_top + 12 and classes == [(top, 1)]
    assert writes == {top + 11: [0, 1], top + 23: [1]}

    for operation, status in ((divide_by_zero, 0x83), (empty_store, 0x8b), (stack_overflow, 0x8a)):
        with pytest.raises(ProgramExit) as error:
            probe(*operation, game_handler=True)
        assert error.value.args == (status,)


def test_phantasie_iii_float_store_outputs_and_interrupt_edges(
    phantasie_iii_export, phantasie_iii_float_runtime, capsys,
):
    tmp_path, _ = phantasie_iii_export
    emulator, runtime_address, data_segment, vectors, setup = phantasie_iii_float_runtime
    bottom, top, limit = unpack_from("<3H", dict(setup)[Address(data_segment, 0x0e)])
    assert top == bottom and (limit - bottom) // 12 + 1 == 15
    records = Address(data_segment, bottom)
    size = limit - bottom + 12
    live_record = Address(data_segment, top + 12)
    field = live_record.offset + 11
    stack_top = Address(data_segment, 0x10)
    scratch = Address(0x7000, 0)
    source = pack("<I", 0x3f80007f)
    regs = {"ds": scratch.segment, "ss": scratch.segment, "sp": 0xff00}
    loaded = emulator.call(
        scratch, regs=regs, writes=[*setup, (scratch, bytes.fromhex("cd35060002 c3")),
                                   (Address(scratch.segment, 0x200), source)],
        reads=[(records, size), (stack_top, 2)], ivt_interrupts=vectors,
    )
    assert loaded.memory[0][1][field - bottom] == 0
    assert loaded.memory[1][1] == pack("<H", live_record.offset)
    prefixed_store = emulator.resolve("root:6a5b")
    wait = emulator.resolve("root:6a5f")
    edges = set()

    def entry(cpu, target):
        ss = cpu.reg_read(x86.UC_X86_REG_SS)
        sp = cpu.reg_read(x86.UC_X86_REG_SP)
        ip, cs = unpack_from("<HH", cpu.mem_read(Address(ss, sp).linear, 4))
        caller = Address(cs, (ip - 2) & 0xffff)
        edges.add((caller.linear, target.linear, cpu.mem_read(caller.linear, 2).hex()))

    for prefixed in (False, True):
        for alias in (False, True):
            output = Address(data_segment + 1, field - 16) if alias else Address(scratch.segment, 0x204)
            stores = []

            def observe_store(cpu):
                record = Address(cpu.reg_read(x86.UC_X86_REG_DS), cpu.reg_read(x86.UC_X86_REG_SI))
                destination = Address(cpu.reg_read(x86.UC_X86_REG_ES), cpu.reg_read(x86.UC_X86_REG_DI))
                stores.append((record, destination))

            hooks = dict.fromkeys((runtime_address(0x12e40), runtime_address(0x12e43)), observe_store)
            patches = [*setup, *loaded.memory]
            reads = [(output, 4), (records, size), (stack_top, 2)]
            if prefixed:
                # Start at the original FSTP ES:[BX] in the routine's tail. Supply its saved BP and far frame.
                start = prefixed_store
                inputs = {**regs, "es": output.segment, "bx": output.offset, "bp": regs["sp"] - 6}
                reads.append((wait, 2))
                for offset in (0x123db, 0x123be):
                    target = runtime_address(offset)
                    hooks[target] = lambda cpu, target=target: entry(cpu, target)
            else:
                start = scratch
                inputs = {**regs, "ds": output.segment}
                patches.append((scratch, bytes.fromhex("cd3516") + pack("<H", output.offset) + b"\xc3"))

            final = emulator.call(start, regs=inputs, writes=patches, reads=reads, far=prefixed,
                                  hooks=hooks, ivt_interrupts=vectors)
            assert stores == [(live_record, output), (live_record, Address(output.segment, output.offset + 2))]
            output_bytes, record_bytes, top_bytes = (item[1] for item in final.memory[:3])
            assert output_bytes == source
            expected = bytearray(loaded.memory[0][1])
            if alias:
                assert output.linear == Address(data_segment, field).linear
                expected[field - bottom:field - bottom + 4] = source
                assert record_bytes[field - bottom] == 0x7f
            else:
                assert output.linear >= records.linear + size
            assert record_bytes == expected
            assert top_bytes == pack("<H", top if prefixed else live_record.offset)
            if prefixed:
                assert final.memory[-1][1] == bytes.fromhex("89c0")  # The WAIT handler patches its own call site.

    assert edges == {
        (prefixed_store.linear, runtime_address(0x123db).linear, "cd3c"),
        (wait.linear, runtime_address(0x123be).linear, "cd3d"),
    }
    if os.environ.get("GHIDRA_HOME"):
        export, project = tmp_path / "export", tmp_path / "float"
        assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
        capsys.readouterr()
        trace = tmp_path / "float_interrupts.json"
        events = [
            event for caller, target, data in sorted(edges)
            for event in ({"kind": "instruction", "address": caller, "bytes": data},
                          {"kind": "edge", "from": caller, "to": target, "flow": "interrupt"})
        ]
        trace.write_text(json.dumps({"version": 1, "events": events}), encoding="utf-8")
        assert main(["trace", str(trace), "--export", str(export), "--project", str(project),
                     "--apply", "--json"]) == 0, capsys.readouterr().err
        applied = json.loads(capsys.readouterr().out)["analysis"]["applied"]
        assert {(row["from"]["unit_address"], row["to"]["unit_address"]) for row in applied if row["kind"] == "flow"} == {
            ("root:6a5b", "root:123db"), ("root:6a5f", "root:123be"),
        }


def test_phantasie_iii_shipped_float_store_destinations(
    phantasie_iii_export, phantasie_iii_float_runtime, phantasie_iii_float_startup,
):
    tmp_path, program = phantasie_iii_export
    emulator, runtime_address, data_segment, vectors, setup = phantasie_iii_float_runtime
    bottom, _, limit = unpack_from("<HHH", dict(setup)[Address(data_segment, 0x0e)])
    records_start = Address(data_segment, bottom).linear
    records_end = Address(data_segment, limit + 12).linear
    assert (bottom, limit) == (0xa0, 0x148)

    # The C startup switches SS to DGROUP and adds 0x6c4e to SP at root:41f7.
    base = program["units"][0]["segment"]
    dgroup = base + 0x28c0
    sp = program["stack"]["offset"] + 0x6c4e - 0x100  # Leave room for the test arguments.
    args = Address(dgroup, sp)
    regs = {"ds": dgroup, "ss": dgroup, "sp": sp}
    code_segment = base + 0x3b2
    # Use the same control word as the software path of the runtime startup.
    control = emulator.call(
        runtime_address(0x11e8d), regs={"ds": data_segment, "ax": 0x1332},
        reads=[(Address(data_segment, 6), 6)],
    )
    setup = (*setup, *control.memory)

    def root(offset):
        return Address(code_segment, offset - 0x3b20)

    operand_decoder = runtime_address(0x1249b)

    def check(start, stores, *, arguments=b"", writes=(), reads=(), far=True, **registers):
        observed = {}
        current = None

        def operand(cpu):
            nonlocal current
            # The handler has decoded the memory operand into ES:SI and has not
            # yet replaced DS with its private data segment at root:124a1.
            bp = cpu.reg_read(x86.UC_X86_REG_BP)
            ss = cpu.reg_read(x86.UC_X86_REG_SS)
            ip, cs = unpack_from("<HH", cpu.mem_read(Address(ss, bp + 0x14).linear, 4))
            # The saved IP still points just past the two-byte INT.
            site = Address(cs, (ip - 2) & 0xffff)
            current = site if site in stores else None
            if current is None:
                return
            destination = Address(cpu.reg_read(x86.UC_X86_REG_ES), cpu.reg_read(x86.UC_X86_REG_SI))
            assert destination == stores[site][0]
            assert site not in observed
            observed[site] = set()

        def returned(_cpu):
            nonlocal current
            current = None

        def audit_writes(cpu):
            def write(cpu, _access, address, size, _value, _data):
                if current is None:
                    return
                assert address + size <= records_start or address >= records_end
                destination, width = stores[current]
                if cpu.reg_read(x86.UC_X86_REG_CS) == operand_decoder.segment and (
                    destination.linear <= address < destination.linear + width
                ):
                    assert address + size <= destination.linear + width
                    observed[current].update(range(address, address + size))

            hook = cpu.hook_add(UC_HOOK_MEM_WRITE, write)
            return lambda: cpu.hook_del(hook)

        argument_writes = [(args, arguments)] if arguments else []
        result = emulator.call(
            start, far=far, regs={**regs, **registers}, writes=[*setup, *writes, *argument_writes],
            reads=reads, hooks={operand_decoder: operand, runtime_address(0x125a2): returned},
            ivt_interrupts=vectors, _setup=audit_writes,
        )
        assert observed == {
            site: set(range(destination.linear, destination.linear + width))
            for site, (destination, width) in stores.items()
        }
        return dict(result.memory)

    text = Address(dgroup, 0x7000)
    double = Address(dgroup, 0x2582)
    ascii_number = b"1.25\0"
    decimal_stores = {
        root(0x606f): (Address(dgroup, 0x2533), 2),
        root(0x6243): (Address(dgroup, 0x2531), 2),
        root(0x6254): (double, 8),
        root(0x6257): (Address(dgroup, 0x2531), 2),
    }
    converted = check(
        root(0x502c), decimal_stores,
        arguments=pack("<HH", text.offset, text.segment), writes=[(text, ascii_number)], reads=[(double, 8)],
    )
    assert converted[double] == pack("<d", 1.25)

    integer = check(
        root(0x67d6), {root(0x606f): (Address(dgroup, 0x2533), 2), root(0x60f4): (double, 8)},
        arguments=pack("<HHHHH", text.offset, text.segment, 2, 0, 16),
        writes=[(text, b"2a")], reads=[(double, 8)],
    )
    assert integer[double] == pack("<d", 42.0)

    extended = Address(dgroup, 0x2538)
    check(
        root(0x6836), {
            root(0x64ea): (Address(dgroup, 0x2569), 2), root(0x6504): (extended, 10),
            root(0x6546): (Address(dgroup, 0x2567), 2), root(0x6560): (extended, 10),
        },
        arguments=pack("<d", 1.25),
    )

    check(
        root(0x69f1), {root(0x688d): (Address(dgroup, sp - 14), 2)},
        arguments=pack("<HH", text.offset, text.segment), writes=[(text, pack("<d", 1.25))],
    )

    # This callback uses two LES loads to find the caller's output slot.
    # Recover its entry from the table populated by the shipped installer.
    callback = Address(dgroup, 0x1dd6)
    _, installed = phantasie_iii_float_startup
    offset, segment = unpack_from("<HH", dict(installed)[callback])
    slot, output = Address(dgroup, 0x7010), Address(dgroup, 0x7020)
    for double_output in (False, True):
        expected = pack("<d" if double_output else "<f", 1.25)
        stores = dict(decimal_stores)
        if not double_output:
            stores[root(0x6a5b)] = (output, len(expected))
        converted = check(
            Address(segment, offset), stores,
            arguments=pack("<5H", double_output, slot.offset, slot.segment, text.offset, text.segment),
            writes=[*installed, (text, ascii_number), (slot, pack("<HH", output.offset, output.segment))],
            reads=[(output, len(expected))],
        )
        assert converted[output] == expected

    # Enter these detached paths directly with valid operands. Neither test establishes a caller.
    stack_top = Address(data_segment, 0x10)
    records = Address(data_segment, bottom)
    record_size = records_end - records_start

    def load_ones(count):
        return emulator.call(
            text, regs=regs, writes=[*setup, (text, bytes.fromhex("cd35e8" * count + "c3"))],
            reads=[(stack_top, 2), (records, record_size)], ivt_interrupts=vectors,
        ).memory

    stored = check(
        root(0x6383), {root(0x6386): (double, 8), root(0x6389): (Address(dgroup, 0x2531), 2)},
        writes=load_ones(1), reads=[(double, 8)], far=False, di=double.offset, cx=0,
    )
    assert stored[double] == pack("<d", 1.0)

    comparison = Address(dgroup, sp - 8)
    compared = check(
        root(0x68a4), {root(0x68ae): (comparison, 2)}, writes=load_ones(2), reads=[(comparison, 2)],
    )
    assert unpack_from("<H", compared[comparison])[0] & 0x4500 == 0x4000  # Equal operands.

    # Place the LINK member in the original window and stop after each conversion call.
    member = next(unit for unit in program["units"] if unit["name"] == "link_0002")
    overlay_segment = member["runtime_linear"] // 16
    image = (tmp_path / "export" / "image.bin").read_bytes()
    start = member["image_offset"]
    overlay_code = (Address(overlay_segment, 0), image[start:start + member["size"]])

    def overlay(offset):
        return Address(overlay_segment, offset)

    bp = sp - 0x40
    local = Address(dgroup, bp - 8)
    conversion_stores = {
        root(0x68c7): (Address(dgroup, sp - 12), 2),
        root(0x68da): (Address(dgroup, sp - 22), 8),
    }
    check(
        overlay(0x22a4), {**conversion_stores, overlay(0x22a7): (local, 4)},
        writes=[overlay_code, (overlay(0x22b2), b"\xcb")], bp=bp,
    )
    far_data = base + 0x1820
    for selector, next_store in ((2, 0x2708), (3, None), (4, 0x26c7), (5, 0x26c7)):
        stores = {**conversion_stores, overlay(0x269b): (local, 4)}
        if next_store is not None:
            stores[overlay(next_store)] = (local, 4)
        check(
            overlay(0x2691), stores, writes=[
                overlay_code, (overlay(0x2715), b"\xcb"), (Address(far_data, 0x9dfc), pack("<H", 64)),
                (Address(far_data, 0x9e90), pack("<H", selector)),
            ], bp=bp,
        )


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


def test_pool_of_radiance_procedure_variable_candidates(tmp_path, capsys):
    directory = os.environ.get("RETRORE_POR_DIR")
    if not directory or not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set RETRORE_POR_DIR and GHIDRA_HOME to run the real-game Ghidra test")
    files = {path.name.upper(): path for path in Path(directory).iterdir()}
    root = files.get("START.EXE") or files["GAME.EXE"]
    export, project = tmp_path / "export", tmp_path / "por"
    assert main(["load", str(root), "--overlay", str(files["GAME.OVR"]), "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["indirect"]["candidate_sites"] == 4

    def site(address):
        assert main(["indirect", "--project", str(project), "--at", address, "--json", "--compact"]) == 0
        row, = json.loads(capsys.readouterr().out)["sites"]
        return row

    # Turbo Pascal procedure variables live in uninitialized DGROUP; only the stores name their targets.
    variable = site("tpov_0096:0d70")
    assert (variable["status"], variable["table"]) == ("candidate", "root_bss:2754")
    assert [(entry["target"], entry["writer"]) for entry in variable["candidates"]] == [
        ("root:0994", "tpov_0035:006f"), ("root:06e6", "tpov_0035:008b"),
    ]
    assert variable["candidates"][0]["evidence"][:2] == ["relocated", "stored"]
    # An array of procedure pointers filled in by one routine, read through call far [di+0x6828].
    array = site("tpov_00b0:001e")
    assert (array["status"], array["table"], array["stop"], len(array["candidates"])) == (
        "candidate", "root_bss:23f8", "next_variable", 139)
    assert array["candidates"][0]["target"] == "root:043a"
