from struct import pack_into

import pytest

from dos16re.jump_tables import JumpTable, recover_jump_tables
from dos16re.mz import Address, LoadedMZ
from dos16re.overlays import Overlay, build_image


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
    root = LoadedMZ(0x1000, b"\xc3", Address(0x1000, 0), Address(0x1000, 0x100))
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
