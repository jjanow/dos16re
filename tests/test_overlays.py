from struct import pack, pack_into, unpack_from

import pytest

from dos16re.mz import Address, LoadedMZ, MZError
from dos16re.overlays import Overlay, build_image


def make_overlay(signature=b"FBOV"):
    base = 0x1000
    root = bytearray(80)
    file_offset = 8 if signature == b"FBOV" else 4
    # A call in the resident code and a call in the overlay both point to the stub.
    pack_into("<BHH", root, 0, 0x9A, 0x20, base + 1)
    pack_into("<HHI4H", root, 16, 0x3FCD, 0, file_offset, 6, 2, 1, 0)
    pack_into("<HHB", root, 48, 0x3FCD, 5, 0)
    loaded = LoadedMZ(base, bytes(root), Address(base, 0), Address(base, 0x100), (Address(0, 3),))
    payload = pack("<BHHBH", 0x9A, 0x20, 1, 0xCB, 3)
    bank = signature + (pack("<I", len(payload)) if file_offset == 8 else b"") + payload
    return loaded, Overlay("code.ovr", "code", bank)


@pytest.mark.parametrize("signature", [b"FBOV", b"TPOV"])
def test_build_image_relocates_overlay_and_rewrites_both_callers(signature):
    root, overlay = make_overlay(signature)
    image, program = build_image(root, "test.exe", [overlay])

    _, unit = program["units"]
    assert unit["name"] == "tpov_0001"
    assert unit["segment"] == 0x1005
    assert unit["entries"] == [5]
    assert unit["relocation_count"] == 1
    assert unpack_from("<BHH", image, 0) == (0x9A, 5, 0x1005)
    assert unpack_from("<BHH", image, 48) == (0xEA, 5, 0x1005)
    assert unpack_from("<BHH", image, unit["image_offset"]) == (0x9A, 5, 0x1005)
    assert len(image) == 86
    assert program["stubs"][0]["file_offset"] == unit["file_offset"] + 5
    assert program["stubs"][0]["original"] == "cd3f050000"
    assert [call["linear"] for call in program["calls"]] == [0x10000, unit["linear"]]


def test_rejects_overlay_fixup_outside_unit():
    root, overlay = make_overlay()
    invalid = Overlay(overlay.source, overlay.name, overlay.image[:-2] + pack("<H", 5))
    with pytest.raises(MZError, match="fixup outside unit"):
        build_image(root, "test.exe", [invalid])


def test_rejects_truncated_overlay_bank():
    root, overlay = make_overlay()
    invalid = Overlay(overlay.source, overlay.name, overlay.image[:-1])
    with pytest.raises(MZError, match="header size"):
        build_image(root, "test.exe", [invalid])


def test_raw_overlays_respect_explicit_layout_and_gaps():
    root, _ = make_overlay()
    placed = Overlay("a.ovr", "a", b"abc", 0x1007)
    first = Overlay("b.ovr", "b", bytes(range(31)))
    last = Overlay("c.ovr", "c", b"xyz")
    image, program = build_image(root, "test.exe", [placed, first, last])

    assert [unit["segment"] for unit in program["units"]] == [0x1000, 0x1007, 0x1005, 0x1008]
    assert image[80:111] == first.image
    assert image[112:115] == placed.image
    assert image[115:128] == bytes(13)
    assert image[128:] == last.image

    clashing = Overlay("d.ovr", "d", b"d", 0x1007)
    with pytest.raises(MZError, match="overlap"):
        build_image(root, "test.exe", [placed, clashing])
