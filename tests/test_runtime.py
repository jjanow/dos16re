from struct import pack_into

import pytest

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
