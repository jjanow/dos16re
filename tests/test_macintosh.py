import json
import os
from pathlib import Path
from struct import pack, pack_into

import pytest

from retrore.cli import main
from retrore.ghidra import import_program, query_address, query_batch
from retrore.hfs import HfsDisk, HfsError
from retrore.macintosh import MacintoshError, build_macintosh_image, is_macintosh


def _resource_fork(code_size=8, *, think=False):
    jumps = pack(">4I8H", 48, 12 if think else 8, 16, 32, 0, 0x3F3C, 1, 0xA9F0, 0, 0x3F3C, 2, 0xA9F0)
    main = pack(">2H", 0x8000 if think else 0, 1) + bytes.fromhex("4ead 002a a86e 4e75")
    main += pack(">I", 4) if think else bytes(code_size - 8)
    worker = pack(">2H", 8, 1) + bytes.fromhex("7007 4e75") + "Démo\0".encode("mac_roman")
    resources = {b"CODE": [(0, jumps), (1, main), (2, worker)]}
    if think:
        resources.update({
            b"DATA": [(0, bytes.fromhex("0000 0002 1234 0000"))],
            b"ZERO": [(0, pack(">2H", 0, 4))],
            b"STRS": [(0, b"zero\0one")],
            b"CREL": [(1, pack(">H", 13))],
            b"DREL": [(0, pack(">H", 0xFFF5))],
        })
    payload = bytearray()
    refs = bytearray()
    types = bytearray(pack(">H", len(resources) - 1))
    for tag, members in resources.items():
        types.extend(pack(">4sHH", tag, len(members) - 1, 2 + len(resources) * 8 + len(refs)))
        for index, resource in members:
            refs.extend(pack(">hHII", index, 0xFFFF, len(payload), 0))
            payload.extend(pack(">I", len(resource)) + resource)
    header = pack(">4I", 256, 256 + len(payload), len(payload), 28 + len(types) + len(refs))
    resource_map = header + bytes(8) + pack(">2H", 28, 28 + len(types) + len(refs)) + types + refs
    return header.ljust(256, b"\0") + payload + resource_map


def _apple_fork(fork, magic=0x00051607):
    return pack(">2I16xH3I", magic, 0x00020000, 1, 2, 38, len(fork)) + fork


def _macbinary(fork):
    header = bytearray(128)
    header[:6] = b"\0\x04Demo"
    header[65:69] = b"APPL"
    header[102:106] = b"mBIN"
    pack_into(">2I", header, 83, 17, len(fork))
    pack_into(">HBB", header, 120, 6, 130, 129)
    return bytes(header) + bytes(256) + fork


def _tree(record):
    header = bytearray(512)
    header[8] = 1
    pack_into(">IIIH", header, 20, 1, 1, 1, 512)
    leaf = bytearray(512)
    pack_into(">4xbxH", leaf, 4, -1, 1)
    leaf[9] = 1
    leaf[14:14 + len(record)] = record
    pack_into(">2H", leaf, 508, 14 + len(record), 14)
    return bytes(header + leaf)


def _hfs(fork, *, dc42=False):
    disk = bytearray(28 * 512)
    allocation = 2048
    extents = (6, 9, 13, 7)
    for index, extent in enumerate(extents):
        block = fork[index * 512:(index + 1) * 512]
        disk[allocation + extent * 512:allocation + extent * 512 + len(block)] = block

    overflow = _tree(pack(">BBIH6H", 7, 0xFF, 16, 3, extents[3], 1, 0, 0, 0, 0))
    disk[allocation + 2 * 512:allocation + 4 * 512] = overflow
    item = bytearray(102)
    item[:2] = b"\x02\0"
    item[4:8] = b"APPL"
    pack_into(">I", item, 20, 16)
    pack_into(">I", item, 36, len(fork))
    pack_into(">6H", item, 86, extents[0], 1, extents[1], 1, extents[2], 1)
    key = pack(">BBIB4sx", 10, 0, 2, 4, b"Demo")
    disk[allocation:allocation + 1024] = _tree(key + item)
    disk[1024:1026] = b"BD"
    pack_into(">HI4xH", disk, 1024 + 18, 22, 512, 4)
    pack_into(">I6HI6H", disk, 1024 + 130, 1024, 2, 2, 0, 0, 0, 0, 1024, 0, 2, 0, 0, 0, 0)
    if dc42:
        return pack(">64xII10xH", len(disk), 0, 0x0100) + disk
    return bytes(disk)


@pytest.mark.parametrize(("wrap", "kind", "origin"), [
    (bytes, "resource_fork", 0),
    (_apple_fork, "appledouble", 38),
    (lambda fork: _apple_fork(fork, 0x00051600), "applesingle", 38),
    (_macbinary, "macbinary", 384),
])
def test_macintosh_contiguous_wrappers(wrap, kind, origin):
    source = wrap(_resource_fork())
    assert is_macintosh(source)
    image, report = build_macintosh_image(source, "Demo", base=0x20000)
    assert report["format"] == "MAC68K"
    assert report["container"] == kind
    assert report["entry"] == {"unit_address": "code1:0000", "linear": 0x20000}
    code1, code2, globals_, params, table = report["units"]
    assert code1["file_offset"] == origin + 300
    assert image[:8] == source[code1["file_offset"]:code1["file_offset"] + 8]
    assert globals_["file_size"] == 0
    assert params["linear"] == report["a5"]["linear"]
    assert table["linear"] == params["linear"] + 32
    assert report["a5_jumps"][1] == {
        "a5_offset": 42,
        "stub": {"unit_address": "a5_jump:000a", "linear": table["linear"] + 10},
        "target": {"unit_address": "code2:0000", "linear": code2["linear"]},
    }
    assert image[table["image_offset"]:table["image_offset"] + 16] == pack(
        ">HHIHHI", 0, 0x4EF9, code1["linear"], 0, 0x4EF9, code2["linear"],
    )
    assert table["relocations"][1] == {"offset": 4, "width": 4, "original": 0x0001A9F0, "value": code1["linear"]}


@pytest.mark.parametrize("dc42", (False, True))
def test_macintosh_fragmented_hfs(dc42, tmp_path, capsys):
    fork = _resource_fork(code_size=1300)
    source = _hfs(fork, dc42=dc42)
    assert is_macintosh(source)
    disk = HfsDisk(source)
    member = disk.read_resource_fork("demo")
    assert member.data == fork
    assert len(member.spans) == 4
    with pytest.raises(HfsError, match="does not contain"):
        disk.read_resource_fork("missing")
    path, out = tmp_path / "disk.image", tmp_path / "out"
    path.write_bytes(source)
    assert main(["load", str(path), "--disk-file", "Demo", "-o", str(out), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["container"] == ("dc42" if dc42 else "hfs")
    code = report["units"][0]
    assert code["file_offset_kind"] == "container"
    assert code["disk_file"] == "Demo"
    assert len(code["file_spans"]) == 4
    binary = (out / "image.bin").read_bytes()
    for span in code["file_spans"]:
        logical, physical, size = (span[key] for key in ("offset", "file_offset", "size"))
        assert binary[logical:logical + size] == source[physical:physical + size]
    assert main(["where-is", "--export", str(out), "--string", "Démo", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["matches"][0]["unit_address"] == "code2:0004"


def test_macintosh_invalid_jump_and_image_sizes():
    fork = bytearray(_resource_fork())
    pack_into(">H", fork, 280, 99)
    with pytest.raises(MacintoshError, match="invalid Macintosh jump target CODE 99"):
        build_macintosh_image(fork, "Demo")
    with pytest.raises(MacintoshError, match="layout exceeds"):
        build_macintosh_image(_resource_fork(), "Demo", base=0xFFFFF0)
    with pytest.raises(HfsError, match="truncated Disk Copy"):
        HfsDisk(_hfs(_resource_fork(), dc42=True)[:-1])


def test_macintosh_think_globals_and_relocations():
    source = _resource_fork(think=True)
    image, report = build_macintosh_image(source, "Demo")
    units = {unit["name"]: unit for unit in report["units"]}
    strings, globals_, code = (units[name] for name in ("strs", "a5_globals", "code1"))
    strs_base = strings["linear"]
    offset = globals_["image_offset"]
    assert image[offset:offset + 12] == pack(">IH6x", strs_base + 2, 0x1234)
    assert globals_["relocations"] == [
        {"offset": 0, "width": 4, "original": 2, "value": strs_base + 2, "resource": "DREL", "resource_id": 0},
    ]
    assert globals_["file_spans"][0]["size"] == 8
    assert globals_["file_size"] == 12
    assert code["relocations"] == [
        {"offset": 8, "width": 4, "original": 4, "value": strs_base + 4, "resource": "CREL", "resource_id": 1},
    ]
    assert image[code["image_offset"] + 8:code["image_offset"] + 12] == pack(">I", strs_base + 4)
    assert "unapplied_resources" not in report


def test_macintosh_ghidra_resolves_calls_and_traps(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Macintosh Ghidra integration test")
    source, out, project = (tmp_path / name for name in ("demo.rsrc", "out", "project"))
    source.write_bytes(_resource_fork())
    assert main(["load", str(source), "-o", str(out)]) == 0
    capsys.readouterr()
    report = import_program(out, project)
    assert report["macintosh"] == {"jump_entries": 2, "a5_calls": 1, "trap_sites": 1, "traps": {"_InitGraf": 1}}
    calls, worker = query_batch(project, [
        {"command": "callees", "address": "code1:0000"},
        {"command": "decomp", "address": "code2:0000"},
    ])["results"]
    targets = calls["result"]["callees"]
    assert any(item["to"].get("unit_address") == "code2:0000" for item in targets)
    assert any((item["to_function"] or {}).get("name") == "_InitGraf" for item in targets)
    assert "return 7;" in worker["result"]["decompilation"]


@pytest.mark.parametrize(("env", "name", "kind", "segments", "jumps", "crel", "drel"), [
    ("RETRORE_POR_MAC_DIR", "Pool of Radiance v1.1.rsrc", "appledouble", 14, 582, 840, 505),
    ("RETRORE_SOTSB_MAC_DIR", "Secret of the Silver Blade.img", "hfs", 15, 859, 1161, 440),
])
def test_gold_box_macintosh_release(env, name, kind, segments, jumps, crel, drel, tmp_path, capsys):
    directory = os.environ.get(env)
    if not directory:
        pytest.skip(f"set {env} to validate the original Macintosh release")
    source = Path(directory) / name
    out, project = tmp_path / "out", tmp_path / "project"
    assert main(["load", str(source), "-o", str(out), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert report["container"] == kind
    assert report["entry"]["unit_address"] == "code1:0008"
    assert sum(unit.get("resource_type") == "CODE" and unit["resource_id"] != 0 for unit in report["units"]) == segments
    assert len(report["a5_jumps"]) == jumps
    fixups = [relocation for unit in report["units"] for relocation in unit["relocations"]]
    assert sum(item.get("resource") == "CREL" for item in fixups) == crel
    assert sum(item.get("resource") == "DREL" for item in fixups) == drel
    if os.environ.get("GHIDRA_HOME"):
        imported = import_program(out, project)
        assert imported["macintosh"]["jump_entries"] == jumps
        assert imported["macintosh"]["a5_calls"] > 1000
        assert imported["macintosh"]["trap_sites"] > 100
        if kind == "appledouble":
            target = next(jump["target"] for jump in report["a5_jumps"] if jump["a5_offset"] == 0x011A)
            calls = query_address("callees", "code1:0008", project)["callees"]
            assert any(call["from"]["unit_address"] == "code1:003c" and call["to"]["linear"] == target["linear"]
                       for call in calls)
