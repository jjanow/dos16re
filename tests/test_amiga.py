import json
import os
from pathlib import Path
from struct import pack, unpack_from

import pytest

from retrore.amiga import HunkError, build_hunk_image
from retrore.cli import main
from retrore.evidence import evidence_bundle
from retrore.search import find_relocations


def _words(*values):
    return pack(f">{len(values)}I", *values)


def _program():
    return b"".join((
        _words(0x3F3, 0, 5, 0, 4, 2, 0x40000004, 1, 0xC0000002, 4, 0),
        _words(0x3E9, 2), bytes.fromhex("4eb9 00000000 4e75"),
        _words(0x3EC, 1, 2, 2, 0, 0x3F2),
        _words(0x3E8, 1), b"vars",
        _words(0x3EA, 3, 4, 0), bytes.fromhex("1234 e921"),
        _words(0x3FC), pack(">6H", 2, 3, 0, 4, 0, 0),
        _words(0x3F1, 1, 0, 0x3F2),
        _words(0x3E9, 1), bytes.fromhex("7007 4e75"),
        _words(0x3F0, 2), b"worker\0\0", _words(0, 0, 0x3F2),
        _words(0x3EB, 2, 0x3F2),
        _words(0x3EA, 0, 0x3F2),
    ))


def test_amiga_export_and_search(tmp_path, capsys):
    source = tmp_path / "demo"
    source.write_bytes(_program())
    out = tmp_path / "out"
    assert main(["load", str(source), "--base-address", "200000", "-o", str(out), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    assert json.loads((out / "map.json").read_text()) == program
    assert program["entry"] == {"unit_address": "h0:0000", "linear": 0x200000}
    code, data, worker, bss, empty = program["units"]
    assert [unit["linear"] for unit in program["units"]] == list(range(0x200000, 0x200050, 16))
    assert [unit["kind"] for unit in program["units"]] == ["code", "data", "code", "bss", "data"]
    assert (data["size"], data["file_size"], data["memory_flags"]) == (16, 12, 2)
    assert (bss["size"], bss["file_offset"], bss["memory_flags"]) == (8, None, 4)
    assert empty["size"] == 0
    assert worker["symbols"] == [{"name": "worker", "offset": 0}]
    assert code["relocations"] == [{"offset": 2, "target": "h2", "original": 0, "value": 0x200020}]

    image = (out / "image.bin").read_bytes()
    assert unpack_from(">I", image, 2) == (0x200020,)
    assert unpack_from(">2I", image, 16) == (0x200034, 0x200030)
    assert image[28:32] == bytes(4)
    assert image[48:56] == bytes(8)
    assert main(["info", str(source), "--base-address", "200000", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == program

    for flag, pattern, position in (
        ("--constant", "0x1234", 8), ("--string", "é!", 10),
    ):
        assert main(["where-is", "--export", str(out), flag, pattern, "--json"]) == 0
        match, = json.loads(capsys.readouterr().out)["matches"]
        assert match == {
            "address": f"{0x200010 + position:08x}",
            "unit_address": f"h1:{position:04x}", "linear": 0x200010 + position,
        }
    assert main(["where-is", "--export", str(out), "--bytes", "00 00 00 00", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["count"] == 0

    assert main(["call", "h0:0", "--export", str(out), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["registers"]["d0"] == 7
    log = tmp_path / "log"
    log.write_text("2000:0000\n", encoding="ascii")
    assert main(["trace", str(log), "--export", str(out), "--json"]) == 1
    assert "require a DOS MZ image" in json.loads(capsys.readouterr().err)["error"]["message"]


@pytest.mark.parametrize("record", [0x3F7, 0x3FC])
def test_unpadded_short_relocations(record):
    source = _words(0x3F3, 0, 1, 0, 0, 1, 0x3E9, 1, 0, record)
    source += pack(">4H", 1, 0, 0, 0) + _words(0x3F2)
    image, _ = build_hunk_image(source, "demo")
    assert image == _words(0x10000)


def _section(kind, data, *records):
    return _words(kind, len(data) // 4) + data + b"".join(records) + _words(0x3F2)


def _tree(relocation_target=1, root_code=bytes.fromhex("4e75 4e71"), second_child_ordinate=2, root_break=False):
    def node(first, *sections):
        # Each section in this fixture is allocated four bytes, except the empty data hunk.
        sizes = [int.from_bytes(section[4:8], "big") for section in sections]
        return _words(0x3F3, 0, 4, first, first + len(sections) - 1, *sizes) + b"".join(sections)

    return_seven = _section(0x3E9, bytes.fromhex("7007 4e75"))
    debug = _words(0x3F1, 6, 0) + b"LINE" + _words(1) + b"main" + _words(42, 0)
    root = node(0, _section(0x3E9, root_code, debug))
    members = [
        node(1, return_seven, _section(0x3EA, b"")),
        node(3, _section(0x3EA, _words(0), _words(0x3EC, 1, relocation_target, 0, 0))),
        node(1, _section(0x3E9, bytes.fromhex("7008 4e75"))),
        node(2, _section(0x3EA, _words(0), _words(0x3EC, 1, 1, 0, 0))),
    ]
    table_start = len(root)
    payload_longwords = 3 + 8 * len(members)
    table = _words(0x3F5, payload_longwords - 1, 3, 0, 0)
    position = table_start + 8 + 4 * payload_longwords + (4 if root_break else 0)
    entries = ((1, 1, 1), (2, 1, 3), (1, 2, 1), (2, second_child_ordinate, 2))
    for index, (level, ordinate, first) in enumerate(entries):
        table += _words(position, 0, 0, level, ordinate, first, first, 0)
        position += len(members[index]) + 4
    return root + table + (_words(0x3F6) if root_break else b"") + b"".join(member + _words(0x3F6) for member in members)


def test_hierarchical_overlays_keep_branch_relocations_and_source(tmp_path, capsys):
    source = tmp_path / "overlay"
    source.write_bytes(_tree())
    out = tmp_path / "out"
    assert main(["load", str(source), "-o", str(out), "--json"]) == 0
    program = json.loads(capsys.readouterr().out)
    tree = program["overlay_tree"]
    assert tree["segment_table_size"] == 4
    assert [(node["id"], node["parent"], node["units"]) for node in tree["nodes"]] == [
        ("root", None, ["h0"]),
        ("ov1_1", "root", ["ov1_1_h1", "ov1_1_h2"]),
        ("ov2_1", "ov1_1", ["ov2_1_h3"]),
        ("ov1_2", "root", ["ov1_2_h1"]),
        ("ov2_2", "ov1_2", ["ov2_2_h2"]),
    ]
    assert [(entry["unit_address"], entry["kind"]) for entry in tree["entries"]] == [
        ("ov1_1_h1:0000", "code"), ("ov2_1_h3:0000", "data"),
        ("ov1_2_h1:0000", "code"), ("ov2_2_h2:0000", "data"),
    ]
    units = program["units"]
    assert len({unit["linear"] for unit in units}) == len(units)
    assert [unit["segment_index"] for unit in units] == [0, 1, 2, 3, 1, 2]
    states = program["load_manifest"]["states"]
    assert [row["unit"] for row in states[-1]["loads"]] == ["h0", "ov1_2_h1", "ov2_2_h2"]
    assert [unit["relocations"][0]["value"] for unit in (units[3], units[5])] == [
        units[1]["linear"], units[4]["linear"],
    ]
    assert [unit["relocations"][0]["target"] for unit in (units[3], units[5])] == ["ov1_1_h1", "ov1_2_h1"]
    assert units[0]["source_lines"] == [{"file": "main", "line": 42, "offset": 0, "record_file_offset": 36}]
    assert units[0]["debug_records"] == [{"format": "LINE", "file_offset": 36, "size": 32}]
    assert source.read_bytes()[units[3]["file_offset"]:units[3]["file_offset"] + 4] == _words(0)
    assert unpack_from(">I", (out / "image.bin").read_bytes(), units[3]["image_offset"]) == (units[1]["linear"],)

    if os.environ.get("GHIDRA_HOME"):
        project = tmp_path / "project"
        assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
        report = json.loads(capsys.readouterr().out)
        assert (report["overlay_entries"], report["source_lines"]) == (2, 1)
        for unit, value in (("ov1_1_h1", 7), ("ov1_2_h1", 8)):
            assert main(["decomp", f"{unit}:0000", "--project", str(project), "--json"]) == 0
            assert f"return {value};" in json.loads(capsys.readouterr().out)["decompilation"]


def test_overlay_rejects_references_to_inactive_slots_and_missing_breaks():
    with pytest.raises(HunkError, match="inactive relocation target"):
        build_hunk_image(_tree(relocation_target=4), "overlay")
    with pytest.raises(HunkError, match="HUNK_BREAK"):
        build_hunk_image(_tree()[:-4] + _words(0), "overlay")
    with pytest.raises(HunkError, match="unlisted bytes"):
        build_hunk_image(_tree() + _words(0), "overlay")


def test_hunk_alink_ordinates_can_repeat_under_different_parents():
    _, export = build_hunk_image(_tree(second_child_ordinate=1, root_break=True), "overlay")
    nodes = export["overlay_tree"]["nodes"]
    assert (nodes[2]["ordinate"], nodes[4]["ordinate"]) == (1, 1)
    assert nodes[2]["parent"] == "ov1_1"
    assert nodes[4]["parent"] == "ov1_2"
    assert nodes[2]["id"] != nodes[4]["id"]


def test_hunk_overlay_manager_signature():
    # The published THOR manager starts with a loader header and its name.
    code = bytes.fromhex("6000 0044 0000 abcd") + bytes(16)
    code += _words(23456) + b"\x07Overlay" + bytes(8) + b"THOR Overlay Manager 1.2\0"
    code += bytes(-len(code) % 4)
    _, export = build_hunk_image(_tree(root_code=code), "overlay")
    assert (export["toolchain"]["family"], export["toolchain"]["version"]) == ("THOR Overlay Manager", "1.2")
    assert export["units"][0]["symbols"] == [
        {"name": name, "offset": offset} for offset, name in
        [(8, "oh_FileHandle"), (12, "oh_OVTab"), (16, "oh_Segments"), (20, "oh_GlobVec")]
    ]


def test_optional_malformed_hunk_line_record_keeps_image():
    root = _section(0x3E9, bytes.fromhex("4e75 4e71"), _words(0x3F1, 2, 0) + b"LINE")
    image, export = build_hunk_image(_words(0x3F3, 0, 1, 0, 0, 1) + root, "broken_line")
    assert image == bytes.fromhex("4e75 4e71")
    assert export["diagnostics"][0]["code"] == "hunk_debug_line_invalid"
    assert "source_lines" not in export["units"][0]


def test_extended_hunk_relocations_and_queries(tmp_path, capsys):
    root = _section(0x3E9, bytes.fromhex("4e75 4e71"))
    data = _section(0x3EA, bytes.fromhex("00ff 0000 00000004 fffffff4 0002 0000"),
                    _words(0x3EE, 1, 0, 1, 0),
                    _words(0x3FE, 1, 0, 2, 0),
                    _words(0x3FD, 1, 0, 4, 0),
                    _words(0x3FD) + pack(">4H", 1, 0, 8, 0),
                    _words(0x3ED, 1, 0, 12, 0))
    source = tmp_path / "reloc"
    source.write_bytes(_words(0x3F3, 0, 2, 0, 1, 1, 4) + root + data)
    out = tmp_path / "out"
    assert main(["load", str(source), "--base-address", "2000", "-o", str(out), "--json"]) == 0
    unit = json.loads(capsys.readouterr().out)["units"][1]
    assert (out / "image.bin").read_bytes()[16:] == bytes.fromhex("00ee 2000 fffffff0 ffffffe4 ffe6 0000")
    assert [(row["kind"], row["width"], row["target_linear"]) for row in unit["relocations"]] == [
        ("pc_relative", 1, 0x1FFF),
        ("absolute", 2, 0x2000),
        ("pc_relative", 4, 0x2004),
        ("pc_relative", 4, 0x1FFC),
        ("pc_relative", 2, 0x2002),
    ]
    result, = find_relocations(out, target="h0:0")["relocations"]
    assert (result["unit_address"], result["kind"], result["target"]["unit_address"]) == (
        "h1:0002", "absolute", "h0:0000",
    )
    if os.environ.get("GHIDRA_HOME"):
        project = tmp_path / "project"
        assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
        assert json.loads(capsys.readouterr().out)["relocations"] == 5
        assert main(["xrefs", "h1:000c", "--project", str(project), "--json"]) == 0
        outgoing = json.loads(capsys.readouterr().out)["outgoing"]
        assert any(row["to"]["unit_address"] == "h0:0002" for row in outgoing)


def test_optional_original_hierarchical_overlay():
    directory = os.environ.get("RETRORE_AMIGA_OVERLAY_DIR")
    if not directory:
        pytest.skip("set RETRORE_AMIGA_OVERLAY_DIR to a directory containing an original overlay executable named overlay")
    source = Path(directory) / "overlay"
    _, program = build_hunk_image(source.read_bytes(), source.name)
    tree = program["overlay_tree"]
    assert tree["manager"] == "hierarchical"
    assert len(tree["nodes"]) > 1 and tree["entries"]


@pytest.mark.parametrize(("code", "encoding", "table", "targets"), [
    ("0c80 00000002 640a e380 4efb0802 6004 6006 4e75 7001 4e75 7002 4e75",
     "branch", "h0:000e", ["h0:000e", "h0:0010"]),
    ("0c80 00000001 6214 e380 303b000c 4efb0000 7001 4e75 4e75 0002 0006 4e75 0000",
     "relative", "h0:0018", ["h0:0012", "h0:0016"]),
])
def test_amiga_recovers_pc_indexed_switch_tables(code, encoding, table, targets, tmp_path, capsys):
    text = bytes.fromhex(code)
    source = _words(0x3F3, 0, 1, 0, 0, len(text) // 4, 0x3E9, len(text) // 4) + text + _words(0x3F2)
    _, export = build_hunk_image(source, "switch")
    switch, = export["jump_tables"]
    assert switch["encoding"] == encoding and switch["entry_size"] == 2
    assert switch["table"]["unit_address"] == table
    assert [target["unit_address"] for target in switch["targets"]] == targets
    if encoding == "branch":
        assert [target["unit_address"] for target in switch["cases"]] == ["h0:0014", "h0:0018"]

    if os.environ.get("GHIDRA_HOME"):
        member, out, project = (tmp_path / name for name in ("switch", "out", "project"))
        member.write_bytes(source)
        assert main(["load", str(member), "-o", str(out)]) == 0
        assert main(["ghidra", "import", str(out), str(project)]) == 0, capsys.readouterr().err
        requests = [{"command": "indirect", "at": switch["address"]["unit_address"]}]
        row, = evidence_bundle(project, requests, export=out)["results"]
        proof = row["export_evidence"]
        assert proof["status"] == "consistent"
        site, = proof["sites"]
        assert site["targets"]["project"] == [target["linear"] for target in switch["targets"]]
        table_bytes = site["ranges"][-1]
        assert (table_bytes["role"], table_bytes["address"]["unit_address"]) == ("table", table)
        assert table_bytes["project_bytes"] == ("60046006" if encoding == "branch" else "00020006")


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda data: data[:-1], "truncated"),
        (lambda data: data + _words(0x3F5), "HUNK_OVERLAY"),
        (lambda data: data[:16] + _words(3) + data[20:], "HUNK_OVERLAY"),
        (lambda data: data[:20] + _words(0x3FFFFFFF) + data[24:], "24-bit address space"),
        (lambda data: data.replace(_words(0x3EC, 1, 2, 2), _words(0x3EC, 1, 5, 2)), "target"),
        (lambda data: data.replace(_words(0x3EC, 1, 2, 2), _words(0x3EC, 1, 2, 6)), "offset"),
    ],
)
def test_malformed_and_unsupported_hunks(edit, message):
    with pytest.raises(HunkError, match=message):
        build_hunk_image(edit(_program()), "demo")


def test_amiga_ghidra_import_and_queries(tmp_path, capsys):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    source, out, project = (tmp_path / name for name in ("demo", "out", "project"))
    source.write_bytes(_program())
    assert main(["load", str(source), "-o", str(out)]) == 0
    capsys.readouterr()

    def query(*args):
        assert main([*args, "--project", str(project), "--json"]) == 0, capsys.readouterr().err
        return json.loads(capsys.readouterr().out)

    assert main(["ghidra", "import", str(out), str(project), "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert (report["format"], report["units"], report["relocations"]) == ("HUNK", 5, 3)

    call, = query("callees", "00010000")["callees"]
    assert call["from"]["unit_address"] == "h0:0000"
    assert call["to"]["unit_address"] == "h2:0000"
    assert call["to_function"]["name"] == "worker"
    assert query("func", "h2:0000")["segments"] == {}
    assert "return 7;" in query("decomp", "h2:0000")["decompilation"]
    assert any(ref["to"]["unit_address"] == "h3:0004" for ref in query("xrefs", "h1:0000")["outgoing"])
    assert {gap["unit"] for gap in query("gaps")["ranges"]} <= {"h0", "h2"}
