import json
import os
import shutil
from pathlib import Path
from struct import pack_into

import pytest

from retrore.cli import main
from retrore.ghidra import GhidraError
from retrore.layout import apply_layout, layout_lines
from retrore.queries import QueryError, normalize_query

requires_ghidra = pytest.mark.skipif(
    not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test",
)


@pytest.mark.parametrize(("request_", "message"), [
    ({"command": "layout"}, "expected a query object with command and address"),
    ({"command": "layout", "address": "root:200", "size": 0}, "size must be an integer between 1 and 1048576"),
    ({"command": "layout", "address": "root:200", "stride": 0x10001}, "stride must be an integer between 1 and 65536"),
    ({"command": "layout", "address": "root:200", "name": "9bad"}, "name must match"),
    ({"command": "layout", "address": "root:200", "apply": True}, "unsupported options for layout: apply"),
    ({"command": "layout", "address": "root:200", "fields": ["fields"]}, "fields for layout must be"),
])
def test_layout_validation(request_, message):
    with pytest.raises(QueryError, match=message):
        normalize_query(request_)


def test_layout_defaults_and_apply_checks(tmp_path):
    request = normalize_query({"command": "layout", "address": "root:200"})
    assert (request["max_functions"], request["limit"], request["offset"]) == (64, 100, 0)
    with pytest.raises(GhidraError, match="only the layout query"):
        apply_layout(tmp_path / "p", {"command": "gaps"})
    with pytest.raises(GhidraError, match="Ghidra project not found"):
        apply_layout(tmp_path / "p", {"command": "layout", "address": "root:200"})


def test_layout_text():
    report = {
        "size": 72,
        "strides": [{"stride": 12, "accesses": 4, "evidence": ["root:0009 INT_MULT by 0xc"], "evidence_total": 1}],
        "conflicts": [{"offset": 0, "kind": "widths", "widths": [1, 2], "overlaps": None, "instructions": []},
                      {"offset": 2, "kind": "overlap", "widths": [2], "overlaps": 3, "instructions": []}],
        "layout": {"kind": "record_array", "size_source": "given", "element_size": 12, "element_size_source": "x",
                   "count": 6, "count_source": "CX INT_SLESS 6 at root:0021", "read_only": False,
                   "initial_text": None,
                   "fields": [{"offset": 0, "widths": [1, 2], "reads": 1, "writes": 1, "inner_strides": []}]},
        "proposal": {"c": "struct s {\n};\n"},
    }
    assert layout_lines(report) == [
        "record_array  6 x 0xc bytes  (72 bytes, given)",
        "count from CX INT_SLESS 6 at root:0021",
        "  +0x0000  width 1/2  1 reads  1 writes",
        "stride 0xc in 4 accesses: root:0009 INT_MULT by 0xc",
        "conflict at +0x0000: widths [1, 2]",
        "conflict at +0x0002: overlaps +0x0003",
        "proposal (apply with --apply):",
        "  struct s {",
        "  };",
    ]


# A record loop: for (i = 0; i < 6; i++) touch rec[i] at 0x200, 12 bytes per record. Offset 0 is read as a
# word and written as a byte (a width conflict); the word at offset 2 overlaps the byte read at offset 3.
_RECORD_LOOP = bytes.fromhex(
    "0e 1f"              # DS = CS
    " 31 c9"             # xor cx, cx
    " 89 c8"             # 0004: mov ax, cx
    " bb 0c 00"          # mov bx, 12
    " f7 e3"             # mul bx
    " 89 c3"             # mov bx, ax
    " c6 87 00 02 01"    # mov byte [bx+0x200], 1
    " c7 87 02 02 34 12"  # mov word [bx+0x202], 0x1234
    " 8b 87 00 02"       # mov ax, [bx+0x200]
    " 02 87 03 02"       # add al, [bx+0x203]
    " a3 50 02"          # mov [0x250], ax
    " 41"                # inc cx
    " 83 f9 06"          # cmp cx, 6
    " 7c db"             # jl 0004
    " c3"
)


@pytest.fixture(scope="module")
def record_project(tmp_path_factory):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    image = _RECORD_LOOP.ljust(0x260, b"\0")
    header = bytearray(32)
    size = len(header) + len(image)
    pack_into("<2s13H", header, 0, b"MZ", size % 512, (size + 511) // 512, 0, 2, 32, 32, 0x30, 0x200, 0, 0, 0, 28, 0)
    directory = tmp_path_factory.mktemp("layout")
    exe = directory / "records.exe"
    exe.write_bytes(header + image)
    export, project = directory / "export", directory / "project"
    assert main(["load", str(exe), "-o", str(export)]) == 0
    assert main(["ghidra", "import", str(export), str(project)]) == 0
    return project


def _json(capsys, *argv):
    assert main([*argv, "--json"]) == 0, capsys.readouterr().err
    return json.loads(capsys.readouterr().out)


@requires_ghidra
def test_layout_recovers_a_record_array(record_project, tmp_path, capsys):
    report = _json(capsys, "layout", "root:0200", "--size", "72", "--compact", "--project", str(record_project))
    layout = report["layout"]
    assert (layout["kind"], layout["element_size"], layout["count"]) == ("record_array", 12, 6)
    assert layout["count_source"].endswith(" INT_SLESS 6 after the increment at root:0027")
    assert [(field["offset"], field["widths"]) for field in layout["fields"]] == [(0, [1, 2]), (2, [2]), (3, [1])]
    assert [(row["offset"], row["kind"]) for row in report["conflicts"]] == [(0, "widths"), (2, "overlap")]
    stride, = report["strides"]
    assert stride["stride"] == 12 and any("INT_MULT by 0xc" in note for note in stride["evidence"])
    accesses = {(row["address"], row["access"], row["width"], row["offset"]) for row in report["accesses"]}
    assert accesses == {("root:000d", "write", 1, 0), ("root:0012", "write", 2, 2), ("root:0018", "read", 2, 0),
                        ("root:001c", "read", 1, 3)}
    assert "struct layout_1000_0200 layout_1000_0200_array[6];" in report["proposal"]["c"]

    text = main(["layout", "root:0200", "--size", "72", "--project", str(record_project)])
    assert text == 0
    assert capsys.readouterr().out.splitlines()[0] == "record_array  6 x 0xc bytes  (72 bytes, given)"

    # Applying writes the structure array into a copy of the project.
    copy = tmp_path / "copy"
    shutil.copytree(Path(record_project).parent, copy)
    project = copy / Path(record_project).name
    applied = _json(capsys, "layout", "root:0200", "--size", "72", "--name", "record", "--apply", "--project",
                    str(project))["applied"]
    assert applied == {"data_type": "record[6]", "path": "/retrore/record", "length": 72}
    inventory = _json(capsys, "inventory", "root", "--compact", "--project", str(project))
    assert {"address": "root:0200", "type": "record[6]"}.items() <= next(
        row for row in inventory["data"] if row["address"] == "root:0200").items()


@pytest.fixture(scope="module")
def phantasie_iv_project(tmp_path_factory):
    directory = os.environ.get("RETRORE_PH4_X68K_DIR")
    if not directory or not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set RETRORE_PH4_X68K_DIR and GHIDRA_HOME to run the real-game Ghidra test")
    program = next(path for path in Path(directory).iterdir() if path.name.upper() == "P4.X")
    output = tmp_path_factory.mktemp("p4")
    assert main(["load", str(program), "-o", str(output / "export")]) == 0
    assert main(["ghidra", "import", str(output / "export"), str(output / "project")]) == 0
    return output / "project"


def test_phantasie_iv_character_records(phantasie_iv_project, capsys):
    # _gmb (bss:2ebd6) runs to _pmb: ten 190-byte records. _save reads fields 0x22 (88fbe), 0x23, 0xb4 (89050),
    # 0xb5, and 0xba of each record, indexed through `muls.l` by 0xbe (rewritten from __CLMUL).
    project = str(phantasie_iv_project)
    report = _json(capsys, "layout", "88f9c", "--compact", "--project", project)
    layout = report["layout"]
    assert (layout["kind"], layout["element_size"], layout["count"]) == ("record_array", 190, 10)
    assert layout["size_source"] == "next symbol _pmb" and report["size"] == 1900
    assert layout["count_source"].endswith(" INT_SLESS 10 at text:75be")
    assert {0x22, 0x23, 0xB4, 0xB5, 0xBA} <= {field["offset"] for field in layout["fields"]}
    stride = report["strides"][0]
    assert stride["stride"] == 190 and "text:1754 INT_MULT by 0xbe" in stride["evidence"] + [
        note for row in report["accesses"] for index in row["index"] for note in index["evidence"]]
    save = {(row["address"], row["offset"]) for row in report["accesses"] if row["function"] == "_save"}
    assert {("text:1766", 0x22), ("text:1794", 0x23)} <= save
    assert not report["conflicts"]

    # A second table in _save: six 8-byte entries at 4f66e indexed by `asl.l #3`, bounded by `cmp.l #6`.
    report = _json(capsys, "layout", "4f66e", "--compact", "--project", project)
    layout = report["layout"]
    assert (layout["element_size"], layout["count"]) == (8, 6)
    assert layout["count_source"].endswith(" INT_SLESS 6 at text:1740")
