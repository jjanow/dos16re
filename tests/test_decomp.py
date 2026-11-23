import json
import os
from struct import pack_into

import pytest

from retrore.cli import main
from retrore.ghidra import GhidraError, query_batch


@pytest.mark.parametrize("options, message", [
    ({"context": -1}, "context must be an integer between 0 and 20"),
    ({"context": True}, "context must be an integer between 0 and 20"),
    ({"slice": 0}, "slice must be an integer between 1 and 128"),
    ({"slice": 129}, "slice must be an integer between 1 and 128"),
    ({"fields": ["excerpt"]}, "fields for decomp must be a nonempty list"),
])
def test_focused_decompilation_options(tmp_path, options, message):
    with pytest.raises(GhidraError, match=message):
        query_batch(tmp_path / "project", [{"command": "decomp", "address": "root:7", **options}])


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test")
def test_focused_decompilation(tmp_path, capsys):
    image = bytes.fromhex(
        "0e 1f a1 00 01 40 50"   # DS = CS; increment a loaded word and push it
        " e8 0b 00 83 c4 02"     # call the helper and clean up its argument
        " 85 c0 74 03 a3 02 01 c3"  # store the result if nonzero
        " 55 8b ec 8b 46 04 03 c0 5d c3"  # helper doubles its argument
    ).ljust(0x104, b"\0")
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(image), 1, 0, 2, 32, 32, 2, 0x200, 0, 0, 0, 28, 0)
    source, export, project = (tmp_path / name for name in ("sample.exe", "export", "project"))
    source.write_bytes(header + image)
    assert main(["load", str(source), "-o", str(export)]) == 0
    capsys.readouterr()
    assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    capsys.readouterr()

    requests = [
        {"address": "root:8", "context": 1, "slice": 1},
        {"address": "root:7", "context": 0, "slice": 12, "fields": ["excerpt", "slice", "decompilation"]},
        {"address": "0fff:001f", "context": 0, "slice": 12},
        {"address": "root:11", "context": 0, "slice": 1},
        {"address": "root:0", "context": 0, "slice": 12},
    ]
    rows = query_batch(project, [{"command": "decomp", **request} for request in requests])["results"]
    limited, call, branch, store, optimized = (row["result"] for row in rows)
    assert main(["decomp", "root:8", "--project", str(project), "--context", "1", "--slice", "1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"contract": 1, **limited}
    assert limited["unit_address"] == "root:0000"
    assert limited["focus"]["address"]["unit_address"] == "root:0007"
    assert limited["focus"]["bytes"] == "e80b00"
    assert "decompilation" not in limited
    assert limited["slice"]["truncated"] is True
    seed, = limited["slice"]["operations"]
    assert seed["opcode"] == "CALL" and seed["focused"]
    assert len(limited["excerpt"]) == 3
    assert [line["focused"] for line in limited["excerpt"]] == [False, True, False]

    assert set(call) == {"excerpt", "slice", "decompilation"}
    line, = call["excerpt"]
    assert line["text"] == call["decompilation"].splitlines()[line["line"] - 1]
    assert [address["unit_address"] for address in line["addresses"]] == ["root:0002", "root:0005", "root:0007"]
    assert call["slice"]["truncated"] is False
    operations = {op["id"]: op for op in call["slice"]["operations"]}
    increment = operations[seed["inputs"][1]["definition"]]
    assert (increment["address"]["unit_address"], increment["opcode"]) == ("root:0005", "INT_ADD")
    load = operations[increment["inputs"][0]["definition"]]
    assert (load["address"]["unit_address"], load["opcode"]) == ("root:0002", "LOAD")

    assert branch["focus"]["address"]["unit_address"] == "root:000f"
    assert "if (" in branch["excerpt"][0]["text"]
    condition, comparison, *_ = branch["slice"]["operations"]
    assert condition["opcode"] == "CBRANCH" and condition["inputs"][1]["definition"] == comparison["id"]
    assert comparison["address"]["unit_address"] == "root:000d"

    assert store["excerpt"][0]["focused"]
    operation, = store["slice"]["operations"]
    assert operation["opcode"] == "STORE" and operation["address"]["unit_address"] == "root:0011"
    assert operation["inputs"][2]["definition"] == seed["id"]
    assert optimized["excerpt"] == []
    assert optimized["slice"] == {"operations": [], "truncated": False}
