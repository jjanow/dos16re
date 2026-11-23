import json
import os
from struct import pack_into

import pytest

from retrore import ghidra
from retrore.cli import main
from retrore.ghidra import GhidraError, query_batch
from retrore.queries import MAX_DEPTH, QUERIES, QueryError, echo, normalize_query, query_definitions, validate_query
from test_amiga import _program as _amiga_program
from test_c64 import _prg, _sys_stub
from test_pc98 import _sample_disk

requires_ghidra = pytest.mark.skipif(
    not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test",
)


def test_definitions_are_plain_data():
    definitions = query_definitions()
    assert json.loads(json.dumps(definitions)) == definitions
    definitions["decomp"]["fields"].append("changed")
    assert "changed" not in QUERIES["decomp"]["fields"]
    for name, definition in definitions.items():
        assert definition["fields_scope"] in ("result", "record")
        assert set(definition["echo"]) <= definition["parameters"].keys()
        for parameter in definition["parameters"].values():
            assert parameter["type"] in ("string", "integer", "boolean", "array")
            assert parameter["description"]
        limit = definition["parameters"].get("limit")
        if name not in ("decomp", "xrefs", "callers", "callees", "func"):
            assert limit["maximum"] <= 1000 and "default" in limit


@pytest.mark.parametrize("command", list(QUERIES))
def test_every_query_has_a_cli_command(command, capsys):
    with pytest.raises(SystemExit) as exit_info:
        main([command, "--help"])
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    assert "--project" in output and "--timeout" in output


@pytest.mark.parametrize("request_, message", [
    ([], "expected a query object with a command"),
    ({"command": "nope", "address": "0"}, "command must use decomp, xrefs, .*, disasm, or project-summary"),
    ({"command": "decomp", "address": "0", "line_offset": 1}, "line_offset requires map_lines"),
    ({"command": "func"}, "expected a query object with command and address"),
    ({"command": "func", "address": 7}, "address must be a string"),
    ({"command": "func", "address": "g:"}, "expected a hexadecimal unit:offset"),
    ({"command": "func", "address": "0", "depth": 1}, "unsupported options for func: depth"),
    ({"command": "xrefs", "address": "0", "direction": "callers"}, "direction must be incoming, outgoing, or both"),
    ({"command": "xrefs", "address": "0", "ref_types": ["1"]}, "ref_types must be a nonempty list"),
    ({"command": "xrefs", "address": "0", "limit": 0}, "limit must be an integer between 1 and 2147483647"),
    ({"command": "inventory"}, "expected a query object with command and unit"),
    ({"command": "inventory", "unit": "a:b"}, "unit must match"),
    ({"command": "inventory", "unit": "root", "limit": 1001}, "limit must be an integer between 1 and 1000"),
    ({"command": "inventory", "unit": "root", "fields": ["name"]}, "fields for inventory must be a nonempty list"),
    ({"command": "callgraph", "address": "0", "depth": MAX_DEPTH + 1}, "depth must be an integer between 1 and 4"),
    ({"command": "callgraph", "address": "0", "max_nodes": 513}, "max_nodes must be an integer between 1 and 512"),
    ({"command": "callgraph", "address": "0", "direction": "both"}, "direction must be callers or callees"),
    ({"command": "context", "address": "0", "limit": 257}, "limit must be an integer between 1 and 256"),
    ({"command": "context", "address": "0", "ref_types": ["READ"]}, "unsupported options for context: ref_types"),
    ({"command": "functions"}, "functions requires addresses or names"),
    ({"command": "functions", "addresses": []}, "functions requires addresses or names"),
    ({"command": "functions", "addresses": ["zz"]}, "expected a hexadecimal unit:offset"),
    ({"command": "functions", "names": [""]}, "each names item must have 1 to 256 characters"),
    ({"command": "functions", "addresses": ["0"] * 257}, "addresses accepts at most 256 items"),
    ({"command": "functions", "addresses": ["0"] * 200, "names": ["a"] * 57},
     "functions accepts at most 256 addresses and names in total"),
    ({"command": "functions", "names": ["a"], "fields": ["query"]}, "fields for functions must be a nonempty list"),
    ({"command": "symbols"}, "symbols requires exactly one of name, prefix, or glob"),
    ({"command": "symbols", "name": "a", "glob": "*"}, "symbols requires exactly one of name, prefix, or glob"),
    ({"command": "symbols", "glob": "*", "ignore_case": 1}, "ignore_case must be a boolean"),
    ({"command": "gaps", "compact": True}, "unsupported options for gaps: compact"),
    ({"command": "coverage", "offset": -1}, "offset must be an integer between 0 and 2147483647"),
])
def test_query_validation(request_, message):
    with pytest.raises(QueryError, match=message):
        validate_query(request_)


def test_batch_validates_every_query_before_launching(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra, "_run", lambda *args, **kwargs: pytest.fail("launched Ghidra"))
    with pytest.raises(GhidraError, match="query 2: depth must be an integer between 1 and 4"):
        query_batch(tmp_path / "project", [
            {"command": "functions", "names": ["main"]},
            {"command": "callgraph", "address": "root:0", "depth": 9},
        ])


def test_defaults_and_echo():
    request = {"command": "callgraph", "address": "root:0"}
    assert normalize_query(request) == {
        **request, "direction": "callees", "depth": 2, "max_nodes": 128, "limit": 128, "offset": 0, "compact": False,
    }
    assert "limit" not in normalize_query({"command": "callers", "address": "root:0"})
    assert echo({"command": "symbols", "prefix": "FUN_", "unit": "OV1", "limit": 5}) == {"prefix": "FUN_", "unit": "OV1"}
    assert echo({"command": "functions", "names": ["main"]}) == {}


def test_fields_require_json(tmp_path, capsys):
    assert main(["symbols", "--glob", "*", "--fields", "name", "--project", str(tmp_path / "p"), "--json"]) == 1
    assert "Ghidra project not found" in json.loads(capsys.readouterr().err)["error"]["message"]
    assert main(["symbols", "--glob", "*", "--fields", "name", "--project", str(tmp_path / "p")]) == 1
    assert "--fields requires --json" in capsys.readouterr().err


def _import(directory, capsys, *load_args):
    export, project = directory / "export", directory / "project"
    assert main(["load", *load_args, "-o", str(export)]) == 0, capsys.readouterr().err
    assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
    capsys.readouterr()
    return project


@pytest.fixture(scope="module")
def dos_project(tmp_path_factory):
    if not os.environ.get("GHIDRA_HOME"):
        pytest.skip("set GHIDRA_HOME to run the Ghidra integration test")
    image = bytes.fromhex(
        "0e 1f a1 00 01 50 0e"   # DS = CS; read a word and push it with CS
        " e8 0b 00 e8 13 00"     # call the far routine at 0x15 and a near routine at 0x20
        " a2 02 01 c3"           # write a byte and return
        " 90 90 90 90"
        " 55 8b ec 8b 46 06 5d ca 02 00"  # 0x15: far routine returns its argument
        " 90"
        " e8 04 00 c3 90 90 90"  # 0x20: call the leaf at 0x27
        " 9a 00 00 00 11 c3"     # 0x27: call the overlay
    ).ljust(0x104, b"\0")
    header = bytearray(32)
    pack_into("<2s13H", header, 0, b"MZ", len(header) + len(image), 1, 0, 2, 32, 32, 2, 0x200, 0, 0, 0, 28, 0)
    directory = tmp_path_factory.mktemp("dos")
    exe, overlay = directory / "sample.exe", directory / "OV1.ovr"
    exe.write_bytes(header + image)
    overlay.write_bytes(b"\xcb")
    export, project = directory / "export", directory / "project"
    assert main(["load", str(exe), "-o", str(export), "--overlay", f"{overlay}@1100"]) == 0
    assert main(["ghidra", "import", str(export), str(project)]) == 0
    return project


def _cli(capsys, *args, status=0):
    assert main(list(args)) == status, capsys.readouterr().err
    return capsys.readouterr().out


def test_dos_bulk_queries(dos_project, capsys, monkeypatch):
    project = str(dos_project)
    requests = [
        {"command": "functions", "addresses": ["root:0", "1000:0016", "root:12"], "names": ["FUN_1000_0015", "nope"],
         "compact": True},
        {"command": "functions", "addresses": ["root:0", "root:15", "root:20"], "limit": 1, "offset": 1,
         "fields": ["prototype"]},
        {"command": "symbols", "prefix": "FUN_"},
        {"command": "symbols", "glob": "fun_1000_00??", "ignore_case": True, "limit": 2, "compact": True},
        {"command": "symbols", "name": "entry", "unit": "ov1"},
        {"command": "inventory", "unit": "root", "compact": True},
        {"command": "inventory", "unit": "root", "limit": 1, "offset": 1, "fields": ["functions", "data"]},
        {"command": "inventory", "unit": "missing"},
        {"command": "callgraph", "address": "root:0", "depth": 1, "compact": True},
        {"command": "callgraph", "address": "root:0", "depth": MAX_DEPTH, "compact": True},
        {"command": "callgraph", "address": "root:0", "max_nodes": 2, "compact": True},
        {"command": "callgraph", "address": "OV1:0", "direction": "callers", "depth": MAX_DEPTH, "compact": True},
        {"command": "context", "address": "root:d", "compact": True},
        {"command": "context", "address": "root:15", "fields": ["calling_convention", "callees"]},
        {"command": "gaps", "limit": 2},
        {"command": "gaps", "unit": "OV1"},
        {"command": "coverage", "compact": True},
        {"command": "callees", "address": "root:0", "compact": True},
    ]
    launches = []
    real_run = ghidra._run
    monkeypatch.setattr(ghidra, "_run", lambda *args, **kwargs: launches.append(args) or real_run(*args, **kwargs))
    rows = query_batch(dos_project, requests)["results"]
    monkeypatch.undo()
    assert len(launches) == 1
    assert [row["command"] for row in rows] == [request["command"] for request in requests]
    assert rows[2]["prefix"] == "FUN_" and rows[7]["unit"] == "missing" and rows[8]["address"] == "root:0"
    assert rows[7]["error"]["code"] == "address_not_found"
    assert rows[7]["error"]["message"] == "unknown unit missing"
    (lookup, narrow, prefixed, glob, unit_name, inventory, inventory_page, _, shallow, deep, capped, callers,
     context, far, gaps, overlay_gaps, coverage, callees) = (row.get("result") for row in rows)

    entry, far_routine, missing, by_name, unknown = lookup["functions"]
    assert entry == {
        "query": "root:0", "name": "entry", "entry": "root:0000",
        "ranges": [{"start": "root:0000", "end": "root:0010"}], "size": 17,
        "prototype": "undefined __cdecl16near entry()", "calling_convention": "__cdecl16near",
    }
    assert far_routine["entry"] == "root:0015" and far_routine["calling_convention"] == "__stdcall16far"
    assert (missing["query"], missing["error"]["code"]) == ("root:12", "no_function")
    assert missing["error"]["message"] == "no analyzed function contains root:12" and missing["error"]["hint"]
    assert by_name == {**far_routine, "query": "FUN_1000_0015"}
    assert (unknown["query"], unknown["error"]["code"]) == ("nope", "no_function")
    assert unknown["error"]["message"] == "no analyzed function named nope"
    assert lookup["pagination"]["functions"] == {"offset": 0, "total": 5, "returned": 5, "next_offset": None}
    # The retf 2 and the [bp+6] read give the far routine one word argument.
    assert narrow["functions"] == [
        {"query": "root:15", "prototype": "undefined __stdcall16far FUN_1000_0015(undefined2 param_1)"}]
    assert narrow["pagination"]["functions"]["next_offset"] == 2

    assert [symbol["name"] for symbol in prefixed["symbols"]] == [
        "FUN_1000_0015", "FUN_1000_0020", "FUN_1000_0027", "FUN_1000_1000",
    ]
    assert prefixed["symbols"][-1]["address"]["unit_address"] == "OV1:0000"
    assert glob["symbols"] == [
        {"name": "FUN_1000_0015", "address": "root:0015", "kind": "Function", "source": "DEFAULT", "namespace": None},
        {"name": "FUN_1000_0020", "address": "root:0020", "kind": "Function", "source": "DEFAULT", "namespace": None},
    ]
    assert glob["pagination"]["symbols"] == {"offset": 0, "total": 3, "returned": 2, "next_offset": 2}
    assert unit_name["symbols"] == []

    assert inventory["unit"] == {"name": "root", "start": "root:0000", "end": "root:0103", "size": 0x104}
    assert [(item["entry"], item["size"]) for item in inventory["functions"]] == [
        ("root:0000", 17), ("root:0015", 10), ("root:0020", 4), ("root:0027", 6),
    ]
    assert [(item["address"], item["type"], item["size"]) for item in inventory["data"]] == [
        ("root:0100", "word", 2), ("root:0102", "byte", 1),
    ]
    assert {label["address"] for label in inventory["labels"]} == {"root:0100", "root:0102"}
    assert set(inventory_page) == {"functions", "data", "pagination"}
    assert inventory_page["functions"][0]["name"] == "FUN_1000_0015"
    assert inventory_page["pagination"]["data"] == {"offset": 1, "total": 2, "returned": 1, "next_offset": None}

    assert [node["function"]["entry"] for node in shallow["nodes"]] == ["root:0000", "root:0015", "root:0020"]
    assert shallow["truncated"] == {"depth": True, "nodes": False}
    assert [(node["function"]["entry"], node["depth"]) for node in deep["nodes"]][-1] == ("OV1:0000", 3)
    assert deep["edges"][-1] == {"from": "root:0027", "to": "OV1:0000", "calls": 1}
    assert deep["truncated"] == {"depth": False, "nodes": False} and deep["unresolved"] == 0
    assert len(capped["nodes"]) == 2 and capped["truncated"] == {"depth": False, "nodes": True}
    assert [(node["function"]["entry"], node["depth"]) for node in callers["nodes"]] == [
        ("OV1:0000", 0), ("root:0027", 1), ("root:0020", 2), ("root:0000", 3),
    ]
    assert callers["edges"][0] == {"from": "root:0027", "to": "OV1:0000", "calls": 1}

    assert context["function"] == {"name": "entry", "entry": "root:0000"}
    assert context["prototype"] == "undefined __cdecl16near entry()"
    assert context["parameters"] == []
    assert context["pagination"]["parameters"] == {"offset": 0, "total": 0, "returned": 0, "next_offset": None}
    assert [(callee["target"], callee["function"]["name"]) for callee in context["callees"]] == [
        ("root:0015", "FUN_1000_0015"), ("root:0020", "FUN_1000_0020"),
    ]
    assert context["data"] == [
        {"address": "root:0100", "name": "FAR1000_0100", "type": "word", "size": 2, "access": ["READ"],
         "access_widths": [2], "references": 1},
        {"address": "root:0102", "name": "FAR1000_0102", "type": "byte", "size": 1, "access": ["WRITE"],
         "access_widths": [1], "references": 1},
    ]
    assert far == {"calling_convention": "__stdcall16far", "callees": [],
                   "pagination": {"callees": {"offset": 0, "total": 0, "returned": 0, "next_offset": None}}}

    full_gaps = json.loads(_cli(capsys, "gaps", "--project", project, "--json"))
    assert gaps["undefined_bytes"] == full_gaps["undefined_bytes"]
    assert gaps["ranges"] == full_gaps["ranges"][:2]
    assert gaps["pagination"]["ranges"] == {
        "offset": 0, "total": len(full_gaps["ranges"]), "returned": 2, "next_offset": 2,
    }
    assert overlay_gaps["ranges"] == [] and overlay_gaps["undefined_bytes"] == 0
    # The root's uninitialized data and stack sit between the root and the overlay.
    root_coverage, bss_coverage, overlay_coverage = coverage["units"]
    assert bss_coverage["unit"] == "root_bss" and not bss_coverage["initialized"]
    assert bss_coverage["functions"] == bss_coverage["instruction_bytes"] == 0
    assert root_coverage["functions"] == 4 and root_coverage["data_bytes"] == 3
    assert root_coverage["undefined_bytes"] == full_gaps["undefined_bytes"]
    assert root_coverage["instruction_bytes"] + 3 + full_gaps["undefined_bytes"] == 0x104
    assert overlay_coverage == {
        "unit": "OV1", "start": "OV1:0000", "size": 1, "initialized": True, "execute": True,
        "functions": 1, "instruction_bytes": 1, "data_bytes": 0, "undefined_bytes": 0,
    }
    assert [edge["to"] for edge in callees["callees"]] == [callee["target"] for callee in context["callees"]]

    # The CLI commands return the same JSON as the batch.
    cli_lookup = _cli(capsys, "functions", "root:0", "1000:0016", "root:12", "--name", "FUN_1000_0015",
                      "--name", "nope", "--compact", "--project", project, "--json", status=1)
    assert json.loads(cli_lookup) == {"contract": 1, **lookup}
    assert json.loads(_cli(capsys, "callgraph", "root:0", "--depth", "1", "--compact", "--project", project,
                           "--json")) == {"contract": 1, **shallow}
    assert json.loads(_cli(capsys, "context", "root:15", "--fields", "calling_convention,callees",
                           "--project", project, "--json")) == {"contract": 1, **far}
    assert json.loads(_cli(capsys, "symbols", "--glob", "fun_1000_00??", "--ignore-case", "--limit", "2",
                           "--compact", "--project", project, "--json")) == {"contract": 1, **glob}
    assert json.loads(_cli(capsys, "gaps", "--limit", "2", "--project", project, "--json")) == {"contract": 1, **gaps}

    text = _cli(capsys, "callgraph", "root:0", "--depth", "1", "--project", project)
    assert text.splitlines()[:2] == ["root:0000  entry", "Walk truncated by depth limit."]
    assert "  root:0000  entry\n    root:0015  FUN_1000_0015\n" in text
    text = _cli(capsys, "context", "root:0", "--limit", "1", "--project", project)
    assert text.splitlines() == [
        "undefined __cdecl16near entry()", "1/2 callees", "  root:0015  FUN_1000_0015  1 calls",
        "1/2 data", "  root:0100 FAR1000_0100 word READ", "Continue with --offset 1",
    ]
    assert "1/4 functions" in _cli(capsys, "inventory", "root", "--limit", "1", "--project", project)
    assert _cli(capsys, "gaps", "--unit", "OV1", "--project", project) == "0 undefined bytes in 0 ranges\n"
    assert "root  260 bytes  " in _cli(capsys, "coverage", "--unit", "root", "--project", project)
    assert "root:12: no analyzed function contains" in _cli(capsys, "functions", "root:12", "--project", project,
                                                             status=1)


@requires_ghidra
def test_amiga_bulk_queries(tmp_path, capsys):
    source = tmp_path / "demo"
    source.write_bytes(_amiga_program())
    project = _import(tmp_path, capsys, str(source))
    lookup, symbols, inventory, graph, context, coverage = (row["result"] for row in query_batch(project, [
        {"command": "functions", "addresses": ["00010000"], "names": ["worker"], "compact": True},
        {"command": "symbols", "glob": "w*", "unit": "h2", "compact": True},
        {"command": "inventory", "unit": "h1", "compact": True},
        {"command": "callgraph", "address": "h0:0", "compact": True},
        {"command": "context", "address": "h0:0", "compact": True},
        {"command": "coverage", "fields": ["unit", "execute", "instruction_bytes"]},
    ])["results"])
    first, worker = lookup["functions"]
    assert first["entry"] == "h0:0000"
    assert (worker["name"], worker["entry"], worker["size"]) == ("worker", "h2:0000", 4)
    assert worker["prototype"] == "undefined worker()"
    assert symbols["symbols"] == [
        {"name": "worker", "address": "h2:0000", "kind": "Function", "source": "IMPORTED", "namespace": None},
    ]
    assert [(item["address"], item["type"]) for item in inventory["data"]] == [
        ("h1:0000", "pointer"), ("h1:0004", "pointer"),
    ]
    assert graph["edges"] == [{"from": "h0:0000", "to": "h2:0000", "calls": 1}]
    callee, = context["callees"]
    assert callee == {"target": "h2:0000", "function": {"name": "worker", "entry": "h2:0000"}, "calls": 1}
    assert coverage["units"][:2] == [
        {"unit": "h0", "execute": True, "instruction_bytes": 8},
        {"unit": "h1", "execute": False, "instruction_bytes": 0},
    ]


@requires_ghidra
def test_c64_bulk_queries(tmp_path, capsys):
    source, addon = tmp_path / "demo.prg", tmp_path / "worker.prg"
    source.write_bytes(_prg(0x0801, _sys_stub() + bytes.fromhex("2000a0 60")))
    addon.write_bytes(_prg(0xA000, bytes.fromhex("a907 8d20d0 60")))
    project = _import(tmp_path, capsys, str(source), "--c64-unit", str(addon), "--c64-bank", "6")
    lookup, symbols, generated, stored, inventory, graph, context, gaps = (row["result"] for row in query_batch(project, [
        {"command": "functions", "addresses": ["080d", "worker:0"], "compact": True},
        {"command": "symbols", "prefix": "cpu_port", "ignore_case": True, "fields": ["name"]},
        {"command": "symbols", "name": "dat_d020", "ignore_case": True, "generated": True, "compact": True},
        {"command": "symbols", "name": "DAT_d020"},
        {"command": "inventory", "unit": "worker", "fields": ["functions"], "compact": True},
        {"command": "callgraph", "address": "a005", "direction": "callers", "compact": True},
        {"command": "context", "address": "worker:0", "compact": True, "fields": ["data"]},
        {"command": "gaps", "unit": "root"},
    ])["results"])
    assert [row["entry"] for row in lookup["functions"]] == ["root:000c", "worker:0000"]
    assert symbols["symbols"] == [{"name": "CPU_PORT_DDR"}, {"name": "CPU_PORT_DATA"}]
    # Ghidra generates DAT_ names for referenced addresses without a stored symbol.
    assert generated["symbols"] == [
        {"name": "DAT_d020", "address": "c64_vic:0020", "kind": "Label", "source": "DEFAULT", "namespace": None},
    ]
    assert stored["symbols"] == []
    assert inventory["functions"] == [{"name": "FUN_a000", "entry": "worker:0000", "size": 6}]
    assert [node["function"]["entry"] for node in graph["nodes"]] == ["worker:0000", "root:000c"]
    assert context["data"] == [
        {"address": "c64_vic:0020", "name": "DAT_d020", "type": None, "size": None, "access": ["WRITE"],
         "access_widths": [1], "references": 1},
    ]
    assert gaps["ranges"] == [{"unit": "root", "size": 12, "linear": 0x801, "start": "root:0000", "end": "root:000b"}]


@requires_ghidra
def test_pc98_bulk_queries(tmp_path, capsys):
    disk = tmp_path / "sample.d77"
    disk.write_bytes(_sample_disk())
    project = _import(tmp_path, capsys, str(disk), "--pc98", "--pc98-sector", "0:0:1@1fc0",
                      "--pc98-sector", "0:0:2@0200", "--pc98-entry", "1fc0:0000", "--pc98-entry", "0200:0040")
    unit = "sector_0_0_2_0200"
    lookup, symbols, inventory, context, coverage = (row["result"] for row in query_batch(project, [
        {"command": "functions", "addresses": ["0200:0000", "root:0"], "fields": ["name", "calling_convention"]},
        {"command": "symbols", "glob": "FAR*", "unit": "blue_vram", "compact": True},
        {"command": "inventory", "unit": unit, "fields": ["unit", "functions"], "compact": True},
        {"command": "context", "address": "0200:0005", "compact": True},
        {"command": "coverage", "unit": unit},
    ])["results"])
    assert lookup["functions"] == [
        {"query": "0200:0000", "name": "FUN_0000_2000", "calling_convention": "__cdecl16far"},
        {"query": "root:0", "name": "thunk_FUN_0000_2000", "calling_convention": "__cdecl16far"},
    ]
    assert symbols["symbols"] == [
        {"name": "FARa800_0012", "address": "blue_vram:0012", "kind": "Label", "source": "ANALYSIS", "namespace": None},
    ]
    assert inventory["unit"]["size"] == 256
    assert [item["entry"] for item in inventory["functions"]] == [f"{unit}:0000", f"{unit}:0040"]
    assert context["function"]["entry"] == f"{unit}:0000"
    write, = context["data"]
    assert (write["address"], write["access"], write["access_widths"]) == ("blue_vram:0012", ["WRITE"], [1])
    row, = coverage["units"]
    assert (row["unit"], row["functions"], row["instruction_bytes"]) == (unit, 2, 12)
