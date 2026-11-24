import json
import os

import pytest

from retrore.cli import main


def _json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _load(capsys, source, export, *args):
    assert main(["load", str(source), "-o", str(export), *args, "--json"]) == 0, capsys.readouterr().err
    return json.loads(capsys.readouterr().out)


def _variants(tmp_path, capsys):
    original, alternate = tmp_path / "one.prg", tmp_path / "two.prg"
    original.write_bytes(bytes.fromhex("00c0 a901 60 ea"))
    alternate.write_bytes(bytes.fromhex("00c0 a902 60 ea"))
    _load(capsys, alternate, tmp_path / "other", "--entry", "c000")
    document = _json(tmp_path / "banks.json", {
        "version": 1, "initial": "first",
        "states": [{"name": "first", "loads": [{"unit": "root"}]},
                   {"name": "second", "loads": [{"unit": "second_bank", "linear": "c000"}]}],
        "transitions": [{"from": "first", "to": "second", "kind": "bank", "trigger": "test IO write"}],
        "variants": [{"export": "other", "unit": "root", "name": "second_bank", "linear": "8000"}],
    })
    return original, document


def test_variants_and_named_transitions_keep_source_addresses(tmp_path, capsys):
    source, document = _variants(tmp_path, capsys)
    export = tmp_path / "image"
    report = _load(capsys, source, export, "--load-manifest", str(document), "--entry", "c000")
    assert [row["name"] for row in report["units"]] == ["second_bank", "root"]
    assert report["entry"]["linear"] == 0xc000
    assert main(["address-map", "c001", "--from", "runtime", "--all-states", "--export", str(export), "--json"]) == 0
    hits = json.loads(capsys.readouterr().out)["matches"]
    assert [(row["state"], row["unit_address"], row["file"]["source"], row["file"]["offset"]) for row in hits] == [
        ("first", "root:0001", "one.prg", 3), ("second", "second_bank:0001", "two.prg", 3),
    ]
    assert hits[1]["variant_source"]["unit"] == "root"
    trace = _json(tmp_path / "trace.json", {"version": 1, "events": [
        {"kind": "instruction", "address": "c000", "bytes": "a901"},
        {"kind": "bank", "state": "second"},
        {"kind": "instruction", "address": "c000", "bytes": "a902"},
        {"kind": "edge", "from": "c000", "from_state": 0, "to": "c000", "to_state": 2},
    ]})
    assert main(["trace", str(trace), "--export", str(export), "--evidence", "--json"]) == 0
    trace_result = json.loads(capsys.readouterr().out)
    assert trace_result["initial_state"] == "first"
    transition, = trace_result["transitions"]
    assert (transition["from"], transition["to"]) == ("first", "second")
    assert transition["placements"] == {"root": None, "second_bank": 0xc000}
    edge, = trace_result["edges"]
    assert [edge[key]["location"]["unit_address"] for key in ("from", "to")] == ["root:0000", "second_bank:0000"]
    assert [row["export_evidence"]["address"]["file"]["source"] for row in trace_result["mapped"]] == ["one.prg", "two.prg"]


def test_replacement_only_shadows_covered_bytes(tmp_path, capsys):
    root, bank = tmp_path / "root.bin", tmp_path / "bank.bin"
    root.write_bytes(bytes.fromhex("b80000c3 90909090 abcdef"))
    bank.write_bytes(bytes.fromhex("ebfe"))
    export = tmp_path / "image"
    document = {"version": 1, "initial": "bank", "states": [{"name": "bank", "loads": [
        {"unit": "root"}, {"unit": "bank", "linear": 0x10004},
    ]}]}
    manifest = _json(tmp_path / "state.json", document)
    args = [str(root), "--dos-raw", "--base-segment", "1000", "--overlay", str(bank), "--load-manifest", str(manifest)]
    assert main(["info", *args, "--json"]) != 0
    error = json.loads(capsys.readouterr().err)["error"]
    assert error["code"] == "load_manifest_invalid" and "overlap" in error["message"]
    document["states"][0]["loads"][1]["replace"] = True
    _json(manifest, document)
    assert main(["load", *args, "-o", str(export), "--json"]) == 0
    state, = json.loads(capsys.readouterr().out)["load_manifest"]["states"]
    assert [(span["unit"], span["linear"], span["offset"], span["size"]) for span in state["spans"]] == [
        ("root", 0x10000, 0, 4), ("bank", 0x10004, 0, 2), ("root", 0x10006, 6, 5),
    ]
    assert main(["address-map", "root:0004", "--export", str(export), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["matches"][0]["runtime"] is None
    trace = _json(tmp_path / "trace.json", {"version": 1, "events": [
        {"kind": "memory", "access": "read", "address": "1000:0003", "size": 5},
    ]})
    assert main(["trace", str(trace), "--export", str(export), "--json"]) == 0
    access, = json.loads(capsys.readouterr().out)["memory"]
    assert [(row["location"]["unit_address"], row["size"]) for row in access["spans"]] == [
        ("root:0003", 1), ("bank:0000", 2), ("root:0006", 2),
    ]
    if os.environ.get("GHIDRA_HOME"):
        project = tmp_path / "dos"
        assert main(["ghidra", "import", str(export), str(project), "--load-views", "--json"]) == 0, capsys.readouterr().err
        view = json.loads(capsys.readouterr().out)["load_views"]["bank"]
        assert view["space"] == "retrore_bank" and [row["unit"] for row in view["blocks"]] == ["root", "bank", "root"]


def test_linker_map_and_masked_signatures(tmp_path, capsys):
    source, export = tmp_path / "demo.com", tmp_path / "image"
    source.write_bytes(bytes.fromhex("b82a00 c3 909090"))
    linker = tmp_path / "demo.map"
    linker.write_text("""Address Publics by Name
  0000:0100 idle _main
  0000:0200 _bss
Address Publics by Value
  0000:0100 _main
  7000:0100 _unmapped
Line numbers for demo.obj(demo.asm) segment _TEXT
   12 0000:0100    13 0000:0103
Program entry point at 0000:0100
""")
    patterns = _json(tmp_path / "compiler.json", {"version": 1, "signatures": [
        {"name": "routine", "toolchain": "demo", "unit": "root", "pattern": "b8 ?? 00 c3"},
        {"name": "ambiguous", "pattern": "90 90"},
        {"name": "psp_only", "pattern": "cd 20"},
    ]})
    report = _load(capsys, source, export, "--linker-map", str(linker), "--signatures", str(patterns))
    assert [(row["name"], row["kind"]) for row in report["toolchain_symbols"]] == [
        ("_main", "linker_public"), ("_bss", "linker_public"), ("routine", "toolchain_signature"),
    ]
    assert [row["status"] for row in report["toolchain_signatures"]] == ["matched", "ambiguous", "missing"]
    assert [row["line"] for row in report["toolchain_source_lines"]] == [12, 13]
    assert report["toolchain_inputs"][0]["skipped"] == 1
    assert main(["lookup", "--name", "routine", "--export", str(export), "--json"]) == 0
    symbol, = json.loads(capsys.readouterr().out)["symbols"]
    assert (symbol["unit_address"], symbol["source"]) == ("root:0100", "compiler.json")
    if os.environ.get("GHIDRA_HOME"):
        project = tmp_path / "project"
        assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
        assert json.loads(capsys.readouterr().out)["toolchain"] == {"symbols": 3, "source_lines": 2}


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME for headless overlay import")
def test_flat_bank_views_in_ghidra(tmp_path, capsys):
    source, document = _variants(tmp_path, capsys)
    export, project = tmp_path / "image", tmp_path / "project"
    _load(capsys, source, export, "--load-manifest", str(document), "--entry", "c000")
    assert main(["ghidra", "import", str(export), str(project), "--load-views", "--json"]) == 0, capsys.readouterr().err
    views = json.loads(capsys.readouterr().out)["load_views"]
    assert list(views) == ["first", "second"]
    for name, unit in (("first", "root"), ("second", "second_bank")):
        row, = views[name]["blocks"]
        assert row["unit"] == unit
        assert row["address"].endswith(":c000")
