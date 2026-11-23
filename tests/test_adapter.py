"""The generated query schema and the MCP stdio adapter."""

import json
import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

import retrore
from retrore.cli import main
from retrore.errors import CONTRACT_VERSION, HINTS
from retrore.mcp import tools
from retrore.queries import QUERIES, QueryError, validate_query
from retrore.schema import DIALECT, query_schema
from test_c64 import _prg
from test_errors import _FAKE, _wait_dead

ROOT = Path(__file__).resolve().parents[1]
# The server subprocess imports the same retrore as the tests: the checkout's src or an installed wheel.
PACKAGE_PATH = Path(retrore.__file__).resolve().parents[1]

# Keywords the schema may use. The validator below implements every assertion keyword in this set.
_ASSERTIONS = {
    "$ref", "type", "const", "enum", "pattern", "minimum", "maximum", "minLength", "maxLength", "minItems",
    "maxItems", "items", "contains", "properties", "required", "additionalProperties", "oneOf", "anyOf", "allOf",
    "if", "then", "not",
}
_ANNOTATIONS = {
    "$schema", "$id", "$defs", "title", "description", "default", "format", "examples", "contract", "commands",
    "x-retrore-max-total-items",
}
_TYPES = {
    "object": lambda value: isinstance(value, dict),
    "array": lambda value: isinstance(value, list),
    "string": lambda value: isinstance(value, str),
    "integer": lambda value: type(value) is int,
    "number": lambda value: type(value) in (int, float),
    "boolean": lambda value: type(value) is bool,
    "null": lambda value: value is None,
}


def _resolve(root: dict, reference: str) -> dict:
    assert reference.startswith("#/"), reference
    node = root
    for part in reference[2:].split("/"):
        node = node[part]
    return node


def _errors(schema: dict, value: object, root: dict, path: str = "$") -> list[str]:
    """Return why value fails schema, using the subset of JSON Schema 2020-12 the generator emits."""
    unknown = schema.keys() - _ASSERTIONS - _ANNOTATIONS
    assert not unknown, f"validator does not implement {unknown}"
    problems = []
    if "$ref" in schema:
        problems += _errors(_resolve(root, schema["$ref"]), value, root, path)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_TYPES[name](value) for name in types):
            return problems + [f"{path}: expected {schema['type']}"]
    if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
        problems.append(f"{path}: expected {schema['const']!r}")
    if "enum" in schema and not any(value == item and type(value) is type(item) for item in schema["enum"]):
        problems.append(f"{path}: not in enum")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            problems.append(f"{path}: does not match {schema['pattern']}")
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)):
            problems.append(f"{path}: wrong length")
    if type(value) in (int, float):
        if not schema.get("minimum", value) <= value <= schema.get("maximum", value):
            problems.append(f"{path}: out of range")
    if isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            problems.append(f"{path}: wrong item count")
        for index, item in enumerate(value):
            if "items" in schema:
                problems += _errors(schema["items"], item, root, f"{path}[{index}]")
        if "contains" in schema and not any(not _errors(schema["contains"], item, root) for item in value):
            problems.append(f"{path}: contains nothing matching")
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                problems.append(f"{path}: missing {name}")
        properties = schema.get("properties", {})
        for name, item in value.items():
            if name in properties:
                problems += _errors(properties[name], item, root, f"{path}.{name}")
            elif schema.get("additionalProperties") is False:
                problems.append(f"{path}: unexpected {name}")
    for branch in schema.get("allOf", []):
        problems += _errors(branch, value, root, path)
    if "anyOf" in schema and all(_errors(branch, value, root, path) for branch in schema["anyOf"]):
        problems.append(f"{path}: matches no anyOf branch")
    if "oneOf" in schema and sum(not _errors(branch, value, root, path) for branch in schema["oneOf"]) != 1:
        problems.append(f"{path}: does not match exactly one oneOf branch")
    if "not" in schema and not _errors(schema["not"], value, root, path):
        problems.append(f"{path}: matches not")
    if "if" in schema and not _errors(schema["if"], value, root, path) and "then" in schema:
        problems += _errors(schema["then"], value, root, path)
    return problems


def _valid(value: object, definition: str | None = None, document: dict | None = None) -> bool:
    document = document or query_schema()
    schema = _resolve(document, f"#/$defs/{definition}") if definition else document
    return not _errors(schema, value, document)


def _registry_accepts(request: object) -> bool:
    try:
        validate_query(request)
    except QueryError:
        return False
    return True


def _readme_batches() -> list[list[dict]]:
    """Return the JSON arrays fed to `retrore batch` in README heredocs."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    batches = []
    for match in re.finditer(r"retrore batch[^\n]*<<'(\w+)'\n(.*?)\n\1\n", text, re.S):
        batches.append(json.loads(match.group(2)))
    return batches


def _sample(name: str, parameter: dict) -> object:
    if parameter["type"] == "string":
        if parameter.get("format") == "address":
            return "c000"
        return parameter["enum"][0] if "enum" in parameter else "root"
    if parameter["type"] == "integer":
        return parameter["minimum"]
    if parameter["type"] == "boolean":
        return True
    return ["c000"] if name == "addresses" else ["READ"] if name == "ref_types" else ["main"]


def _minimal(command: str) -> dict:
    """Build the smallest valid request for a command from its registry definition."""
    definition = QUERIES[command]
    parameters = definition["parameters"]
    request = {"command": command}
    request.update((name, _sample(name, parameter)) for name, parameter in parameters.items()
                   if parameter.get("required"))
    for group in definition.get("one_of", []) + definition.get("any_of", []):
        request[group[0]] = _sample(group[0], parameters[group[0]])
    return request


def test_schema_document_shape():
    document = query_schema()
    assert document["$schema"] == DIALECT
    assert document["contract"] == CONTRACT_VERSION
    assert json.loads(json.dumps(document)) == document
    assert list(document["commands"]) == list(QUERIES)
    assert [branch["$ref"] for branch in document["$defs"]["request"]["oneOf"]] == [
        f"#/$defs/{command}_request" for command in QUERIES
    ]
    requests = {name.removesuffix("_request") for name in document["$defs"] if name.endswith("_request")}
    assert requests == QUERIES.keys()
    assert set(document["$defs"]["error"]["properties"]["code"]["examples"]) == HINTS.keys()


def test_schema_command(capsys):
    assert main(["schema", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == query_schema()
    assert main(["schema"]) == 0
    output = capsys.readouterr().out.splitlines()
    assert output[0].startswith(f"Query contract {CONTRACT_VERSION}")
    assert [line.split()[0] for line in output[1:-1]] == list(QUERIES)


def test_readme_examples_validate():
    batches = _readme_batches()
    assert len(batches) >= 2
    for batch in batches:
        assert _valid(batch, "batch"), _errors(query_schema()["$defs"]["batch"], batch, query_schema())
        assert _valid(batch)
        for request in batch:
            assert _valid(request, "request") and _registry_accepts(request)
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    error = json.loads(re.search(r'```json\n(\{"contract".*?)\n```', text, re.S).group(1))
    assert _valid(error, "error_report")
    assert not _valid({**error, "contract": CONTRACT_VERSION + 1}, "error_report")


@pytest.mark.parametrize("command", list(QUERIES))
def test_every_command_has_a_minimal_request(command):
    request = _minimal(command)
    assert _registry_accepts(request)
    assert _valid(request, f"{command}_request") and _valid(request, "request") and _valid([request])
    assert not _valid({**request, "unknown": 1}, "request")
    assert not _valid({**request, "fields": []}, "request")
    assert _valid({**request, "fields": QUERIES[command]["fields"][:1]}, "request")
    for name, parameter in QUERIES[command]["parameters"].items():
        if parameter.get("required"):
            assert not _valid({key: value for key, value in request.items() if key != name}, "request")


@pytest.mark.parametrize("request_", [
    {"command": "decomp", "address": "OV1:20a5", "context": 2, "slice": 12},
    {"command": "decomp", "address": "1000:0015", "fields": ["name", "focus"], "slice": 4},
    {"command": "decomp", "address": "c004", "fields": ["excerpt"]},
    {"command": "decomp", "address": "c004", "fields": ["slice"], "context": 1},
    {"command": "decomp", "address": "g:"},
    {"command": "decomp", "address": "c004 "},
    {"command": "decomp", "address": "123456789"},
    {"command": "decomp", "address": 7},
    {"command": "decomp", "address": "c004", "context": 21},
    {"command": "decomp", "address": "c004", "context": True},
    {"command": "decomp", "address": "c004", "context": 1.0},
    {"command": "nope", "address": "0"},
    {"address": "0"},
    {"command": "func", "address": "0", "depth": 1},
    {"command": "xrefs", "address": "0", "direction": "callers"},
    {"command": "xrefs", "address": "0", "direction": "incoming", "ref_types": ["READ", "unconditional_call"]},
    {"command": "xrefs", "address": "0", "ref_types": []},
    {"command": "xrefs", "address": "0", "ref_types": ["1"]},
    {"command": "xrefs", "address": "0", "limit": 0},
    {"command": "xrefs", "address": "0", "offset": 0, "compact": False},
    {"command": "inventory", "unit": "a:b"},
    {"command": "inventory", "unit": "root", "limit": 1000, "fields": ["functions", "data"]},
    {"command": "inventory", "unit": "root", "limit": 1001},
    {"command": "inventory", "unit": "root", "fields": ["name"]},
    {"command": "callgraph", "address": "0", "depth": 4, "max_nodes": 512, "direction": "callers"},
    {"command": "callgraph", "address": "0", "depth": 5},
    {"command": "callgraph", "address": "0", "direction": "both"},
    {"command": "context", "address": "0", "ref_types": ["READ"]},
    {"command": "functions"},
    {"command": "functions", "addresses": []},
    {"command": "functions", "addresses": [], "names": ["main"]},
    {"command": "functions", "addresses": ["zz"]},
    {"command": "functions", "names": [""]},
    {"command": "functions", "addresses": ["0"] * 257},
    {"command": "functions", "names": ["a"], "fields": ["query"]},
    {"command": "symbols"},
    {"command": "symbols", "glob": "FAR*", "unit": "root", "ignore_case": True},
    {"command": "symbols", "name": "a", "glob": "*"},
    {"command": "symbols", "glob": "*", "ignore_case": 1},
    {"command": "gaps"},
    {"command": "gaps", "compact": True},
    {"command": "coverage", "offset": -1},
    {"command": "coverage", "unit": "OV1", "fields": ["unit", "undefined_bytes"]},
])
def test_schema_agrees_with_registry_validation(request_):
    assert _valid(request_, "request") == _registry_accepts(request_)


def test_schema_leaves_the_total_lookup_cap_to_validation():
    # JSON Schema cannot sum array lengths; the cap is an annotation and the registry enforces it.
    request = {"command": "functions", "addresses": ["0"] * 200, "names": ["a"] * 57}
    assert _valid(request, "request") and not _registry_accepts(request)
    assert query_schema()["$defs"]["functions_request"]["x-retrore-max-total-items"]["maximum"] == 256


def test_batch_schema_rejects_invalid_arrays():
    assert not _valid([], "batch")
    assert not _valid({"command": "func", "address": "0"}, "batch")
    assert not _valid([{"command": "func", "address": "0"}, {"command": "func"}], "batch")


def test_tool_schemas_follow_the_registry():
    document = query_schema()
    listed = {tool["name"]: tool for tool in tools()}
    assert list(listed) == [*QUERIES, "batch", "where_is", "info", "load"]
    for command in QUERIES:
        request, schema = document["$defs"][f"{command}_request"], listed[command]["inputSchema"]
        assert schema["$schema"] == DIALECT and schema["type"] == "object"
        assert not schema.keys() & {"oneOf", "anyOf", "allOf"}
        assert schema["properties"] == {
            "project": schema["properties"]["project"],
            **{name: value for name, value in request["properties"].items() if name != "command"},
            "timeout": schema["properties"]["timeout"],
        }
        assert schema["required"] == ["project", *request["required"][1:]]
        assert schema["additionalProperties"] is False
    batch = listed["batch"]["inputSchema"]
    assert batch["$defs"] == document["$defs"] and batch["required"] == ["project", "requests"]
    assert not _errors(batch, {"project": "p", "requests": [{"command": "func", "address": "0"}]}, batch)
    assert _errors(batch, {"project": "p", "requests": [{"command": "func"}]}, batch)


def test_program_tool_schemas_follow_the_cli_options():
    listed = {tool["name"]: tool["inputSchema"] for tool in tools()}
    info, load = listed["info"], listed["load"]
    assert info["required"] == ["program"] and load["required"] == ["program", "output"]
    assert load["properties"] == {**info["properties"], "output": load["properties"]["output"]}
    properties = info["properties"]
    assert properties["c64"]["type"] == "boolean" and properties["entry"]["type"] == "array"
    assert properties["x1_lsn"]["items"] == {"type": "string"} and "LSN[+COUNT]@HEX" in properties["x1_lsn"]["description"]
    assert properties["pc88_disk"]["type"] == "integer"
    assert properties["pc88_low"]["enum"] == ["ram", "n88-rom", "n-rom"]
    assert "json" not in properties and info["additionalProperties"] is False
    assert not _errors(load, {"program": "a.prg", "output": "out", "entry": ["c000"], "c64": True}, load)
    assert _errors(info, {"program": "a.prg", "entry": "c000"}, info)


def _environment(**extra: str) -> dict:
    return {**os.environ, "PYTHONPATH": str(PACKAGE_PATH), **extra}


def _session(messages: list, *, timeout: float = 60, **environment: str) -> dict:
    """Send messages to `retrore mcp` at once and return the responses by id."""
    lines = "".join((message if isinstance(message, str) else json.dumps(message)) + "\n" for message in messages)
    process = subprocess.run(
        [sys.executable, "-m", "retrore", "mcp"], input=lines, capture_output=True, text=True, timeout=timeout,
        env=_environment(**environment), check=True,
    )
    responses = [json.loads(line) for line in process.stdout.splitlines()]
    assert all(response["jsonrpc"] == "2.0" for response in responses)
    return {response["id"]: response for response in responses}


def _initialize(version: str = "2025-11-25") -> list[dict]:
    return [
        {"jsonrpc": "2.0", "id": 0, "method": "initialize",
         "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]


def _call(identifier: int, name: str, arguments: dict, **params: object) -> dict:
    return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
            "params": {"name": name, "arguments": arguments, **params}}


def test_mcp_session(tmp_path):
    missing = str(tmp_path / "missing")
    responses = _session([
        *_initialize(),
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        _call(2, "func", {"project": missing, "address": "c000"}),
        _call(3, "func", {"project": missing, "address": "g:"}),
        _call(4, "callgraph", {"project": missing, "address": "c000", "depth": 9}),
        _call(5, "func", {"project": missing, "address": "c000", "timeout": -1}),
        _call(6, "func", {"project": missing, "address": "c000", "command": "decomp"}),
        _call(7, "batch", {"project": missing, "requests": []}),
        _call(8, "nope", {}),
        {"jsonrpc": "2.0", "id": 9, "method": "ping"},
        {"jsonrpc": "2.0", "id": 10, "method": "resources/list"},
        "not json",
        _call(11, "func", {"project": missing, "address": "c000", "timeout": None}),
        _call(12, "batch", {"project": missing, "requests": [{"command": "func"}], "timeout": None}),
    ])
    assert len(responses) == 14
    initialized = responses[0]["result"]
    assert initialized["protocolVersion"] == "2025-11-25"
    assert initialized["capabilities"] == {"tools": {"listChanged": False}}
    assert initialized["serverInfo"]["name"] == "retrore" and initialized["instructions"]
    assert responses[1]["result"]["tools"] == tools()

    not_found = responses[2]["result"]
    assert not_found["isError"] is True
    assert not_found["structuredContent"] == {"contract": CONTRACT_VERSION, "error": {
        "code": "project_not_found", "message": f"Ghidra project not found at {missing}.gpr",
        "hint": HINTS["project_not_found"]}}
    assert json.loads(not_found["content"][0]["text"]) == not_found["structuredContent"]
    for identifier, message in ((3, "expected a hexadecimal unit:offset"), (4, "depth must be an integer between 1"),
                                (5, "timeout: expected a nonnegative number"), (6, "the tool name selects"),
                                (7, "expected a nonempty JSON array"),
                                (11, "timeout: expected a nonnegative number"),
                                (12, "timeout: expected a nonnegative number")):
        result = responses[identifier]["result"]
        assert result["isError"] is True, identifier
        error = result["structuredContent"]["error"]
        assert error["code"] == "invalid_request" and error["message"].startswith(message), error
    assert responses[8]["error"]["code"] == -32602
    assert responses[9]["result"] == {}
    assert responses[10]["error"]["code"] == -32601
    assert responses[None]["error"]["code"] == -32700


def test_mcp_cli_error_parity(tmp_path, capsys):
    missing = tmp_path / "missing"
    assert main(["func", "c000", "--project", str(missing), "--json"]) == 1
    cli = json.loads(capsys.readouterr().err)
    response = _session([*_initialize(), _call(1, "func", {"project": str(missing), "address": "c000"})])
    assert response[1]["result"]["structuredContent"] == cli


def test_mcp_current_protocol(tmp_path):
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}}
    responses = _session([
        {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": meta}},
        _call(3, "func", {"project": str(tmp_path / "p"), "address": "c000"}, _meta=meta),
        {"jsonrpc": "2.0", "id": 4, "method": "tools/list",
         "params": {"_meta": {**meta, "io.modelcontextprotocol/protocolVersion": "1900-01-01"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/list",
         "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/list"},
    ])
    discover = responses[1]["result"]
    assert discover["resultType"] == "complete" and "2026-07-28" in discover["supportedVersions"]
    assert discover["capabilities"] == {"tools": {"listChanged": False}}
    assert discover["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "retrore"
    listed = responses[2]["result"]
    assert listed["resultType"] == "complete" and listed["tools"] == tools()
    assert listed["ttlMs"] > 0 and listed["cacheScope"] == "public"
    called = responses[3]["result"]
    assert called["resultType"] == "complete" and called["isError"] is True
    assert called["structuredContent"]["error"]["code"] == "project_not_found"
    unsupported = responses[4]["error"]
    assert unsupported["code"] == -32022 and unsupported["data"]["requested"] == "1900-01-01"
    assert responses[5]["error"]["code"] == -32602
    assert responses[6]["error"]["code"] == -32602


def _c64_export(tmp_path: Path) -> tuple[Path, Path]:
    # JSR $C004, RTS; LDA #$07, STA $D020, RTS: the README's synthetic program.
    program = tmp_path / "demo.prg"
    program.write_bytes(_prg(0xC000, bytes.fromhex("2004c060 a907 8d20d0 60")))
    export = tmp_path / "export"
    assert main(["load", str(program), "--entry", "c000", "-o", str(export)]) == 0
    return program, export


def test_mcp_where_is_matches_the_cli(tmp_path, capsys):
    _, export = _c64_export(tmp_path)
    capsys.readouterr()
    assert main(["where-is", "--export", str(export), "--bytes", "8d 20 d0", "--json"]) == 0
    by_bytes = json.loads(capsys.readouterr().out)
    assert main(["where-is", "--export", str(export), "--constant", "0xd020", "--json"]) == 0
    by_constant = json.loads(capsys.readouterr().out)
    responses = _session([
        *_initialize(),
        _call(1, "where_is", {"export": str(export), "bytes": "8d 20 d0"}),
        _call(2, "where_is", {"export": str(export), "constant": "0xd020"}),
        _call(3, "where_is", {"export": str(export), "constant": 0xD020, "width": 2}),
        _call(4, "where_is", {"export": str(export), "bytes": "8d", "string": "x"}),
        _call(5, "where_is", {"export": str(export), "string": "x", "width": 2}),
        _call(6, "where_is", {"export": str(tmp_path / "missing"), "bytes": "00"}),
    ])
    assert by_bytes["count"] == 1
    assert responses[1]["result"] == {"content": [{"type": "text", "text": json.dumps(by_bytes)}],
                                      "structuredContent": by_bytes, "isError": False}
    assert responses[2]["result"]["structuredContent"] == by_constant
    assert by_constant["pattern"] == "20d0" and by_constant["count"] == 1
    assert responses[3]["result"]["structuredContent"] == by_constant
    assert responses[4]["result"]["structuredContent"]["error"]["message"].startswith("specify exactly one")
    assert responses[5]["result"]["structuredContent"]["error"]["message"] == "--width requires --constant"
    assert responses[6]["result"]["structuredContent"]["error"]["code"] == "io_error"


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test")
def test_mcp_query_matches_the_cli(tmp_path, capsys):
    _, export = _c64_export(tmp_path)
    project = tmp_path / "project"
    assert main(["ghidra", "import", str(export), str(project)]) == 0
    capsys.readouterr()
    assert main(["callees", "c000", "--project", str(project), "--limit", "1", "--json"]) == 0
    single = capsys.readouterr().out
    batch_requests = [{"command": "decomp", "address": "c004", "fields": ["name", "address"]},
                      {"command": "functions", "addresses": ["c000", "c004"], "compact": True}]
    batch_file = tmp_path / "batch.json"
    batch_file.write_text(json.dumps(batch_requests), encoding="utf-8")
    assert main(["batch", str(batch_file), "--project", str(project), "--json"]) == 0
    batch = capsys.readouterr().out

    responses = _session([
        *_initialize(),
        _call(1, "callees", {"project": str(project), "address": "c000", "limit": 1}),
        _call(2, "batch", {"project": str(project), "requests": batch_requests}),
    ], timeout=600)
    for identifier, output in ((1, single), (2, batch)):
        result = responses[identifier]["result"]
        assert result["isError"] is False
        assert result["structuredContent"] == json.loads(output)
        assert result["content"] == [{"type": "text", "text": output.strip()}]
    callees = json.loads(single)["callees"]
    assert [callee["to_function"]["name"] for callee in callees] == ["FUN_c004"]


@pytest.mark.skipif(os.name == "nt", reason="select() needs a POSIX pipe")
def test_mcp_answers_each_line_before_stdin_closes():
    process = subprocess.Popen(
        [sys.executable, "-m", "retrore", "mcp", "--json"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        env=_environment(),
    )
    try:
        for message in [*_initialize(), {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]:
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()
            if "id" in message:
                ready, _, _ = select.select([process.stdout], [], [], 30)
                assert ready, "no response before stdin closed"
                assert json.loads(process.stdout.readline())["id"] == message["id"]
    finally:
        process.stdin.close()
        assert process.wait(timeout=30) == 0
        process.stdout.close()


def test_mcp_info_and_load_match_the_cli(tmp_path, capsys):
    program, export = _c64_export(tmp_path)
    capsys.readouterr()
    assert main(["info", str(program), "--entry", "c000", "--c64-bank", "6", "--json"]) == 0
    info = json.loads(capsys.readouterr().out)
    loaded = tmp_path / "mcp-export"
    responses = _session([
        *_initialize(),
        _call(1, "info", {"program": str(program), "entry": ["c000"], "c64_bank": "6"}),
        _call(2, "load", {"program": str(program), "entry": ["c000"], "output": str(loaded)}),
        _call(4, "info", {"program": str(program), "c64": True, "apple2": True}),
        _call(5, "info", {"program": str(program), "base_address": "zz"}),
        _call(6, "info", {"program": str(program), "entry": "c000"}),
        _call(7, "info", {"program": str(program), "json": True}),
        _call(8, "load", {"program": str(program)}),
        _call(9, "info", {"program": str(tmp_path / "missing.prg")}),
    ])
    assert responses[1]["result"]["structuredContent"] == info and responses[1]["result"]["isError"] is False
    assert responses[2]["result"]["structuredContent"] == json.loads((export / "map.json").read_text())
    assert (loaded / "image.bin").read_bytes() == (export / "image.bin").read_bytes()
    # Calls run concurrently, so a second export to the same directory goes in a later session.
    responses |= _session([*_initialize(), _call(3, "load", {"program": str(program), "output": str(loaded)})])
    for identifier, code, message in (
        (3, "io_error", "[Errno 17] File exists"),
        (4, "invalid_request", "argument --apple2: not allowed with argument --c64"),
        (5, "invalid_request", "argument --base-address: expected a hexadecimal address"),
        (6, "invalid_request", "entry must be a list"),
        (7, "invalid_request", "unsupported options for info: json"),
        (8, "invalid_request", "the following arguments are required: -o/--output"),
        (9, "io_error", "[Errno 2]"),
    ):
        result = responses[identifier]["result"]
        assert result["isError"] is True, identifier
        error = result["structuredContent"]["error"]
        assert (error["code"], error["message"][:len(message)]) == (code, message), identifier


def _read_response(process: subprocess.Popen, seconds: float = 30) -> dict:
    ready, _, _ = select.select([process.stdout], [], [], seconds)
    assert ready, "no response"
    return json.loads(process.stdout.readline())


def _wait_for_pid(pid_file: Path, previous: str = "") -> int:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        text = pid_file.read_text() if pid_file.exists() else ""
        if text and text != previous:
            return int(text)
        time.sleep(0.05)
    pytest.fail("the fake headless run did not start")


@pytest.mark.skipif(os.name == "nt", reason="the fake launcher is a POSIX script")
def test_mcp_calls_run_concurrently_and_cancel(tmp_path):
    support = tmp_path / "ghidra" / "support"
    support.mkdir(parents=True)
    launcher = support / "analyzeHeadless"
    launcher.write_text(_FAKE.format(python=sys.executable), encoding="utf-8")
    launcher.chmod(0o755)
    project = tmp_path / "demo.gpr"
    project.write_text("", encoding="utf-8")
    pid_file = tmp_path / "grandchild.pid"
    _, export = _c64_export(tmp_path)
    process = subprocess.Popen(
        [sys.executable, "-m", "retrore", "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        env=_environment(GHIDRA_HOME=str(tmp_path / "ghidra"), FAKE_GHIDRA_MODE="hang_soft",
                         FAKE_GHIDRA_PID=str(pid_file)),
    )

    def send(message: dict) -> None:
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()

    def cancel(identifier: int) -> None:
        send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": identifier}})

    try:
        for message in _initialize():
            send(message)
        assert _read_response(process)["id"] == 0
        send(_call(1, "func", {"project": str(project), "address": "c000"}))
        first = _wait_for_pid(pid_file)
        # A second call on the same project waits for the first; other tools answer meanwhile.
        send(_call(2, "decomp", {"project": str(tmp_path / "demo"), "address": "c000"}))
        send(_call(3, "func", {"project": str(project), "address": "c000"}))
        send(_call(4, "where_is", {"export": str(export), "bytes": "8d 20 d0"}))
        response = _read_response(process)
        assert response["id"] == 4 and response["result"]["structuredContent"]["count"] == 1
        send(_call(3, "func", {"project": str(project), "address": "c000"}))
        assert _read_response(process)["error"]["message"] == "request id is already in use by a call in progress"
        time.sleep(0.5)
        assert pid_file.read_text() == str(first)

        cancel(1)
        _wait_dead(first)
        second = _wait_for_pid(pid_file, str(first))
        cancel(2)
        cancel(3)
        _wait_dead(second)
        send({"jsonrpc": "2.0", "id": 5, "method": "ping"})
        assert _read_response(process) == {"jsonrpc": "2.0", "id": 5, "result": {}}
    finally:
        process.stdin.close()
        assert process.wait(timeout=60) == 0
        # Cancelled calls send no response.
        assert process.stdout.read() == ""
        process.stdout.close()
