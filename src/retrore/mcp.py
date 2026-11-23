"""A Model Context Protocol server over stdio for retrore queries.

JSON-RPC 2.0 messages arrive one per line on stdin and leave one per line on stdout. The server is
dual-era: legacy clients open with `initialize` (protocol 2025-11-25 and earlier), and current clients
(2026-07-28) send `io.modelcontextprotocol/*` metadata in each request's `_meta`.

Tools come from the query registry. A tool call builds the same request the CLI builds and runs it
through the same functions, so validation, results, and error objects match `--json` output.
"""

import contextlib
import copy
import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import IO

from .cli import HANDLED_ERRORS, error_report
from .errors import CONTRACT_VERSION
from .ghidra import QUERY_TIMEOUT, GhidraError, check_timeout, query, query_batch
from .queries import query_definitions
from .schema import DIALECT, query_schema
from .search import WIDTHS, find_bytes, search_pattern

MODERN_VERSIONS = ("2026-07-28",)
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
SUPPORTED_VERSIONS = MODERN_VERSIONS + LEGACY_VERSIONS

_META_VERSION = "io.modelcontextprotocol/protocolVersion"
_META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
_META_SERVER = "io.modelcontextprotocol/serverInfo"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
UNSUPPORTED_VERSION = -32022

# Tool definitions do not change while the server runs.
_CACHE_TTL_MS = 3_600_000

INSTRUCTIONS = (
    "retrore answers questions about retro executables analyzed in a headless Ghidra project. Pass the "
    "project path (the .gpr file or its path without the suffix) to each query tool, and prefer the batch "
    "tool for several queries: each call launches Ghidra once. Results and error objects match the CLI's "
    f"--json output under query contract {CONTRACT_VERSION}; branch on error.code. Create projects with the "
    "CLI: `retrore load PROGRAM -o EXPORT` and `retrore ghidra import EXPORT PROJECT`."
)

_PROJECT = {"type": "string", "minLength": 1,
            "description": "path to the Ghidra project (.gpr file, or its path without the suffix)"}


def _timeout_schema(default: str) -> dict:
    return {"type": "number", "minimum": 0,
            "description": f"stop headless Ghidra after this many seconds (default: {default}; 0 disables the limit)"}


def _flatten(schema: dict) -> dict:
    """Move top-level composition keywords into the description.

    Some tool-calling APIs reject `oneOf`, `anyOf`, and `allOf` at the top level of a tool's input
    schema. Those constraints stay enforced by retrore's validation, and `retrore schema` keeps them.
    """
    return {key: value for key, value in schema.items() if key not in ("oneOf", "anyOf", "allOf")}


class UnknownTool(LookupError):
    """No tool has the requested name."""


class InvalidArguments(GhidraError):
    """Tool arguments outside the query request, such as project or timeout, are invalid."""


def server_version() -> str:
    try:
        return version("retrore")
    except PackageNotFoundError:
        return "0+unknown"


def _query_tool(command: str, definition: dict, document: dict) -> dict:
    request = document["$defs"][f"{command}_request"]
    schema = copy.deepcopy(request)
    schema.pop("title", None)
    del schema["properties"]["command"]
    schema["required"].remove("command")
    schema["properties"] = {"project": _PROJECT, **schema["properties"],
                            "timeout": _timeout_schema(f"{QUERY_TIMEOUT} seconds")}
    schema["required"].insert(0, "project")
    schema = {"$schema": DIALECT, **_flatten(schema)}
    description = request["description"]
    for group in definition.get("one_of", []):
        description += f". Requires exactly one of {', '.join(group)}"
    for group in definition.get("any_of", []):
        description += f". Requires at least one nonempty {' or '.join(group)}"
    return {"name": command, "title": f"retrore {command}", "description": description + ".",
            "inputSchema": schema}


def _batch_tool(document: dict) -> dict:
    return {
        "name": "batch",
        "title": "retrore batch",
        "description": "Run an ordered array of query requests in one read-only Ghidra session. Each request has "
                       "a command and that command's parameters, as for the individual tools. Rows carry either "
                       "result or a coded error.",
        "inputSchema": {
            "$schema": DIALECT,
            "type": "object",
            "properties": {
                "project": _PROJECT,
                "requests": {"$ref": "#/$defs/batch"},
                "timeout": _timeout_schema("the larger of 600 seconds and 60 seconds per query"),
            },
            "required": ["project", "requests"],
            "additionalProperties": False,
            "$defs": document["$defs"],
        },
    }


def _where_is_tool() -> dict:
    return {
        "name": "where_is",
        "title": "retrore where-is",
        "description": "Find a byte pattern across the file-backed units of an export from `retrore load`. Give "
                       "exactly one of bytes, string, or constant. Matches can overlap.",
        "inputSchema": {
            "$schema": DIALECT,
            "type": "object",
            "properties": {
                "export": {"type": "string", "minLength": 1, "description": "directory from retrore load"},
                "bytes": {"type": "string", "description": "hexadecimal bytes, spaces allowed"},
                "string": {"type": "string", "description": "literal string in the image's supported encoding"},
                "constant": {"type": ["integer", "string"],
                             "description": "integer, or decimal or 0x-prefixed string, in the image's byte order"},
                "width": {"enum": list(WIDTHS), "description": "constant width in bytes (default 2)"},
            },
            "required": ["export"],
            "additionalProperties": False,
        },
    }


def tools() -> list[dict]:
    """Return every tool definition in a stable order."""
    definitions = query_definitions()
    reserved = {"batch", "where_is"} & definitions.keys()
    if reserved:
        raise RuntimeError(f"query names collide with adapter tools: {', '.join(sorted(reserved))}")
    document = query_schema()
    return [*(_query_tool(command, definition, document) for command, definition in definitions.items()),
            _batch_tool(document), _where_is_tool()]


def _project(arguments: dict) -> Path:
    project = arguments.get("project")
    if not isinstance(project, str) or not project:
        raise InvalidArguments("project must be a nonempty path string")
    return Path(project)


def _timeout(arguments: dict, default: float | None) -> float | None:
    if "timeout" not in arguments:
        return default
    if arguments["timeout"] is None:
        # Passing None to the query functions would disable the budget; require a number instead.
        raise InvalidArguments("timeout: expected a nonnegative number of seconds")
    try:
        return check_timeout(arguments["timeout"])
    except GhidraError as error:
        raise InvalidArguments(f"timeout: {error}") from None


def _call_query(command: str, arguments: dict) -> dict:
    project, timeout = _project(arguments), _timeout(arguments, QUERY_TIMEOUT)
    request = {name: value for name, value in arguments.items() if name not in ("project", "timeout")}
    if "command" in request:
        raise InvalidArguments(f"the tool name selects the command; remove command from the {command} arguments")
    return query(project, {"command": command, **request}, timeout=timeout)


def _call_batch(arguments: dict) -> dict:
    unknown = arguments.keys() - {"project", "requests", "timeout"}
    if unknown:
        raise InvalidArguments(f"unsupported options for batch: {', '.join(sorted(unknown))}")
    return query_batch(_project(arguments), arguments.get("requests"), timeout=_timeout(arguments, None))


def _call_where_is(arguments: dict) -> dict:
    unknown = arguments.keys() - {"export", "bytes", "string", "constant", "width"}
    if unknown:
        raise InvalidArguments(f"unsupported options for where_is: {', '.join(sorted(unknown))}")
    export = arguments.get("export")
    if not isinstance(export, str) or not export:
        raise InvalidArguments("export must be a nonempty path string")
    pattern, width = search_pattern(hex_bytes=arguments.get("bytes"), string=arguments.get("string"),
                                    constant=arguments.get("constant"), width=arguments.get("width"))
    return find_bytes(Path(export), pattern, width=width)


def call_tool(name: str, arguments: dict) -> dict:
    """Run a tool and return an MCP CallToolResult. Unknown tool names raise UnknownTool."""
    if name == "batch":
        run = _call_batch
    elif name == "where_is":
        run = _call_where_is
    elif name in query_definitions():
        def run(arguments: dict) -> dict:
            return _call_query(name, arguments)
    else:
        raise UnknownTool(name)
    try:
        report, failed = run(arguments), False
    except HANDLED_ERRORS as error:
        report, failed = error_report(error), True
    return {"content": [{"type": "text", "text": json.dumps(report)}], "structuredContent": report,
            "isError": failed}


class Server:
    """Answer JSON-RPC messages; one instance serves one stdio connection."""

    def __init__(self) -> None:
        self.legacy_version: str | None = None
        self.info = {"name": "retrore", "title": "retrore", "version": server_version()}

    def handle(self, message: object) -> dict | None:
        """Return the response to one decoded message, or None for a notification."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            identifier = message.get("id") if isinstance(message, dict) else None
            if isinstance(message, dict) and "method" not in message and ("result" in message or "error" in message):
                return None  # A response to a request we never send; ignore it.
            return _error(identifier if _valid_id(identifier) else None, INVALID_REQUEST, "Invalid Request")
        if "id" not in message:
            self._notify(message["method"])
            return None
        identifier = message["id"]
        if not _valid_id(identifier):
            return _error(None, INVALID_REQUEST, "request id must be a string or integer")
        params = message.get("params", {})
        if not isinstance(params, dict):
            return _error(identifier, INVALID_PARAMS, "params must be an object")
        try:
            result = self._dispatch(message["method"], params)
        except _RpcError as error:
            return _error(identifier, error.code, error.message, error.data)
        except Exception as error:  # noqa: BLE001 - a bug must not end the session.
            return _error(identifier, INTERNAL_ERROR, f"internal error: {type(error).__name__}: {error}")
        return {"jsonrpc": "2.0", "id": identifier, "result": result}

    def _notify(self, method: str) -> None:
        # notifications/initialized and notifications/cancelled need no action: calls run one at a time.
        pass

    def _dispatch(self, method: str, params: dict) -> dict:
        if method == "initialize":
            return self._initialize(params)
        if method == "ping":
            return {}
        meta = params.get("_meta")
        modern = isinstance(meta, dict) and _META_VERSION in meta
        if modern:
            self._check_modern(meta)
        elif method != "server/discover" and self.legacy_version is None:
            raise _RpcError(INVALID_PARAMS, f"missing {_META_VERSION} in _meta; send it with each request "
                                            "or open the connection with initialize")
        if method == "server/discover":
            result = {"supportedVersions": list(SUPPORTED_VERSIONS), "capabilities": _capabilities(),
                      "instructions": INSTRUCTIONS, "ttlMs": _CACHE_TTL_MS, "cacheScope": "public"}
        elif method == "tools/list":
            result = {"tools": tools()}
            if modern:
                result |= {"ttlMs": _CACHE_TTL_MS, "cacheScope": "public"}
        elif method == "tools/call":
            name, arguments = params.get("name"), params.get("arguments", {})
            if not isinstance(name, str):
                raise _RpcError(INVALID_PARAMS, "tools/call needs a tool name")
            if not isinstance(arguments, dict):
                raise _RpcError(INVALID_PARAMS, "tool arguments must be an object")
            try:
                result = call_tool(name, arguments)
            except UnknownTool:
                raise _RpcError(INVALID_PARAMS, f"Unknown tool: {name}") from None
        else:
            raise _RpcError(METHOD_NOT_FOUND, f"Method not found: {method}")
        if modern or method == "server/discover":
            result = {"resultType": "complete", **result,
                      "_meta": {**result.get("_meta", {}), _META_SERVER: self.info}}
        return result

    def _initialize(self, params: dict) -> dict:
        requested = params.get("protocolVersion")
        self.legacy_version = requested if requested in LEGACY_VERSIONS else LEGACY_VERSIONS[0]
        return {"protocolVersion": self.legacy_version, "capabilities": _capabilities(), "serverInfo": self.info,
                "instructions": INSTRUCTIONS}

    def _check_modern(self, meta: dict) -> None:
        requested = meta[_META_VERSION]
        if requested not in MODERN_VERSIONS:
            raise _RpcError(UNSUPPORTED_VERSION, "Unsupported protocol version",
                            {"supported": list(SUPPORTED_VERSIONS), "requested": requested})
        if not isinstance(meta.get(_META_CAPABILITIES), dict):
            raise _RpcError(INVALID_PARAMS, f"missing {_META_CAPABILITIES} in _meta")


class _RpcError(Exception):
    def __init__(self, code: int, message: str, data: object = None) -> None:
        super().__init__(message)
        self.code, self.message, self.data = code, message, data


def _valid_id(identifier: object) -> bool:
    return isinstance(identifier, str) or (isinstance(identifier, int) and not isinstance(identifier, bool))


def _capabilities() -> dict:
    return {"tools": {"listChanged": False}}


def _error(identifier: object, code: int, message: str, data: object = None) -> dict:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": identifier, "error": error}


def serve(stdin: IO[bytes] | None = None, stdout: IO[str] | None = None) -> int:
    """Serve newline-delimited JSON-RPC on stdio until stdin closes."""
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout
    server = Server()
    # Only protocol messages may reach stdout; anything else printed during a call goes to stderr.
    with contextlib.redirect_stdout(sys.stderr):
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except (UnicodeError, ValueError):
                response = _error(None, PARSE_ERROR, "Parse error")
            else:
                response = (_error(None, INVALID_REQUEST, "JSON-RPC batches are not supported")
                            if isinstance(message, list) else server.handle(message))
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()
    return 0
