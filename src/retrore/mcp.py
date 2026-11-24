"""A Model Context Protocol server over stdio for retrore queries.

JSON-RPC 2.0 messages arrive one per line on stdin and leave one per line on stdout. The server is
dual-era: legacy clients open with `initialize` (protocol 2025-11-25 and earlier), and current clients
(2026-07-28) send `io.modelcontextprotocol/*` metadata in each request's `_meta`.

Tools come from the query registry. A tool call builds the same request the CLI builds and runs it
through the same functions, so validation, results, and error objects match `--json` output.
"""

import argparse
import contextlib
import copy
import json
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import IO

from . import worker
from .cli import (
    HANDLED_ERRORS, _export_image, _hex_segment, _overlay_segments, _runtime_loads, build_program, error_report,
    program_options,
)
from .errors import CONTRACT_VERSION
from .evidence import ADDRESS_SPACES, FILE_OFFSET_KINDS, MAX_BYTES, inspect_bytes, map_address
from .ghidra import QUERY_TIMEOUT, GhidraError, cancellable, check_cancelled, check_timeout, query, query_batch
from .queries import query_definitions
from .schema import DIALECT, query_schema
from .search import (
    ENCODINGS, POINTER_KINDS, WIDTHS, find_bytes, find_pointers, find_relocations, find_text, lookup_symbols,
    search_pattern,
)

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

# Tool calls run on worker threads. Calls on one Ghidra project wait for each other because Ghidra locks
# the project; other calls run concurrently up to this many at a time.
MAX_CONCURRENT_CALLS = 4

# Tool definitions do not change while the server runs.
_CACHE_TTL_MS = 3_600_000

INSTRUCTIONS = (
    "retrore answers questions about retro executables analyzed in a headless Ghidra project. Pass the "
    "project path (the .gpr file or its path without the suffix) to each query tool, and prefer the batch "
    "tool for independent queries. The server keeps each project open in Ghidra between calls, so the first "
    "call on a project takes a few seconds and later calls are fast; calls on one project run one at a time. "
    "Results and error objects match the CLI's --json output under query contract "
    f"{CONTRACT_VERSION}; branch on error.code. Inspect and export programs with the info and load tools, "
    "then create the project with the CLI: `retrore ghidra import EXPORT PROJECT`."
)

_PROJECT = {"type": "string", "minLength": 1,
            "description": "path to the Ghidra project (.gpr file, or its path without the suffix)"}
_PROJECT_PROGRAM = {"type": "string", "minLength": 1,
                    "description": "exact program name at the project root (default image.bin)"}


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
    schema["properties"] = {"project": _PROJECT, "program": _PROJECT_PROGRAM, **schema["properties"],
                            "timeout": _timeout_schema(f"{QUERY_TIMEOUT} seconds")}
    schema["required"].insert(0, "project")
    schema = {"$schema": DIALECT, **_flatten(schema)}
    description = request["description"]
    for group in definition.get("one_of", []):
        description += f". Requires exactly one of {', '.join(group)}"
    for group in definition.get("any_of", []):
        description += f". Requires at least one nonempty {' or '.join(group)}"
    for name, required in definition.get("dependent_required", {}).items():
        description += f". {name} requires {' and '.join(required)}"
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
                "program": _PROJECT_PROGRAM,
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
                       "exactly one of bytes, string, constant, or pointer. Matches can overlap. Strings are tried "
                       "in every text encoding of the export's platform (PETSCII and screen codes on the C64, "
                       "high-bit ASCII on the Apple II, ATASCII and screen codes on Atari 8-bit, Shift-JIS on "
                       "Japanese machines). A pointer search finds stored DOS near and far pointers, 68k longs, "
                       "or 6502 and Z80 words holding an address, and marks relocation-backed hits. Request "
                       "absolute-short for 68k short addresses or split for 6502 split table candidates.",
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
                "pointer": {"type": "string", "minLength": 1,
                            "description": "find stored pointers to this unit:offset, seg:off, or hex address"},
                "pointer_kinds": {"type": "array", "minItems": 1, "items": {"enum": list(POINTER_KINDS)},
                                  "description": "only these pointer kinds. DOS: far, near. Flat: absolute. "
                                                 "68k: absolute-short. 6502: split."},
                "encoding": {"enum": list(ENCODINGS),
                             "description": "string encoding (default: every encoding of the export's platform)"},
                "ignore_case": {"type": "boolean", "description": "match strings in either letter case"},
            },
            "required": ["export"],
            "additionalProperties": False,
        },
    }


_EXPORT = {"type": "string", "minLength": 1, "description": "directory from retrore load"}
_ADDRESS_TEXT = {"type": "string", "minLength": 1, "description": "unit:offset, seg:off, or hexadecimal address"}


def _relocations_tool() -> dict:
    return {
        "name": "relocations",
        "title": "retrore relocs",
        "description": "List loader relocations in an export from `retrore load`, as `retrore relocs --json` "
                       "does. DOS relocations patch segment words; 68k relocations patch longs. Filter by unit, "
                       "site range (at and size), or target (DOS: same segment; 68k: value in [target, +size)).",
        "inputSchema": {
            "$schema": DIALECT,
            "type": "object",
            "properties": {
                "export": _EXPORT, "unit": {"type": "string", "minLength": 1, "description": "unit name"},
                "at": _ADDRESS_TEXT, "target": _ADDRESS_TEXT,
                "size": {"type": "integer", "minimum": 1, "description": "range size in bytes for at and target"},
                "limit": {"type": "integer", "minimum": 1, "description": "maximum relocations"},
                "offset": {"type": "integer", "minimum": 0, "description": "skip this many after filtering"},
            },
            "required": ["export"],
            "additionalProperties": False,
        },
    }


def _lookup_tool() -> dict:
    return {
        "name": "lookup",
        "title": "retrore lookup",
        "description": "Look up names from an export's map.json without Ghidra, as `retrore lookup --json` does: "
                       "unit symbols, entry points, overlay entries and stubs, runtime signatures, hardware "
                       "labels, and memory regions. Give a name (exact, or * and ? pattern) or an address to get "
                       "the nearest symbol at or below it.",
        "inputSchema": {
            "$schema": DIALECT,
            "type": "object",
            "properties": {
                "export": _EXPORT,
                "name": {"type": "string", "minLength": 1, "description": "exact name or * and ? pattern"},
                "address": _ADDRESS_TEXT,
                "ignore_case": {"type": "boolean", "description": "match names ignoring case"},
                "limit": {"type": "integer", "minimum": 1, "description": "maximum symbols for a name search"},
            },
            "required": ["export"],
            "additionalProperties": False,
        },
    }


_EXPORT_EVIDENCE = {
    "bytes": ("Read initialized bytes before and after loader edits", {
        "size": {"type": "integer", "minimum": 1, "maximum": MAX_BYTES, "default": 32},
        "source_file": {"type": "string", "minLength": 1, "description": "Original unpacked DOS MZ file"},
    }),
    "address_map": ("Map a location across the address spaces of an export", {
        "space": {"type": "string", "enum": list(ADDRESS_SPACES), "default": "logical"},
        "source": {"type": "string", "minLength": 1},
        "member": {"type": "string", "minLength": 1},
        "offset_kind": {"type": "string", "enum": list(FILE_OFFSET_KINDS)},
        "source_file": {"type": "string", "minLength": 1, "description": "Original unpacked DOS MZ file"},
        "runtime_base": {"type": "string", "pattern": "^[a-fA-F0-9]{1,4}$"},
        "overlay_segments": {"type": "array", "items": {"type": "string"},
                             "description": "DOS overlay placements as UNIT=HEX"},
        "runtime_loads": {"type": "array", "items": {"type": "string"},
                          "description": "Linear runtime placements as UNIT=HEX or UNIT=unmapped"},
    }),
}


def _evidence_tool(name: str) -> dict:
    description, properties = _EXPORT_EVIDENCE[name]
    return {"name": name, "title": f"retrore {name.replace('_', '-')}", "description": description + ".",
            "inputSchema": {"$schema": DIALECT, "type": "object",
                            "properties": {"export": _EXPORT, "address": _ADDRESS_TEXT, **properties},
                            "required": ["export", "address"], "additionalProperties": False}}


class _ToolParser(argparse.ArgumentParser):
    """An argument parser that reports errors as invalid tool arguments instead of exiting."""

    def error(self, message: str) -> None:
        raise InvalidArguments(message)


_PROGRAM_TOOLS = {
    "info": "Summarize a program image, as `retrore info --json` does: detect the format, load the program "
            "and any selected disk members, overlays, units, or sectors, and return the program map.",
    "load": "Export a program image, as `retrore load --json` does: write image.bin and map.json to a new "
            "output directory and return the program map. Existing files are never overwritten.",
}


def _program_parser(command: str) -> _ToolParser:
    parser = _ToolParser(prog=f"retrore {command}", parents=[program_options()], add_help=False)
    if command == "load":
        parser.add_argument("-o", "--output", type=Path, required=True, metavar="OUT",
                            help="new or empty directory for image.bin and map.json")
    return parser


def _option_name(action: argparse.Action) -> str:
    if not action.option_strings:
        return action.dest
    return max(action.option_strings, key=len).lstrip("-").replace("-", "_")


def _option_schema(action: argparse.Action) -> dict:
    text = action.help or ""
    if action.metavar and not action.choices:
        text = f"{text} ({action.metavar})" if text else action.metavar
    if isinstance(action, argparse._StoreTrueAction):
        return {"type": "boolean", "description": text}
    value = {"type": "integer"} if action.type is int else {"type": "string"}
    if action.choices:
        value = {"enum": list(action.choices)}
    if isinstance(action, argparse._AppendAction):
        return {"type": "array", "items": value, "description": f"{text}; repeatable"}
    return {**value, "description": text}


def _program_tool(command: str) -> dict:
    properties, required = {}, []
    for action in _program_parser(command)._actions:
        name = _option_name(action)
        properties[name] = _option_schema(action)
        if action.required or not action.option_strings:
            required.append(name)
    properties["program"]["description"] = ("path to the executable, disk image, or raw file; relative paths "
                                            "resolve against the server's working directory")
    return {
        "name": command,
        "title": f"retrore {command}",
        "description": _PROGRAM_TOOLS[command] + " Option values use the CLI's text formats, such as hexadecimal "
                       "addresses and FILE@HEX.",
        "inputSchema": {"$schema": DIALECT, "type": "object", "properties": properties, "required": required,
                        "additionalProperties": False},
    }


def _program_argv(command: str, arguments: dict) -> list[str]:
    """Translate tool arguments into the CLI's argument list, so argparse applies the same checks."""
    actions = {_option_name(action): action for action in _program_parser(command)._actions}
    unknown = arguments.keys() - actions.keys()
    if unknown:
        raise InvalidArguments(f"unsupported options for {command}: {', '.join(sorted(unknown))}")
    options, positional = [], []
    for name, value in arguments.items():
        action = actions[name]
        if not action.option_strings:
            if not isinstance(value, str) or not value:
                raise InvalidArguments(f"{name} must be a nonempty path string")
            positional.append(value)
            continue
        flag = max(action.option_strings, key=len)
        if isinstance(action, argparse._StoreTrueAction):
            if type(value) is not bool:
                raise InvalidArguments(f"{name} must be a boolean")
            options += [flag] if value else []
            continue
        repeated = isinstance(action, argparse._AppendAction)
        if repeated and not isinstance(value, list):
            raise InvalidArguments(f"{name} must be a list")
        for item in value if repeated else [value]:
            if action.type is int and type(item) is int:
                item = str(item)
            if not isinstance(item, str):
                raise InvalidArguments(f"{name} must use {'integers' if action.type is int else 'strings'}")
            # FLAG=VALUE keeps a value that starts with "-" from being read as an option.
            options.append(f"{flag}={item}")
    return [*options, "--", *positional]


def _call_program(command: str, arguments: dict) -> dict:
    args = _program_parser(command).parse_args(_program_argv(command, arguments))
    args.command = command
    image, program_map, _ = build_program(args)
    if command == "load":
        _export_image(args.output, image, program_map)
    return program_map


def tools() -> list[dict]:
    """Return every tool definition in a stable order."""
    definitions = query_definitions()
    reserved = {"batch", "where_is", "relocations", "lookup", *_EXPORT_EVIDENCE, *_PROGRAM_TOOLS} & definitions.keys()
    if reserved:
        raise RuntimeError(f"query names collide with adapter tools: {', '.join(sorted(reserved))}")
    document = query_schema()
    return [*(_query_tool(command, definition, document) for command, definition in definitions.items()),
            _batch_tool(document), _where_is_tool(), _relocations_tool(), _lookup_tool(),
            *map(_evidence_tool, _EXPORT_EVIDENCE), *map(_program_tool, _PROGRAM_TOOLS)]


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


_project_locks: dict[Path, threading.Lock] = {}
_project_locks_guard = threading.Lock()


@contextlib.contextmanager
def _project_session(project: Path):
    """Wait for other calls on the same project, giving up if this call is cancelled meanwhile."""
    with _project_locks_guard:
        key = project.resolve()
        lock = _project_locks.setdefault(key.with_name(key.name.removesuffix(".gpr")), threading.Lock())
    while not lock.acquire(timeout=0.2):
        check_cancelled("query")
    try:
        check_cancelled("query")
        yield
    finally:
        lock.release()


def _call_query(command: str, arguments: dict) -> dict:
    project, timeout = _project(arguments), _timeout(arguments, QUERY_TIMEOUT)
    program = _optional(arguments, "program", str)
    request = {name: value for name, value in arguments.items() if name not in ("project", "program", "timeout")}
    if "command" in request:
        raise InvalidArguments(f"the tool name selects the command; remove command from the {command} arguments")
    with _project_session(project):
        return query(project, {"command": command, **request}, timeout=timeout, program=program)


def _call_batch(arguments: dict) -> dict:
    unknown = arguments.keys() - {"project", "program", "requests", "timeout"}
    if unknown:
        raise InvalidArguments(f"unsupported options for batch: {', '.join(sorted(unknown))}")
    project, timeout = _project(arguments), _timeout(arguments, None)
    with _project_session(project):
        return query_batch(project, arguments.get("requests"), timeout=timeout,
                           program=_optional(arguments, "program", str))


def _export_arguments(tool: str, arguments: dict, allowed: set[str]) -> Path:
    unknown = arguments.keys() - {"export", *allowed}
    if unknown:
        raise InvalidArguments(f"unsupported options for {tool}: {', '.join(sorted(unknown))}")
    export = arguments.get("export")
    if not isinstance(export, str) or not export:
        raise InvalidArguments("export must be a nonempty path string")
    return Path(export)


def _optional(arguments: dict, name: str, kind: type) -> object:
    value = arguments.get(name)
    if value is not None and (type(value) is not kind or (kind is str and not value)):
        raise InvalidArguments(f"{name} must be a {'nonempty string' if kind is str else kind.__name__}")
    return value


def _call_where_is(arguments: dict) -> dict:
    export = _export_arguments("where_is", arguments, {
        "bytes", "string", "constant", "width", "pointer", "pointer_kinds", "encoding", "ignore_case"})
    if ("encoding" in arguments or arguments.get("ignore_case")) and "string" not in arguments:
        raise InvalidArguments("encoding and ignore_case require string")
    if "pointer_kinds" in arguments and "pointer" not in arguments:
        raise InvalidArguments("pointer_kinds requires pointer")
    if "pointer" in arguments:
        if any(name in arguments for name in ("bytes", "string", "constant", "width")):
            raise InvalidArguments("specify exactly one of bytes, string, constant, or pointer")
        kinds = arguments.get("pointer_kinds")
        if kinds is not None and (not isinstance(kinds, list) or not kinds
                                  or any(not isinstance(kind, str) for kind in kinds)):
            raise InvalidArguments("pointer_kinds must be a nonempty list of " + ", ".join(POINTER_KINDS))
        return find_pointers(export, _optional(arguments, "pointer", str), kinds=tuple(kinds) if kinds else None)
    if "string" in arguments and not any(name in arguments for name in ("bytes", "constant", "width")):
        return find_text(export, arguments["string"], encoding=_optional(arguments, "encoding", str),
                         ignore_case=bool(_optional(arguments, "ignore_case", bool)))
    pattern, width = search_pattern(hex_bytes=arguments.get("bytes"), string=arguments.get("string"),
                                    constant=arguments.get("constant"), width=arguments.get("width"))
    return find_bytes(export, pattern, width=width)


def _call_relocations(arguments: dict) -> dict:
    export = _export_arguments("relocations", arguments, {"unit", "at", "target", "size", "limit", "offset"})
    return find_relocations(
        export, unit=_optional(arguments, "unit", str), at=_optional(arguments, "at", str),
        target=_optional(arguments, "target", str), size=_optional(arguments, "size", int),
        limit=_optional(arguments, "limit", int), offset=_optional(arguments, "offset", int) or 0,
    )


def _call_lookup(arguments: dict) -> dict:
    export = _export_arguments("lookup", arguments, {"name", "address", "ignore_case", "limit"})
    return lookup_symbols(
        export, name=_optional(arguments, "name", str), address=_optional(arguments, "address", str),
        ignore_case=bool(_optional(arguments, "ignore_case", bool)), limit=_optional(arguments, "limit", int),
    )


def _call_evidence(name: str, arguments: dict) -> dict:
    export = _export_arguments(name, arguments, {"address", *_EXPORT_EVIDENCE[name][1]})
    address = _optional(arguments, "address", str)
    if address is None:
        raise InvalidArguments("address is required")
    original = _optional(arguments, "source_file", str)
    source_file = Path(original) if original is not None else None
    if name == "bytes":
        size = _optional(arguments, "size", int)
        return inspect_bytes(export, address, size=32 if size is None else size, source_file=source_file)
    runtime_base = _optional(arguments, "runtime_base", str)
    segments = arguments.get("overlay_segments", [])
    if not isinstance(segments, list) or any(not isinstance(value, str) for value in segments):
        raise InvalidArguments("overlay_segments must be an array of UNIT=HEX assignments")
    loads = arguments.get("runtime_loads", [])
    if not isinstance(loads, list) or any(not isinstance(value, str) for value in loads):
        raise InvalidArguments("runtime_loads must be an array of UNIT=HEX or UNIT=unmapped assignments")
    try:
        base = _hex_segment(runtime_base) if runtime_base is not None else None
    except argparse.ArgumentTypeError as error:
        raise InvalidArguments(str(error)) from error
    return map_address(export, address, space=_optional(arguments, "space", str) or "logical",
                       source=_optional(arguments, "source", str), member=_optional(arguments, "member", str),
                       runtime_base=base, overlay_segments=_overlay_segments(segments),
                       runtime_loads=_runtime_loads(loads), source_file=source_file,
                       offset_kind=_optional(arguments, "offset_kind", str))


def call_tool(name: str, arguments: dict) -> dict:
    """Run a tool and return an MCP CallToolResult. Unknown tool names raise UnknownTool."""
    if name == "batch":
        run = _call_batch
    elif name == "where_is":
        run = _call_where_is
    elif name == "relocations":
        run = _call_relocations
    elif name == "lookup":
        run = _call_lookup
    elif name in _EXPORT_EVIDENCE:
        def run(arguments: dict) -> dict:
            return _call_evidence(name, arguments)
    elif name in _PROGRAM_TOOLS:
        def run(arguments: dict) -> dict:
            return _call_program(name, arguments)
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
        # Cancellation events of tool calls in progress, by request id.
        self.calls: dict[object, threading.Event] = {}
        self._calls_guard = threading.Lock()

    def begin_call(self, identifier: object) -> threading.Event | None:
        """Register a tool call in progress, or return None if its id is already in use."""
        with self._calls_guard:
            if identifier in self.calls:
                return None
            event = self.calls[identifier] = threading.Event()
            return event

    def end_call(self, identifier: object) -> None:
        with self._calls_guard:
            self.calls.pop(identifier, None)

    def handle(self, message: object) -> dict | None:
        """Return the response to one decoded message, or None for a notification."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            identifier = message.get("id") if isinstance(message, dict) else None
            if isinstance(message, dict) and "method" not in message and ("result" in message or "error" in message):
                return None  # A response to a request we never send; ignore it.
            return _error(identifier if _valid_id(identifier) else None, INVALID_REQUEST, "Invalid Request")
        if "id" not in message:
            self._notify(message["method"], message.get("params"))
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

    def _notify(self, method: str, params: object) -> None:
        # notifications/initialized needs no action. A cancelled call stops its headless Ghidra run.
        if method == "notifications/cancelled" and isinstance(params, dict):
            with self._calls_guard:
                event = self.calls.get(params.get("requestId"))
            if event is not None:
                event.set()

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


def _is_tool_call(message: object) -> bool:
    return (isinstance(message, dict) and message.get("jsonrpc") == "2.0" and message.get("method") == "tools/call"
            and _valid_id(message.get("id")))


def serve(stdin: IO[bytes] | None = None, stdout: IO[str] | None = None,
          workers: int = MAX_CONCURRENT_CALLS, *, use_worker: bool = True) -> int:
    """Serve newline-delimited JSON-RPC on stdio until stdin closes and calls in progress finish.

    Tool calls run on worker threads and may answer out of order; other messages are answered in order.
    A call cancelled with notifications/cancelled stops its headless Ghidra run and sends no response.
    With use_worker, each project's queries go to one persistent Ghidra worker that stays open between
    calls (see retrore.worker); it stops after the idle timeout and when the server exits.
    """
    with contextlib.ExitStack() as stack:
        if use_worker:
            stack.enter_context(worker.hosting("mcp"))
            stack.enter_context(_exit_on_termination())
        return _serve(stdin, stdout, workers)


@contextlib.contextmanager
def _exit_on_termination():
    """Turn SIGTERM and SIGHUP into SystemExit so the server stops its workers before exiting."""
    previous = {}
    if threading.current_thread() is threading.main_thread() and hasattr(signal, "SIGHUP"):
        for number in (signal.SIGTERM, signal.SIGHUP):
            if signal.getsignal(number) is signal.SIG_DFL:
                previous[number] = signal.signal(number, _exit_on_signal)
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _exit_on_signal(number: int, frame: object) -> None:
    raise SystemExit(128 + number)


def _serve(stdin: IO[bytes] | None, stdout: IO[str] | None, workers: int) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout
    server = Server()
    output = threading.Lock()

    def write(response: dict) -> None:
        with output:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()

    def run(message: dict, event: threading.Event) -> None:
        try:
            with cancellable(event):
                response = server.handle(message)
        finally:
            server.end_call(message["id"])
        if not event.is_set():
            write(response)

    # Only protocol messages may reach stdout; anything else printed during a call goes to stderr.
    with contextlib.redirect_stdout(sys.stderr), ThreadPoolExecutor(workers, "retrore-mcp") as pool:
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except (UnicodeError, ValueError):
                response = _error(None, PARSE_ERROR, "Parse error")
            else:
                if _is_tool_call(message):
                    event = server.begin_call(message["id"])
                    if event is not None:
                        pool.submit(run, message, event)
                        continue
                    response = _error(message["id"], INVALID_REQUEST, "request id is already in use by a call "
                                                                      "in progress")
                else:
                    response = (_error(None, INVALID_REQUEST, "JSON-RPC batches are not supported")
                                if isinstance(message, list) else server.handle(message))
            if response is not None:
                write(response)
    return 0
