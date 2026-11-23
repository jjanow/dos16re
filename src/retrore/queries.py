"""Definitions and validation for Ghidra project queries.

Every query command, its parameters, selectable fields, and hard caps live in ``QUERIES``. Validation,
the CLI, and ``retrore batch`` read from it, and ``query_definitions()`` returns it as plain data for
tools that generate request schemas. Parameter definitions use JSON Schema keywords.
"""

import copy
import re

MAX_INT = 0x7FFFFFFF
ADDRESS_PATTERN = r"(?:[^:]+:)?[0-9a-fA-F]{1,8}"
UNIT_PATTERN = r"[^:\s]{1,64}"
MAX_LOOKUPS = 256
MAX_DEPTH = 4


class QueryError(ValueError):
    """A query request does not match its definition."""


def _address(description="hexadecimal unit:offset, seg:off, or flat address"):
    return {"type": "string", "format": "address", "pattern": ADDRESS_PATTERN, "description": description}


def _integer(minimum, maximum, description, default=None):
    definition = {"type": "integer", "minimum": minimum, "maximum": maximum, "description": description}
    if default is not None:
        definition["default"] = default
    return definition


def _paging(maximum=MAX_INT, default=None, items="references per list"):
    return {
        "limit": _integer(1, maximum, f"maximum {items}", default),
        "offset": _integer(0, MAX_INT, f"skip this many {items} after filtering", 0 if default else None),
    }


_COMPACT = {"type": "boolean", "default": False,
            "description": "return addresses as unit:offset strings where available"}
_UNIT_FILTER = {"type": "string", "pattern": UNIT_PATTERN, "description": "restrict results to one unit"}
_REFERENCE_OPTIONS = {
    **_paging(),
    "ref_types": {"type": "array", "minItems": 1,
                  "items": {"type": "string", "pattern": "[A-Za-z][A-Za-z0-9_]*"},
                  "description": "keep exact Ghidra reference types, ignoring case"},
    "compact": _COMPACT,
}

QUERIES = {
    "decomp": {
        "description": "decompile a function in a Ghidra project",
        "parameters": {
            "address": {**_address(), "required": True},
            "context": _integer(0, 20, "C lines around the selected instruction"),
            "slice": _integer(1, 128, "backward p-code operations from the selected instruction"),
        },
        "fields": ["address", "unit_address", "linear", "name", "decompilation"],
        "conditional_fields": {"context": ["excerpt", "focus"], "slice": ["slice", "focus"]},
        "fields_scope": "result",
        "echo": ["address"],
    },
    "xrefs": {
        "description": "list references to and from an address",
        "parameters": {
            "address": {**_address(), "required": True},
            **_REFERENCE_OPTIONS,
            "direction": {"type": "string", "enum": ["incoming", "outgoing", "both"], "default": "both",
                          "description": "select reference direction"},
        },
        "fields": ["address", "incoming", "outgoing"],
        "fields_scope": "result",
        "echo": ["address"],
    },
    "callers": {
        "description": "list calls to a function",
        "parameters": {"address": {**_address(), "required": True}, **_REFERENCE_OPTIONS},
        "fields": ["function", "callers"],
        "fields_scope": "result",
        "echo": ["address"],
    },
    "callees": {
        "description": "list calls made by a function",
        "parameters": {"address": {**_address(), "required": True}, **_REFERENCE_OPTIONS},
        "fields": ["function", "callees"],
        "fields_scope": "result",
        "echo": ["address"],
    },
    "func": {
        "description": "report a function's bounds, segment context, and callers",
        "parameters": {"address": {**_address(), "required": True}, **_REFERENCE_OPTIONS},
        "fields": ["function", "ranges", "size", "address", "segments", "callers"],
        "fields_scope": "result",
        "echo": ["address"],
    },
    "functions": {
        "description": "look up functions by address or name",
        "parameters": {
            "addresses": {"type": "array", "maxItems": MAX_LOOKUPS, "items": _address(),
                          "description": "addresses inside the functions to report"},
            "names": {"type": "array", "maxItems": MAX_LOOKUPS,
                      "items": {"type": "string", "minLength": 1, "maxLength": 256},
                      "description": "exact function names"},
            **_paging(MAX_LOOKUPS, MAX_LOOKUPS, "lookup rows"),
            "compact": _COMPACT,
        },
        "any_of": [["addresses", "names"]],
        "max_total_items": {"keys": ["addresses", "names"], "maximum": MAX_LOOKUPS},
        "fields": ["name", "entry", "ranges", "size", "prototype", "calling_convention"],
        "fields_scope": "record",
        "echo": [],
    },
    "symbols": {
        "description": "find symbols by exact name, prefix, or glob",
        "parameters": {
            "name": {"type": "string", "minLength": 1, "maxLength": 256, "description": "exact symbol name"},
            "prefix": {"type": "string", "minLength": 1, "maxLength": 256, "description": "symbol name prefix"},
            "glob": {"type": "string", "minLength": 1, "maxLength": 256,
                     "description": "symbol name pattern using * and ?"},
            "unit": _UNIT_FILTER,
            "ignore_case": {"type": "boolean", "default": False, "description": "match names ignoring case"},
            "generated": {"type": "boolean", "default": False,
                          "description": "also match Ghidra's generated names for referenced addresses "
                                         "without a stored symbol, such as DAT_, LAB_, and SUB_"},
            **_paging(1000, 100, "symbols"),
            "compact": _COMPACT,
        },
        "one_of": [["name", "prefix", "glob"]],
        "fields": ["name", "address", "kind", "source", "namespace"],
        "fields_scope": "record",
        "echo": ["name", "prefix", "glob", "unit"],
    },
    "inventory": {
        "description": "list the functions, labels, and defined data in one unit",
        "parameters": {
            "unit": {"type": "string", "pattern": UNIT_PATTERN, "required": True, "description": "unit name"},
            **_paging(1000, 100, "records per list"),
            "compact": _COMPACT,
        },
        "fields": ["unit", "functions", "labels", "data"],
        "fields_scope": "result",
        "echo": ["unit"],
    },
    "callgraph": {
        "description": "walk callers or callees from a function",
        "parameters": {
            "address": {**_address(), "required": True},
            "direction": {"type": "string", "enum": ["callers", "callees"], "default": "callees",
                          "description": "walk toward callers or callees"},
            "depth": _integer(1, MAX_DEPTH, "maximum call depth from the root", 2),
            "max_nodes": _integer(1, 512, "stop adding functions after this many, including the root", 128),
            **_paging(512, 128, "nodes and edges per list"),
            "compact": _COMPACT,
        },
        "fields": ["root", "nodes", "edges", "unresolved", "truncated"],
        "fields_scope": "result",
        "echo": ["address"],
    },
    "context": {
        "description": "report a function's prototype, callees, and referenced data",
        "parameters": {
            "address": {**_address(), "required": True},
            **_paging(256, 32, "parameters, callees, and data references per list"),
            "compact": _COMPACT,
        },
        "fields": ["function", "prototype", "calling_convention", "return_type", "parameters", "callees", "data"],
        "fields_scope": "result",
        "echo": ["address"],
    },
    "gaps": {
        "description": "report undefined ranges in executable units",
        "parameters": {
            "unit": _UNIT_FILTER, **_paging(1000, 100, "ranges"),
            "classify": {"type": "boolean", "default": False,
                         "description": "score each range as likely code, data, or padding and list the evidence"},
        },
        "fields": ["unit", "size", "linear", "start", "end"],
        "conditional_fields": {"classify": ["class", "code_score", "data_score", "conflict", "entry", "evidence",
                                            "counts"]},
        "fields_scope": "record",
        "echo": ["unit"],
    },
    "coverage": {
        "description": "summarize instruction, data, and undefined bytes per unit",
        "parameters": {"unit": _UNIT_FILTER, **_paging(1000, 100, "units"), "compact": _COMPACT},
        "fields": ["unit", "start", "size", "initialized", "execute", "functions",
                   "instruction_bytes", "data_bytes", "undefined_bytes"],
        "fields_scope": "record",
        "echo": ["unit"],
    },
    "indirect": {
        "description": "list indirect calls and jumps with their proved targets, or candidate table entries "
                       "and the evidence for each",
        "parameters": {
            "unit": _UNIT_FILTER,
            "at": _address("report only the indirect instruction at this address"),
            "status": {"type": "string", "enum": ["resolved", "candidate", "unresolved"],
                       "description": "keep sites with this status"},
            **_paging(1000, 100, "sites"),
            "compact": _COMPACT,
        },
        "fields": ["address", "function", "instruction", "kind", "status", "targets", "table", "segment",
                   "candidates", "stop", "reason"],
        "fields_scope": "record",
        "echo": ["unit", "at"],
    },
}

# Messages kept from the original validator.
_MESSAGES = {"ref_types": "ref_types must be a nonempty list of Ghidra reference type names"}


def query_definitions() -> dict:
    """Return a copy of every query definition as plain JSON-compatible data."""
    return copy.deepcopy(QUERIES)


def query_names() -> list[str]:
    return list(QUERIES)


def option_names() -> list[str]:
    """Return every optional parameter name used by any query."""
    names = []
    for definition in QUERIES.values():
        for name, parameter in definition["parameters"].items():
            if not parameter.get("required") and name not in names:
                names.append(name)
    return names


def _either(values: list[str], conjunction: str = "or") -> str:
    if len(values) <= 2:
        return f" {conjunction} ".join(values)
    return f"{', '.join(values[:-1])}, {conjunction} {values[-1]}"


def _fields_allowed(definition: dict, request: dict) -> set[str]:
    allowed = set(definition["fields"])
    for option, extra in definition.get("conditional_fields", {}).items():
        if option in request:
            allowed.update(extra)
    return allowed


def _check_integer(name: str, parameter: dict, value: object) -> None:
    minimum, maximum = parameter["minimum"], parameter["maximum"]
    if type(value) is not int or not minimum <= value <= maximum:
        raise QueryError(f"{name} must be an integer between {minimum} and {maximum}")


def _check_string(name: str, parameter: dict, value: object) -> None:
    if parameter.get("format") == "address":
        if not isinstance(value, str):
            raise QueryError(f"{name} must be a string")
        if not re.fullmatch(ADDRESS_PATTERN, value):
            raise QueryError("expected a hexadecimal unit:offset, seg:off, or flat address")
        return
    if "enum" in parameter:
        if value not in parameter["enum"]:
            raise QueryError(f"{name} must be {_either(parameter['enum'])}")
        return
    if not isinstance(value, str):
        raise QueryError(f"{name} must be a string")
    if "pattern" in parameter and not re.fullmatch(parameter["pattern"], value):
        raise QueryError(f"{name} must match {parameter['pattern']}")
    if not parameter.get("minLength", 0) <= len(value) <= parameter.get("maxLength", MAX_INT):
        raise QueryError(f"{name} must have {parameter.get('minLength', 0)} to "
                         f"{parameter.get('maxLength', MAX_INT)} characters")


def _check_array(name: str, parameter: dict, value: object) -> None:
    items = parameter["items"]
    if not isinstance(value, list) or len(value) < parameter.get("minItems", 0):
        raise QueryError(_MESSAGES.get(name, f"{name} must be a list"))
    if len(value) > parameter.get("maxItems", MAX_INT):
        raise QueryError(f"{name} accepts at most {parameter['maxItems']} items")
    for item in value:
        if name in _MESSAGES:
            if not isinstance(item, str) or not re.fullmatch(items["pattern"], item):
                raise QueryError(_MESSAGES[name])
        else:
            _check_string(f"each {name} item", items, item)


def validate_query(request: object) -> None:
    """Raise QueryError unless request matches a query definition."""
    if not isinstance(request, dict) or "command" not in request:
        raise QueryError("expected a query object with a command")
    command = request["command"]
    if not isinstance(command, str) or command not in QUERIES:
        raise QueryError(f"command must use {_either(list(QUERIES))}")
    definition = QUERIES[command]
    parameters = definition["parameters"]
    required = [name for name, parameter in parameters.items() if parameter.get("required")]
    if not set(required) <= request.keys():
        raise QueryError(f"expected a query object with command and {_either(required, 'and')}")

    # Check order follows the original validator so that existing messages stay the same.
    for name in required:
        if parameters[name]["type"] == "string":
            _check_string(name, parameters[name], request[name])
    for name, parameter in parameters.items():
        if parameter["type"] == "integer" and name not in ("limit", "offset") and name in request:
            _check_integer(name, parameter, request[name])
    unknown = request.keys() - {"command", "fields", *parameters}
    if unknown:
        raise QueryError(f"unsupported options for {command}: {', '.join(sorted(unknown))}")
    if "fields" in request:
        fields, allowed = request["fields"], _fields_allowed(definition, request)
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(field, str) or field not in allowed for field in fields)):
            raise QueryError(f"fields for {command} must be a nonempty list chosen from {', '.join(sorted(allowed))}")
    ordered = sorted(
        (name for name in parameters if name in request and name not in required),
        key=lambda name: ({"string": 0, "array": 1, "boolean": 2}.get(parameters[name]["type"], 3),
                          name != "offset"),
    )
    for name in ordered:
        parameter, value = parameters[name], request[name]
        if parameter["type"] == "string":
            _check_string(name, parameter, value)
        elif parameter["type"] == "array":
            _check_array(name, parameter, value)
        elif parameter["type"] == "boolean":
            if type(value) is not bool:
                raise QueryError(f"{name} must be a boolean")
        else:
            _check_integer(name, parameter, value)

    for group in definition.get("one_of", []):
        present = [name for name in group if name in request]
        if len(present) != 1:
            raise QueryError(f"{command} requires exactly one of {_either(group)}")
    for group in definition.get("any_of", []):
        if not any(request.get(name) for name in group):
            raise QueryError(f"{command} requires {_either(group)}")
    total = definition.get("max_total_items")
    if total and sum(len(request.get(name, [])) for name in total["keys"]) > total["maximum"]:
        raise QueryError(f"{command} accepts at most {total['maximum']} {_either(total['keys'], 'and')} in total")


def normalize_query(request: dict) -> dict:
    """Return a validated request with parameter defaults applied."""
    validate_query(request)
    normalized = dict(request)
    for name, parameter in QUERIES[request["command"]]["parameters"].items():
        if "default" in parameter:
            normalized.setdefault(name, parameter["default"])
    return normalized


def echo(request: dict) -> dict:
    """Return the identifying request keys echoed in batch results."""
    return {name: request[name] for name in QUERIES[request["command"]]["echo"] if name in request}
