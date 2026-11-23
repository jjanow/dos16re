"""JSON Schema for the query contract, generated from the query registry.

Nothing here is maintained by hand per command: every request schema comes from
``queries.query_definitions()`` and every known error code from ``errors.HINTS``. A new registry
entry appears in the schema, the CLI's `retrore schema`, and the MCP adapter without other changes.
"""

import copy

from .errors import CONTRACT_VERSION, HINTS
from .queries import query_definitions

DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ID = f"urn:retrore:query-contract:{CONTRACT_VERSION}"

# Registry keys that are not JSON Schema keywords and must not reach a property schema.
_REGISTRY_ONLY = ("required",)


def _anchored(pattern: str) -> str:
    # The registry matches whole strings; JSON Schema `pattern` searches, so anchor it.
    return f"^(?:{pattern})$"


def _property(parameter: dict) -> dict:
    schema = {key: value for key, value in parameter.items() if key not in _REGISTRY_ONLY}
    if "pattern" in schema:
        schema["pattern"] = _anchored(schema["pattern"])
    if "items" in schema:
        schema["items"] = _property(schema["items"])
    return schema


def _fields(definition: dict) -> tuple[dict, list[dict]]:
    """Return the `fields` property and the conditions that unlock conditional fields."""
    base = list(definition["fields"])
    unlocks: dict[str, list[str]] = {}
    for option, extra in definition.get("conditional_fields", {}).items():
        for field in extra:
            if field not in base:
                unlocks.setdefault(field, []).append(option)
    scope = "each record" if definition["fields_scope"] == "record" else "the top-level result"
    schema = {
        "type": "array", "minItems": 1, "items": {"enum": base + list(unlocks)},
        "description": f"select fields of {scope}",
    }
    conditions = [
        {
            "if": {"required": ["fields"], "properties": {"fields": {"contains": {"const": field}}}},
            "then": {"anyOf": [{"required": [option]} for option in options]},
        }
        for field, options in unlocks.items()
    ]
    for field, options in unlocks.items():
        schema["description"] += f"; {field} requires {' or '.join(options)}"
    return schema, conditions


def request_schema(command: str, definition: dict) -> dict:
    """Return the JSON Schema of one query request."""
    parameters = definition["parameters"]
    required = [name for name, parameter in parameters.items() if parameter.get("required")]
    properties = {"command": {"const": command}}
    properties.update((name, _property(parameter)) for name, parameter in parameters.items())
    properties["fields"], conditions = _fields(definition)
    schema = {
        "title": f"{command} request",
        "description": definition["description"],
        "type": "object",
        "properties": properties,
        "required": ["command", *required],
        "additionalProperties": False,
    }
    for group in definition.get("one_of", []):
        conditions.append({"oneOf": [{"required": [name]} for name in group]})
    for group in definition.get("any_of", []):
        conditions.append({"anyOf": [
            {"required": [name], "properties": {name: {"minItems": 1}}} for name in group
        ]})
    if conditions:
        schema["allOf"] = conditions
    total = definition.get("max_total_items")
    if total:
        # JSON Schema cannot bound the sum of several array lengths; retrore enforces it on validation.
        schema["x-retrore-max-total-items"] = copy.deepcopy(total)
        schema["description"] += (f"; at most {total['maximum']} {' and '.join(total['keys'])} in total")
    return schema


def error_schema() -> dict:
    return {
        "title": "error",
        "description": "a coded error; branch on code, show message and hint to people",
        "type": "object",
        "properties": {
            "code": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$", "examples": sorted(HINTS),
                     "description": "stable machine-readable code; new codes may be added within a contract"},
            "message": {"type": "string"},
            "hint": {"type": ["string", "null"]},
        },
        "required": ["code", "message", "hint"],
    }


def query_schema() -> dict:
    """Return the complete JSON Schema document for query requests, batches, and errors."""
    definitions = query_definitions()
    defs = {f"{command}_request": request_schema(command, definition) for command, definition in definitions.items()}
    defs["request"] = {
        "title": "query request",
        "description": "one query request, discriminated by command",
        "oneOf": [{"$ref": f"#/$defs/{command}_request"} for command in definitions],
    }
    defs["batch"] = {
        "title": "batch request",
        "description": "an ordered array of query requests run in one Ghidra session",
        "type": "array", "minItems": 1,
        "items": {"$ref": "#/$defs/request"},
    }
    defs["error"] = error_schema()
    defs["error_report"] = {
        "title": "error report",
        "description": "the JSON a failed command prints to stderr with --json",
        "type": "object",
        "properties": {
            "contract": {"const": CONTRACT_VERSION},
            "error": {"$ref": "#/$defs/error"},
            "packer": {"type": "string"},
        },
        "required": ["contract", "error"],
    }
    return {
        "$schema": DIALECT,
        "$id": SCHEMA_ID,
        "title": "retrore query contract",
        "description": "A single query request or a batch of them. $defs holds each command's request, the batch "
                       "array, and the error objects.",
        "contract": CONTRACT_VERSION,
        "commands": {command: definition["description"] for command, definition in definitions.items()},
        "anyOf": [{"$ref": "#/$defs/request"}, {"$ref": "#/$defs/batch"}],
        "$defs": defs,
    }
