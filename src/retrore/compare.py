"""Compare functions from two read-only Ghidra listings."""

from collections import defaultdict
from pathlib import Path

from . import ghidra

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
_CANDIDATE_LIMIT = 8
_EVIDENCE_LIMIT = 8
_MIN_BODY_INSTRUCTIONS = 3


def compare_projects(before: Path, after: Path, *, before_program: str = "image.bin",
                     after_program: str = "image.bin", limit: int = DEFAULT_LIMIT, offset: int = 0,
                     timeout: float | None = ghidra.QUERY_TIMEOUT) -> dict:
    """Read the projects and report exact normalized bodies and reviewable match candidates."""
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise ghidra.GhidraError(f"limit must be between 1 and {MAX_LIMIT}")
    if type(offset) is not int or offset < 0:
        raise ghidra.GhidraError("offset must be nonnegative")
    ghidra._check_program_name(before_program)
    ghidra._check_program_name(after_program)
    ghidra._require_project(before)
    ghidra._require_project(after)
    first = ghidra._query_json(before, "fingerprints", {}, timeout=timeout, program=before_program)
    second = (first if ghidra._project_parts(before) == ghidra._project_parts(after)
              and before_program == after_program else
              ghidra._query_json(after, "fingerprints", {}, timeout=timeout, program=after_program))
    return _compare(first, second, limit, offset)


def _stable_name(function: dict) -> str | None:
    name = (function["stable_name"] or "").lstrip("_")
    return name if name and not name.startswith(("FUN_", "LAB_", "thunk_FUN_")) else None


def _fingerprint(function: dict) -> str | None:
    return function["fingerprint"] if function["instructions"] >= _MIN_BODY_INSTRUCTIONS else None


def _index(functions: dict, key) -> dict:
    groups = defaultdict(list)
    for identifier, function in functions.items():
        signature = key(function)
        if signature is not None:
            groups[signature].append(identifier)
    return groups


def _contexts(functions: dict, anchors: dict) -> dict:
    callers = defaultdict(set)
    for identifier, function in functions.items():
        for callee in function["calls"]:
            callers[callee].add(identifier)

    def names(ids):
        known = set()
        for identifier in ids:
            if identifier in anchors:
                known.add("match:" + anchors[identifier])
            elif identifier in functions and (name := _stable_name(functions[identifier])):
                known.add("name:" + name)
        return known

    return {
        identifier: (
            frozenset(names(callers[identifier] - {identifier})),
            frozenset(names(set(function["calls"]) - {identifier}) | {
                "external:" + name for name in function["external_calls"]}),
            frozenset(function["data"]),
        ) for identifier, function in functions.items()
    }


def _context_key(context):
    callers, callees, data = context
    # Shared data by itself can name a whole subsystem. Require call evidence and at least two facts.
    return context if (callers or callees) and len(callers) + len(callees) + len(data) >= 2 else None


def _routine(function: dict) -> dict:
    return {name: function[name] for name in ("name", "address", "unit", "offset", "instructions")}


def _compare(before: dict, after: dict, limit: int, offset: int) -> dict:
    same_language = before["language"] == after["language"]
    first = {function["id"]: function for function in before["functions"]}
    second = {function["id"]: function for function in after["functions"]}
    left, right = dict(first), dict(second)
    pairs = {}

    def pair_unique(left_key, right_key, matched_by):
        left_index, right_index = _index(left, left_key), _index(right, right_key)
        for signature, identifiers in left_index.items():
            candidates = right_index.get(signature, ())
            if len(identifiers) == len(candidates) == 1:
                source, destination = identifiers[0], candidates[0]
                pairs[source] = destination, matched_by
                del left[source]
                del right[destination]

    pair_unique(_stable_name, _stable_name, "symbol")
    if same_language:
        if before["sha256"] and before["sha256"] == after["sha256"]:
            def source_location(function):
                if function["unit"] is not None and function["instructions"]:
                    return function["unit"], function["offset"], function["fingerprint"]
                return None

            pair_unique(source_location, source_location, "same_executable_location")
        pair_unique(_fingerprint, _fingerprint, "normalized_instructions")

    def contexts():
        return _contexts(first, {identifier: identifier for identifier in pairs}), _contexts(
            second, {destination: source for source, (destination, _) in pairs.items()})

    left_context, right_context = contexts()
    # Distinguish identical bodies using known neighbors, then suggest changed ones by context alone.
    if same_language:
        def body_context(function, side):
            context = _context_key(side[function["id"]])
            return (function["fingerprint"], context) if function["instructions"] and context else None

        pair_unique(lambda function: body_context(function, left_context),
                    lambda function: body_context(function, right_context), "instructions_and_context")
        left_context, right_context = contexts()
    pair_unique(lambda function: _context_key(left_context[function["id"]]),
                lambda function: _context_key(right_context[function["id"]]), "call_graph_and_data")
    left_context, right_context = contexts()

    matches = []
    counts = {"same_body": 0, "changed_candidate": 0, "cross_port_candidate": 0, "unverified_candidate": 0}
    for source, original in first.items():
        if source not in pairs:
            continue
        destination, matched_by = pairs[source]
        revised = second[destination]
        comparable = same_language and bool(original["instructions"]) and bool(revised["instructions"])
        if comparable:
            status = "same_body" if original["fingerprint"] == revised["fingerprint"] else "changed_candidate"
        else:
            status = "unverified_candidate" if same_language else "cross_port_candidate"
        counts[status] += 1
        old_context, new_context = left_context[source], right_context[destination]
        shared = {}
        differences = []
        for kind, old, new in zip(("callers", "callees", "data"), old_context, new_context):
            overlap = sorted(old & new)
            shared[kind] = {"count": len(overlap), "examples": overlap[:_EVIDENCE_LIMIT]}
            if old != new:
                differences.append(kind)
        before_name, after_name = _stable_name(original), _stable_name(revised)
        if before_name != after_name and before_name and after_name:
            differences.append("symbol")
        matches.append({"before": _routine(original), "after": _routine(revised), "status": status,
                        "matched_by": matched_by, "evidence": {
                            "before_fingerprint": original["fingerprint"],
                            "after_fingerprint": revised["fingerprint"],
                            "same_raw_instruction_bytes": (comparable and
                                                           original["raw_sha256"] == revised["raw_sha256"]),
                            "shared": shared, "different_known_context": differences,
                        }})

    def unpaired(source: dict, target: dict, source_context: dict, target_context: dict) -> list[dict]:
        keys = [("symbol", _stable_name, _stable_name), ("call_graph_and_data",
            lambda function: _context_key(source_context[function["id"]]),
            lambda function: _context_key(target_context[function["id"]]),
        )]
        if same_language:
            keys.append(("normalized_instructions", _fingerprint, _fingerprint))
        groups = [(reason, key, _index(target, other)) for reason, key, other in keys]
        cached = {}
        rows = []
        for function in source.values():
            signatures = tuple(key(function) for _, key, _ in groups)
            if signatures not in cached:
                options = defaultdict(list)
                for signature, (reason, _, group) in zip(signatures, groups):
                    for identifier in group.get(signature, ()):
                        options[identifier].append(reason)
                cached[signatures] = {"candidate_count": len(options), "candidates": [
                    {**_routine(target[identifier]), "matched_by": options[identifier]}
                    for identifier in sorted(options)[:_CANDIDATE_LIMIT]
                ]}
            rows.append({**_routine(function), **cached[signatures]})
        return rows

    unpaired_before = unpaired(left, right, left_context, right_context)
    unpaired_after = unpaired(right, left, right_context, left_context)
    counts["unpaired_before"], counts["unpaired_after"] = len(unpaired_before), len(unpaired_after)
    counts["ambiguous_before"] = sum(row["candidate_count"] > 0 for row in unpaired_before)
    counts["ambiguous_after"] = sum(row["candidate_count"] > 0 for row in unpaired_after)
    report = {"comparison_version": 1}
    for side, listing in (("before", before), ("after", after)):
        report[side] = {key: listing[key] for key in ("program", "language", "sha256")} | {
            "function_count": len(listing["functions"])}
    report["counts"] = counts
    report["pagination"] = {}
    for key, rows in (("matches", matches), ("unpaired_before", unpaired_before), ("unpaired_after", unpaired_after)):
        page = rows[offset:offset + limit]
        report[key] = page
        report["pagination"][key] = {"offset": offset, "total": len(rows), "returned": len(page),
                                     "next_offset": offset + limit if offset + limit < len(rows) else None}
    return report
