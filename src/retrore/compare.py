"""Compare functions from two read-only Ghidra listings."""

from collections import defaultdict
from pathlib import Path

from . import ghidra
from .storage_compare import storage_content_matches

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
_CANDIDATE_LIMIT = 8
_EVIDENCE_LIMIT = 8
_MIN_BODY_INSTRUCTIONS = 3


def compare_projects(before: Path, after: Path, *, before_program: str = "image.bin",
                     after_program: str = "image.bin", limit: int = DEFAULT_LIMIT, offset: int = 0,
                     storage: bool = False, instructions: bool = False, semantics: bool = False,
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
    request = {name: True for name, enabled in (("storage", storage), ("instructions", instructions),
                                                ("semantics", semantics)) if enabled}
    first = ghidra._query_json(before, "fingerprints", request, timeout=timeout, program=before_program)
    second = (first if ghidra._project_parts(before) == ghidra._project_parts(after)
              and before_program == after_program else
              ghidra._query_json(after, "fingerprints", request, timeout=timeout, program=after_program))
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


def _semantic_key(function: dict) -> tuple | None:
    profile = function.get("semantics")
    if not profile:
        return None
    operations, branches, constants = (profile[name] for name in ("operations", "branch_degrees", "constants"))
    if len(constants) < 2 or len(operations) < 3 or sum(operations.values()) < 4:
        return None
    return tuple(sorted(operations.items())), tuple(branches), tuple(constants)


def _routine(function: dict) -> dict:
    return {name: function[name] for name in ("name", "address", "unit", "offset", "instructions")}


def _storage_blocks(before: list[dict], after: list[dict]) -> list[dict]:
    first, second = (dict(enumerate(blocks)) for blocks in (before, after))
    old_names, new_names = (_index(side, lambda block: block["unit"]) for side in (first, second))

    def attributes(block):
        return tuple(block[key] for key in ("space", "type", "initialized", "read", "write", "execute"))

    def contents(block):
        if block.get("non_uniform", True) and (digest := block.get("content_sha256")):
            return attributes(block), block["size"], digest
        return None

    old_contents, new_contents = (_index(side, contents) for side in (first, second))
    fixed = {}

    for index, old in first.items():
        unit = old["unit"]
        if len(old_names[unit]) != 1:
            continue
        if unit in new_names:
            destinations = new_names[unit]
        else:
            signature = contents(old)
            if signature is None or len(old_contents[signature]) != 1:
                continue
            destinations = new_contents.get(signature, ())
        if len(destinations) != 1:
            continue
        new = after[destinations[0]]
        new_unit = new["unit"]
        if new_unit != unit and (new_unit in old_names or len(new_names[new_unit]) != 1):
            continue
        if attributes(old) != attributes(new):
            continue
        fixed[index] = destinations[0]

    rename_sources = {i for i, row in first.items() if row["unit"] not in new_names
                      and len(old_names[row["unit"]]) == 1 and i not in fixed}
    used = set(fixed.values())
    rename_destinations = {i for i, row in second.items() if row["unit"] not in old_names
                           and len(new_names[row["unit"]]) == 1 and i not in used}
    renamed, ranges = storage_content_matches(first, second, attributes, fixed, rename_sources, rename_destinations)
    matches = fixed | renamed
    pairs = []
    for index, old in first.items():
        if index not in matches:
            continue
        destination = matches[index]
        new = second[destination]
        unit, new_unit = old["unit"], new["unit"]
        pair = {"unit": unit, "space": old["space"], "size": old["size"],
                "before_start": old["start"], "after_start": new["start"]}
        if unit != new_unit or old["size"] != new["size"]:
            pair.update(after_unit=new_unit, after_size=new["size"])
        if (index, destination) in ranges:
            pair["ranges"] = ranges[index, destination]
            if pair["ranges"]:
                pair["after_sha256"] = new["content_sha256"]
        pairs.append(pair)
    return pairs


def _storage_offsets(before: list[int], after: list[int]) -> dict | None:
    # Normalized instructions compare in listing order. The two entries must also line up in that order.
    if len(before) != len(after) or 0 not in before or 0 not in after or before.index(0) != after.index(0):
        return None
    if before == after:
        return {"same": True}
    return {"before": before, "after": after}


def _instruction_map(before: dict, after: dict) -> list[dict]:
    first, second = before["instruction_sites"], after["instruction_sites"]
    old_entry, new_entry = ({"unit": row["unit"], "offset": row["offset"]} for row in (before, after))
    if (old_entry not in first or new_entry not in second or len(first) != len(second)
            or first.index(old_entry) != second.index(new_entry)):
        return []
    return [{"before": old, "after": new} for old, new in zip(first, second) if old is not None and new is not None]


def _compare(before: dict, after: dict, limit: int, offset: int) -> dict:
    same_language = before["language"] == after["language"]
    storage = ("storage_blocks" in before and "storage_blocks" in after and same_language
               and before["compiler"] == after["compiler"])
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
    if not same_language:
        pair_unique(_semantic_key, _semantic_key, "pcode_shape")
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
        if matched_by == "pcode_shape":
            matches[-1]["evidence"]["semantics"] = original["semantics"]
        if storage and status == "same_body":
            offsets = _storage_offsets(original["instruction_offsets"], revised["instruction_offsets"])
            if offsets is not None:
                matches[-1]["storage_offsets"] = offsets
        if (status == "same_body" and offset < len(matches) <= offset + limit
                and original.get("instruction_sites") is not None and revised.get("instruction_sites") is not None):
            instructions = _instruction_map(original, revised)
            if instructions:
                matches[-1]["instruction_map"] = instructions

    def unpaired(source: dict, target: dict, source_context: dict, target_context: dict) -> list[dict]:
        keys = [("symbol", _stable_name, _stable_name), ("call_graph_and_data",
            lambda function: _context_key(source_context[function["id"]]),
            lambda function: _context_key(target_context[function["id"]]),
        )]
        if same_language:
            keys.append(("normalized_instructions", _fingerprint, _fingerprint))
        else:
            keys.append(("pcode_shape", _semantic_key, _semantic_key))
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
            if not same_language and _semantic_key(function) is not None:
                rows[-1]["semantics"] = function["semantics"]
        return rows

    unpaired_before = unpaired(left, right, left_context, right_context)
    unpaired_after = unpaired(right, left, right_context, left_context)
    counts["unpaired_before"], counts["unpaired_after"] = len(unpaired_before), len(unpaired_after)
    counts["ambiguous_before"] = sum(row["candidate_count"] > 0 for row in unpaired_before)
    counts["ambiguous_after"] = sum(row["candidate_count"] > 0 for row in unpaired_after)
    report = {"comparison_version": 1}
    if storage:
        blocks = _storage_blocks(before["storage_blocks"], after["storage_blocks"])
        report["storage_blocks"] = blocks
        if any("ranges" in block for block in blocks):
            report["comparison_version"] = 3
        elif any("after_unit" in block for block in blocks):
            report["comparison_version"] = 2
    for side, listing in (("before", before), ("after", after)):
        report[side] = {key: listing[key] for key in ("program", "language", "sha256")} | {
            "function_count": len(listing["functions"])}
        if listing.get("semantics"):
            report[side]["semantic_profiles"] = sum(row.get("semantics") is not None for row in listing["functions"])
            report[side]["usable_semantic_profiles"] = sum(_semantic_key(row) is not None for row in listing["functions"])
    report["counts"] = counts
    report["pagination"] = {}
    for key, rows in (("matches", matches), ("unpaired_before", unpaired_before), ("unpaired_after", unpaired_after)):
        page = rows[offset:offset + limit]
        report[key] = page
        report["pagination"][key] = {"offset": offset, "total": len(rows), "returned": len(page),
                                     "next_offset": offset + limit if offset + limit < len(rows) else None}
    return report
