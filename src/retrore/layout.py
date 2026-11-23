"""Data layout recovery: text output for the layout query and its write-enabled apply run."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from . import ghidra, worker
from .errors import CONTRACT_VERSION
from .queries import QueryError, normalize_query

_FIELD_PREVIEW = 12


def apply_layout(project: Path, request: dict, *, timeout: float | None = ghidra.QUERY_TIMEOUT) -> dict:
    """Run the layout query in a writable headless session and apply the proposed type.

    Queries and workers open projects read-only, so applying stops the project's worker first and then
    saves the program when the script finishes. The result is the layout report plus an "applied" record.
    """
    try:
        normalized = normalize_query(request)
    except QueryError as error:
        raise ghidra.GhidraError(str(error)) from error
    if normalized["command"] != "layout":
        raise ghidra.GhidraError("only the layout query can be applied")
    ghidra._require_project(project)
    worker.stop(project)
    with TemporaryDirectory() as temp:
        input_file = Path(temp) / "input.json"
        input_file.write_text(json.dumps({**normalized, "apply": True}), encoding="utf-8")
        report = ghidra._run(project, ["-process", "image.bin", "-noanalysis"], "RetroreQuery.java", "single",
                             str(input_file), timeout=timeout)
    return {"contract": CONTRACT_VERSION, **report}


def layout_lines(report: dict) -> list[str]:
    """Short text for a layout report: the inferred shape, its evidence, and conflicts."""
    lines = []
    layout = report.get("layout")
    if layout is not None:
        shape = layout["kind"]
        if layout["element_size"] is not None:
            count = layout["count"] if layout["count"] is not None else "?"
            shape += f"  {count} x 0x{layout['element_size']:x} bytes"
        lines.append(f"{shape}  ({report.get('size', '?')} bytes, {layout['size_source']})")
        if layout["count_source"]:
            lines.append(f"count from {layout['count_source']}")
        if layout["initial_text"]:
            lines.append(f"initial text {layout['initial_text']!r}")
        for field in layout["fields"][:_FIELD_PREVIEW]:
            widths = "/".join(str(width) for width in field["widths"])
            inner = f"  inner stride {','.join(map(str, field['inner_strides']))}" if field["inner_strides"] else ""
            if field.get("bulk"):
                inner += f"  {field['bulk']} in block loops"
            lines.append(f"  +0x{field['offset']:04x}  width {widths}  {field['reads']} reads  "
                         f"{field['writes']} writes{inner}")
        if len(layout["fields"]) > _FIELD_PREVIEW:
            lines.append("  Use --json for every field.")
    for stride in report.get("strides", [])[:3]:
        notes = "; ".join(stride["evidence"][:2])
        lines.append(f"stride 0x{stride['stride']:x} in {stride['accesses']} accesses: {notes}")
    for conflict in report.get("conflicts", []):
        if conflict["kind"] == "widths":
            lines.append(f"conflict at +0x{conflict['offset']:04x}: widths {conflict['widths']}")
        else:
            lines.append(f"conflict at +0x{conflict['offset']:04x}: overlaps +0x{conflict['overlaps']:04x}")
    if "applied" in report:
        applied = report["applied"]
        lines.append(f"applied {applied['data_type']} ({applied['length']} bytes)")
    elif "proposal" in report:
        lines.append("proposal (apply with --apply):")
        lines.extend("  " + line for line in report["proposal"]["c"].splitlines())
    return lines
