"""Map exported locations back to their loader inputs and inspect initialized bytes."""

from functools import cached_property
from hashlib import sha256
from pathlib import Path

from .ghidra import GhidraError, query_batch
from .image import M68K_FORMATS, ImageError, ImageUnit, image_units, read_map
from .mz import Address
from .search import SearchError, resolve_address
from .trace import _runtime_units

ADDRESS_SPACES = ("logical", "linear", "runtime", "image", "file")
MAX_BYTES = 4096


class EvidenceError(ValueError):
    """An invalid address mapping or byte request."""


class ExportEvidence:
    def __init__(self, export: Path, runtime_base: int | None = None, overlay_segments: dict | None = None):
        self.image = (export / "image.bin").read_bytes()
        self.program = read_map(export)
        self.units = image_units(self.program, len(self.image))
        self.records = {record["name"]: record for record in self.program["units"]}
        self.format = self.program.get("format", "MZ")
        if self.format == "MZ":
            self.runtime = {unit.name: start for start, unit in
                            _runtime_units(self.units, runtime_base, overlay_segments or {})}
        else:
            if runtime_base is not None or overlay_segments:
                raise EvidenceError("runtime segment overrides require a DOS MZ export")
            self.runtime = {unit.name: unit.linear for unit in self.units}

    def file_spans(self, unit: ImageUnit) -> list[dict]:
        record = self.records[unit.name]
        if "file_spans" in record:
            spans = record["file_spans"]
        else:
            offset = record.get("file_offset")
            if self.format == "MZ" and unit.name != "root" and "file_offset" not in record:
                offset = 0
            spans = [] if offset is None or unit.file_size == 0 else [
                {"offset": 0, "file_offset": offset, "size": unit.file_size},
            ]
        if not isinstance(spans, list):
            raise ImageError(f"invalid file spans for unit {unit.name}")
        end = 0
        for span in spans:
            if not isinstance(span, dict):
                raise ImageError(f"invalid file span for unit {unit.name}")
            start, offset, size = (span.get(key) for key in ("offset", "file_offset", "size"))
            if (any(type(value) is not int for value in (start, offset, size))
                    or start < end or offset < 0 or size <= 0 or start + size > unit.file_size):
                raise ImageError(f"invalid file span for unit {unit.name}")
            end = start + size
        return spans

    def file_source(self, unit: ImageUnit) -> dict:
        record = self.records[unit.name]
        member = record.get("disk_file")
        return {"source": record.get("source", self.program.get("program")),
                "member": member, "offset_kind": record.get("file_offset_kind", "member" if member else "file")}

    def location(self, unit: ImageUnit, offset: int) -> dict:
        report = unit.location(offset)
        report.update(unit=unit.name, unit_offset=offset, image_offset=unit.image_offset + offset,
                      initialized=offset < unit.file_size, runtime=None, file=None)
        start = self.runtime.get(unit.name)
        if start is not None:
            linear = start + offset
            address = report["address"]
            if self.format == "MZ":
                address = str(Address(start >> 4, offset) if offset <= 0xFFFF else
                              Address(linear >> 4, linear & 0xF))
            report["runtime"] = {"address": address, "linear": linear}
        for span in self.file_spans(unit):
            if span["offset"] <= offset < span["offset"] + span["size"]:
                report["file"] = {**self.file_source(unit),
                                  "offset": span["file_offset"] + offset - span["offset"]}
                break
        return report

    def matches(self, address: str, space: str, source: str | None, member: str | None):
        if not isinstance(address, str) or not address or space not in ADDRESS_SPACES:
            raise EvidenceError("expected an address and a supported address space")
        if space != "file" and (source is not None or member is not None):
            raise EvidenceError("source and member selectors require file offsets")
        if space == "logical":
            head, colon, tail = address.rpartition(":")
            selected = next((unit for unit in self.units if unit.name.casefold() == head.casefold()), None)
            if colon and selected is not None:
                offset = _hex(tail)
                if offset < selected.size:
                    yield selected, offset
                return
            value = resolve_address(self.program, self.units, address)["linear"]
        elif space == "runtime" and ":" in address:
            value = resolve_address(self.program, [], address)["linear"]
        else:
            value = _hex(address)
        for unit in self.units:
            if space == "file":
                file = self.file_source(unit)
                if (source is not None and file["source"] != source) or (
                    member is not None and file["member"] != member
                ):
                    continue
                for span in self.file_spans(unit):
                    displacement = value - span["file_offset"]
                    if 0 <= displacement < span["size"]:
                        yield unit, span["offset"] + displacement
                continue
            start = (self.runtime.get(unit.name) if space == "runtime" else
                     unit.image_offset if space == "image" else unit.linear)
            if start is not None and 0 <= value - start < unit.size:
                yield unit, value - start

    @cached_property
    def original(self) -> tuple[bytearray, list[dict]]:
        original = bytearray(self.image)
        evidence = []

        def undo(position: int, previous: bytes, kind: str) -> None:
            patch_end = position + len(previous)
            if position < 0 or patch_end > len(original):
                raise ImageError("loader fixup is outside image.bin")
            evidence.append({"kind": kind, "image_offset": position, "size": len(previous),
                             "before": previous.hex(), "after": original[position:patch_end].hex()})
            original[position:patch_end] = previous

        try:
            if self.format == "MZ":
                origin = self.units[0].linear
                for record in reversed(self.program.get("calls", [])):
                    undo(record["linear"] - origin, bytes.fromhex(record["original"]), "overlay_call")
                for record in reversed(self.program.get("stubs", [])):
                    undo(record["address"]["linear"] - origin, bytes.fromhex(record["original"]), "overlay_stub")
                positions = self.program.get("relocations", [])
                if "root_relocation_order" in self.program:
                    positions = self.program["root_relocation_order"] + [
                        position for position in positions if position >= self.units[0].size
                    ]
                base_segment = self.units[0].segment
                for position in reversed(positions):
                    value = int.from_bytes(original[position:position + 2], "little")
                    undo(position, ((value - base_segment) & 0xFFFF).to_bytes(2, "little"), "relocation")
            elif self.format in M68K_FORMATS:
                for unit in reversed(self.units):
                    for fixup in reversed(self.records[unit.name].get("relocations", [])):
                        undo(unit.image_offset + fixup["offset"],
                             fixup["original"].to_bytes(fixup.get("width", 4), "big"), "relocation")
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            raise ImageError(f"invalid loader fixup in map.json: {error}") from error
        evidence.reverse()
        return original, evidence


def _hex(text: str) -> int:
    if not 1 <= len(text) <= 8 or any(character not in "0123456789abcdefABCDEF" for character in text):
        raise EvidenceError("expected a hexadecimal offset or address of up to eight digits")
    return int(text, 16)


def map_address(export: Path, address: str, *, space: str = "logical", source: str | None = None,
                member: str | None = None, runtime_base: int | None = None,
                overlay_segments: dict | None = None) -> dict:
    image = ExportEvidence(export, runtime_base, overlay_segments)
    matches = [image.location(unit, offset) for unit, offset in image.matches(address, space, source, member)]
    return {"input": address, "space": space, "count": len(matches), "matches": matches}


def _inspect_bytes(image: ExportEvidence, address: str, size: int) -> dict:
    if type(size) is not int or not 1 <= size <= MAX_BYTES:
        raise EvidenceError(f"size must be between 1 and {MAX_BYTES} bytes")
    match = next(image.matches(address, "logical", None, None), None)
    if match is None:
        raise EvidenceError(f"address {address} is outside the exported units")
    unit, offset = match
    length = min(size, max(unit.file_size - offset, 0))
    start = unit.image_offset + offset
    end = start + length
    original = b""
    evidence = []
    files = []
    if length:
        restored, edits = image.original
        original = restored[start:end]
        evidence = [edit for edit in edits if edit["image_offset"] < end
                    and start < edit["image_offset"] + edit["size"]]
        for span in image.file_spans(unit):
            left = max(offset, span["offset"])
            right = min(offset + length, span["offset"] + span["size"])
            if left < right:
                files.append({**image.file_source(unit), "unit_offset": left,
                              "file_offset": span["file_offset"] + left - span["offset"], "size": right - left})
    return {"address": image.location(unit, offset), "requested": size, "size": length, "truncated": length < size,
            "loaded": image.image[start:end].hex(), "original": original.hex(), "file_spans": files,
            "evidence": evidence}


def inspect_bytes(export: Path, address: str, *, size: int = 32) -> dict:
    return _inspect_bytes(ExportEvidence(export), address, size)


def evidence_bundle(project: Path, requests: list, *, export: Path | None = None, program: str | None = None,
                    timeout: float | None = None) -> dict:
    """Bundle selected query results and compare any disassembly with its loader evidence."""
    if not isinstance(requests, list) or not requests:
        raise GhidraError("expected a nonempty JSON array of evidence queries")
    report = query_batch(project, [
        {"command": "project-summary", "fields": ["program", "language", "compiler", "function_count"]}, *requests,
    ], program=program, timeout=timeout)
    summary, *rows = report["results"]
    if "error" in summary:
        raise GhidraError(summary["error"]["message"], code=summary["error"]["code"])
    bundle = {**report, "bundle_version": 1, "project": summary["result"], "requests": requests, "results": rows}
    if export is None:
        return bundle
    image = ExportEvidence(export)
    bundle["export"] = {"program": image.program.get("program"), "format": image.format,
                        "image_sha256": sha256(image.image).hexdigest()}
    for request, row in zip(requests, rows, strict=True):
        if request["command"] != "disasm" or "error" in row:
            continue
        result = row["result"]
        if not {"start", "size", "rows"} <= result.keys():
            row["export_evidence"] = {"status": "unavailable", "reason": "disasm fields must include start, size, rows"}
            continue
        location = result["start"]
        try:
            observed = _inspect_bytes(image, location["unit_address"] or location["address"], result["size"])
        except (EvidenceError, SearchError) as error:
            row["export_evidence"] = {"status": "unavailable", "reason": str(error)}
            continue
        project_bytes = "".join(part.get("bytes", "") for part in result["rows"])
        same_address = observed["address"]["linear"] == location["linear"]
        if (same_address and not observed["address"]["initialized"]
                and all(part["kind"] == "uninitialized" for part in result["rows"])):
            row["export_evidence"] = {"status": "unavailable", "reason": "range is uninitialized",
                                      "bytes": observed}
            continue
        same_bytes = observed["size"] == result["size"] and observed["loaded"] == project_bytes
        row["export_evidence"] = {"status": "consistent" if same_address and same_bytes else "conflict",
                                  "bytes": observed}
    return bundle
