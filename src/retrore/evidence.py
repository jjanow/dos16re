"""Map exported locations back to their loader inputs and inspect initialized bytes."""

from functools import cached_property
from hashlib import sha256
from itertools import groupby
from pathlib import Path

from .ghidra import GhidraError, query_batch
from .image import (
    ATARI8_FORMAT, M68K_FORMATS, ImageError, ImageUnit, RuntimePlacementError, dos_runtime_units, explicit_runtime_units,
    image_units, read_map, runtime_spans,
)
from .load_manifest import LoadManifestError, manifest_states, state_loads, state_spans
from .mz import Address, MZExecutable
from .search import SearchError, resolve_address

ADDRESS_SPACES = ("logical", "linear", "runtime", "image", "file")
FILE_OFFSET_KINDS = ("file", "member", "container")
MAX_BYTES = 4096


class EvidenceError(ValueError):
    """An invalid address mapping or byte request."""


class ExportEvidence:
    def __init__(self, export: Path, runtime_base: int | None = None, overlay_segments: dict | None = None, *,
                 runtime_loads: dict | None = None, source_file: Path | None = None, state: str | None = None):
        self.image = (export / "image.bin").read_bytes()
        self.program = read_map(export)
        self.units = image_units(self.program, len(self.image))
        self.records = {record["name"]: record for record in self.program["units"]}
        self.format = self.program.get("format", "MZ")
        self.manifest = manifest_states(self.program, self.units)
        self.state = state
        self.root_file_offset = None
        if source_file is not None:
            if self.format != "MZ" or self.program.get("packer"):
                raise EvidenceError("source-file recovery requires an unpacked DOS export")
            root = self.units[0]
            source = source_file.read_bytes()
            if self.program.get("dos_format") in ("COM", "RAW"):
                spans = self.file_spans(root)
                prefix = spans[0]["offset"] if spans else root.file_size
                if source != self.image[root.image_offset + prefix:root.image_offset + root.file_size]:
                    raise EvidenceError("source file does not match the original DOS load module")
            else:
                executable = MZExecutable.parse(source)
                start = root.image_offset
                if executable.packer or executable.image != self.original[0][start:start + root.file_size]:
                    raise EvidenceError("source file does not match the original DOS load module")
                self.root_file_offset = executable.header.header_size
                recorded = self.records[root.name].get("file_offset")
                if recorded is not None and self.root_file_offset != recorded:
                    raise EvidenceError("source file header size differs from the export")
        try:
            runtime_overrides = bool(runtime_loads or overlay_segments or runtime_base is not None)
            if state is not None and (self.manifest is None or runtime_overrides):
                raise EvidenceError("selecting a state requires a load manifest and excludes runtime overrides")
            if self.manifest is not None and not runtime_overrides:
                self.select_runtime_state(state if state is not None else self.manifest["initial"])
            elif runtime_loads:
                if runtime_base is not None or overlay_segments:
                    raise EvidenceError("runtime loads cannot be combined with DOS segment overrides")
                self.runtime = explicit_runtime_units(self.units, runtime_loads, self.format)
            elif self.format == "MZ":
                placements = dos_runtime_units(self.units, runtime_base, overlay_segments or {})
                self.runtime = {unit.name: start for start, unit in placements}
            else:
                if runtime_base is not None or overlay_segments:
                    raise EvidenceError("runtime segment overrides require a DOS MZ export")
                self.runtime = {unit.name: unit.linear for unit in self.units}
            if self.state is None:
                self.runtime_spans = runtime_spans(self.units, self.runtime)
        except (RuntimePlacementError, LoadManifestError) as error:
            raise EvidenceError(str(error)) from error

    def select_runtime_state(self, state: str) -> None:
        self.runtime = state_loads(self.manifest, state)
        self.runtime_spans = state_spans(self.manifest, state, self.units)
        self.state = state

    def identity(self) -> dict:
        return {"program": self.program.get("program"), "format": self.format,
                "image_sha256": sha256(self.image).hexdigest()}

    def file_spans(self, unit: ImageUnit, *, container: bool = False) -> list[dict]:
        record = self.records[unit.name]
        if container:
            if record.get("file_offset_kind") == "container" and "container_spans" not in record:
                return self.file_spans(unit)
            spans = record.get("container_spans", [])
        elif "file_spans" in record:
            spans = record["file_spans"]
        elif self.format == ATARI8_FORMAT and "file_offset" not in record:
            spans = self.legacy_atari8_spans.get(unit.name, [])
        else:
            offset = record.get("file_offset")
            if self.format == "MZ" and offset is None:
                if unit.name == "root":
                    offset = self.root_file_offset
                elif "file_offset" not in record:
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

    @cached_property
    def legacy_atari8_spans(self) -> dict:
        """Recover visible source offsets from the ordered segments in early Atari maps."""
        sources = self.program.get("sources", [])
        if not isinstance(sources, list) or any(not isinstance(source, dict) for source in sources):
            raise ImageError("invalid Atari source records")
        result = {}
        for unit in self.units:
            record = self.records[unit.name]
            if "file_spans" in record or "file_offset" in record:
                continue
            candidates = [source for source in sources if isinstance(source.get("name"), str)
                          and unit.name in (source["name"], f"{source['name']}_{unit.linear:04x}")
                          and all(source.get(key) == record.get(key) for key in ("source", "disk_file"))]
            if len(candidates) != 1:
                continue
            offsets = [None] * unit.file_size
            segments = candidates[0].get("segments", [])
            if not isinstance(segments, list) or any(not isinstance(segment, dict) for segment in segments):
                raise ImageError(f"invalid Atari source segments for unit {unit.name}")
            for segment in segments:
                start, size, offset = (segment.get(key) for key in ("linear", "size", "file_offset"))
                if any(type(value) is not int or value < 0 for value in (start, size, offset)):
                    raise ImageError(f"invalid Atari source segment for unit {unit.name}")
                left, right = max(start, unit.linear), min(start + size, unit.linear + unit.file_size)
                if left < right:
                    offsets[left - unit.linear:right - unit.linear] = range(offset + left - start, offset + right - start)
            spans = []
            for base, group in groupby(enumerate(offsets), lambda row: None if row[1] is None else row[1] - row[0]):
                if base is not None:
                    first, offset = next(group)
                    spans.append({"offset": first, "file_offset": offset, "size": 1 + sum(1 for _ in group)})
            result[unit.name] = spans
        return result

    def file_source(self, unit: ImageUnit, *, container: bool = False) -> dict:
        record = self.records[unit.name]
        member = record.get("disk_file")
        source = {"source": record.get("source", self.program.get("program")),
                  "member": member, "offset_kind": ("container" if container else
                                                     record.get("file_offset_kind", "member" if member else "file"))}
        if isinstance(member_id := record.get("member_id"), str):
            source["member_id"] = member_id
        return source

    def location(self, unit: ImageUnit, offset: int) -> dict:
        report = unit.location(offset)
        report.update(unit=unit.name, unit_offset=offset, image_offset=unit.image_offset + offset,
                      initialized=offset < unit.file_size, runtime=None, file=None)
        if variant := self.records[unit.name].get("variant_source"):
            report["variant_source"] = variant
        start = self.runtime.get(unit.name)
        if start is not None and any(span.unit is unit and span.offset <= offset < span.offset + span.size
                                     for span in self.runtime_spans):
            linear = start + offset
            if unit.segment is not None:
                relative = (start & 0xF) + offset
                address = str(Address(start >> 4, relative) if relative <= 0xFFFF else
                              Address(linear >> 4, linear & 0xF))
            else:
                address = f"{linear:0{unit.address_width}x}"
            report["runtime"] = {"address": address, "linear": linear}
        for span in self.file_spans(unit):
            if span["offset"] <= offset < span["offset"] + span["size"]:
                report["file"] = {**self.file_source(unit),
                                  "offset": span["file_offset"] + offset - span["offset"]}
                break
        for span in self.file_spans(unit, container=True):
            if span["offset"] <= offset < span["offset"] + span["size"]:
                report["container"] = {**self.file_source(unit, container=True),
                                       "offset": span["file_offset"] + offset - span["offset"]}
                break
        return report

    def matches(self, address: str, space: str, source: str | None, member: str | None,
                offset_kind: str | None = None):
        if not isinstance(address, str) or not address or space not in ADDRESS_SPACES:
            raise EvidenceError("expected an address and a supported address space")
        if space != "file" and any(value is not None for value in (source, member, offset_kind)):
            raise EvidenceError("source, member, and offset kind selectors require file offsets")
        if offset_kind is not None and offset_kind not in FILE_OFFSET_KINDS:
            raise EvidenceError("invalid file offset kind")
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
        if space == "runtime":
            for span in self.runtime_spans:
                if span.linear <= value < span.end:
                    yield span.unit, span.offset + value - span.linear
            return
        for unit in self.units:
            if space == "file":
                file = self.file_source(unit)
                member_id = file.get("member_id")
                id_match = member is not None and member_id is not None and member.casefold() == f"id:{member_id}".casefold()
                if (source is not None and file["source"] != source) or (
                    member is not None and file["member"] != member and not id_match
                ):
                    continue
                if offset_kind is None or offset_kind == file["offset_kind"]:
                    spans = self.file_spans(unit)
                elif offset_kind == "container":
                    spans = self.file_spans(unit, container=True)
                else:
                    continue
                for span in spans:
                    displacement = value - span["file_offset"]
                    if 0 <= displacement < span["size"]:
                        yield unit, span["offset"] + displacement
                continue
            start = unit.image_offset if space == "image" else unit.linear
            if 0 <= value - start < unit.size:
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
                overlay_edits = self.program.get("overlay_edits", [])
                edited_relocations = {edit["image_offset"] for edit in overlay_edits if edit["kind"] == "relocation"}
                positions = [position for position in positions if position not in edited_relocations]
                if "root_relocation_order" in self.program:
                    positions = self.program["root_relocation_order"] + [
                        position for position in positions if position >= self.units[0].size
                    ]
                base_segment = self.units[0].segment
                for edit in reversed(overlay_edits):
                    undo(edit["image_offset"], bytes.fromhex(edit["original"]), edit["kind"])
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
                overlay_segments: dict | None = None, runtime_loads: dict | None = None,
                source_file: Path | None = None, offset_kind: str | None = None,
                state: str | None = None, all_states: bool = False) -> dict:
    image = ExportEvidence(export, runtime_base, overlay_segments, runtime_loads=runtime_loads,
                           source_file=source_file, state=state)
    if all_states:
        if image.manifest is None or image.state is None or state is not None:
            raise EvidenceError("mapping every state requires a load manifest and excludes state and runtime overrides")
        matches = []
        for row in image.manifest["states"]:
            name = row["name"]
            image.select_runtime_state(name)
            for unit, offset in image.matches(address, space, source, member, offset_kind):
                location = image.location(unit, offset)
                if location["runtime"] is not None:
                    matches.append({**location, "state": name})
    else:
        matches = [image.location(unit, offset)
                   for unit, offset in image.matches(address, space, source, member, offset_kind)]
    report = {"input": address, "space": space, "count": len(matches), "matches": matches}
    if image.state is not None and not all_states:
        report["state"] = image.state
    return report


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
    report = {"address": image.location(unit, offset), "requested": size, "size": length, "truncated": length < size,
              "loaded": image.image[start:end].hex(), "file_spans": []}
    if length:
        restored, edits = image.original
        original = restored[start:end]
        evidence = [edit for edit in edits if edit["image_offset"] < end
                    and start < edit["image_offset"] + edit["size"]]
        for container, name in ((False, "file_spans"), (True, "container_spans")):
            for span in image.file_spans(unit, container=container):
                left = max(offset, span["offset"])
                right = min(offset + length, span["offset"] + span["size"])
                if left < right:
                    report.setdefault(name, []).append({
                        **image.file_source(unit, container=container), "unit_offset": left,
                        "file_offset": span["file_offset"] + left - span["offset"], "size": right - left,
                    })
    return {**report, "original": original.hex(), "evidence": evidence}


def inspect_bytes(export: Path, address: str, *, size: int = 32, source_file: Path | None = None) -> dict:
    return _inspect_bytes(ExportEvidence(export, source_file=source_file), address, size)


def _compare_bytes(image: ExportEvidence, location: dict, size: int, project_bytes: str,
                   *, uninitialized: bool = False) -> dict:
    try:
        observed = _inspect_bytes(image, location["unit_address"] or location["address"], size)
    except (EvidenceError, SearchError) as error:
        return {"status": "unavailable", "reason": str(error)}

    same_address = observed["address"]["linear"] == location["linear"]
    if same_address and uninitialized and not observed["address"]["initialized"]:
        return {"status": "unavailable", "reason": "range is uninitialized", "bytes": observed}

    conflicts = []
    if not same_address:
        conflicts.append("address_mismatch")
    if observed["size"] * 2 != len(project_bytes):
        conflicts.append("initialized_size_mismatch")
    else:
        if observed["loaded"] != project_bytes:
            conflicts.append("byte_mismatch")
        if observed["size"] != size:
            conflicts.append("incomplete_range")
    if conflicts:
        return {"status": "conflict", "conflicts": conflicts, "bytes": observed}
    return {"status": "consistent", "bytes": observed}


def compare_project_range(image: ExportEvidence, region: dict) -> dict:
    address, data = region["address"], region["bytes"]
    return {"address": address, "project_bytes": data,
            **_compare_bytes(image, address, region["size"], data, uninitialized=region["uninitialized"])}


def _decomp_evidence(image: ExportEvidence, result: dict) -> dict:
    instruction_bytes = result.pop("_instruction_bytes", None)
    if instruction_bytes is None:
        return {"status": "unavailable", "reason": "Ghidra did not return instruction bytes"}

    instructions = []
    for item in instruction_bytes["instructions"]:
        address, data = item["address"], item["bytes"]
        comparison = _compare_bytes(image, address, len(data) // 2, data)
        instructions.append({"address": address, "project_bytes": data, **comparison})
    truncated = instruction_bytes["truncated"]
    report = {"instructions": instructions, "truncated": truncated}
    statuses = {item["status"] for item in instructions}
    if "conflict" in statuses:
        return {**report, "status": "conflict"}
    if not instructions:
        return {**report, "status": "unavailable", "reason": "no instruction bytes in the returned decomp fields"}
    if "unavailable" in statuses or truncated:
        return {**report, "status": "unavailable", "reason": "instruction coverage is incomplete"}
    return {**report, "status": "consistent"}


def _switch_records(image: ExportEvidence) -> dict:
    records = {}
    try:
        for table in image.program.get("jump_tables", ()):
            targets = table["targets"]
            count = len(table.get("cases", targets))
            width = table.get("entry_size", 4 if image.format in M68K_FORMATS else 2)
            if type(width) is not int or width not in (2, 4) or count == 0:
                raise ValueError("invalid jump table size")
            records[table["address"]["linear"]] = {
                "guard": table["guard"]["linear"], "table": table["table"]["linear"], "size": width * count,
                "targets": sorted({target["linear"] for target in targets}),
            }
    except (KeyError, TypeError, ValueError) as error:
        raise ImageError(f"invalid jump table in map.json: {error}") from error
    return records


def _flow_evidence(image: ExportEvidence, switches: dict, result: dict) -> dict:
    proof = result.pop("_flow_bytes", None)
    if proof is None:
        return {"status": "unavailable", "reason": "Ghidra did not return indirect flow evidence"}

    sites = []
    for item in proof["sites"]:
        address = item["address"]
        ranges = []
        for region in item["ranges"]:
            comparison = compare_project_range(image, region["range"])
            if region["truncated"] and comparison["status"] == "consistent":
                comparison.update(status="unavailable", reason="only a prefix of the range was checked")
            ranges.append({"role": region["role"], **comparison})
        site = {"address": address, "ranges": ranges}
        if item["targets"] is not None:
            expected = switches[address["linear"]]["targets"]
            site["targets"] = {"project": item["targets"], "export": expected}
            if item["targets"] != expected:
                site["conflicts"] = ["target_mismatch"]
        statuses = {region["status"] for region in ranges}
        if "conflicts" in site or "conflict" in statuses:
            site["status"] = "conflict"
        elif item["incomplete"] or "unavailable" in statuses:
            site.update(status="unavailable", reason="indirect flow byte coverage is incomplete")
        else:
            site["status"] = "consistent"
        sites.append(site)

    report = {"sites": sites, "truncated": proof["truncated"]}
    statuses = {site["status"] for site in sites}
    if "conflict" in statuses:
        return {**report, "status": "conflict"}
    if not sites:
        return {**report, "status": "unavailable", "reason": "no indirect sites in the returned page"}
    if "unavailable" in statuses or proof["truncated"]:
        return {**report, "status": "unavailable", "reason": "indirect flow byte coverage is incomplete"}
    return {**report, "status": "consistent"}


def evidence_bundle(project: Path, requests: list, *, export: Path | None = None, program: str | None = None,
                    timeout: float | None = None) -> dict:
    """Bundle selected query results and compare Ghidra bytes with loader evidence."""
    if not isinstance(requests, list) or not requests:
        raise GhidraError("expected a nonempty JSON array of evidence queries")
    image = ExportEvidence(export) if export is not None else None
    switches = None
    if image is not None and any(isinstance(item, dict) and item.get("command") == "indirect" for item in requests):
        switches = _switch_records(image)
    report = query_batch(project, [
        {"command": "project-summary", "fields": ["program", "language", "compiler", "function_count"]}, *requests,
    ], program=program, timeout=timeout, _instruction_bytes=image is not None, _flow_bytes=switches)
    summary, *rows = report["results"]
    if "error" in summary:
        raise GhidraError(summary["error"]["message"], code=summary["error"]["code"])
    bundle = {**report, "bundle_version": 1, "project": summary["result"], "requests": requests, "results": rows}
    if image is None:
        return bundle
    bundle["export"] = image.identity()
    for request, row in zip(requests, rows, strict=True):
        if "error" in row:
            continue
        result = row["result"]
        if request["command"] == "decomp":
            row["export_evidence"] = _decomp_evidence(image, result)
        elif request["command"] == "indirect":
            row["export_evidence"] = _flow_evidence(image, switches, result)
        elif request["command"] == "disasm":
            if {"start", "size", "rows"} <= result.keys():
                parts = result["rows"]
                row["export_evidence"] = _compare_bytes(
                    image, result["start"], result["size"], "".join(part.get("bytes", "") for part in parts),
                    uninitialized=all(part["kind"] == "uninitialized" for part in parts),
                )
            else:
                row["export_evidence"] = {"status": "unavailable",
                                          "reason": "disasm fields must include start, size, rows"}
    return bundle
