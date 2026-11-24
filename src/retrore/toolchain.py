"""Import real-mode linker listings and reusable byte signatures into an export."""

import json
import re
from hashlib import sha256
from pathlib import Path

from .errors import CodedError
from .image import image_units
from .signatures import _pattern


class ToolchainError(CodedError):
    """Invalid toolchain evidence supplied with a load."""

    default_code = "toolchain_invalid"


_PAIR = r"([0-9a-f]{1,5}):([0-9a-f]{1,4})"
_PUBLIC_HEADER = re.compile(r"^(?:address\s+)?publics by (?:name|value)\s*$", re.IGNORECASE)
_PUBLIC = re.compile(r"^" + _PAIR + r"\s+(?:idle\s+)?(\S+)(?:\s|$)", re.IGNORECASE)
_LINE_HEADER = re.compile(r"^line numbers for\s+(.+?)\s+segment\s+\S+", re.IGNORECASE)
_LINE = re.compile(r"\b([0-9]+)\s+" + _PAIR + r"\b", re.IGNORECASE)
_ENTRY = re.compile(r"^program entry point at\s+" + _PAIR + r"\s*$", re.IGNORECASE)
_BYTE_TOKEN = re.compile(r"[0-9a-fA-F]{2}|\?\?")


def import_linker_map(path: Path, program: dict) -> None:
    """Load 16-bit LINK/TLINK segmented publics and optional source lines."""
    if program["format"] != "MZ" or program.get("dos_format") == "RAW":
        raise ToolchainError("segmented LINK/TLINK maps require a DOS MZ or COM export")
    data = path.read_bytes()
    origin = program["units"][0]["linear"]
    end = program["memory_end"]
    overlays = [(unit["runtime_linear"], unit["runtime_linear"] + unit["size"])
                for unit in program["units"] if "runtime_linear" in unit]
    symbols, source_lines = {}, {}
    public = False
    source = None
    recognized = False
    skipped = set()

    def loaded(segment: str, offset: str) -> int:
        return origin + ((int(segment, 16) * 16 + int(offset, 16)) & 0xFFFFF)

    def is_resident(linear: int) -> bool:
        return origin <= linear < end and not any(start <= linear < stop for start, stop in overlays)

    for number, raw in enumerate(data.decode("cp437").splitlines(), 1):
        line = raw.strip().rstrip("\x1a")
        if _PUBLIC_HEADER.fullmatch(line):
            recognized, public, source = True, True, None
            continue
        if match := _LINE_HEADER.match(line):
            module = match[1]
            source = module.rsplit("(", 1)[-1].removesuffix(")")
            recognized, public = True, False
            continue
        if match := _ENTRY.fullmatch(line):
            if loaded(*match.groups()) != program["entry"]["linear"]:
                raise ToolchainError(f"{path.name} entry does not match the loaded program")
            public, source = False, None
            continue
        if public and (match := _PUBLIC.match(line)):
            segment, offset, name = match.groups()
            linear = loaded(segment, offset)
            if is_resident(linear) and name.casefold() not in ("abs", "absolute"):
                symbols.setdefault((linear, name), {"name": name, "linear": linear, "kind": "linker_public",
                                                    "source": path.name, "map_line": number})
            else:
                skipped.add((linear, name))
        elif source and (matches := list(_LINE.finditer(line))) and _LINE.sub("", line).strip() == "":
            for match in matches:
                line_number, segment, offset = match.groups()
                linear = loaded(segment, offset)
                if is_resident(linear) and int(line_number) > 0:
                    key = linear, source, int(line_number)
                    source_lines.setdefault(key, {"linear": linear, "file": source, "line": int(line_number),
                                                  "source": path.name, "map_line": number})
                else:
                    skipped.add((linear, source, line_number))
        elif line:
            public, source = False, None
    if not recognized:
        raise ToolchainError(f"{path.name} has no LINK/TLINK public-symbol or line-number section")
    program.setdefault("toolchain_symbols", []).extend(symbols.values())
    program.setdefault("toolchain_source_lines", []).extend(source_lines.values())
    program.setdefault("toolchain_inputs", []).append({"kind": "linker_map", "source": path.name,
                                                         "sha256": sha256(data).hexdigest(),
                                                         "symbols": len(symbols), "source_lines": len(source_lines),
                                                         "skipped": len(skipped)})
    if skipped:
        program.setdefault("diagnostics", []).append({"code": "linker_addresses_unmapped", "source": path.name,
                                                      "message": f"{len(skipped)} linker records did not resolve to resident memory"})


def import_signatures(path: Path, image: bytes, program: dict) -> None:
    """Match supplied byte masks against initialized units, retaining evidence for unique matches."""
    data = path.read_bytes()
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except (UnicodeError, ValueError) as error:
        raise ToolchainError(f"invalid signature JSON: {error}") from error
    if (not isinstance(document, dict) or document.keys() != {"version", "signatures"}
            or type(document["version"]) is not int or document["version"] != 1
            or not isinstance(document["signatures"], list)):
        raise ToolchainError("expected a version 1 signature catalog with a signatures array")
    units = image_units(program, len(image))
    results = []
    for index, row in enumerate(document["signatures"], 1):
        if not isinstance(row, dict) or row.keys() - {"name", "pattern", "unit", "toolchain"}:
            raise ToolchainError(f"invalid signature {index}")
        name, pattern, scope, toolchain = (row.get(key) for key in ("name", "pattern", "unit", "toolchain"))
        if (not isinstance(name, str) or not name.strip() or not isinstance(pattern, str)
                or any(key in row and (not isinstance(row[key], str) or not row[key].strip())
                       for key in ("unit", "toolchain"))):
            raise ToolchainError(f"signature {index} needs a name, a byte pattern and valid optional strings")
        tokens = pattern.split()
        if (not 1 <= len(tokens) <= 512 or not all(_BYTE_TOKEN.fullmatch(token) for token in tokens)
                or all(token == "??" for token in tokens)):
            raise ToolchainError(f"{name!r} needs 1–512 hex byte or ?? tokens with at least one fixed byte")
        compiled = _pattern(pattern)
        selected = [unit for unit in units if scope is None or scope.casefold() == unit.name.casefold()]
        if not selected:
            raise ToolchainError(f"{name!r} refers to an unknown unit {scope!r}")
        hits = []
        for unit in selected:
            start, end = unit.image_offset, unit.image_offset + unit.file_size
            # The DOS flat prefix is a synthesized PSP or a gap ahead of the file bytes.
            if unit.name == "root" and program.get("dos_format") in ("COM", "RAW"):
                start += program["load_offset"]
            match = compiled.search(image, start, end)
            if match is not None:
                hits.append((unit, match))
                if len(hits) > 1:
                    break
                second = compiled.search(image, match.start() + 1, end)
                if second is not None:
                    hits.append((unit, second))
                    break
        candidates = [{"linear": unit.linear + match.start() - unit.image_offset,
                       "unit": unit.name, "bytes": match.group().hex()} for unit, match in hits]
        result = {"name": name, "pattern": " ".join(tokens).lower(), "source": path.name,
                  "catalog_index": index, "candidates": candidates,
                  "status": ("missing", "matched", "ambiguous")[len(candidates)]}
        if toolchain is not None:
            result["toolchain"] = toolchain
        if len(candidates) == 1:
            program.setdefault("toolchain_symbols", []).append({**candidates[0], "name": name,
                                                                "kind": "toolchain_signature", "source": path.name})
        results.append(result)
    program.setdefault("toolchain_signatures", []).extend(results)
    program.setdefault("toolchain_inputs", []).append({"kind": "signatures", "source": path.name,
                                                         "sha256": sha256(data).hexdigest()})
