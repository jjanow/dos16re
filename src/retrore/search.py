"""Search file-backed portions of an exported program."""

import fnmatch
import re
from array import array
from bisect import bisect_right
from pathlib import Path

from .image import (
    APPLE2_FORMAT, ATARI8_FORMAT, C64_FORMAT, FLAT16_FORMATS, GENESIS_FORMAT, M68K_FORMATS, MAC68K_FORMAT,
    MOS6502_FORMATS, MSX2_FORMAT, NES_FORMAT,
    PC88_FORMAT, PC98_FORMAT, X1_FORMAT, X68K_FORMAT, ImageError, ImageUnit, image_units, read_map,
)

WIDTHS = (1, 2, 4, 8)
POINTER_KINDS = ("far", "near", "absolute", "absolute-short", "split")


class SearchError(ValueError):
    """An invalid search pattern or image export."""


# Text encodings. Each maps one character to the byte strings that can represent it on the platform, or to
# nothing when the character has no representation. Python codecs cover the PC and Japanese machines; the
# 8-bit home computers use their own tables.

def _codec(name: str):
    def encode(char: str) -> list[bytes]:
        try:
            return [char.encode(name)]
        except UnicodeEncodeError:
            return []
    return encode


def _ascii_printable(char: str) -> int | None:
    code = ord(char)
    return code if 0x20 <= code <= 0x7E else None


def _petscii(char: str) -> list[bytes]:
    """Unshifted (uppercase and graphics) PETSCII. Both letter cases show as capitals."""
    code = _ascii_printable(char.upper())
    if char == "£":
        return [b"\x5c"]
    if code is None or code > 0x5D or char in "\\":
        return []
    return [bytes([code])]


def _petscii_shifted(char: str) -> list[bytes]:
    """Shifted (lowercase) PETSCII: lowercase letters at $41-$5A, capitals at $61-$7A or $C1-$DA."""
    if char.isascii() and char.isalpha():
        index = ord(char.lower()) - 0x61
        return [bytes([0x41 + index])] if char.islower() else [bytes([0x61 + index]), bytes([0xC1 + index])]
    return _petscii(char)


def _c64_screen(char: str) -> list[bytes]:
    """VIC-II screen codes of the uppercase character set: @ is 0 and A-Z are 1-26."""
    if char == "£":
        return [b"\x1c"]
    code = _ascii_printable(char.upper())
    if code is None or code > 0x5D or char == "\\":
        return []
    return [bytes([code - 0x40 if code >= 0x40 else code])]


def _c64_screen_shifted(char: str) -> list[bytes]:
    """Screen codes of the lowercase character set: a-z are 1-26 and capitals $41-$5A."""
    if char.isascii() and char.isupper():
        return [bytes([ord(char)])]
    return _c64_screen(char)


def _apple2(char: str) -> list[bytes]:
    """Apple II text: ASCII with bit 7 set, as the monitor and most programs store it."""
    code = _ascii_printable(char)
    return [] if code is None else [bytes([code | 0x80])]


def _atari_screen(char: str) -> list[bytes]:
    """Atari 8-bit internal (screen) codes: ATASCII $20-$5F at $00-$3F, $00-$1F at $40-$5F."""
    code = _ascii_printable(char)
    if code is None:
        return []
    return [bytes([code - 0x20 if code < 0x60 else code])]


ENCODINGS = {
    "ascii": _codec("ascii"),
    "latin-1": _codec("latin-1"),
    "cp437": _codec("cp437"),
    "shift-jis": _codec("cp932"),
    "mac-roman": _codec("mac_roman"),
    "petscii": _petscii,
    "petscii-shifted": _petscii_shifted,
    "c64-screen": _c64_screen,
    "c64-screen-shifted": _c64_screen_shifted,
    "apple2": _apple2,
    "atascii": _codec("ascii"),
    "atari-screen": _atari_screen,
}
# Encodings tried for each format, in reporting order. `pattern` in results uses the first one.
PLATFORM_ENCODINGS = {
    "MZ": ("cp437",),
    PC98_FORMAT: ("shift-jis",),
    X68K_FORMAT: ("shift-jis",),
    MAC68K_FORMAT: ("mac-roman",),
    GENESIS_FORMAT: ("ascii", "shift-jis"),
    "HUNK": ("latin-1",),
    "PRG": ("ascii",),
    C64_FORMAT: ("petscii", "petscii-shifted", "c64-screen", "c64-screen-shifted"),
    APPLE2_FORMAT: ("apple2", "ascii"),
    ATARI8_FORMAT: ("atascii", "atari-screen"),
    NES_FORMAT: ("ascii",),
    MSX2_FORMAT: ("ascii", "shift-jis"),
    PC88_FORMAT: ("ascii", "shift-jis"),
    X1_FORMAT: ("ascii", "shift-jis"),
}


# Single codecs for find_bytes with a plain string; find_text tries every platform encoding.
_STRING_CODECS = {
    "MZ": "cp437", "HUNK": "latin-1", "PRG": "ascii", X68K_FORMAT: "cp932", PC98_FORMAT: "cp932",
    MAC68K_FORMAT: "mac_roman",
}


def search_pattern(
    *, hex_bytes: str | None = None, string: str | None = None, constant: str | int | None = None,
    width: int | None = None,
) -> tuple[bytes | str | int, int]:
    """Return the pattern and constant width for exactly one of hex bytes, a string, or a constant.

    A constant is an integer or a decimal or 0x-prefixed string. `width` applies only to constants.
    """
    given = [name for name, value in (("bytes", hex_bytes), ("string", string), ("constant", constant))
             if value is not None]
    if len(given) != 1:
        raise SearchError("specify exactly one of bytes, string, or constant")
    if width is not None and constant is None:
        raise SearchError("--width requires --constant")
    if width is not None and (type(width) is not int or width not in WIDTHS):
        raise SearchError(f"width must be one of {', '.join(map(str, WIDTHS))}")
    try:
        if hex_bytes is not None:
            if not isinstance(hex_bytes, str):
                raise ValueError("bytes must be a string of hexadecimal digits")
            return bytes.fromhex(hex_bytes), width or 2
        if string is not None:
            if not isinstance(string, str):
                raise ValueError("string must be a string")
            return string, width or 2
        if isinstance(constant, str):
            base = 16 if constant.lstrip("+-").lower().startswith("0x") else 10
            return int(constant, base), width or 2
        if type(constant) is not int:
            raise ValueError("constant must be an integer or a decimal or 0x-prefixed string")
        return constant, width or 2
    except ValueError as error:
        raise SearchError(str(error)) from error


def _load(export: Path) -> tuple[bytes, dict, list[ImageUnit]]:
    image = (export / "image.bin").read_bytes()
    program = read_map(export)
    return image, program, image_units(program, len(image))


def _text_regex(text: str, encoding: str, ignore_case: bool) -> tuple[re.Pattern, bytes] | None:
    """Return a regex matching text in one encoding and its exact-case bytes, or None if a character is missing."""
    encode = ENCODINGS[encoding]
    parts, exact = [], b""
    for char in text:
        forms = encode(char)
        if not forms:
            return None
        exact += forms[0]
        if ignore_case:
            forms = [*forms, *(form for variant in (char.lower(), char.upper()) if variant != char
                               for form in encode(variant))]
        alternatives = sorted({re.escape(form) for form in forms})
        parts.append(alternatives[0] if len(alternatives) == 1 else b"(?:" + b"|".join(alternatives) + b")")
    return re.compile(b"(?=(" + b"".join(parts) + b"))", re.DOTALL), exact


def find_text(
    export: Path, text: str, *, encoding: str | None = None, ignore_case: bool = False, limit: int | None = None,
) -> dict:
    """Find text in each of the format's encodings, or in one named encoding. Matches can overlap.

    Matches name their encoding and bytes when several encodings or letter cases were tried.
    """
    if not isinstance(text, str) or not text:
        raise SearchError("search pattern must contain at least one byte")
    if encoding is not None and encoding not in ENCODINGS:
        raise SearchError(f"encoding must be one of {', '.join(ENCODINGS)}")
    image, program, units = _load(export)
    encodings = (encoding,) if encoding else PLATFORM_ENCODINGS[program.get("format", "MZ")]
    compiled = [(name, _text_regex(text, name, ignore_case)) for name in encodings]
    usable = [(name, entry) for name, entry in compiled if entry is not None]
    if not usable:
        raise SearchError(f"{text!r} cannot be encoded in {', '.join(encodings)}")
    found: dict[int, tuple[int, str, bytes]] = {}
    for unit in units:
        start, end = unit.image_offset, unit.image_offset + unit.file_size
        for name, (regex, _) in usable:
            for match in regex.finditer(image, start, end):
                if match.end(1) <= end:
                    found.setdefault(match.start(1), (len(found), name, match.group(1)))
    unit_starts = [unit.image_offset for unit in units]
    matches = []
    for position in sorted(found):
        if limit is not None and len(matches) >= limit:
            break
        unit = units[bisect_right(unit_starts, position) - 1]
        _, name, data = found[position]
        match = unit.location(position - unit.image_offset)
        if len(usable) > 1 or ignore_case:
            match |= {"encoding": name, "bytes": data.hex()}
        matches.append(match)
    return {
        "pattern": usable[0][1][1].hex(), "encodings": [name for name, _ in usable],
        "skipped_encodings": [name for name, entry in compiled if entry is None],
        "count": len(found), "matches": matches,
    }


def find_bytes(export: Path, pattern: bytes | str | int, *, width: int = 2, limit: int | None = None) -> dict:
    image = (export / "image.bin").read_bytes()
    try:
        program = read_map(export)
        units = image_units(program, len(image))
        image_format = program.get("format", "MZ")
        if isinstance(pattern, str):
            pattern = pattern.encode(_STRING_CODECS.get(image_format, "ascii"))
        elif isinstance(pattern, int):
            pattern = pattern.to_bytes(width, "big" if image_format in M68K_FORMATS else "little", signed=pattern < 0)
    except ImageError:
        raise
    except (ValueError, OverflowError) as error:
        raise SearchError(str(error)) from error
    if not pattern:
        raise SearchError("search pattern must contain at least one byte")
    matches = []
    count = 0
    for unit in units:
        start, end = unit.image_offset, unit.image_offset + unit.file_size
        position = image.find(pattern, start, end)
        while position != -1:
            count += 1
            if limit is None or len(matches) < limit:
                matches.append(unit.location(position - start))
            position = image.find(pattern, position + 1, end)
    return {"pattern": pattern.hex(), "count": count, "matches": matches}


# Addresses -----------------------------------------------------------------------------------------------------

_HEX = re.compile(r"[0-9a-fA-F]{1,8}")


def segmented(program: dict) -> bool:
    return program.get("format", "MZ") in ("MZ", PC98_FORMAT)


def resolve_address(program: dict, units: list[ImageUnit], text: str) -> dict:
    """Resolve unit:offset, seg:off (DOS and PC-98), or a flat hexadecimal linear address.

    Returns {"linear", "segment", "offset"}; segment and offset are None for flat formats.
    """
    if not isinstance(text, str):
        raise SearchError("address must be a string")
    head, colon, tail = text.strip().rpartition(":")
    if not _HEX.fullmatch(tail):
        raise SearchError(f"invalid address {text!r}: expected unit:offset, seg:off, or a hexadecimal address")
    value = int(tail, 16)
    if colon:
        unit = next((unit for unit in units if unit.name.casefold() == head.casefold()), None)
        if unit is not None:
            linear = unit.linear + value
            return _with_segment(program, units, linear, unit.segment if value <= 0xFFFF else None)
        if segmented(program) and _HEX.fullmatch(head) and int(head, 16) <= 0xFFFF and value <= 0xFFFF:
            segment = int(head, 16)
            return {"linear": segment * 16 + value, "segment": segment, "offset": value}
        raise SearchError(f"unknown unit {head!r} in {text!r}")
    return _with_segment(program, units, value, None)


def _with_segment(program: dict, units: list[ImageUnit], linear: int, segment: int | None) -> dict:
    if not segmented(program):
        return {"linear": linear, "segment": None, "offset": None}
    if segment is None:
        unit = _unit_at(units, linear)
        segment = unit.segment if unit is not None and 0 <= linear - unit.segment * 16 <= 0xFFFF else linear >> 4
    return {"linear": linear, "segment": segment, "offset": linear - segment * 16}


def _unit_at(units: list[ImageUnit], linear: int) -> ImageUnit | None:
    for unit in units:
        if unit.linear <= linear < unit.linear + max(unit.size, 1):
            return unit
    return None


def locate(program: dict, units: list[ImageUnit], linear: int) -> dict:
    """Describe a linear address with its unit address when a unit covers it."""
    unit = _unit_at(units, linear)
    if unit is not None:
        return unit.location(linear - unit.linear)
    if segmented(program):
        return {"address": f"{linear >> 4:04x}:{linear & 0xF:04x}", "unit_address": None, "linear": linear}
    width = 4 if program.get("format") in FLAT16_FORMATS else 8
    return {"address": f"{linear:0{width}x}", "unit_address": None, "linear": linear}


# Pointers ------------------------------------------------------------------------------------------------------

def _relocation_sites(program: dict, units: list[ImageUnit]) -> set[tuple[int, int]] | None:
    """Return image offsets and widths of fixups, or None when the format has no relocations."""
    image_format = program.get("format", "MZ")
    if image_format == "MZ":
        return {(offset, 2) for offset in program.get("relocations", ())}
    if image_format in M68K_FORMATS:
        by_name = {unit.name: unit for unit in units}
        return {(by_name[unit["name"]].image_offset + reloc["offset"], reloc.get("width", 4))
                for unit in program["units"] for reloc in unit.get("relocations", ())
                if reloc.get("kind") != "pc_relative"}
    return None


# LDA abs,X/Y; STA zp/abs; LDA abs,X/Y using the same index; STA zp/abs. A backreference
# requires the same LDA opcode. The stores must write adjacent bytes of one pointer.
_SPLIT_LOADS = re.compile(rb"(?=([\xbd\xb9])(..)(?:\x85(.)|\x8d(..))\1(..)(?:\x85(.)|\x8d(..)))", re.DOTALL)


def _split_pointers(image: bytes, units: list[ImageUnit], linear: int) -> dict[tuple[int, int], dict]:
    """Match 6502 low/high table entries backed by indexed loads that assemble a pointer."""
    hits: dict[tuple[int, int], dict] = {}
    if not 0 <= linear < 0x10000:
        return hits
    for code in units:
        start, end = code.image_offset, code.image_offset + code.file_size
        for match in _SPLIT_LOADS.finditer(image, start, end):
            opcode, first, first_zp, first_abs, second, second_zp, second_abs = match.groups()
            first_store = int.from_bytes(first_zp or first_abs, "little")
            second_store = int.from_bytes(second_zp or second_abs, "little")
            if abs(first_store - second_store) != 1:
                continue
            if first_store > second_store:
                first, second = second, first
            low, high = int.from_bytes(first, "little"), int.from_bytes(second, "little")
            low_unit, high_unit = _unit_at(units, low), _unit_at(units, high)
            if low_unit is None or high_unit is None:
                continue
            low_offset, high_offset = low - low_unit.linear, high - high_unit.linear
            low_position = low_unit.image_offset + low_offset
            high_position = high_unit.image_offset + high_offset
            # X and Y are bytes. The table lengths are unknown, so stop before the planes overlap,
            # or the first entry leaves a file-backed unit.
            count = min(0x100, abs(low - high), low_unit.file_size - low_offset, high_unit.file_size - high_offset)
            for index in range(count):
                if image[low_position + index] | image[high_position + index] << 8 != linear:
                    continue
                low_entry, high_entry = low_position + index, high_position + index
                row = hits.setdefault((low_entry, high_entry), {
                    "high": high_unit.location(high_offset + index), "evidence": [],
                })
                row["evidence"].append({
                    "instruction": code.location(match.start() - start),
                    "index_register": "x" if opcode == b"\xbd" else "y", "index": index,
                    "low_table": low_unit.location(low_offset), "high_table": high_unit.location(high_offset),
                })
    return hits


def find_pointers(export: Path, target: str, *, kinds: tuple[str, ...] | None = None,
                  limit: int | None = None) -> dict:
    """Find stored addresses of a target, with optional 68k short or 6502 split pointer candidates.

    `relocated` says whether a loader relocation covers the stored segment word, short, or long. It is null for
    formats without relocations and for DOS near pointers, which relocations never cover.
    """
    image, program, units = _load(export)
    resolved = resolve_address(program, units, target)
    linear = resolved["linear"]
    image_format = program.get("format", "MZ")
    relocations = _relocation_sites(program, units)
    defaults = ("far", "near") if segmented(program) else ("absolute",)
    big = image_format in M68K_FORMATS
    available = defaults
    if big:
        available += ("absolute-short",)
    elif image_format in MOS6502_FORMATS:
        available += ("split",)
    kinds = tuple(dict.fromkeys(kinds or defaults))
    if any(kind not in available for kind in kinds):
        raise SearchError(f"pointer kinds for {image_format} are {', '.join(available)}")
    formats = []
    width = 4 if big else 2
    if "absolute" in kinds and 0 <= linear < 1 << (8 * width):
        formats.append(("absolute", width, linear))
    # A 68k absolute short sign-extends to 32 bits. These exports map the 24-bit bus.
    if "absolute-short" in kinds and (0 <= linear < 0x8000 or 0xFF8000 <= linear <= 0xFFFFFF
                                      or 0xFFFF8000 <= linear <= 0xFFFFFFFF):
        formats.append(("absolute-short", 2, linear & 0xFFFF))
    hits = []  # (position, size, kind, value, relocated, details)
    for unit in units:
        start, end = unit.image_offset, unit.image_offset + unit.file_size
        if segmented(program):
            if "far" in kinds:
                low, high = max(0, (linear - 0xFFFF + 15) // 16), linear // 16
                for alignment in (0, 1):
                    first = start + alignment
                    count = (end - first) // 2
                    if count < 2:
                        continue
                    words = array("H", image[first:first + count * 2])
                    for index in range(count - 1):
                        segment = words[index + 1]
                        if low <= segment <= high and words[index] + segment * 16 == linear:
                            position = first + index * 2
                            backed = None if relocations is None else (position + 2, 2) in relocations
                            hits.append((position, 4, "far", f"{segment:04x}:{words[index]:04x}", backed, None))
            if "near" in kinds:
                pattern = resolved["offset"].to_bytes(2, "little")
                position = image.find(pattern, start, end - 1)
                while position != -1:
                    hits.append((position, 2, "near", f"{resolved['offset']:04x}", None, None))
                    position = image.find(pattern, position + 1, end - 1)
            continue
        for kind, width, value in formats:
            pattern = value.to_bytes(width, "big" if big else "little")
            position = image.find(pattern, start, end)
            while position != -1:
                if not big or (unit.linear + position - start) % 2 == 0:
                    backed = None if relocations is None else (position, width) in relocations
                    hits.append((position, width, kind, f"{value:0{width * 2}x}", backed, None))
                position = image.find(pattern, position + 1, end)
    if "split" in kinds:
        split = _split_pointers(image, units, linear)
        hits.extend((low, 2, "split", f"{linear:04x}", None, details) for (low, _), details in sorted(split.items()))
    hits.sort(key=lambda hit: (hit[0], -hit[1]))
    unit_starts = [unit.image_offset for unit in units]
    matches = []
    for position, size, kind, value, backed, details in hits:
        if limit is not None and len(matches) >= limit:
            break
        unit = units[bisect_right(unit_starts, position) - 1]
        matches.append({**unit.location(position - unit.image_offset), "kind": kind, "size": size,
                        "value": value, "relocated": backed, **(details or {})})
    counts = {kind: sum(1 for hit in hits if hit[2] == kind) for kind in kinds}
    return {
        "target": locate(program, units, linear), "kinds": list(kinds), "count": len(hits), "counts": counts,
        "relocated": sum(1 for hit in hits if hit[4]), "has_relocations": relocations is not None,
        "matches": matches,
    }


# Relocations ---------------------------------------------------------------------------------------------------

def _range(program: dict, units: list[ImageUnit], text: str | None, size: int | None) -> tuple[int, int] | None:
    if text is None:
        return None
    start = resolve_address(program, units, text)["linear"]
    return start, start + (size or 1)


def find_relocations(
    export: Path, *, unit: str | None = None, at: str | None = None, target: str | None = None,
    size: int | None = None, limit: int | None = None, offset: int = 0,
) -> dict:
    """List loader relocations, optionally only those in a unit, at a site range, or pointing into a target.

    DOS relocations patch segment words; their `value` is the relocated segment and a target matches when
    that segment equals the target's segment. 68k relocations report the resolved linear target.
    """
    if size is not None and (type(size) is not int or size < 1):
        raise SearchError("size must be a positive integer")
    if type(offset) is not int or offset < 0 or (limit is not None and (type(limit) is not int or limit < 1)):
        raise SearchError("limit must be positive and offset nonnegative")
    image, program, units = _load(export)
    image_format = program.get("format", "MZ")
    site_range = _range(program, units, at, size)
    selected_unit = None
    if unit is not None:
        selected_unit = next((item for item in units if item.name.casefold() == unit.casefold()), None)
        if selected_unit is None:
            raise SearchError(f"unknown unit {unit!r}")
    unit_starts = [item.image_offset for item in units]
    records = []
    if image_format == "MZ":
        target_segment = None if target is None else resolve_address(program, units, target)["segment"]
        by_segment = {item.segment: item.name for item in units}
        for unit in program["units"]:
            for displacement in unit.get("segment_offsets", ()):
                by_segment[unit["segment"] + displacement // 16] = unit["name"]
        for position in program.get("relocations", ()):
            owner = units[bisect_right(unit_starts, position) - 1]
            segment = int.from_bytes(image[position:position + 2], "little")
            if target_segment is not None and segment != target_segment:
                continue
            records.append((position, owner, {"value": f"{segment:04x}", "segment_unit": by_segment.get(segment)}))
    elif image_format in M68K_FORMATS:
        target_range = _range(program, units, target, size)
        by_name = {item.name: item for item in units}
        for record in program["units"]:
            owner = by_name[record["name"]]
            for reloc in record.get("relocations", ()):
                value = reloc["value"]
                target_linear = reloc.get("target_linear", value)
                if target_range and not target_range[0] <= target_linear < target_range[1]:
                    continue
                extra = {
                    "value": f"{value:08x}",
                    "target": locate(program, units, target_linear), "original": reloc["original"],
                }
                if "kind" in reloc:
                    extra.update(kind=reloc["kind"], width=reloc["width"])
                if "target" in reloc:
                    extra["hunk"] = reloc["target"]
                records.append((owner.image_offset + reloc["offset"], owner, extra))
    rows = []
    for position, owner, extra in sorted(records, key=lambda row: row[0]):
        linear = owner.linear + position - owner.image_offset
        if selected_unit is not None and owner is not selected_unit:
            continue
        if site_range and not site_range[0] <= linear < site_range[1]:
            continue
        rows.append({**owner.location(position - owner.image_offset), **extra})
    page = rows[offset:] if limit is None else rows[offset:offset + limit]
    return {
        "has_relocations": image_format == "MZ" or (image_format in M68K_FORMATS and image_format != GENESIS_FORMAT),
        "count": len(rows), "relocations": page,
        "pagination": {"offset": offset, "total": len(rows), "returned": len(page),
                       "next_offset": offset + len(page) if offset + len(page) < len(rows) else None},
    }


# Symbols -------------------------------------------------------------------------------------------------------

def program_symbols(program: dict, units: list[ImageUnit]) -> list[dict]:
    """Collect named addresses from map.json: unit symbols, entries, overlay entries and stubs, runtime
    signatures, hardware labels, memory regions, and unit starts. Names follow the Ghidra importers."""
    symbols = []

    def add(name: str, kind: str, linear: int, size: int | None = None) -> None:
        row = {"name": name, "kind": kind, **locate(program, units, linear)}
        if size is not None:
            row["size"] = size
        symbols.append(row)

    by_name = {unit.name: unit for unit in units}
    for unit in program["units"]:
        placed = by_name[unit["name"]]
        add(unit["name"], "unit", placed.linear, placed.size)
        for symbol in unit.get("symbols", ()):
            add(symbol["name"], "symbol", placed.linear + symbol["offset"])
        if segmented(program):
            for entry in unit.get("entries", ()):
                add(f"{unit['name']}_{entry:04x}", "overlay_entry", placed.linear + entry)
    entry = program.get("entry")
    if entry:
        add("entry", "entry", entry["linear"])
    for other in program.get("entries", ())[1:]:
        add(f"entry_{other['linear']:04x}", "entry", other["linear"])
    for stub in program.get("stubs", ()):
        add(f"stub_{stub['unit']}_{stub['address']['offset']:04x}", "stub", stub["address"]["linear"])
    for signature in program.get("runtime_signatures", ()):
        add(signature["name"], "runtime", signature["address"]["linear"])
    for symbol in program.get("toolchain_symbols", ()):
        add(symbol["name"], symbol["kind"], symbol["linear"])
        symbols[-1]["source"] = symbol["source"]
    for label in program.get("hardware_labels", ()):
        add(label["name"], "hardware", label["linear"])
    for region in program.get("memory_map", ()):
        add(region["name"], "region", region["linear"], region["size"])
    return symbols


def lookup_symbols(
    export: Path, *, name: str | None = None, address: str | None = None, ignore_case: bool = False,
    limit: int | None = None,
) -> dict:
    """Find symbols by exact name or * and ? pattern, or report the nearest symbol at or below an address."""
    if (name is None) == (address is None):
        raise SearchError("specify exactly one of name or address")
    image_size = (export / "image.bin").stat().st_size
    program = read_map(export)
    units = image_units(program, image_size)
    symbols = program_symbols(program, units)
    if name is not None:
        if not isinstance(name, str) or not name:
            raise SearchError("name must be a nonempty string")
        fold = str.casefold if ignore_case else (lambda value: value)
        wanted = fold(name)
        matched = [row for row in symbols if fnmatch.fnmatchcase(fold(row["name"]), wanted)]
        page = matched if limit is None else matched[:limit]
        return {"name": name, "count": len(matched), "symbols": page}
    linear = resolve_address(program, units, address)["linear"]
    points = sorted((row for row in symbols if row["kind"] not in ("unit", "region")), key=lambda row: row["linear"])
    keys = [row["linear"] for row in points]
    index = bisect_right(keys, linear) - 1
    nearest = None
    if index >= 0:
        same = [row for row in points if row["linear"] == keys[index]]
        nearest = {**same[0], "distance": linear - keys[index]}
        if len(same) > 1:
            nearest["aliases"] = [row["name"] for row in same[1:]]
    following = next((row for row in points if row["linear"] > linear), None)
    containing = [row["name"] for row in symbols if row["kind"] in ("unit", "region")
                  and row["linear"] <= linear < row["linear"] + max(row.get("size", 0), 1)]
    return {"address": locate(program, units, linear), "nearest": nearest,
            "next": None if following is None else {**following, "distance": following["linear"] - linear},
            "containing": containing}
