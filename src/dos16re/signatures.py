"""Recognize compiler startups and runtime routines measured with DOS probes (see PLAN.md)."""

import re
from dataclasses import dataclass
from struct import unpack_from

from .mz import LoadedMZ


def _pattern(hex_bytes: str) -> re.Pattern[bytes]:
    return re.compile(b"".join(
        b"." if token == "??" else re.escape(bytes.fromhex(token))
        for token in hex_bytes.split()
    ), re.DOTALL)


@dataclass(frozen=True)
class Compiler:
    group: str
    family: str
    version: str | None
    evidence: str


_PASCAL_ENTRY = "ba ?? ?? 8e da 8c 06 ?? ?? 33 ed "
_PASCAL_HEAP = "8b c4 05 13 00 b1 04 d3 e8 8c d2 03 c2 a3 ?? ?? a3 ?? ?? 03 06 ?? ?? a3 ?? ?? a3 ?? ?? a3 ?? ?? "
_PASCAL_STARTUPS = (
    ("5.5", _pattern(_PASCAL_ENTRY + _PASCAL_HEAP + "26 a1 02 00")),
    ("6.0", _pattern(_PASCAL_ENTRY + _PASCAL_HEAP + "a3 ?? ?? 26 8b 16 02 00")),
    ("7.0", _pattern(_PASCAL_ENTRY + "e8 ?? ?? e8 ?? ?? " + _PASCAL_HEAP)),
)
_BORLAND_C_START = _pattern("ba ?? ?? 2e 89 16 ?? ?? b4 30 cd 21 8b 2e 02 00 8b 1e 2c 00 8e da")
_BORLAND_C_MARKERS = (
    (b"Turbo-C - Copyright (c) 1988 Borland Intl.", "Turbo C", "2.x"),
    (b"Turbo C++ - Copyright 1990 Borland Intl.", "Turbo C++", None),
    (b"Borland C++ - Copyright 1991 Borland Intl.", "Borland C++", None),
)
_MICROSOFT_C_STARTUPS = (
    ("5.x", 11, _pattern("b4 30 cd 21 3c 02 73 02 cd 20 bf ?? ?? 8b 36 02 00 2b f7 81 fe 00 10")),
    ("6.x", 14, _pattern("b4 30 cd 21 3c 02 73 05 33 c0 06 50 cb bf ?? ?? 8b 36 02 00 2b f7 81 fe 00 10")),
)


def detect_compiler(root: LoadedMZ, *, pascal_overlays: bool) -> Compiler | None:
    image = root.image
    origin = root.base_segment * 16
    entry = root.entry.linear - origin
    if not 0 <= entry < len(image):
        return None
    relocations = {address.linear for address in root.relocations}

    if entry + 3 in relocations and image[entry:entry + 3] == b"\x9a\0\0":
        segment, = unpack_from("<H", image, entry + 3)
        startup = segment * 16 - origin
        if startup >= 0 and startup + 1 in relocations:
            for version, pattern in _PASCAL_STARTUPS:
                if pattern.match(image, startup):
                    return Compiler("pascal", "Turbo Pascal", version, "System unit startup")

    if entry + 1 in relocations and _BORLAND_C_START.match(image, entry):
        markers = [(family, version) for marker, family, version in _BORLAND_C_MARKERS if marker in image]
        if len(markers) == 1:
            family, version = markers[0]
            return Compiler("borland_c", family, version, "startup and runtime identification string")
        return Compiler("borland_c", "Borland C runtime", None, "startup")

    for version, relocation, pattern in _MICROSOFT_C_STARTUPS:
        if entry + relocation in relocations and pattern.match(image, entry):
            return Compiler("microsoft_c", "Microsoft C", version, "startup")

    if pascal_overlays:
        return Compiler("pascal", "Turbo Pascal", None, "Turbo Pascal overlay directory")
    return None


@dataclass(frozen=True)
class Parameter:
    name: str
    type: str
    registers: tuple[str, ...] = ()  # Most significant word first for joined storage.


@dataclass(frozen=True)
class Prototype:
    name: str
    result: str
    parameters: tuple[Parameter, ...]
    stack_purge: int | None = None  # Pascal RETF operand. None denotes near cdecl.
    result_registers: tuple[str, ...] = ()
    variadic: bool = False


def _pascal(name: str, stack_purge: int, *parameters: Parameter, result: str = "void") -> Prototype:
    return Prototype(name, result, parameters, stack_purge)


_SOURCE_DEST = (Parameter("source", "farptr"), Parameter("destination", "farptr"))
_WRITE_STRING = _pascal("System_WriteString", 6, Parameter("width", "int"), Parameter("value", "farptr"),
                        Parameter("text", "farptr"))
_WRITE_LN = _pascal("System_WriteLn", 4, Parameter("text", "farptr"))
_GET_MEM = _pascal("System_GetMem", 2, Parameter("size", "uint"), result="farptr")
_FREE_MEM = _pascal("System_FreeMem", 6, Parameter("size", "uint"), Parameter("memory", "farptr"))
_OVR_INIT = _pascal("Overlay_OvrInit", 4, Parameter("filename", "farptr"))

_PASCAL = (
    (Prototype("System_RAdd", "Real48", (
        Parameter("left", "Real48", ("DX", "BX", "AX")),
        Parameter("right", "Real48", ("DI", "SI", "CX")),
    ), stack_purge=0, result_registers=("DX", "BX", "AX")),
     "e8 ?? ?? 72 3b cb e8 ?? ?? 72 35 cb 8b c8 8b f3 8b fa e8 ?? ?? 72 29 cb"),
    (_pascal("System_StringCopy", 4, *_SOURCE_DEST),
     "fc 8b dc 8c da 36 c4 7f 08 36 c5 77 04 ac aa 8a c8 32 ed f3 a4 8e da ca 04 00"),
    (_pascal("System_StringConcat", 4, *_SOURCE_DEST),
     "fc 8b dc 8c da 36 c4 7f 08 36 c5 77 04 26 8a 0d 32 ed ac 26 00 05 73 08 26 c6 05 ff"),
    (_pascal("System_SetUnion", 4, *_SOURCE_DEST),
     "fc 8b dc 8c da 36 c4 7f 08 36 c5 77 04 b9 10 00 ad 26 0b 05 ab e2 f9 8e da ca 04 00"),
    (_WRITE_STRING, "55 8b ec 1e c4 7e 0c 06 57 e8 ?? ?? 75 25 c5 76 08 8b 4e 06 fc ac 32 e4 2b c8"),
    (_WRITE_STRING, "55 8b ec c4 5e 08 26 8a 07 32 e4 c4 5e 0c 8b 56 06 2b d0 7e 05 50 e8 ?? ?? 58"),
    (_WRITE_LN, "8b dc 36 c4 7f 04 06 57 e8 ?? ?? 75 0a b0 0d e8 ?? ?? b0 0a e8 ?? ?? 5f 07 26 89 5d 08"),
    (_WRITE_LN, "55 8b ec c4 7e 06 06 57 e8 ?? ?? 75 0a b0 0d e8 ?? ?? b0 0a e8 ?? ?? 5f 07 26 89 5d 08"),
    (_WRITE_LN, "55 8b ec c4 5e 06 b8 02 00 be ?? ?? 8c da e8 ?? ?? 75 0a 26 83 7f 1a 00 74 03 e8 ?? ?? 5d ca 04 00"),
    (_GET_MEM, "8b dc 36 8b 47 04 e8 ?? ?? 72 07 8b c1 8b d3 ca 02 00"),
    (_GET_MEM, "55 8b ec 8b 46 06 e8 c0 00 5d 72 03 ca 02 00"),
    (_FREE_MEM, "8b dc 36 8b 47 04 36 c4 4f 06 8c c3 e8 ?? ?? 72 03 ca 06 00"),
    (_FREE_MEM, "55 8b ec 8b 46 06 c4 4e 08 8c c3 e8 ?? ?? 5d 72 03 ca 06 00"),
    (_OVR_INIT, "55 8b ec 81 ec 82 00 fc 83 3e ?? ?? 00 74 1f a0 ?? ?? 88 46 fe e8 ?? ??"),
)

_STRCPY = Prototype("strcpy", "char*", (Parameter("destination", "char*"), Parameter("source", "char*")))
_STRLEN = Prototype("strlen", "uint", (Parameter("s", "char*"),))
_PUTS = Prototype("puts", "int", (Parameter("s", "char*"),))
_PRINTF = Prototype("printf", "int", (Parameter("format", "char*"),), variadic=True)
_MALLOC = Prototype("malloc", "void*", (Parameter("size", "uint"),))
_FREE = Prototype("free", "void", (Parameter("memory", "void*"),))

_BORLAND_C = (
    (_STRCPY, "55 8b ec 56 57 1e 07 fc 8b 7e 06 8b f7 32 c0 b9 ff ff f2 ae f7 d1 8b 7e 04 f3 a4 8b 46 04"),
    (_STRCPY, "55 8b ec 56 57 8c d8 8e c0 fc 8b 7e 06 8b f7 32 c0 b9 ff ff f2 ae f7 d1 8b 7e 04 f3 a4 8b 46 04"),
    (_STRLEN, "55 8b ec 56 57 1e 07 fc 8b 7e 04 32 c0 b9 ff ff f2 ae 8b c1 f7 d0 48"),
    (_STRLEN, "55 8b ec 57 8c d8 8e c0 8b 7e 04 33 c0 fc b9 ff ff f2 ae 91 f7 d0 48 5f 5d c3"),
    (_PUTS, "55 8b ec 56 57 8b 76 04 56 e8 ?? ?? 59 8b f8 56 57 b8 ?? ?? 50 e8 ?? ?? 3b c7 74 05 b8 ff ff"),
    (_PRINTF, "55 8b ec b8 ?? ?? 50 b8 ?? ?? 50 ff 76 04 8d 46 06 50 e8 ?? ?? eb 00"),
    (_PRINTF, "55 8b ec b8 ?? ?? 50 b8 ?? ?? 50 ff 76 04 8d 46 06 50 e8 ?? ?? 5d c3"),
    (_MALLOC, "55 8b ec 56 57 8b 7e 04 0b ff 74 05 83 ff f4 76 04 33 c0 eb"),
    (_MALLOC, "56 57 8b f4 8b 44 06 0b c0 74 52 05 05 00 72 36 25 fe ff 3d 08 00 73 03 b8 08 00"),
    (_FREE, "56 57 8b f4 8b 5c 06 83 eb 04 72 0e 3b 1e ?? ?? 74 05 e8 ?? ?? eb 03"),
)

_MICROSOFT_C = (
    (_STRCPY, "55 8b ec 8b d7 8b de 8b 76 06 8b fe 8c d8 8e c0 33 c0 b9 ff ff f2 ae f7 d1 8b 7e 04 8b c7"),
    (_STRLEN, "55 8b ec 8b d7 8c d8 8e c0 8b 7e 04 33 c0 b9 ff ff f2 ae f7 d1 49 91 8b fa 5d c3"),
    (_PUTS, "55 8b ec 83 ec 08 57 56 be ?? ?? ff 76 04 e8 ?? ?? 83 c4 02 8b f8 56 e8 ?? ?? 83 c4 02 89 46 fe"),
    (_PUTS, "55 8b ec 83 ec 06 57 56 ff 76 04 e8 ?? ?? 83 c4 02 8b f8 be ?? ?? 56 e8 ?? ?? 83 c4 02 89 46 fe"),
    (_PRINTF, "55 8b ec 83 ec 08 57 56 be ?? ?? 8d 46 06 89 46 fc 56 e8 ?? ?? 83 c4 02 8b f8 8d 46 06"),
    (_PRINTF, "55 8b ec 83 ec 04 57 56 be ?? ?? 56 e8 ?? ?? 83 c4 02 8b f8 8d 46 06 50 ff 76 04"),
    (_MALLOC, "55 8b ec 56 57 bb ?? ?? 83 3f 00 75 29 1e 07 b8 05 00 e8 ?? ?? 75 05 33 c0 99"),
    (_FREE, "55 8b ec 8b 5e 04 0b db 74 04 80 4f fe 01 8b e5 5d c3"),
    (Prototype("_nmalloc", _MALLOC.result, _MALLOC.parameters),
     "55 8b ec 56 57 8b 4e 04 83 f9 e8 77 12 bb ?? ?? e8 ?? ?? 73 0f e8 ?? ?? 72 05"),
    (Prototype("_nfree", _FREE.result, _FREE.parameters),
     "55 8b ec 56 8b 5e 04 be ?? ?? 39 5c 06 73 0d 4b 4b 80 0f 01 39 5c 08 76 03 89 5c 08"),
)

_CATALOG = {
    group: tuple((prototype, _pattern(pattern)) for prototype, pattern in entries)
    for group, entries in (("pascal", _PASCAL), ("borland_c", _BORLAND_C), ("microsoft_c", _MICROSOFT_C))
}


def match_runtime(compiler: Compiler, unit: bytes) -> list[tuple[int, Prototype]]:
    matches: dict[int, set[Prototype]] = {}
    for prototype, pattern in _CATALOG[compiler.group]:
        for match in pattern.finditer(unit):
            matches.setdefault(match.start(), set()).add(prototype)
    return [
        (offset, next(iter(choices)))
        for offset, choices in sorted(matches.items())
        if len(choices) == 1
    ]
