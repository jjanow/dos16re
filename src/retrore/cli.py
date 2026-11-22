"""Inspect and analyze DOS, AmigaDOS, Atari ST, Commodore 64, Apple II, and Atari 8-bit programs."""

import argparse
import json
import sys
from contextlib import ExitStack
from pathlib import Path

from .amiga import HUNK_MAGIC, HunkError, build_hunk_image
from .apple2 import DEFAULT_LC, DISK_SUFFIXES, Apple2Error, Apple2Unit, Binary, SectorImage, build_apple2_image
from .atari8 import (
    ATR_MAGIC, DEFAULT_PORTB, XEX_MAGIC, Atari8Binary, Atari8Error, Atari8Source, AtrImage, Segment, build_atari8_image,
)
from .atari_st import PRG_MAGIC, PrgError, build_prg_image
from .c64 import DEFAULT_BANK, C64Error, D64Image, PrgUnit, build_c64_image
from .emulator import DEFAULT_INSTRUCTION_LIMIT, Emulator, EmulatorError
from .ghidra import GhidraError, analysis_gaps, decompile, import_program, query_address, query_batch
from .image import APPLE2_FORMAT, ATARI8_FORMAT, DEFAULT_M68K_BASE, MOS6502_FORMATS, ImageError
from .mz import DEFAULT_BASE_SEGMENT, MZError, MZExecutable, UnsupportedPacker
from .overlays import Overlay, address_record, build_image
from .search import SearchError, find_bytes
from .trace import TraceError, import_trace

_PREVIEW_LIMIT = 10


def _hex_segment(value: str) -> int:
    try:
        segment = int(value, 16)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a hexadecimal segment") from None
    if not 0 <= segment <= 0xFFFF:
        raise argparse.ArgumentTypeError("segment must be between 0000 and ffff")
    return segment


def _hex_address(value: str) -> int:
    try:
        return int(value, 16)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a hexadecimal address") from None


def _overlay(value: str) -> tuple[Path, int | None]:
    path, suffix, segment = value.rpartition("@")
    if suffix:
        return Path(path), _hex_segment(segment)
    return Path(value), None


def _unit_path(value: str) -> tuple[Path, int | None]:
    path, suffix, address = value.rpartition("@")
    if suffix:
        return Path(path), _hex_address(address)
    return Path(value), None


def _c64_image(args: argparse.Namespace, data: bytes) -> tuple[bytes, dict]:
    if args.base_segment is not None or args.overlay:
        raise C64Error("--base-segment and --overlay apply to DOS executables")
    source = args.program.name
    if args.disk_file:
        disk = D64Image(data)
        units = [
            PrgUnit(
                "root" if index == 0 else name, source, disk.read_prg(name),
                address=args.base_address if index == 0 else None, disk_file=name.upper(),
            )
            for index, name in enumerate(args.disk_file)
        ]
    elif args.program.suffix.lower() == ".d64":
        raise C64Error("select a D64 program with --disk-file NAME")
    else:
        units = [PrgUnit("root", source, data, args.base_address)]
    units.extend(PrgUnit(path.stem, path.name, path.read_bytes(), address) for path, address in args.c64_unit)
    bank = DEFAULT_BANK if args.c64_bank is None else args.c64_bank
    return build_c64_image(units, source, bank=bank, entries=args.entry)


def _apple2_image(args: argparse.Namespace, data: bytes) -> tuple[bytes, dict]:
    if args.base_segment is not None or args.overlay:
        raise Apple2Error("--base-segment and --overlay apply to DOS executables")
    if args.c64 or args.c64_unit or args.c64_bank is not None:
        raise Apple2Error("C64 options require a Commodore 64 program")
    source = args.program.name
    disk = None
    if args.apple2_raw:
        if args.disk_file or args.apple2_disk_order:
            raise Apple2Error("--apple2-raw cannot be used with Apple II disk options")
        units = [Apple2Unit("root", source, Binary(data, None), args.base_address)]
    elif args.disk_file or args.program.suffix.lower() in DISK_SUFFIXES or args.apple2_disk_order:
        if not args.disk_file:
            raise Apple2Error("select an Apple II disk binary with --disk-file NAME")
        order = args.apple2_disk_order
        if order is None and args.program.suffix.lower() == ".po":
            order = "prodos"
        disk = SectorImage(data, order=order)
        units = [
            Apple2Unit("root" if index == 0 else name, source, disk.read_binary(name),
                       args.base_address if index == 0 else None, name.upper())
            for index, name in enumerate(args.disk_file)
        ]
    else:
        units = [Apple2Unit("root", source, Binary.from_dos(data, source), args.base_address)]

    for path, address in args.apple2_unit:
        contents = path.read_bytes()
        binary = Binary.from_dos(contents, path.name) if address is None else Binary(contents, None)
        units.append(Apple2Unit(path.stem, path.name, binary, address))
    lc = DEFAULT_LC if args.apple2_lc is None else args.apple2_lc
    image, program = build_apple2_image(units, source, lc=lc, entries=args.entry)
    if disk is not None:
        program["disk"] = {"filesystem": disk.filesystem, "sector_order": disk.order}
    return image, program


def _atari8_image(args: argparse.Namespace, data: bytes) -> tuple[bytes, dict]:
    if args.base_segment is not None or args.overlay:
        raise Atari8Error("--base-segment and --overlay apply to DOS executables")
    if args.c64_unit or args.c64_bank is not None:
        raise Atari8Error("C64 options require a Commodore 64 program")
    if args.apple2_unit or args.apple2_lc is not None or args.apple2_disk_order:
        raise Atari8Error("Apple II options require an Apple II program")
    source = args.program.name
    is_disk = args.program.suffix.lower() == ".atr" or data.startswith(ATR_MAGIC)
    disk = None
    if args.atari8_raw:
        if args.disk_file or args.base_address is None:
            raise Atari8Error("--atari8-raw needs --base-address and accepts a standalone file")
        sources = [Atari8Source("root", source, Atari8Binary((Segment(args.base_address, data),), "raw"))]
    elif args.base_address is not None:
        raise Atari8Error("--base-address requires --atari8-raw for Atari 8-bit programs")
    elif is_disk or args.disk_file:
        disk = AtrImage(data)
        if args.disk_file:
            sources = [
                Atari8Source("root" if index == 0 else name.upper(), source,
                             Atari8Binary.from_xex(disk.read_file(name), name), name.upper())
                for index, name in enumerate(args.disk_file)
            ]
        else:
            sources = [Atari8Source("root", source, disk.boot_binary())]
    else:
        sources = [Atari8Source("root", source, Atari8Binary.from_xex(data, source))]
    for path, address in args.atari8_unit:
        contents = path.read_bytes()
        binary = (Atari8Binary.from_xex(contents, path.name) if address is None
                  else Atari8Binary((Segment(address, contents),), "raw"))
        sources.append(Atari8Source(path.stem, path.name, binary))
    portb = DEFAULT_PORTB if args.atari8_portb is None else args.atari8_portb
    image, program = build_atari8_image(sources, source, portb=portb, entries=args.entry)
    if disk is not None:
        program["disk"] = {"sector_size": disk.sector_size, "sector_count": disk.sector_count}
    return image, program


def _export_image(output: Path, image: bytes, program_map: dict) -> None:
    output.mkdir(parents=True, exist_ok=True)
    image_path = output / "image.bin"
    map_path = output / "map.json"
    map_text = json.dumps(program_map, indent=2) + "\n"

    with ExitStack() as rollback:
        with image_path.open("xb") as image_file:
            rollback.callback(image_path.unlink)
            image_file.write(image)
        with map_path.open("x", encoding="utf-8") as map_file:
            rollback.callback(map_path.unlink)
            map_file.write(map_text)
        rollback.pop_all()


def _assignment(text: str, expected: str) -> tuple[str, str]:
    key, equals, value = text.partition("=")
    if not equals or not key or not value:
        raise ValueError(f"expected {expected}, got {text!r}")
    return key, value


def _call(args: argparse.Namespace) -> None:
    regs = {}
    writes = []
    reads = []
    try:
        for group in args.regs:
            for assignment in group.split(","):
                name, value = _assignment(assignment, "REG=HEX")
                regs[name.strip()] = int(value, 16)
        for assignment in args.mem:
            address, value = _assignment(assignment, "ADDR=HEXBYTES")
            writes.append((address, bytes.fromhex(value)))
        for assignment in args.read:
            address, value = _assignment(assignment, "ADDR=SIZE")
            base = 16 if value.lower().startswith("0x") else 10
            reads.append((address, int(value, base)))
        limit = int(args.limit)
    except ValueError as error:
        raise EmulatorError(str(error)) from error
    result = Emulator.from_export(args.export).call(
        args.address, regs=regs, writes=writes, reads=reads, far=args.far, limit=limit,
    )
    if args.json:
        print(json.dumps({
            "address": address_record(result.address),
            "registers": result.registers,
            "memory": [{"address": address_record(address), "data": data.hex()} for address, data in result.memory],
        }))
    else:
        print(f"Returned from {result.address}  AX={result.registers['ax']:04x} DX={result.registers['dx']:04x}")
        for address, data in result.memory:
            print(f"{address}  {data.hex()}")


def _location(record: dict) -> str:
    return record["unit_address"] or record["address"]


def _print_references(groups: tuple[str, ...], report: dict) -> None:
    remaining = _PREVIEW_LIMIT
    for group in groups:
        references = report[group]
        print(f"{len(references)} {group}")
        for reference in references[:remaining]:
            source = _location(reference["from"])
            target = _location(reference["to"])
            peer = reference["to_function" if group in ("outgoing", "callees") else "from_function"]
            name = f"  {peer['name']}" if peer else ""
            print(f"  {source} -> {target}  {reference['type']}{name}")
        remaining = max(0, remaining - len(references))
    if sum(len(report[group]) for group in groups) > _PREVIEW_LIMIT:
        print("Use --json for all references.")


def _address_query(args: argparse.Namespace) -> None:
    report = query_address(args.command, args.address, args.project)
    if args.json:
        print(json.dumps(report))
        return
    if args.command == "xrefs":
        print(_location(report["address"]))
        _print_references(("incoming", "outgoing"), report)
        return

    function = report["function"]
    print(f"{_location(function['entry'])}  {function['name']}")
    if args.command == "func":
        ranges = report["ranges"]
        start = _location(ranges[0]["start"])
        end = _location(ranges[-1]["end"])
        print(f"{start}–{end}  {report['size']} bytes in {len(ranges)} ranges")
        segments = " ".join(
            f"{name}={value:04x}" if value is not None else f"{name}=?"
            for name, value in report["segments"].items()
        )
        if segments:
            print(f"{_location(report['address'])}  {segments}")
    _print_references(("callers" if args.command == "func" else args.command,), report)


def _batch(args: argparse.Namespace) -> int:
    try:
        data = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")
        requests = json.loads(data)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise GhidraError(f"invalid batch JSON: {error}") from error

    report = query_batch(args.project, requests)
    results = report["results"]
    errors = [row for row in results if "error" in row]
    if args.json:
        print(json.dumps(report))
    else:
        print(f"{len(results) - len(errors)}/{len(results)} queries succeeded")
        for row in errors[:_PREVIEW_LIMIT]:
            print(f"  {row['command']} {row['address']}: {row['error']}")
    return int(bool(errors))


def _where_is(args: argparse.Namespace) -> None:
    if args.width is not None and args.constant is None:
        raise SearchError("--width requires --constant")
    try:
        if args.bytes is not None:
            pattern = bytes.fromhex(args.bytes)
        elif args.string is not None:
            pattern = args.string
        else:
            base = 16 if args.constant.lstrip("+-").lower().startswith("0x") else 10
            pattern = int(args.constant, base)
    except ValueError as error:
        raise SearchError(str(error)) from error
    report = find_bytes(args.export, pattern, width=args.width or 2, limit=None if args.json else _PREVIEW_LIMIT)
    if args.json:
        print(json.dumps(report))
        return
    print(f"{report['count']} matches")
    for match in report["matches"]:
        print(f"{match['unit_address']}  {match['address']}")
    if report["count"] > _PREVIEW_LIMIT:
        print("Use --json for all matches.")


def _trace(args: argparse.Namespace) -> None:
    overlay_segments = {}
    try:
        for value in args.overlay_segment:
            name, segment = _assignment(value, "UNIT=HEX")
            name = name.casefold()
            if name in overlay_segments:
                raise ValueError(f"runtime segment specified twice for {name}")
            overlay_segments[name] = _hex_segment(segment)
    except (ValueError, argparse.ArgumentTypeError) as error:
        raise TraceError(str(error)) from error
    report = import_trace(
        args.trace, args.export, runtime_base=args.runtime_base, overlay_segments=overlay_segments, project=args.project,
    )
    if args.json:
        print(json.dumps(report))
        return
    mapped, unmapped = report["mapped"], report["unmapped"]
    print(f"{report['instructions']} instruction records, {len(mapped)} mapped addresses, {len(unmapped)} unmapped")
    analysis = report["analysis"]
    if analysis is None:
        rows = [f"{_location(hit)}  {hit['count']} hits" for hit in mapped[:_PREVIEW_LIMIT]]
        total = len(mapped)
    else:
        functions, missed = analysis["functions"], analysis["missed"]
        print(f"{len(functions)} executed functions, {len(missed)} addresses missed by disassembly")
        rows = [f"{_location(hit)}  {hit['reason']}" for hit in missed[:_PREVIEW_LIMIT]]
        for entry in functions[:_PREVIEW_LIMIT - len(rows)]:
            function = entry["function"]
            rows.append(f"{_location(function['entry'])}  {function['name']}  {entry['count']} hits")
        total = len(functions) + len(missed)
    for row in rows:
        print(f"  {row}")
    if total > _PREVIEW_LIMIT or unmapped or report["ignored_lines"]:
        print("Use --json for the full trace report.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="retrore", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    load_parser = commands.add_parser("load", help="export a program image")
    load_parser.add_argument("-o", "--output", type=Path, required=True, metavar="OUT")
    info_parser = commands.add_parser("info", help="summarize a program image")

    for command in (load_parser, info_parser):
        command.add_argument("program", type=Path, metavar="PROGRAM")
        base = command.add_mutually_exclusive_group()
        base.add_argument(
            "--base-segment",
            type=_hex_segment,
            metavar="HEX",
            help=f"DOS load segment (default: {DEFAULT_BASE_SEGMENT:04x})",
        )
        base.add_argument(
            "--base-address", type=_hex_address, metavar="HEX",
            help=f"Amiga/Atari ST base (default {DEFAULT_M68K_BASE:06x}) or C64/Apple II/raw Atari 8-bit load address",
        )
        command.add_argument("--json", action="store_true", help="print JSON")
        command.add_argument(
            "--overlay", type=_overlay, action="append", default=[], metavar="FILE[@SEG]",
            help="add a Turbo Pascal overlay bank or raw overlay (optionally at hex SEG)",
        )
        platform = command.add_mutually_exclusive_group()
        platform.add_argument("--c64", action="store_true", help="interpret the input as a Commodore 64 program")
        platform.add_argument("--apple2", action="store_true", help="interpret the input as an Apple II program")
        platform.add_argument("--apple2-raw", action="store_true", help="load raw Apple II bytes at --base-address")
        platform.add_argument("--atari8", action="store_true", help="interpret the input as an Atari 8-bit program")
        platform.add_argument("--atari8-raw", action="store_true", help="load raw Atari 8-bit bytes at --base-address")
        command.add_argument(
            "--disk-file", action="append", default=[], metavar="NAME",
            help="select a D64 PRG, Apple II binary, or ATR XEX (first is root, repeat for additional files)",
        )
        command.add_argument(
            "--c64-unit", type=_unit_path, action="append", default=[], metavar="FILE[@HEX]",
            help="add a co-resident PRG file (optional hex load address override)",
        )
        command.add_argument(
            "--c64-bank", type=_hex_address, metavar="HEX",
            help=f"effective C64 bank bits CHAREN/HIRAM/LORAM (0–7, default {DEFAULT_BANK})",
        )
        command.add_argument(
            "--apple2-unit", type=_unit_path, action="append", default=[], metavar="FILE[@HEX]",
            help="add a co-resident DOS binary or raw Apple II file at @HEX",
        )
        command.add_argument(
            "--apple2-disk-order", choices=("dos", "prodos", "physical"),
            help="override Apple II sector ordering and interpret the input as a sector image",
        )
        command.add_argument(
            "--apple2-lc", type=_hex_address, metavar="HEX",
            help=f"effective Apple II Language Card switch (c080–c08f, default {DEFAULT_LC:04x})",
        )
        command.add_argument(
            "--atari8-unit", type=_unit_path, action="append", default=[], metavar="FILE[@HEX]",
            help="load an additional Atari XEX or raw file at @HEX",
        )
        command.add_argument(
            "--atari8-portb", type=_hex_address, metavar="HEX",
            help=f"effective Atari XL/XE PORTB byte (default {DEFAULT_PORTB:02x})",
        )
        command.add_argument(
            "--entry", type=_hex_address, action="append", default=[], metavar="HEX",
            help="seed C64, Apple II, or Atari 8-bit machine-code analysis at this address (repeatable)",
        )

    ghidra_parser = commands.add_parser("ghidra", help="manage a headless Ghidra import")
    ghidra_commands = ghidra_parser.add_subparsers(dest="ghidra_command", required=True)
    import_parser = ghidra_commands.add_parser("import", help="import and analyze an exported image")
    import_parser.add_argument("export", metavar="OUT", type=Path)
    import_parser.add_argument("project", metavar="PROJECT", type=Path)
    decomp_parser = commands.add_parser("decomp", help="decompile a function in a Ghidra project")
    decomp_parser.add_argument("address", metavar="ADDR")
    decomp_parser.add_argument("--project", metavar="PROJECT", type=Path, required=True)
    gaps_parser = commands.add_parser("gaps", help="report undefined ranges in an analyzed Ghidra project")
    gaps_parser.add_argument("--project", metavar="PROJECT", type=Path, required=True)
    batch_parser = commands.add_parser("batch", help="run multiple address queries in one Ghidra session")
    batch_parser.add_argument("input", metavar="FILE", nargs="?", default="-", help="JSON request file (default: stdin)")
    batch_parser.add_argument("--project", metavar="PROJECT", type=Path, required=True)
    address_queries = {
        "xrefs": "list references to and from an address",
        "callers": "list calls to a function",
        "callees": "list calls made by a function",
        "func": "report a function's bounds, segment context, and callers",
    }
    for name, help_text in address_queries.items():
        query_parser = commands.add_parser(name, help=help_text)
        query_parser.add_argument("address", metavar="ADDR", help="hexadecimal unit:offset, DOS seg:off, or flat address")
        query_parser.add_argument("--project", metavar="PROJECT", type=Path, required=True)
        query_parser.add_argument("--json", action="store_true", help="print JSON")

    search_parser = commands.add_parser("where-is", help="find a byte pattern across exported units")
    search_parser.add_argument("--export", metavar="OUT", type=Path, required=True, help="directory from retrore load")
    pattern = search_parser.add_mutually_exclusive_group(required=True)
    pattern.add_argument("--bytes", metavar="HEX", help="hexadecimal bytes")
    pattern.add_argument("--string", metavar="TEXT", help="literal string in the image's supported encoding")
    pattern.add_argument("--constant", metavar="N", help="decimal or 0x-prefixed integer in the image's byte order")
    search_parser.add_argument("--width", type=int, choices=(1, 2, 4, 8), help="constant width in bytes (default 2)")
    call_parser = commands.add_parser("call", help="run a routine in an exported DOS image")
    call_parser.add_argument("address", metavar="ADDR", help="hexadecimal seg:off or unit:offset")
    call_parser.add_argument("--export", metavar="OUT", type=Path, required=True, help="directory from retrore load")
    call_parser.add_argument("--far", action="store_true", help="expect RETF (default: near RET)")
    call_parser.add_argument("--regs", action="append", default=[], metavar="REG=HEX,...", help="set initial registers")
    call_parser.add_argument(
        "--mem", action="append", default=[], metavar="ADDR=HEXBYTES", help="write memory before call",
    )
    call_parser.add_argument(
        "--read", action="append", default=[], metavar="ADDR=SIZE", help="read memory after return",
    )
    call_parser.add_argument(
        "--limit", default=DEFAULT_INSTRUCTION_LIMIT, metavar="N",
        help=f"maximum instructions (default: {DEFAULT_INSTRUCTION_LIMIT})",
    )
    trace_parser = commands.add_parser("trace", help="map a DOSBox-X CPU log to an exported DOS image")
    trace_parser.add_argument("trace", metavar="LOGCPU.TXT", type=Path)
    trace_parser.add_argument("--export", metavar="OUT", type=Path, required=True, help="directory from retrore load")
    trace_parser.add_argument("--project", metavar="PROJECT", type=Path, help="compare with the analyzed Ghidra project")
    trace_parser.add_argument(
        "--runtime-base", metavar="HEX", type=_hex_segment, help="runtime root load segment (defaults to the export base)",
    )
    trace_parser.add_argument(
        "--overlay-segment", metavar="UNIT=HEX", action="append", default=[], help="map an overlay at its runtime segment",
    )
    for command in (import_parser, decomp_parser, gaps_parser, batch_parser, search_parser, call_parser, trace_parser):
        command.add_argument("--json", action="store_true", help="print JSON")

    args = parser.parse_args(argv)
    try:
        if args.command == "batch":
            return _batch(args)
        if args.command == "ghidra":
            report = import_program(args.export, args.project)
            summary = f"Imported {report['units']} units into {args.project}"
            print(json.dumps(report) if args.json else summary)
            return 0
        if args.command == "decomp":
            report = decompile(args.address, args.project)
            print(json.dumps(report) if args.json else report["decompilation"].strip())
            return 0
        if args.command == "gaps":
            report = analysis_gaps(args.project)
            if args.json:
                print(json.dumps(report))
            else:
                ranges = report["ranges"]
                print(f"{report['undefined_bytes']} undefined bytes in {len(ranges)} ranges")
                for gap in ranges[:10]:
                    print(f"{gap['start']}–{gap['end']}  {gap['size']} bytes")
                if len(ranges) > 10:
                    print("Use --json for all ranges.")
            return 0
        if args.command == "call":
            _call(args)
            return 0
        if args.command in address_queries:
            _address_query(args)
            return 0
        if args.command == "where-is":
            _where_is(args)
            return 0
        if args.command == "trace":
            _trace(args)
            return 0
        data = args.program.read_bytes()
        hunk = data.startswith(HUNK_MAGIC)
        m68k = hunk or data.startswith(PRG_MAGIC)
        extension = args.program.suffix.lower()
        atari8 = args.atari8 or args.atari8_raw or (
            not (args.c64 or args.apple2 or args.apple2_raw or args.apple2_disk_order or extension in DISK_SUFFIXES)
            and (extension in (".atr", ".xex") or
                 extension not in (".d64", ".prg") and data.startswith((ATR_MAGIC, XEX_MAGIC)))
        )
        if atari8:
            image, program_map = _atari8_image(args, data)
        elif args.atari8_unit or args.atari8_portb is not None:
            raise Atari8Error("--atari8-unit and --atari8-portb require an Atari 8-bit program")
        elif args.apple2 or args.apple2_raw or args.apple2_disk_order or (not args.c64 and extension in DISK_SUFFIXES):
            image, program_map = _apple2_image(args, data)
        elif args.apple2_unit or args.apple2_lc is not None:
            raise Apple2Error("--apple2-unit and --apple2-lc require an Apple II program")
        elif args.c64 or args.disk_file or extension == ".d64" or (
            extension == ".prg" and not (m68k or data.startswith(b"MZ"))
        ):
            image, program_map = _c64_image(args, data)
        elif args.c64_unit or args.c64_bank is not None or args.entry:
            raise C64Error("--c64-unit and --c64-bank require C64, while --entry accepts C64, Apple II, or Atari 8-bit")
        elif m68k:
            if args.base_segment is not None or args.overlay:
                raise MZError("--base-segment and --overlay apply to DOS executables")
            base_address = DEFAULT_M68K_BASE if args.base_address is None else args.base_address
            loader = build_hunk_image if hunk else build_prg_image
            image, program_map = loader(data, args.program.name, base_address)
        else:
            if args.base_address is not None:
                raise MZError("--base-address applies to Amiga, Atari ST, C64, Apple II, and raw Atari 8-bit programs")
            executable = MZExecutable.parse(data)
            base_segment = DEFAULT_BASE_SEGMENT if args.base_segment is None else args.base_segment
            loaded = executable.load(base_segment)
            overlays = [
                Overlay(path.name, path.stem, path.read_bytes(), segment)
                for path, segment in args.overlay
            ]
            image, program_map = build_image(loaded, args.program.name, overlays)
        if args.command == "load":
            _export_image(args.output, image, program_map)
    except (Apple2Error, Atari8Error, C64Error, EmulatorError, GhidraError, HunkError, ImageError, MZError, PrgError, SearchError,
            TraceError, OSError) as error:
        report = {"error": str(error)}
        if isinstance(error, UnsupportedPacker):
            report["packer"] = error.packer
        message = json.dumps(report) if args.json else f"retrore: {error}"
        print(message, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(program_map))
    elif args.command == "load":
        print(f"Wrote image.bin and map.json to {args.output}")
    elif program_map["format"] == "HUNK":
        print(f"Amiga Hunk  entry h0:0000 ({base_address:06x})  {len(program_map['units'])} hunks")
    elif program_map["format"] == "PRG":
        print(f"Atari ST GEMDOS  entry text:0000 ({base_address:06x})")
        print("  ".join(f"{unit['name'].upper()} {unit['size']} bytes" for unit in program_map["units"]))
    elif program_map["format"] in MOS6502_FORMATS:
        entries = program_map["entries"]
        if program_map["format"] == APPLE2_FORMAT:
            platform = f"Apple II  LC {program_map['language_card']:04x}"
        elif program_map["format"] == ATARI8_FORMAT:
            platform = f"Atari 8-bit  PORTB {program_map['portb']:02x}"
        else:
            platform = f"C64 PRG  bank {program_map['bank']}"
        print(f"{platform}  {len(program_map['units'])} units  {len(entries)} entry points")
        if entries:
            addresses = ", ".join(f"{entry['linear']:04x}" for entry in entries[:_PREVIEW_LIMIT])
            print(f"  entries  {addresses}")
        for unit in program_map["units"][:_PREVIEW_LIMIT]:
            print(f"  {unit['name']}  {unit['linear']:04x}  {unit['size']} bytes")
    else:
        packer = f" ({loaded.packer})" if loaded.packer else ""
        print(f"MZ{packer}  entry {loaded.entry}  stack {loaded.stack}")
        print(f"root  {loaded.base_segment:04x}:0000  {len(loaded.image)} bytes")
        compiler = program_map["compiler"]
        if compiler:
            identity = " ".join(filter(None, (compiler["family"], compiler["version"])))
            print(f"compiler  {identity}")
        if overlays:
            unit_count = len(program_map["units"]) - 1
            stub_count = len(program_map.get("stubs", []))
            print(f"{unit_count} overlay units, {stub_count} stubs")
    return 0
