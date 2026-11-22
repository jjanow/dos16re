"""Command-line interface for inspecting, exporting, and running DOS code."""

import argparse
import json
import sys
from contextlib import ExitStack
from pathlib import Path

from .emulator import DEFAULT_INSTRUCTION_LIMIT, Emulator, EmulatorError
from .ghidra import GhidraError, analysis_gaps, decompile, import_program, query_address
from .image import ImageError
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


def _overlay(value: str) -> tuple[Path, int | None]:
    path, suffix, segment = value.rpartition("@")
    if suffix:
        return Path(path), _hex_segment(segment)
    return Path(value), None


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
        print(f"{_location(report['address'])}  {segments}")
    _print_references(("callers" if args.command == "func" else args.command,), report)


def _where_is(args: argparse.Namespace) -> None:
    if args.width is not None and args.constant is None:
        raise SearchError("--width requires --constant")
    try:
        if args.bytes is not None:
            pattern = bytes.fromhex(args.bytes)
        elif args.string is not None:
            pattern = args.string.encode("cp437")
        else:
            base = 16 if args.constant.lstrip("+-").lower().startswith("0x") else 10
            value = int(args.constant, base)
            pattern = value.to_bytes(args.width or 2, "little", signed=value < 0)
    except (ValueError, OverflowError) as error:
        raise SearchError(str(error)) from error
    report = find_bytes(args.export, pattern, limit=None if args.json else _PREVIEW_LIMIT)
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
    parser = argparse.ArgumentParser(prog="dos16re", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    load_parser = commands.add_parser("load", help="export a relocated DOS program and its overlays")
    load_parser.add_argument("-o", "--output", type=Path, required=True, metavar="OUT")
    info_parser = commands.add_parser("info", help="summarize an MZ load module")

    for command in (load_parser, info_parser):
        command.add_argument("program", type=Path, metavar="PROGRAM")
        command.add_argument(
            "--base-segment",
            type=_hex_segment,
            default=DEFAULT_BASE_SEGMENT,
            metavar="HEX",
            help=f"load segment (default: {DEFAULT_BASE_SEGMENT:04x})",
        )
        command.add_argument("--json", action="store_true", help="print JSON")
        command.add_argument(
            "--overlay", type=_overlay, action="append", default=[], metavar="FILE[@SEG]",
            help="add a Turbo Pascal overlay bank or raw overlay (optionally at hex SEG)",
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
    address_queries = {
        "xrefs": "list references to and from an address",
        "callers": "list calls to a function",
        "callees": "list calls made by a function",
        "func": "report a function's bounds, segment context, and callers",
    }
    for name, help_text in address_queries.items():
        query_parser = commands.add_parser(name, help=help_text)
        query_parser.add_argument("address", metavar="ADDR", help="hexadecimal seg:off or unit:offset")
        query_parser.add_argument("--project", metavar="PROJECT", type=Path, required=True)
        query_parser.add_argument("--json", action="store_true", help="print JSON")

    search_parser = commands.add_parser("where-is", help="find a byte pattern across exported units")
    search_parser.add_argument("--export", metavar="OUT", type=Path, required=True, help="directory from dos16re load")
    pattern = search_parser.add_mutually_exclusive_group(required=True)
    pattern.add_argument("--bytes", metavar="HEX", help="hexadecimal bytes")
    pattern.add_argument("--string", metavar="TEXT", help="literal DOS code page 437 string")
    pattern.add_argument("--constant", metavar="N", help="decimal or 0x-prefixed integer, encoded little-endian")
    search_parser.add_argument("--width", type=int, choices=(1, 2, 4, 8), help="constant width in bytes (default 2)")
    call_parser = commands.add_parser("call", help="run a routine in an exported DOS image")
    call_parser.add_argument("address", metavar="ADDR", help="hexadecimal seg:off or unit:offset")
    call_parser.add_argument("--export", metavar="OUT", type=Path, required=True, help="directory from dos16re load")
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
    trace_parser.add_argument("--export", metavar="OUT", type=Path, required=True, help="directory from dos16re load")
    trace_parser.add_argument("--project", metavar="PROJECT", type=Path, help="compare with the analyzed Ghidra project")
    trace_parser.add_argument(
        "--runtime-base", metavar="HEX", type=_hex_segment, help="runtime root load segment (defaults to the export base)",
    )
    trace_parser.add_argument(
        "--overlay-segment", metavar="UNIT=HEX", action="append", default=[], help="map an overlay at its runtime segment",
    )
    for command in (import_parser, decomp_parser, gaps_parser, search_parser, call_parser, trace_parser):
        command.add_argument("--json", action="store_true", help="print JSON")

    args = parser.parse_args(argv)
    try:
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
        executable = MZExecutable.parse(args.program.read_bytes())
        loaded = executable.load(args.base_segment)
        overlays = [
            Overlay(path.name, path.stem, path.read_bytes(), segment)
            for path, segment in args.overlay
        ]
        image, program_map = build_image(loaded, args.program.name, overlays)
        if args.command == "load":
            _export_image(args.output, image, program_map)
    except (EmulatorError, GhidraError, ImageError, MZError, SearchError, TraceError, OSError) as error:
        report = {"error": str(error)}
        if isinstance(error, UnsupportedPacker):
            report["packer"] = error.packer
        message = json.dumps(report) if args.json else f"dos16re: {error}"
        print(message, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(program_map))
    elif args.command == "load":
        print(f"Wrote image.bin and map.json to {args.output}")
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
