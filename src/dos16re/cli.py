"""Command-line interface for inspecting, exporting, and running DOS code."""

import argparse
import json
import sys
from contextlib import ExitStack
from pathlib import Path

from .emulator import DEFAULT_INSTRUCTION_LIMIT, Emulator, EmulatorError
from .ghidra import GhidraError, analysis_gaps, decompile, import_program
from .mz import DEFAULT_BASE_SEGMENT, MZError, MZExecutable, UnsupportedPacker
from .overlays import Overlay, address_record, build_image


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
    for command in (import_parser, decomp_parser, gaps_parser, call_parser):
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
        executable = MZExecutable.parse(args.program.read_bytes())
        loaded = executable.load(args.base_segment)
        overlays = [
            Overlay(path.name, path.stem, path.read_bytes(), segment)
            for path, segment in args.overlay
        ]
        image, program_map = build_image(loaded, args.program.name, overlays)
        if args.command == "load":
            _export_image(args.output, image, program_map)
    except (EmulatorError, GhidraError, MZError, OSError) as error:
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
