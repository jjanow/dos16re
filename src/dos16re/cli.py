"""Command-line interface for inspecting and exporting DOS executables."""

import argparse
import json
import sys
from contextlib import ExitStack
from pathlib import Path

from .mz import DEFAULT_BASE_SEGMENT, Address, LoadedMZ, MZError, MZExecutable


def _hex_segment(value: str) -> int:
    try:
        segment = int(value, 16)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a hexadecimal segment") from None
    if not 0 <= segment <= 0xFFFF:
        raise argparse.ArgumentTypeError("segment must be between 0000 and ffff")
    return segment


def _address_record(address: Address) -> dict[str, int]:
    return {"segment": address.segment, "offset": address.offset, "linear": address.linear}


def _export_image(output: Path, loaded: LoadedMZ, program_map: dict) -> None:
    output.mkdir(parents=True, exist_ok=True)
    image_path = output / "image.bin"
    map_path = output / "map.json"
    map_text = json.dumps(program_map, indent=2) + "\n"

    with ExitStack() as rollback:
        with image_path.open("xb") as image_file:
            rollback.callback(image_path.unlink)
            image_file.write(loaded.image)
        with map_path.open("x", encoding="utf-8") as map_file:
            rollback.callback(map_path.unlink)
            map_file.write(map_text)
        rollback.pop_all()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dos16re", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    load_parser = commands.add_parser("load", help="export a relocated MZ load module")
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

    args = parser.parse_args(argv)
    try:
        executable = MZExecutable.parse(args.program.read_bytes())
        loaded = executable.load(args.base_segment)
        program_map = {
            "version": 1,
            "format": "MZ",
            "program": args.program.name,
            "entry": _address_record(loaded.entry),
            "stack": _address_record(loaded.stack),
            "relocation_count": executable.header.relocation_count,
            "units": [
                {
                    "name": "root",
                    "segment": loaded.base_segment,
                    "linear": Address(loaded.base_segment, 0).linear,
                    "image_offset": 0,
                    "size": len(loaded.image),
                }
            ],
        }
        if args.command == "load":
            _export_image(args.output, loaded, program_map)
    except (MZError, OSError) as error:
        message = json.dumps({"error": str(error)}) if args.json else f"dos16re: {error}"
        print(message, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(program_map))
    elif args.command == "load":
        print(f"Wrote image.bin and map.json to {args.output}")
    else:
        print(f"MZ  entry {loaded.entry}  stack {loaded.stack}")
        print(f"root  {loaded.base_segment:04x}:0000  {len(loaded.image)} bytes")
    return 0
