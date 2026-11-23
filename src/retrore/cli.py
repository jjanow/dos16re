"""Inspect and analyze executables from DOS and other retro platforms."""

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
from .d88 import D88_SUFFIXES, D88Disk, D88Error
from .emulator import DEFAULT_INSTRUCTION_LIMIT, Emulator, EmulatorError
from .errors import CONTRACT_VERSION, EXIT_FAILURE, error_record
from .ghidra import (
    BATCH_SECONDS_PER_QUERY, IMPORT_TIMEOUT, QUERY_TIMEOUT, GhidraError, analysis_gaps, check_timeout, decompile,
    import_program, query, query_address, query_batch,
)
from .image import (
    APPLE2_FORMAT, ATARI8_FORMAT, DEFAULT_M68K_BASE, FLAT16_FORMATS, MSX2_FORMAT, PC88_FORMAT, PC98_FORMAT, X1_FORMAT,
    ImageError,
)
from .msx2 import COM_ADDRESS, Msx2Error, Msx2Source, MsxDosDisk, build_msx2_image
from .mz import DEFAULT_BASE_SEGMENT, Address, MZError, MZExecutable, UnsupportedPacker
from .overlays import Overlay, address_record, build_image
from .pc88 import (
    BOOT_ADDRESS as PC88_BOOT_ADDRESS, DISK_SUFFIXES as PC88_DISK_SUFFIXES, HIGH_BANKS, LOW_BANKS,
    Pc88Error, boot_source, build_pc88_image, copy_source, disk_source,
)
from .pc98 import HDM_SUFFIX, IPL_SEGMENT, HdmDisk, Pc98Error, Pc98Source, build_pc98_image
from .queries import QUERIES, option_names
from .schema import DIALECT, query_schema
from .search import WIDTHS, SearchError, find_bytes, search_pattern
from .trace import TraceError, import_trace
from .x1 import DISK_SUFFIXES as X1_DISK_SUFFIXES
from .x1 import MEMORY_VIEWS as X1_VIEWS
from .x1 import X1Error, build_x1_image
from .x1 import boot_source as x1_boot_source
from .x1 import copy_source as x1_copy_source
from .x1 import disk_source as x1_disk_source
from .x1 import lsn_source as x1_lsn_source
from .z80 import Z80Source

_PREVIEW_LIMIT = 10

# Errors that commands report as coded error objects instead of tracebacks.
HANDLED_ERRORS = (
    Apple2Error, Atari8Error, C64Error, D88Error, EmulatorError, GhidraError, HunkError, ImageError, MZError,
    Msx2Error, Pc88Error, Pc98Error, PrgError, SearchError, TraceError, X1Error, OSError,
)


def error_report(error: BaseException) -> dict:
    """Return the `--json` error object for a handled error."""
    report = {"contract": CONTRACT_VERSION, "error": error_record(error)}
    if isinstance(error, UnsupportedPacker):
        report["packer"] = error.packer
    return report


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


def _runtime_copy(value: str) -> tuple[int, int, int]:
    span, at, destination = value.partition("@")
    address, colon, size = span.partition(":")
    if not at or not colon:
        raise argparse.ArgumentTypeError("expected hexadecimal SRC:SIZE@DEST")
    return _hex_address(address), _hex_address(size), _hex_address(destination)


def _disk_sector(value: str) -> tuple[int, int, int, int, int]:
    chs, at, address = value.partition("@")
    if not at:
        raise argparse.ArgumentTypeError("expected decimal C:H:R[+COUNT] and hexadecimal @HEX")
    chs, plus, count = chs.partition("+")
    try:
        cylinder, head, record = map(int, chs.split(":"))
        sectors = int(count) if plus else 1
    except ValueError:
        raise argparse.ArgumentTypeError("expected decimal C:H:R[+COUNT] and hexadecimal @HEX") from None
    return cylinder, head, record, sectors, _hex_address(address)


def _x1_chr(value: str) -> tuple:
    return ("chr", *_disk_sector(value))


def _x1_lsn(value: str) -> tuple:
    span, at, address = value.partition("@")
    lsn, plus, count = span.partition("+")
    try:
        if not at:
            raise ValueError
        return "lsn", int(lsn, 16), int(count) if plus else 1, _hex_address(address)
    except (ValueError, argparse.ArgumentTypeError):
        raise argparse.ArgumentTypeError("expected hexadecimal LSN, decimal [+COUNT], and hexadecimal @HEX") from None


def _segmented_address(value: str) -> Address:
    segment, colon, offset = value.partition(":")
    if not colon:
        raise argparse.ArgumentTypeError("expected hexadecimal SEG:OFF")
    return Address(_hex_segment(segment), _hex_segment(offset))


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


def _msx2_image(args: argparse.Namespace, data: bytes) -> tuple[bytes, dict]:
    if args.base_segment is not None or args.overlay:
        raise Msx2Error("--base-segment and --overlay apply to DOS executables")
    if (args.c64_unit or args.c64_bank is not None or args.apple2_unit or args.apple2_lc is not None
            or args.apple2_disk_order or args.atari8_unit or args.atari8_portb is not None):
        raise Msx2Error("C64, Apple II, and Atari 8-bit options cannot be used with --msx2")
    disk = bool(args.disk_file) or args.program.suffix.lower() == ".dsk"
    name = args.program.name
    entries = args.entry
    sources = []
    if disk:
        if not args.disk_file:
            raise Msx2Error("select an MSX-DOS disk member with --disk-file NAME[@HEX]")
        filesystem = MsxDosDisk(data)
        for index, spec in enumerate(args.disk_file):
            member, separator, suffix = spec.rpartition("@")
            if separator:
                try:
                    address = _hex_address(suffix)
                except argparse.ArgumentTypeError as error:
                    raise Msx2Error(f"invalid MSX-DOS member load address in {spec!r}") from error
            else:
                member, address = spec, None
            if index == 0 and args.base_address is not None:
                if address is not None:
                    raise Msx2Error("specify the root member address once with @HEX or --base-address")
                address = args.base_address
            com = member.lower().endswith(".com")
            if address is None:
                if index != 0 or not com:
                    raise Msx2Error(f"specify an MSX2 load address for {member!r} with @HEX")
                address = COM_ADDRESS
            if index == 0 and com and not entries:
                entries = [address]
            sources.append(Msx2Source("root" if index == 0 else member.upper(), name, address,
                                      filesystem.read_file(member), member.upper()))
    else:
        com = args.program.suffix.lower() == ".com"
        address = args.base_address
        if address is None:
            if not com:
                raise Msx2Error("--base-address is required for raw MSX2 files")
            address = COM_ADDRESS
        if com and not entries:
            entries = [address]
        sources.append(Msx2Source("root", name, address, data))
    for path, address in args.msx2_unit:
        if address is None:
            raise Msx2Error(f"specify an MSX2 load address for {path.name!r} with @HEX")
        sources.append(Msx2Source(path.stem, path.name, address, path.read_bytes()))
    root = sources[0]
    copies = []
    for address, size, destination in args.msx2_copy:
        offset = address - root.address
        if not 0 <= offset < offset + size <= len(root.data):
            raise Msx2Error(f"MSX2 copy {address:x}:{size:x} is outside the root file")
        copies.append(Msx2Source(f"copy_{destination:04x}", root.source, destination, root.data[offset:offset + size],
                                 root.disk_file, offset))
    sources[1:1] = copies
    return build_msx2_image(sources, name, entries, disk=disk)


def _pc88_image(args: argparse.Namespace, data: bytes) -> tuple[bytes, dict]:
    if args.base_segment is not None or args.overlay:
        raise Pc88Error("--base-segment and --overlay apply to DOS executables")
    if args.disk_file:
        raise Pc88Error("select PC-88 disk sectors with --pc88-sector, or omit it for the boot sector")
    if (args.c64_unit or args.c64_bank is not None or args.apple2_unit or args.apple2_lc is not None
            or args.apple2_disk_order or args.atari8_unit or args.atari8_portb is not None
            or args.msx2_unit or args.msx2_copy):
        raise Pc88Error("other platform options cannot be used with --pc88")
    filename = args.program.name
    disk = None
    entries = args.entry
    low = args.pc88_low
    if args.program.suffix.lower() in PC88_DISK_SUFFIXES or args.pc88_sector or args.pc88_disk is not None:
        if args.base_address is not None:
            raise Pc88Error("set disk load addresses with --pc88-sector C:H:R[+COUNT]@HEX")
        disk = D88Disk(data, args.pc88_disk if args.pc88_disk is not None else 1)
        if args.pc88_sector:
            sources = [
                disk_source(disk, filename, "root" if index == 0 else f"sector_{cylinder}_{head}_{record}_{address:04x}",
                            address, cylinder, head, record, count)
                for index, (cylinder, head, record, count, address) in enumerate(args.pc88_sector)
            ]
        else:
            sources = [boot_source(disk, filename)]
            entries = entries or [PC88_BOOT_ADDRESS]
            low = low or "n88-rom"
    elif args.base_address is None:
        raise Pc88Error("--base-address is required for raw PC-88 files")
    else:
        sources = [Z80Source("root", filename, args.base_address, data)]
    for address, size, destination in args.pc88_copy:
        sources.append(copy_source(sources, address, size, destination))
    for path, address in args.pc88_unit:
        if address is None:
            raise Pc88Error(f"specify a PC-88 load address for {path.name!r} with @HEX")
        sources.append(Z80Source(path.stem, path.name, address, path.read_bytes()))
    return build_pc88_image(sources, filename, entries, low or "ram", args.pc88_high or "ram", disk)


def _x1_image(args: argparse.Namespace, data: bytes) -> tuple[bytes, dict]:
    if args.base_segment is not None or args.overlay:
        raise X1Error("--base-segment and --overlay apply to DOS executables")
    if args.disk_file:
        raise X1Error("select X1 disk sectors with --x1-sector or --x1-lsn, or omit them for the IPL")
    if (args.c64_unit or args.c64_bank is not None or args.apple2_unit or args.apple2_lc is not None
            or args.apple2_disk_order or args.atari8_unit or args.atari8_portb is not None
            or args.msx2_unit or args.msx2_copy):
        raise X1Error("other platform options cannot be used with --x1")
    filename = args.program.name
    disk = header = None
    entries = args.entry
    sources = []
    if args.program.suffix.lower() in X1_DISK_SUFFIXES or args.x1_sector or args.x1_disk is not None or args.x1_ipl:
        if args.base_address is not None:
            raise X1Error("set disk load addresses with --x1-sector C:H:R[+COUNT]@HEX or --x1-lsn LSN[+COUNT]@HEX")
        disk = D88Disk(data, args.x1_disk if args.x1_disk is not None else 1)
        if args.x1_ipl or not args.x1_sector:
            boot, header = x1_boot_source(disk, filename)
            sources.append(boot)
            entries = [header.exec_address, *entries]
        for kind, *selection in args.x1_sector:
            if kind == "chr":
                cylinder, head, record, count, address = selection
                name = f"sector_{cylinder}_{head}_{record}_{address:04x}"
                source = x1_disk_source(disk, filename, name, address, cylinder, head, record, count)
            else:
                lsn, count, address = selection
                source = x1_lsn_source(disk, filename, f"lsn_{lsn:04x}_{address:04x}", address, lsn, count)
            sources.append(source if sources else Z80Source(
                "root", source.source, source.address, source.data,
                file_offset=source.file_offset, file_spans=source.file_spans))
    elif args.base_address is None:
        raise X1Error("--base-address is required for raw X1 files")
    else:
        sources.append(Z80Source("root", filename, args.base_address, data))
    for address, size, destination in args.x1_copy:
        sources.append(x1_copy_source(sources, address, size, destination))
    for path, address in args.x1_unit:
        if address is None:
            raise X1Error(f"specify an X1 load address for {path.name!r} with @HEX")
        sources.append(Z80Source(path.stem, path.name, address, path.read_bytes()))
    return build_x1_image(sources, filename, entries, args.x1_view or "ram", disk, header)


def _pc98_image(args: argparse.Namespace, data: bytes) -> tuple[bytes, dict]:
    if (args.base_address is not None or args.overlay or args.disk_file or args.entry
            or args.c64_unit or args.c64_bank is not None
            or args.apple2_unit or args.apple2_lc is not None or args.apple2_disk_order
            or args.atari8_unit or args.atari8_portb is not None or args.msx2_unit or args.msx2_copy):
        raise Pc98Error("use PC-98 load and entry options with --pc98")
    filename = args.program.name
    extension = args.program.suffix.lower()
    disk = None
    if extension == HDM_SUFFIX:
        if args.pc98_disk is not None:
            raise Pc98Error("--pc98-disk applies to D88/D77 containers")
        disk = HdmDisk(data)
    elif extension in D88_SUFFIXES or args.pc98_sector or args.pc98_disk is not None:
        disk = D88Disk(data, args.pc98_disk if args.pc98_disk is not None else 1)

    if disk is not None:
        if args.base_segment is not None:
            raise Pc98Error("set PC-98 disk load segments with --pc98-sector C:H:R[+COUNT]@SEG")
        selections = args.pc98_sector or [(0, 0, 1, 1, IPL_SEGMENT)]
        sources = [
            Pc98Source.from_disk(disk, "root" if index == 0 else f"sector_{c}_{h}_{r}_{seg:04x}",
                                 filename, c, h, r, count, seg)
            for index, (c, h, r, count, seg) in enumerate(selections)
        ]
    else:
        if args.base_segment is None:
            raise Pc98Error("--base-segment is required for raw PC-98 files")
        sources = [Pc98Source("root", filename, args.base_segment, data)]
    for path, segment in args.pc98_unit:
        if segment is None:
            raise Pc98Error("specify a PC-98 unit load segment with FILE@SEG")
        sources.append(Pc98Source(path.stem, path.name, segment, path.read_bytes()))
    return build_pc98_image(sources, filename, args.pc98_entry, disk)


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


def _location(record: dict | str) -> str:
    if isinstance(record, str):
        return record
    return record["unit_address"] or record["address"]


def _print_references(groups: tuple[str, ...], report: dict) -> None:
    remaining = _PREVIEW_LIMIT
    pages = report.get("pagination", {})
    for group in groups:
        references = report[group]
        page = pages.get(group)
        count = f"{page['returned']}/{page['total']}" if page else str(len(references))
        print(f"{count} {group}")
        for reference in references[:remaining]:
            source = _location(reference["from"])
            target = _location(reference["to"])
            peer = reference["to_function" if group in ("outgoing", "callees") else "from_function"]
            name = f"  {peer['name']}" if peer else ""
            print(f"  {source} -> {target}  {reference['type']}{name}")
        remaining = max(0, remaining - len(references))
        if page and page["next_offset"] is not None:
            direction = f" --direction {group}" if group in ("incoming", "outgoing") else ""
            print(f"  Continue with --offset {page['next_offset']}{direction}")
    if sum(len(report[group]) for group in groups) > _PREVIEW_LIMIT:
        print("Use --json for the full page." if pages else "Use --json for all references.")


def _query_options(args: argparse.Namespace) -> dict:
    fields = args.fields
    if fields is not None and not args.json:
        raise GhidraError("--fields requires --json")
    options = {"fields": fields.split(",")} if fields is not None else {}
    for name in option_names():
        value = getattr(args, name, None)
        if value is not None:
            options[name] = value
    return options


def _decomp(args: argparse.Namespace) -> None:
    report = decompile(args.address, args.project, timeout=args.timeout, **_query_options(args))
    if args.json:
        print(json.dumps(report))
        return
    if "decompilation" in report:
        print(report["decompilation"].strip())
        return
    focus = report["focus"]
    print(f"{_location(focus['address'])}  {focus['instruction']}")
    if "excerpt" in report:
        for line in report["excerpt"]:
            marker = ">" if line["focused"] else " "
            print(f"{marker} {line['line']:4} {line['text']}")
        if not report["excerpt"]:
            print("No decompiled C line maps to this instruction.")
    if "slice" in report:
        operations = report["slice"]["operations"]
        for operation in operations[:_PREVIEW_LIMIT]:
            inputs = ", ".join(value["storage"] for value in operation["inputs"])
            print(f"  {_location(operation['address'])}  {operation['opcode']} {inputs}".rstrip())
        if not operations:
            print("No high p-code maps to this instruction.")
        if len(operations) > _PREVIEW_LIMIT:
            print("Use --json for all returned operations.")
        if report["slice"]["truncated"]:
            print("Slice truncated at the requested operation limit.")


def _address_query(args: argparse.Namespace) -> None:
    report = query_address(args.command, args.address, args.project, timeout=args.timeout, **_query_options(args))
    if args.json:
        print(json.dumps(report))
        return
    if args.command == "xrefs":
        print(_location(report["address"]))
        _print_references(tuple(group for group in ("incoming", "outgoing") if group in report), report)
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

    report = query_batch(args.project, requests, timeout=args.timeout)
    results = report["results"]
    errors = [row for row in results if "error" in row]
    if args.json:
        print(json.dumps(report))
    else:
        print(f"{len(results) - len(errors)}/{len(results)} queries succeeded")
        for row in errors[:_PREVIEW_LIMIT]:
            target = "".join(f" {value}" for key, value in row.items() if key not in ("command", "error"))
            print(f"  {row['command']}{target}: {row['error']['code']}: {row['error']['message']}")
    return int(bool(errors))


_REGISTRY_COMMANDS = ("functions", "symbols", "inventory", "callgraph", "context", "coverage")


def _add_query_parser(commands: argparse._SubParsersAction, command: str) -> argparse.ArgumentParser:
    """Add a subcommand whose arguments come from the query registry."""
    definition = QUERIES[command]
    parser = commands.add_parser(command, help=definition["description"])
    for name, parameter in definition["parameters"].items():
        flag = "--" + name.replace("_", "-")
        text = parameter["description"]
        if parameter["type"] == "integer":
            default = f", default {parameter['default']}" if "default" in parameter else ""
            text = f"{text} ({parameter['minimum']}–{parameter['maximum']}{default})"
        if parameter.get("required"):
            parser.add_argument(name, metavar="ADDR" if name == "address" else name.upper(), help=text)
        elif name == "addresses":
            parser.add_argument(name, metavar="ADDR", nargs="*", help=text)
        elif parameter["type"] == "array":
            parser.add_argument(flag.removesuffix("s"), dest=name, action="append", metavar=name[:-1].upper(),
                                help=f"{text} (repeatable)")
        elif parameter["type"] == "boolean":
            parser.add_argument(flag, action="store_true", default=None, help=text)
        elif parameter["type"] == "integer":
            parser.add_argument(flag, type=int, metavar="N", help=text)
        else:
            parser.add_argument(flag, choices=parameter.get("enum"), metavar=None if "enum" in parameter else name.upper(),
                                help=text)
    parser.add_argument("--project", metavar="PROJECT", type=Path, required=True)
    parser.add_argument("--json", action="store_true", help="print JSON")
    scope = "record" if definition["fields_scope"] == "record" else "top-level"
    parser.add_argument("--fields", metavar="FIELD,...", help=f"select {scope} JSON fields")
    return parser


def _registry_request(args: argparse.Namespace) -> dict:
    request = {"command": args.command}
    for name, parameter in QUERIES[args.command]["parameters"].items():
        if parameter.get("required"):
            request[name] = getattr(args, name)
    request.update(_query_options(args))
    return {name: value for name, value in request.items() if value != []}


def _print_page(report: dict, group: str, rows: list[str]) -> None:
    page = report.get("pagination", {}).get(group)
    count = f"{page['returned']}/{page['total']}" if page else str(len(rows))
    print(f"{count} {group}")
    for row in rows[:_PREVIEW_LIMIT]:
        print(f"  {row}")
    if len(rows) > _PREVIEW_LIMIT:
        print("  Use --json for the full page.")


def _print_continue(report: dict) -> None:
    offsets = [page["next_offset"] for page in report.get("pagination", {}).values() if page["next_offset"] is not None]
    if offsets:
        print(f"Continue with --offset {min(offsets)}")


def _registry_query(args: argparse.Namespace) -> int:
    report = query(args.project, _registry_request(args), timeout=args.timeout)
    command = args.command
    if args.json:
        print(json.dumps(report))
    elif command == "functions":
        _print_page(report, "functions", [
            f"{row['query']}: {row['error']['message']}" if "error" in row else f"{_location(row['entry'])}  {row['prototype']}"
            for row in report["functions"]
        ])
    elif command == "symbols":
        _print_page(report, "symbols", [
            f"{_location(row['address'])}  {row['name']}  {row['kind']}" for row in report["symbols"]
        ])
    elif command == "inventory":
        unit = report["unit"]
        print(f"{unit['name']}  {_location(unit['start'])}–{_location(unit['end'])}  {unit['size']} bytes")
        _print_page(report, "functions", [f"{_location(row['entry'])}  {row['name']}" for row in report["functions"]])
        _print_page(report, "labels", [f"{_location(row['address'])}  {row['name']}" for row in report["labels"]])
        _print_page(report, "data", [
            f"{_location(row['address'])}  {row['type']}  {row['name'] or ''}".rstrip() for row in report["data"]
        ])
    elif command == "callgraph":
        root, truncated = report["root"], report["truncated"]
        print(f"{_location(root['entry'])}  {root['name']}")
        limits = [name for name in ("depth", "nodes") if truncated[name]]
        if limits:
            print(f"Walk truncated by {' and '.join(limits)} limit.")
        if report["unresolved"]:
            print(f"{report['unresolved']} calls without an analyzed function")
        _print_page(report, "nodes", [
            f"{'  ' * node['depth']}{_location(node['function']['entry'])}  {node['function']['name']}"
            for node in report["nodes"]
        ])
        page = report["pagination"]["edges"]
        print(f"{page['returned']}/{page['total']} edges")
    elif command == "context":
        print(report["prototype"])
        _print_page(report, "callees", [
            f"{_location(row['target'])}  {row['function']['name'] if row['function'] else '?'}  {row['calls']} calls"
            for row in report["callees"]
        ])
        _print_page(report, "data", [
            " ".join(filter(None, (_location(row["address"]), row["name"], row["type"], "/".join(row["access"]))))
            for row in report["data"]
        ])
    else:
        _print_page(report, "units", [
            f"{row['unit']}  {row['size']} bytes  {row['instruction_bytes']} code  {row['data_bytes']} data  "
            f"{row['undefined_bytes']} undefined  {row['functions']} functions"
            for row in report["units"]
        ])
    if not args.json:
        _print_continue(report)
    return int(command == "functions" and any("error" in row for row in report["functions"]))


def _paged_gaps(args: argparse.Namespace) -> None:
    report = query(args.project, _registry_request(args), timeout=args.timeout)
    if args.json:
        print(json.dumps(report))
        return
    page = report["pagination"]["ranges"]
    print(f"{report['undefined_bytes']} undefined bytes in {page['total']} ranges")
    for gap in report["ranges"][:_PREVIEW_LIMIT]:
        print(f"{gap['start']}–{gap['end']}  {gap['size']} bytes")
    if len(report["ranges"]) > _PREVIEW_LIMIT:
        print("Use --json for the full page.")
    _print_continue(report)


def _where_is(args: argparse.Namespace) -> None:
    pattern, width = search_pattern(hex_bytes=args.bytes, string=args.string, constant=args.constant, width=args.width)
    report = find_bytes(args.export, pattern, width=width, limit=None if args.json else _PREVIEW_LIMIT)
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


def _schema(args: argparse.Namespace) -> None:
    document = query_schema()
    if args.json:
        print(json.dumps(document, indent=2))
        return
    print(f"Query contract {document['contract']}, JSON Schema {DIALECT}")
    width = max(map(len, document["commands"]))
    for command, description in document["commands"].items():
        print(f"  {command:<{width}}  {description}")
    print("Use --json for the request, batch, and error schemas.")


def _seconds(value: str) -> float:
    try:
        return check_timeout(float(value))
    except GhidraError as error:
        raise argparse.ArgumentTypeError(str(error)) from None


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
            help=f"DOS load segment (default: {DEFAULT_BASE_SEGMENT:04x}) or raw PC-98 load segment",
        )
        base.add_argument(
            "--base-address", type=_hex_address, metavar="HEX",
            help=f"Amiga/Atari ST base (default {DEFAULT_M68K_BASE:06x}) or 8-bit program load address",
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
        platform.add_argument("--msx2", action="store_true", help="interpret the input as an MSX-DOS .COM, raw file, or FAT12 disk")
        platform.add_argument("--pc88", action="store_true", help="interpret the input as a PC-88 D88/D77 disk or raw file")
        platform.add_argument("--pc98", action="store_true", help="interpret the input as a PC-98 disk or raw file")
        platform.add_argument("--x1", action="store_true", help="interpret the input as a Sharp X1 D88 disk or raw file")
        command.add_argument(
            "--disk-file", action="append", default=[], metavar="NAME[@HEX]",
            help="select a disk member (first is root, repeat for additional files, @HEX applies to MSX2)",
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
            "--msx2-unit", type=_unit_path, action="append", default=[], metavar="FILE@HEX",
            help="load an additional MSX2 file at its runtime address",
        )
        command.add_argument(
            "--msx2-copy", type=_runtime_copy, action="append", default=[], metavar="SRC:SIZE@DEST",
            help="copy a hexadecimal root RAM span to DEST before loading MSX2 overlays",
        )
        command.add_argument("--pc88-disk", type=int, metavar="INDEX", help="select a 1-based disk in a D88 container")
        command.add_argument(
            "--pc88-sector", type=_disk_sector, action="append", default=[], metavar="C:H:R[+COUNT]@HEX",
            help="load a disk sector span by decimal cylinder, head, and sector ID (default: IPL at c000)",
        )
        command.add_argument(
            "--pc88-copy", type=_runtime_copy, action="append", default=[], metavar="SRC:SIZE@DEST",
            help="copy a hexadecimal span after the root and disk loads and before additional raw files",
        )
        command.add_argument(
            "--pc88-unit", type=_unit_path, action="append", default=[], metavar="FILE@HEX",
            help="load an additional raw PC-88 file at its runtime address",
        )
        command.add_argument("--pc88-low", choices=LOW_BANKS, help="select visible memory below 8000")
        command.add_argument("--pc88-high", choices=HIGH_BANKS, help="select RAM or a graphics VRAM plane at c000")
        command.add_argument("--pc98-disk", type=int, metavar="INDEX", help="select a 1-based disk in a D88 container")
        command.add_argument(
            "--pc98-sector", type=_disk_sector, action="append", default=[], metavar="C:H:R[+COUNT]@SEG",
            help="load a decimal disk sector span at hexadecimal SEG:0000 (default: IPL at 1fc0:0000)",
        )
        command.add_argument(
            "--pc98-unit", type=_overlay, action="append", default=[], metavar="FILE@SEG",
            help="load a co-resident raw PC-98 file at hexadecimal SEG:0000",
        )
        command.add_argument(
            "--pc98-entry", type=_segmented_address, action="append", default=[], metavar="SEG:OFF",
            help="seed PC-98 analysis at a hexadecimal segment and offset (repeatable)",
        )
        command.add_argument("--x1-disk", type=int, metavar="INDEX", help="select a 1-based disk in a D88 container")
        command.add_argument(
            "--x1-ipl", action="store_true",
            help="load the IPL boot payload before explicit X1 sectors (default when no sectors are selected)",
        )
        command.add_argument(
            "--x1-sector", dest="x1_sector", type=_x1_chr, action="append", default=[], metavar="C:H:R[+COUNT]@HEX",
            help="load a disk sector span by decimal cylinder, head, and sector ID",
        )
        command.add_argument(
            "--x1-lsn", dest="x1_sector", type=_x1_lsn, action="append", metavar="LSN[+COUNT]@HEX",
            help="load a disk sector span by hexadecimal X1 logical sector number (16 sectors per side)",
        )
        command.add_argument(
            "--x1-copy", type=_runtime_copy, action="append", default=[], metavar="SRC:SIZE@DEST",
            help="copy a hexadecimal span after the disk loads and before additional raw files",
        )
        command.add_argument(
            "--x1-unit", type=_unit_path, action="append", default=[], metavar="FILE@HEX",
            help="load an additional raw X1 file at its runtime address",
        )
        command.add_argument("--x1-view", choices=X1_VIEWS, help="select RAM or the IPL ROM for reads below 8000")
        command.add_argument(
            "--entry", type=_hex_address, action="append", default=[], metavar="HEX",
            help="seed 8-bit machine-code analysis at this address (repeatable)",
        )

    ghidra_parser = commands.add_parser("ghidra", help="manage a headless Ghidra import")
    ghidra_commands = ghidra_parser.add_subparsers(dest="ghidra_command", required=True)
    import_parser = ghidra_commands.add_parser("import", help="import and analyze an exported image")
    import_parser.add_argument("export", metavar="OUT", type=Path)
    import_parser.add_argument("project", metavar="PROJECT", type=Path)
    decomp_parser = commands.add_parser("decomp", help="decompile a function in a Ghidra project")
    decomp_parser.add_argument("address", metavar="ADDR")
    decomp_parser.add_argument("--project", metavar="PROJECT", type=Path, required=True)
    decomp_parser.add_argument("--fields", metavar="FIELD,...", help="select top-level JSON fields")
    decomp_parser.add_argument("--context", type=int, metavar="N", help="show N C lines around the selected instruction (0–20)")
    decomp_parser.add_argument("--slice", type=int, metavar="N", help="trace up to N backward p-code operations (1–128)")
    gaps_parser = commands.add_parser("gaps", help="report undefined ranges in an analyzed Ghidra project")
    gaps_parser.add_argument("--project", metavar="PROJECT", type=Path, required=True)
    gaps_paging = QUERIES["gaps"]["parameters"]
    gaps_parser.add_argument("--unit", metavar="UNIT", help=gaps_paging["unit"]["description"])
    for name in ("limit", "offset"):
        parameter = gaps_paging[name]
        gaps_parser.add_argument(f"--{name}", type=int, metavar="N", help=(
            f"{parameter['description']} ({parameter['minimum']}–{parameter['maximum']}"
            f", default {parameter['default']})"))
    gaps_parser.add_argument("--fields", metavar="FIELD,...", help="select record JSON fields")
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
        query_parser.add_argument("address", metavar="ADDR", help="hexadecimal unit:offset, seg:off, or flat address")
        query_parser.add_argument("--project", metavar="PROJECT", type=Path, required=True)
        query_parser.add_argument("--json", action="store_true", help="print JSON")
        query_parser.add_argument("--fields", metavar="FIELD,...", help="select top-level JSON fields")
        query_parser.add_argument("--limit", type=int, metavar="N", help="maximum references per list")
        query_parser.add_argument("--offset", type=int, metavar="N", help="skip N references per list after filtering")
        query_parser.add_argument("--ref-type", dest="ref_types", action="append", metavar="TYPE",
                                  help="filter by exact Ghidra reference type (repeatable)")
        query_parser.add_argument("--compact", action="store_true", default=None,
                                  help="return addresses as unit:offset strings where available")
        if name == "xrefs":
            query_parser.add_argument("--direction", choices=("incoming", "outgoing", "both"), help="select reference direction")
    for name in _REGISTRY_COMMANDS:
        _add_query_parser(commands, name)

    schema_parser = commands.add_parser("schema", help="print the JSON Schema of query requests and errors")
    schema_parser.add_argument("--json", action="store_true", help="print the JSON Schema document")
    mcp_parser = commands.add_parser("mcp", help="serve queries to MCP clients over stdio")
    mcp_parser.add_argument("--json", action="store_true", help="accepted for consistency; output is always JSON-RPC")
    search_parser = commands.add_parser("where-is", help="find a byte pattern across exported units")
    search_parser.add_argument("--export", metavar="OUT", type=Path, required=True, help="directory from retrore load")
    pattern = search_parser.add_mutually_exclusive_group(required=True)
    pattern.add_argument("--bytes", metavar="HEX", help="hexadecimal bytes")
    pattern.add_argument("--string", metavar="TEXT", help="literal string in the image's supported encoding")
    pattern.add_argument("--constant", metavar="N", help="decimal or 0x-prefixed integer in the image's byte order")
    search_parser.add_argument("--width", type=int, choices=WIDTHS, help="constant width in bytes (default 2)")
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
    for command in (import_parser, decomp_parser, gaps_parser, batch_parser, *map(commands.choices.get, address_queries),
                    *map(commands.choices.get, _REGISTRY_COMMANDS)):
        default = IMPORT_TIMEOUT if command is import_parser else None if command is batch_parser else QUERY_TIMEOUT
        described = (f"the larger of {QUERY_TIMEOUT} and {BATCH_SECONDS_PER_QUERY} per query"
                     if default is None else default)
        command.add_argument(
            "--timeout", type=_seconds, default=default, metavar="SECONDS",
            help=f"stop headless Ghidra after SECONDS (default: {described}; 0 disables the limit)",
        )

    args = parser.parse_args(argv)
    if args.command == "schema":
        _schema(args)
        return 0
    if args.command == "mcp":
        from .mcp import serve  # The adapter imports this module.
        return serve()
    try:
        if args.command == "batch":
            return _batch(args)
        if args.command == "ghidra":
            report = import_program(args.export, args.project, timeout=args.timeout)
            summary = f"Imported {report['units']} units into {args.project}"
            print(json.dumps(report) if args.json else summary)
            return 0
        if args.command == "decomp":
            _decomp(args)
            return 0
        if args.command in _REGISTRY_COMMANDS:
            return _registry_query(args)
        paging = ("unit", "limit", "offset", "fields")
        if args.command == "gaps" and any(getattr(args, name) is not None for name in paging):
            _paged_gaps(args)
            return 0
        if args.command == "gaps":
            report = analysis_gaps(args.project, timeout=args.timeout)
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
        if not args.pc88 and (args.pc88_disk is not None or args.pc88_sector or args.pc88_copy or args.pc88_unit
                             or args.pc88_low or args.pc88_high):
            raise Pc88Error("PC-88 options require --pc88")
        if not args.pc98 and (args.pc98_disk is not None or args.pc98_sector or args.pc98_unit or args.pc98_entry):
            raise Pc98Error("PC-98 options require --pc98")
        if not args.x1 and (args.x1_disk is not None or args.x1_ipl or args.x1_sector or args.x1_copy
                            or args.x1_unit or args.x1_view):
            raise X1Error("X1 options require --x1")
        if args.x1:
            image, program_map = _x1_image(args, data)
        elif args.pc98:
            image, program_map = _pc98_image(args, data)
        elif args.pc88:
            image, program_map = _pc88_image(args, data)
        elif args.msx2:
            image, program_map = _msx2_image(args, data)
        elif args.msx2_unit or args.msx2_copy:
            raise Msx2Error("--msx2-unit and --msx2-copy require --msx2")
        elif atari8:
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
            raise C64Error("--c64-unit and --c64-bank require C64, while --entry accepts 8-bit programs")
        elif m68k:
            if args.base_segment is not None or args.overlay:
                raise MZError("--base-segment and --overlay apply to DOS executables")
            base_address = DEFAULT_M68K_BASE if args.base_address is None else args.base_address
            loader = build_hunk_image if hunk else build_prg_image
            image, program_map = loader(data, args.program.name, base_address)
        else:
            if args.base_address is not None:
                raise MZError("--base-address applies to Amiga, Atari ST, and 8-bit programs")
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
    except HANDLED_ERRORS as error:
        report = error_report(error)
        message = json.dumps(report) if args.json else f"retrore: {error}"
        print(message, file=sys.stderr)
        return EXIT_FAILURE

    if args.json:
        print(json.dumps(program_map))
    elif args.command == "load":
        print(f"Wrote image.bin and map.json to {args.output}")
    elif program_map["format"] == "HUNK":
        print(f"Amiga Hunk  entry h0:0000 ({base_address:06x})  {len(program_map['units'])} hunks")
    elif program_map["format"] == "PRG":
        print(f"Atari ST GEMDOS  entry text:0000 ({base_address:06x})")
        print("  ".join(f"{unit['name'].upper()} {unit['size']} bytes" for unit in program_map["units"]))
    elif program_map["format"] == PC98_FORMAT:
        entry = program_map["entry"]
        print(f"PC-98  entry {entry['segment']:04x}:{entry['offset']:04x}  {len(program_map['units'])} units")
    elif program_map["format"] in FLAT16_FORMATS:
        entries = program_map["entries"]
        if program_map["format"] == APPLE2_FORMAT:
            platform = f"Apple II  LC {program_map['language_card']:04x}"
        elif program_map["format"] == ATARI8_FORMAT:
            platform = f"Atari 8-bit  PORTB {program_map['portb']:02x}"
        elif program_map["format"] == MSX2_FORMAT:
            platform = "MSX2  MSX-DOS RAM"
        elif program_map["format"] == PC88_FORMAT:
            platform = f"PC-88  {program_map['memory_view']}"
        elif program_map["format"] == X1_FORMAT:
            ipl = program_map.get("ipl")
            platform = f"X1  {program_map['memory_view']}" + (f"  IPL {ipl['name']!r}" if ipl else "")
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
