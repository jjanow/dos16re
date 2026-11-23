# retrore

Standalone reverse-engineering tools for 16-bit real-mode DOS programs, AmigaDOS Hunk executables,
Atari ST GEMDOS executables, Commodore 64 PRGs, Apple II binaries, Atari 8-bit executables, MSX2 programs,
and NEC PC-88 and PC-98 programs.
Install and run `retrore` independently of any game or remaster project. The games in [PLAN.md](PLAN.md)
are optional validation targets for particular executable formats and compiler patterns.

## Installation

From the `retrore` checkout, use Python 3.12 or newer to install the CLI in a virtual environment.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/retrore --help
```

File inspection and image export work with the Python install. See [Ghidra](#ghidra) for the
additional setup for project import, decompilation, and cross-reference queries.

### Compatibility

The package requires Python 3.12 or newer. The table records the Linux setups used for local
verification and configured for release CI.

| Check | Python | Ghidra | JDK |
|---|---|---|---|
| Local standalone suite | 3.14 | — | — |
| Local suite with headless tests enabled | 3.14 | 12.2 | OpenJDK 25 |
| Release CI configuration for the installed wheel | 3.12 | 12.2 | Temurin 25 |

See the [release workflow](.github/workflows/release-ci.yml) for the exact CI setup.

### Try a synthetic program

From the checkout, generate a tiny Commodore 64 PRG with a two-byte load address and a routine
that writes `7` to the VIC-II border color register. The example uses only synthetic bytes and
saves its files in a fresh temporary directory. Set up [Ghidra](#ghidra) before running the import
and batch commands.

```sh
demo_dir=$(mktemp -d)
.venv/bin/python - "$demo_dir/demo.prg" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_bytes(bytes.fromhex(
    "00 c0 "       # Load address $C000
    "20 04 c0 60 " # JSR $C004, RTS
    "a9 07 "       # LDA #$07
    "8d 20 d0 60"  # STA $D020, RTS
))
PY
.venv/bin/retrore info "$demo_dir/demo.prg" --json
.venv/bin/retrore load "$demo_dir/demo.prg" --entry c000 -o "$demo_dir/export" --json
.venv/bin/retrore ghidra import "$demo_dir/export" "$demo_dir/project" --json
.venv/bin/retrore batch --project "$demo_dir/project" --json <<'JSON'
[
  {"command": "callees", "address": "c000", "limit": 1},
  {"command": "decomp", "address": "c004"},
  {"command": "xrefs", "address": "c006", "direction": "outgoing", "ref_types": ["WRITE"], "limit": 1}
]
JSON
```

The batch results show a call from `$C000` to `$C004`, decompiled C for the callee, and a `WRITE`
reference from `$C006` to `$D020`. Compare those addresses with the instructions in the generated PRG.

### Claude Code and other coding agents

Claude Code can run `retrore` through Bash and read its `--json` output. From the `retrore` checkout,
add the installed CLI to `PATH`, then launch Claude Code from your analysis project. Replace
`/path/to/analysis-project` with the directory where you keep your analysis inputs and outputs.

```sh
export PATH="$(pwd -P)/.venv/bin:$PATH"
retrore --help
cd /path/to/analysis-project && claude
```

Try asking Claude Code to run `retrore info ./PROGRAM.EXE --json` on an executable in that project
and summarize the format, entry point, and any compiler evidence. For decompilation and references,
set `GHIDRA_HOME` before launching the agent and make a compatible JDK available. The same workflow
works with other agents that can run shell commands. For a separately launched agent, give it the
absolute path to `.venv/bin/retrore` inside your checkout.

For repeated use, save the following as `.claude/skills/retrore/SKILL.md` in the analysis project or
`~/.claude/skills/retrore/SKILL.md` for all local projects. Invoke it with `/retrore ./PROGRAM.EXE`
and describe what you want to learn. The skill uses the CLI on `PATH`. You can also put the
executable's absolute path in the skill.
[Claude Code skills documentation](https://code.claude.com/docs/en/skills)

```markdown
---
name: retrore
description: Inspect retro executables and query their Ghidra analysis with retrore.
---

Run `retrore` through Bash and use `--json` to read results. Use the input path
and analysis goal provided by the user.
Start with `retrore info INPUT --json` to identify the format and entry point.
Use `retrore load INPUT -o EXPORT --json` to create `image.bin` and `map.json`.
For decompilation or references, run `retrore ghidra import EXPORT PROJECT --json`,
then `retrore decomp ADDRESS --project PROJECT --json` or
`retrore xrefs ADDRESS --project PROJECT --json`.
Use `retrore COMMAND --help` to check supported arguments and cite the addresses
and tool evidence behind your findings.
```

An MCP adapter is on the [analysis roadmap](PLAN.md#phase-8-faster-queries-and-reproducible-releases).

## DOS loader

The loader restores the original load module from EXEPACK and LZEXE 0.90, 0.91, and 0.91e executables.
It applies segment relocations and records the original initial `CS:IP` and `SS:SP`. Recognized unsupported
packers such as PKLITE produce a diagnostic.

```sh
.venv/bin/retrore info PROGRAM.EXE
.venv/bin/retrore load PROGRAM.EXE -o out/program --json
.venv/bin/retrore load START.EXE --overlay GAME.OVR -o out/pool
.venv/bin/retrore load PHANTASI.EXE --overlay OV1.OVR --overlay OV2.OVR -o out/phantasie
```

Both commands accept `--json`, `--base-segment HEX` (default `1000`), and repeatable `--overlay FILE`.
For a raw overlay, use `--overlay FILE@SEG` to choose a hexadecimal segment above the root image.
The loader assigns each remaining overlay unit a distinct paragraph-aligned segment.

`load` creates `image.bin` and `map.json` in an output directory where both filenames are available.
Byte zero is at the root unit's linear address. The map gives the
image offsets and sizes of initialized units, and the image is zero-padded between them. Stack memory can
extend beyond the image. Turbo Pascal units use their original resident descriptor segment in their names,
such as `tpov_0085`. Their map records include file offsets and exported entries. Direct far calls identified
through relocations target the resident overlay code. Stubs become far jumps for indirect callers. The map
records the bytes replaced at each site.

The optional `relocations` list gives the image-relative offsets of relocated 16-bit words in the root and
Turbo Pascal units.

When the loader finds a bounded CS-relative word jump table, `map.json` records the dispatch, table,
default branch, and case targets in index order. It uses the `cmp` and `ja` or `jae` guard to size the table.
For adjacent tables in flat overlays, it can infer the original runtime offset from the table's file position.

`info` reports the compiler when it recognizes the startup code or a Turbo Pascal overlay directory.
The JSON output includes `compiler` with the evidence and any identified version. `compiler` is `null` when
the evidence is inconclusive. `load` and `info` both report candidate `runtime_signatures` with unit addresses
and prototypes. Patterns wildcard relocated segment words and link-dependent operands.

The catalog covers Turbo Pascal 5.5, 6.0, and 7.0 helpers for Real48 addition, strings, sets, text output, heap
allocation, and overlays. It also covers selected small-model C routines from Turbo C 2.01, Turbo C++ 1.01,
Borland C++ 2.0, and Microsoft C 5.1 and 6.0a. The compiler report identifies the linked runtime and only
includes a version when supported by the evidence. See the validation notes in [PLAN.md](PLAN.md#phase-5-runtime-signatures).

## Amiga loader

`info` and `load` detect classic AmigaDOS Hunk executables by their header. If starting from an ADF,
unpack it with `xdftool DISK.adf unpack out/disk` and pass the extracted executable to `retrore`.

```sh
.venv/bin/retrore info out/disk/PROGRAM --json
.venv/bin/retrore load out/disk/PROGRAM -o out/amiga
.venv/bin/retrore ghidra import out/amiga out/amiga-project
.venv/bin/retrore decomp h0:0000 --project out/amiga-project --json
```

The loader places resident CODE, DATA, and BSS hunks at distinct 16-byte-aligned addresses.
The default image base is `0x10000`. Use `--base-address HEX` to select another aligned address
in the 24-bit address space, including `0` for zero-based analysis notes. The layout is for static
analysis. It records the requested Amiga memory flags and zero-fills BSS, unused allocation, and gaps.

`map.json` identifies hunks as `h0`, `h1`, and so on. Each unit records its file span and memory
allocation, symbols, and applied absolute 32-bit relocations, including the compact variant. Ghidra
uses its big-endian 68k language, imports the symbols, and analyzes from the executable's entry in
`h0`. Amiga Ghidra queries accept `hN:offset` or a flat hexadecimal address. `HUNK_OVERLAY` files
produce an unsupported-format diagnostic. The `call` and `trace` commands are DOS-specific.
[Amiga ROM Kernel Reference Manual, DOS, chapter 11](https://developer.amigaos3.net/sites/default/files/downloads/2024-10/Amiga_ROM_Kernel_Reference_Manual_DOS.pdf)

## Atari ST loader

`info` and `load` detect GEMDOS executables by their `0x601a` header. Pass an executable from the
original disk, such as a `.PRG`, `.TOS`, or `.TTP` file.

```sh
.venv/bin/retrore info PROGRAM.PRG --json
.venv/bin/retrore load PROGRAM.PRG --base-address 10000 -o out/atari-st
.venv/bin/retrore ghidra import out/atari-st out/atari-st-project
.venv/bin/retrore decomp text:0000 --project out/atari-st-project --json
```

The loader places TEXT, DATA, and zero-filled BSS consecutively. Use `--base-address HEX` to set the
even TEXT base in the 24-bit address space. The default is `0x10000`. Use `0` to match notes that use
TEXT-relative addresses throughout. The loader adds the base to each longword in the GEMDOS relocation
table and preserves the original values in `map.json`. Files marked absolute keep their original TEXT
and DATA bytes. The map includes program flags, file spans, and available DRI/GST symbols with offsets
relative to their sections.
[Atari GEMDOS developer manual, Executable Files](https://www.bitsavers.org/pdf/atari/ST/Atari_ST_GEM_Programming_1986/GEM_0042.pdf)

Ghidra imports the symbols and starts 68k analysis at `text:0000`. Use `text:offset`, `data:offset`,
`bss:offset`, or a flat hexadecimal address in queries. This layout covers the resident GEMDOS image.

## Commodore 64 loader

`info` and `load` accept a Commodore 64 `.prg` or a named PRG from a `.d64` disk image. Use `--c64`
for extracted files without an extension or when the PRG's two-byte address matches another format's
signature. D64 selection accepts ASCII member names, ignoring letter case, and reads closed PRGs from
35-, 40-, and 42-track sector images with optional error tables.
[VICE disk format documentation](https://vice-emu.sourceforge.io/vice_17.html)

```sh
.venv/bin/retrore info DISK.d64 --disk-file MAIN --json
.venv/bin/retrore load DISK.d64 --disk-file MAIN --disk-file HELPERS --entry c000 -o out/c64
.venv/bin/retrore ghidra import out/c64 out/c64-project
.venv/bin/retrore decomp c000 --project out/c64-project --json
```

The loader strips the two-byte little-endian load address and places each payload unchanged.
The first `--disk-file` is `root`. Repeat it for co-resident files on that disk, or add extracted
PRGs with `--c64-unit FILE`. Use `--base-address HEX` for the root or `--c64-unit FILE@HEX` for an
additional PRG when the program copies it to a different address. `map.json` records the original
load address and the source of each payload. Export modules that reuse the same addresses in
separate layouts.

Each export represents one CPU view of a stock C64. `--c64-bank 0` exposes RAM beneath ROM and I/O.
The default `7` exposes BASIC ROM, KERNAL ROM, and I/O, while `6` exposes RAM at `$A000` and keeps
KERNAL ROM and I/O visible. Choose a bank where each PRG resides in visible RAM. The JSON memory map
records the read and write destinations. Ghidra creates uninitialized blocks for the remaining memory
and names the 6510 port registers. For software that changes the port at runtime, export one layout
per bank you want to analyze. [Commodore 64 Programmer's Reference Guide, memory management](https://www.commodore.ca/manuals/c64_programmers_reference/c64-programmers_reference_guide-05-basic_to_machine_language.pdf)

PRG headers specify a load address. A single-line BASIC `SYS` stub at `$0801` can supply a machine-code
entry inside the payload. Use repeatable `--entry HEX` to specify entry points for raw machine code or
more complex programs. The Ghidra importer uses its 6502 language for 6510 instructions. Queries accept
a flat hexadecimal address or `unit:offset`. `where-is --string` uses literal ASCII bytes. Use `--bytes`
for other PETSCII characters.

## Apple II loader

`info` and `load` read named binary (type B) members of 35-track Apple DOS 3.3 or SSI RDOS 2.1/3.3
sector images. Use `--disk-file NAME` to select a member by its case-insensitive name. `.dsk` and `.do`
default to DOS sector order, and `.po` selects ProDOS sector order. RDOS 2.1 supports native 13-sector
images (`.d13`) and padded 16-sector images. For padded images, the reader checks the catalog code to
identify the order and defaults to physical order if the marker is absent. Use `--apple2-disk-order`
with `dos`, `prodos`, or `physical` to select the order explicitly.
[Beneath Apple DOS](https://www.duxburysystems.org/downloads/library/texas/apple/manuals/beneathdos.pdf)
[CiderPress II RDOS format notes](https://github.com/fadden/CiderPress2/blob/main/DiskArc/FS/RDOS-notes.md)

```sh
.venv/bin/retrore info DISK.dsk --disk-file MAIN --json
.venv/bin/retrore load DISK.dsk --disk-file MAIN --disk-file HELPERS --entry 0800 -o out/apple2
.venv/bin/retrore ghidra import out/apple2 out/apple2-project
.venv/bin/retrore decomp 0800 --project out/apple2-project --json
```

The loader takes the address and length from the DOS binary header or the RDOS catalog. Use `--apple2`
for a standalone DOS binary with a four-byte header, or `--apple2-raw --base-address HEX` for raw bytes.
The first `--disk-file` is `root`. Repeat it for co-resident binaries on the same disk, or add a DOS
binary with `--apple2-unit FILE` or raw bytes with `--apple2-unit FILE@HEX`. `--base-address HEX` also
overrides the root's recorded load address. Export each alternative that reuses a load address separately.

Each export captures one Apple II Plus CPU view. `--apple2-lc` selects the effective Language Card
switch state from `c080` through `c08f`. The default `c082` exposes ROM. `c083` and `c08b` expose
writable bank 2 and bank 1 respectively at `$D000`–`$DFFF`, with shared Language Card RAM above them.
The map records read and write destinations. Ghidra creates placeholder blocks for unloaded ranges,
including ROM and soft switches. Export a separate view for each bank needed during analysis.
[Apple Language Card manual, appendix D](https://www.applelogic.org/files/LANGCARDMAN.pdf)

Use repeatable `--entry HEX` to seed 6502 code analysis at known entry points. Queries accept a flat
hexadecimal address or `unit:offset`. `where-is --string` matches literal ASCII bytes. Use `--bytes`
for high-bit Apple II text.

## Atari 8-bit loader

`info` and `load` recognize Atari DOS segmented binaries (XEX, including `.COM` files with an XEX
header) and ATR disk images. With an ATR, use `--disk-file NAME.EXT` to select a case-insensitive
Atari DOS 2.x member. Without a member, the loader exports the initial sectors named by the OS disk
boot header and seeds analysis at the load address plus six. ATR supports 128-byte sectors and
256-byte data sectors with three 128-byte boot sectors.
[Atari 400/800 Operating System Manual, section 10](https://www.atarimania.com/documents/atari-800-technical-reference-notes.pdf)
[Atari800 disk image implementation](https://github.com/atari800/atari800/blob/master/src/sio.c)

```sh
.venv/bin/retrore info PROGRAM.xex --json
.venv/bin/retrore load DISK.atr --disk-file MAIN.COM -o out/atari8
.venv/bin/retrore ghidra import out/atari8 out/atari8-project
.venv/bin/retrore decomp 2000 --project out/atari8-project --json
```

Use `--atari8-raw --base-address HEX` for standalone raw bytes. To build a snapshot of co-resident or
overlaid files, repeat `--disk-file` or add `--atari8-unit FILE` for another XEX and
`--atari8-unit FILE@HEX` for raw bytes. Segments apply in file order, then additional files apply in
the order specified. Later writes replace earlier bytes. Export alternative overlays separately
to analyze each one. The map retains original segment locations and file offsets and groups adjacent
bytes from the same source for analysis.

`--atari8-portb HEX` selects a static 130XE CPU view. The default `ff` leaves OS ROM visible, exposes
RAM at `$A000`–`$BFFF`, and selects base RAM at `$4000`–`$7FFF`. The map records ROM, I/O, and
banked RAM regions. XEX load records that address ROM or I/O appear under `unmapped_writes`.
Each export captures one CPU view, including when software writes to PORTB during loading or execution.
[Altirra Hardware Reference Manual](https://www.atari800xl.eu/docs/reference/altirra-hardware-reference-manual.pdf)

Ghidra uses 6502 analysis and labels selected OS vectors and hardware registers. For XEX files,
the loader looks for RUNAD and INITAD vectors in the load records, with the first segment as the
default RUNAD. It seeds entries that are present in the snapshot and have not been replaced by a later
file. Use repeatable `--entry HEX` to supply the seed list explicitly. The loader applies file bytes
without executing boot or init routines. Queries use flat hexadecimal addresses or `unit:offset`.
`where-is --string` searches literal ASCII bytes. For other ATASCII values, use `--bytes`.
[Atari800 binary loader implementation](https://github.com/atari800/atari800/blob/master/src/binload.c)

## MSX2 loader

Pass `--msx2` to `info` or `load` to select MSX2. A standalone `.COM` or the first `.COM` member
of a disk loads and starts at `$0100` by default. Raw files use `--base-address HEX`, and raw FAT12
floppies use `--disk-file NAME[@HEX]` to select a case-insensitive root-directory member. The disk
reader handles fragmented files on images with a FAT12 BIOS parameter block and 512-byte sectors.
[MSX Technical Data Book, disk driver chapter](https://sysadminmosaic.ru/_media/msx/msx_technical_data_book/msx_technical_data_book_text.pdf)

```sh
.venv/bin/retrore info PROGRAM.COM --msx2 --json
.venv/bin/retrore load DISK.dsk --msx2 --disk-file MAIN.COM --disk-file HELPER.OVR@8000 \
  --entry 0100 --entry 8000 -o out/msx2
.venv/bin/retrore ghidra import out/msx2 out/msx2-project
.venv/bin/retrore decomp HELPER.OVR:0000 --project out/msx2-project --json
```

Each export represents the four RAM pages visible to an MSX-DOS program. Use explicit addresses for
additional disk members and for standalone overlays supplied with `--msx2-unit FILE@HEX`. Use
`--msx2-copy SRC:SIZE@DEST` for a resident copy made from the original root file at runtime. All three
numbers are hexadecimal. The root loads first, then the resident copies, then the additional disk
members and standalone units. Later loads replace bytes at overlapping addresses, and the map keeps
source file offsets for the surviving ranges. Export each alternative overlay in a separate snapshot.

Repeat `--entry HEX` for the routines that should seed Z80 analysis, including any relocated or raw
entry points. Queries accept flat hexadecimal addresses or `unit:offset`. Ghidra labels `BDOS` and
selected I/O ports. The exported view uses caller-supplied memory placement and covers MSX-DOS RAM.
[Ghidra Z80 language definition](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/Z80/data/languages/z80.ldefs)

## NEC PC-88 loader

Pass `--pc88` to `info` or `load`. A `.d88` or `.d77` image defaults to loading the 256-byte
IPL from cylinder 0, head 0, sector ID 1 at `$C000`. For a container with multiple disks, use
`--pc88-disk INDEX` to select one by its 1-based index. A raw input needs `--base-address HEX`.
[D88 disk format](https://illusioncity.net/PC88/D88STRUC.txt)
[PC-8801 IPL demonstration](https://www.kiwi-us.com/~ohta/pc88/ipl.htm)

```sh
.venv/bin/retrore info DISK.d88 --pc88 --json
.venv/bin/retrore load DISK.d88 --pc88 --pc88-sector 0:0:1@c000 --pc88-sector 0:0:2+4@8000 \
  --entry c000 -o out/pc88
.venv/bin/retrore ghidra import out/pc88 out/pc88-project
.venv/bin/retrore decomp c000 --project out/pc88-project --json
```

Supply repeatable `--pc88-sector C:H:R[+COUNT]@HEX` options to choose the disk spans and their load
addresses. Specify cylinder, head, sector ID, and count in decimal. A span follows ascending sector
IDs within each track and continues onto the next track in cylinder and head order. Explicit spans
replace the default IPL selection. Use `--entry HEX` to seed analysis in an explicit layout.
`map.json` records original container offsets, including a `file_spans` list for loads whose bytes
cross sector headers.

After disk placement, use `--pc88-copy SRC:SIZE@DEST` to copy hexadecimal spans from a single visible
load. Repeat `--pc88-unit FILE@HEX` to apply additional raw loads after the copies. Later loads
replace overlapping bytes. Export alternative overlays and bank states separately.

The default IPL view uses N88-BASIC ROM below `$8000` and main RAM at `$C000` and above. Explicit
loads default to main RAM throughout. Use `--pc88-low ram|n88-rom|n-rom` and
`--pc88-high ram|blue|red|green` to select the visible ROM window and graphics VRAM plane.
The ROM window is represented as uninitialized memory. The export describes one main-CPU view,
with the text window at its default address. Disk and bank switching are supplied by the caller.
Ghidra labels selected hardware ports in the `pc88_ports` block. The command
`xrefs pc88_ports:0031 --project out/pc88-project --json` queries the graphics memory control port.
[MAME PC-8801 memory and I/O maps](https://github.com/mamedev/mame/blob/master/src/mame/nec/pc8801.cpp)

## NEC PC-98 loader

Pass `--pc98` to `info` or `load` for D88/D77 disks, 1232 KiB raw HDM floppies, or raw binaries.
The default disk selection is cylinder 0, head 0, sector ID 1 at `1fc0:0000`. Use
`--pc98-disk INDEX` to select a disk in a concatenated D88/D77 container (1-based).
[NEC PC-9800 Technical Data Book](https://vtda.org/docs/computing/NEC/PC-9800TechnicalDataBookHARDWARE%2BOCR_1993.pdf)

```sh
.venv/bin/retrore info DISK.d88 --pc98 --json
.venv/bin/retrore load DISK.d88 --pc98 --pc98-sector 0:0:1@1fc0 --pc98-sector 0:1:1+2@3f00 \
  --pc98-entry 1fc0:0000 --pc98-entry 3f00:0000 -o out/pc98
.venv/bin/retrore ghidra import out/pc98 out/pc98-project --json
.venv/bin/retrore decomp 3f00:0000 --project out/pc98-project --json
```

Repeat `--pc98-sector C:H:R[+COUNT]@SEG` to select co-resident pieces. Cylinder, head, sector ID,
and count are decimal. Each span follows sector IDs in ascending order and continues to the next
track when needed. The hexadecimal segment places the span at `SEG:0000`. Explicit selections
replace the default IPL selection. The map records original disk offsets, with `file_spans` for
multi-sector loads.

Use `--base-segment HEX` for a raw root file and repeat `--pc98-unit FILE@SEG` for additional raw
loads. A layout represents one set of non-overlapping loads in conventional RAM. Export a separate
layout when another stage or disk replaces those bytes. The first load is the root and its start is
the default entry. Repeat `--pc98-entry SEG:OFF` to seed explicit entries, including in stages
reached through an indirect transfer.

The map describes the PC-9801 conventional RAM, text and graphics VRAM, C-Bus window, and IPL ROM.
Ghidra imports the program as 16-bit real-mode x86 and represents VRAM and IPL ROM as uninitialized
blocks. Query loaded code by `seg:off` or `unit:offset` and graphics references by block name,
such as `blue_vram:0012`. [MAME PC-9801 memory map](https://github.com/mamedev/mame/blob/master/src/mame/nec/pc9801.cpp)

## Ghidra

Set `GHIDRA_HOME` to your Ghidra installation directory, which contains `support/analyzeHeadless`, and use a JDK
supported by that installation. Set `JAVA_HOME` if your shell defaults to a different JDK. See
[Compatibility](#compatibility) for the tested setup.

```sh
export GHIDRA_HOME=/path/to/ghidra
export JAVA_HOME=/path/to/jdk-25
```

Pass the project path with or without its `.gpr` extension.

For DOS, the importer creates one memory block per unit, names overlay entries and stubs, and runs
Ghidra's auto-analysis.
The importer marks recovered table words as data, adds computed jump references, and disassembles each case
so auto-analysis can discover the routines they call.

After analysis, the importer recognizes `push cs` followed by a direct near `call` when the callee's return
instructions agree on a far return and stack cleanup. It applies the far calling convention to the callee.
It also names and types runtime signature matches at analyzed function entries. Import JSON reports the
number of far procedures recognized and runtime signatures applied.

After auto-analysis, the importer tracks DS, ES, and SS through recovered control flow. It recognizes the
startup DGROUP assignment, relocation-backed segment words, and register transfers such as
`push ds` / `pop es`. It applies the inferred context in Ghidra and adds typed references to direct memory
operands in the loaded image. The listing uses names like `DGROUP_4433` and `FAR2820_97f0`. Names use the
relocated segment. Ghidra 12.2 may still print some ES-relative accesses as numeric offsets in decompiled C.

The analysis assumes DS and SS are preserved across ordinary calls. It uses the startup DGROUP as the
default for functions reached only through unresolved control flow and drops values when incoming paths
disagree. A resolved direct write invalidates any overlapping relocation-backed segment word.
Re-export images made by older versions to include the relocation metadata.

```sh
.venv/bin/retrore ghidra import out/pool out/pool-project
.venv/bin/retrore decomp tpov_0025:1036 --project out/pool-project --json
.venv/bin/retrore ghidra import out/phantasie out/phantasie-project
.venv/bin/retrore decomp OV1:20bb --project out/phantasie-project --json
.venv/bin/retrore gaps --project out/phantasie-project --json
```

`decomp` accepts any address in an analyzed function. For DOS, use a hexadecimal `unit:offset` or
`seg:off` address. The JSON response includes the function's entry address and decompiled C.

`gaps` reports ranges of undefined bytes in executable image blocks. These ranges may contain code,
data, or padding. Text output shows the total and the first ten ranges. JSON includes all ranges with
inclusive `unit:offset` endpoints, the starting linear address, and byte counts.

## Program queries

```sh
.venv/bin/retrore xrefs OV1:20bb --project out/phantasie-project --json
.venv/bin/retrore callers OV1:20bb --project out/phantasie-project
.venv/bin/retrore callees OV1:20bb --project out/phantasie-project
.venv/bin/retrore func OV1:20bb --project out/phantasie-project --json
.venv/bin/retrore where-is --export out/phantasie --bytes 'b8 00 4c'
.venv/bin/retrore where-is --export out/phantasie --string 'Mystic'
.venv/bin/retrore where-is --export out/phantasie --constant 0x1234 --width 2 --json
```

`xrefs` reports incoming and outgoing references Ghidra recorded at the exact address, including code and
data references. `callers` and `callees` accept any address inside an analyzed function and list individual
resolved call sites. Callers target the function entry. JSON includes the source and target addresses,
reference type, operand index, and enclosing functions when available.

`func` reports the function entry, inclusive body ranges, total body size in bytes, and callers. For DOS
it gives Ghidra's DS, ES, and SS values at the requested address. Unknown values appear as `?` in text
and `null` in JSON.

`where-is` searches relocated, file-backed bytes in the export. Matches can overlap and must fit
within a unit's file-backed span. `--string` uses DOS CP437, Amiga Latin-1, PC-98 CP932, or ASCII
on the other platforms. Use
`--bytes` to search for Atari ST text containing bytes above `0x7f`.
`--constant` accepts a decimal or `0x`-prefixed integer and encodes it in the platform's byte order
at the specified width (1, 2, 4, or 8 bytes, default 2).

Text output previews up to ten references or matches. Use `--json` for the full results with
`unit:offset` and linear addresses where available. Ghidra queries also report the address as
displayed by the analyzed project.

### Limit Ghidra address query results

On `xrefs`, `callers`, `callees`, and `func`, use `--limit N` and `--offset N` to page each reference
list. The offsets start at zero and apply after filtering. `--ref-type TYPE` accepts an exact Ghidra
reference type such as `READ` or `UNCONDITIONAL_CALL`, ignoring case. Repeat it to keep any of the
specified types. `xrefs` accepts `--direction incoming` or `--direction outgoing` to select one list.

```sh
.venv/bin/retrore xrefs OV1:20bb --project out/phantasie-project --json \
  --direction incoming --ref-type UNCONDITIONAL_CALL --limit 10 --compact --fields incoming
```

When paging, `pagination` reports `offset`, `total`, `returned`, and `next_offset` for each reference
list included. Use the same filters and pass `next_offset` as `--offset` to get the next page. A
`null` offset means you reached the end of that list. `--compact` returns each address record as a
`unit:offset` string when available, or its Ghidra display address. `--fields FIELD,...` selects
top-level result fields in JSON, including for `decomp`. Paging metadata accompanies any selected
reference lists. Request only metadata fields from `decomp` to skip decompiling the body.

### Focused decompilation

Pass a call, branch, or memory instruction address to `decomp` to see the relevant C and the
values that reach the instruction. `--context N` returns up to N lines before and after the first
matching C line (0–20). `--slice N` returns up to N Ghidra high p-code operations (1–128), starting
at the selected instruction and following input definitions within the function. Use either option
on its own or combine them.

```sh
.venv/bin/retrore decomp OV1:20a5 --project out/phantasie-project --context 2 --slice 12 --json
```

The top-level address still identifies the function entry. `focus` gives the selected instruction's
start address, disassembly, and loaded bytes, including when the query address is inside the
instruction. `excerpt` lists C line numbers and addresses from Ghidra's p-code markup. In `slice`,
operations marked `focused` seed the search. Inputs give their storage, size in bytes, and the local
operation ID of their definition, when known. A bounded slice reports `truncated: true` if there
are more operations, and a definition can refer to an operation beyond the limit.

The slice follows Ghidra's recovered input definitions within one function. Call arguments reflect
Ghidra's prototype analysis. A load traces its address calculation and any other input definitions
Ghidra recovered. Instructions eliminated by the decompiler can yield an empty excerpt or slice.
[Ghidra p-code reference](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html)

Use plain `decomp` or select `decompilation` explicitly with `--fields` to get the entire C body.
To retrieve the instruction bytes at any returned address, query it with `--context 0 --fields focus --json`.

### Batch Ghidra queries

`batch` runs `decomp`, `xrefs`, `callers`, `callees`, and `func` against one project in a single
read-only headless session. Decompilations share one decompiler. The command works with projects
from every supported platform and accepts the same addresses as the individual commands.

```sh
.venv/bin/retrore batch --project out/phantasie-project --json <<'EOF'
[
  {"command": "decomp", "address": "OV1:20bb"},
  {"command": "decomp", "address": "OV1:20a5", "context": 2, "slice": 12},
  {"command": "callers", "address": "OV1:20bb"},
  {"command": "xrefs", "address": "OV1:20a5", "direction": "outgoing", "limit": 10, "compact": true}
]
EOF
```

Pass a UTF-8 JSON file as the positional argument or pipe the array on stdin. Each request contains
a `command` and an `address`. Optional fields match the individual commands. Use the arrays `fields`
and `ref_types`, the integers `limit`, `offset`, `context`, and `slice`, the boolean `compact`, and
the string `direction` where supported. The JSON response contains `contract` and a `results` array in
request order. Each row echoes those two fields and includes either `result`, with the individual command's
JSON, or an `error` object with `code`, `message`, and `hint`. The CLI writes the whole batch report to
stdout and exits with status 1 if any query fails. An invalid request array or a headless launch failure
uses the command's error stream. A batch launches Ghidra once, so it costs about the same as one single
query. See [benchmarks](docs/benchmarks.md).

### Errors, exit statuses, and time budgets

`ghidra import`, `decomp`, `gaps`, `batch`, `xrefs`, `callers`, `callees`, and `func` accept
`--timeout SECONDS`. Imports default to 3600 seconds and queries to 600. `0` disables the limit.
When the budget runs out, retrore stops the whole `analyzeHeadless` process group, JVM included.
It sends SIGTERM first so Ghidra can release the project lock, then SIGKILL after 10 seconds. The
Python functions in `retrore.ghidra` take the same `timeout` keyword.

With `--json`, a failed command prints this object to stderr:

```json
{"contract": 1, "error": {"code": "no_function", "message": "no analyzed function contains c00a", "hint": "..."}}
```

| Exit status | Meaning |
|---|---|
| 0 | Success |
| 1 | The command failed and printed an error, or a batch finished with at least one failed query |
| 2 | Invalid command-line usage, reported by argparse in plain text even with `--json` |

`code` is stable, and scripts should branch on it. `message` and `hint` are for people and may change.

| Code | Meaning |
|---|---|
| `ghidra_not_found` | `GHIDRA_HOME` does not contain `support/analyzeHeadless` |
| `project_not_found` | The `--project` path has no `.gpr` file |
| `export_invalid` | `map.json` or `image.bin` is missing or invalid |
| `unsupported_map_version` | `map.json` comes from a newer retrore |
| `timeout` | The headless run exceeded `--timeout` |
| `headless_failed` | `analyzeHeadless` exited without a result; the message ends with the log tail |
| `script_error` | A retrore Ghidra script reported an unclassified failure |
| `invalid_request` | The query or batch request failed validation |
| `address_not_found` | The address is malformed for the project or outside the loaded image |
| `no_function` | No analyzed function or instruction contains the address |
| `project_mismatch` | A trace was compared with a project imported from a different image |
| `query_failed` | Ghidra could not answer the query, for example when decompilation fails |
| `unsupported_packer` | The DOS executable uses a packer retrore cannot unpack; `packer` names it |
| `input_invalid` | The input program or options are invalid for the selected platform |
| `io_error` | A file could not be read or written |

Batch rows use the same `error` object, with the query codes `address_not_found`, `no_function`, and
`query_failed`.

### Versions and compatibility

`map.json` carries an integer major `version`, currently 1. Readers treat a map without `version`
as version 1. They reject a larger version with `unsupported_map_version` and other invalid
values with `export_invalid`. New optional fields do not change the version, and readers ignore
fields they do not know. A change that older readers would misread, such as a changed meaning or
a removed field, increments `version`. The checked-in [unversioned fixtures](tests/fixtures/maps) cover
the DOS, Amiga, C64, MSX2, and PC-98 exporters, and the tests check that current code still reads them.

Ghidra query JSON carries a top-level `contract` integer, currently 1. It is present on single queries
(even with `--fields`), `gaps`, batch reports, and error objects. It is not present inside batch row
results. Adding fields, query commands, or error codes keeps the contract number. Renaming or removing
a field, or changing its type or meaning, increments it.

## Emulator harness

`call` runs a routine from an exported image with Unicorn. Each call starts with a fresh copy of the
image and the exported `SS:SP`, which you can override through `--regs`. Supply the data segments,
arguments, and memory the routine expects. The harness pushes a synthetic return frame below the
configured `SP`, so stack arguments start at the configured `SS:SP`. Use `--far` for a routine that
ends in `RETF`. The default is a near `RET`.

```sh
.venv/bin/retrore call root:1234 --export out/program --regs ax=10,ds=2000 \
  --mem 2000:0100=3412 --read 2000:0100=2 --json
```

Addresses and register values are hexadecimal. `--mem` writes literal bytes in the order given.
`--read` sizes are decimal or `0x`-prefixed. Repeat these options for additional ranges. JSON returns
the resolved address, final registers as integers, and requested memory bytes as hex strings. The
default instruction limit is one million. Set `--limit N` for another budget.

The Python API supports interrupt handlers, port I/O, and execution hooks. For example, a routine
that calls BIOS to read a key can receive a scripted Enter key.

```python
from pathlib import Path

from unicorn.x86_const import UC_X86_REG_AX

from retrore.emulator import Emulator


def read_key(cpu, vector):
    cpu.reg_write(UC_X86_REG_AX, 0x1C0D)


emulator = Emulator.from_export(Path("out/program"))
result = emulator.call("root:1234", interrupts={0x16: read_key})
print(result.registers["ax"])
```

Use `on_in(cpu, port, size)` to return a port value and `on_out(cpu, port, size, value)` to handle a
port write. Pass `hooks={address: callback}` to run `callback(cpu)` before executing an instruction
at that address. These callbacks receive the live Unicorn CPU. Turbo Pascal stubs use the resident
overlays, including when an original `INT 3Fh` stub is restored. Unhandled interrupts and port I/O
stop the call with an error.

## DOSBox-X traces

In a heavy-debug build of DOSBox-X, break in the loaded program and run `LOGS 100` to write
`LOGCPU.TXT` for the next 0x100 instruction records. The importer also accepts `LOG`, `LOGL`,
and `LOGC` output from builds that provide those commands. Start the capture after unpacking
when working with a packed executable. [DOSBox-X debugger source](https://github.com/joncampbell123/dosbox-x/blob/master/src/debug/debug.cpp#L2940-L2975)

```sh
.venv/bin/retrore trace LOGCPU.TXT --export out/program --runtime-base 0813 \
  --overlay-segment OV1=4200 --project out/program-project --json
```

Set `--runtime-base` to the hexadecimal segment where DOS loaded the root module. It defaults to
the export's base segment. Map each captured overlay with `--overlay-segment UNIT=HEX` using the
unit name from `map.json` and its runtime load segment. Use one capture per layout when overlays
reuse a load address.

The report counts hits at each address, combining equivalent segment:offset pairs and showing the
first observed pair. JSON includes unmapped addresses and the count of ignored nonblank lines.
With `--project`, a read-only Ghidra query lists executed functions and hit counts. It also lists
traced addresses where disassembly has no instruction start because the address is undefined,
defined as data, or inside an instruction.

## Tests

Install `pytest` with `.venv/bin/python -m pip install pytest`, then run tests with
`.venv/bin/python -m pytest`. The real-game tests read Pool of Radiance DOS v1.3 from
`RETRORE_POR_DIR`, the Phantasie I DOS MZ edition from `RETRORE_PH1_DIR`, and Phantasie III's
`MAIN.EXE` from `RETRORE_PH3_DIR`. Point `RETRORE_PH1_AMIGA_DIR` and `RETRORE_PH3_AMIGA_DIR` to
the extracted Amiga directories containing `game` and `PhantasieIII` respectively. Set
`RETRORE_PH2_ST_DIR` to the extracted Phantasie II v1.0 Atari ST disk directory with `PHANT.PRG` and
`UTILIT2.PRG`. Set `RETRORE_PH1_C64_DIR` to the directory containing
`Phantasie_I_1986_SSI_Side_A.d64`. Set `RETRORE_PH1_APPLE2_DIR` to the directory containing
`phantasie1-4am-side-a-boot.dsk` and `RETRORE_PH3_APPLE2_DIR` to the directory containing
`Phantasie_III_1987_SSI_cr_Disk_1_of_3_Side_A.dsk`. Point `RETRORE_PH1_ATARI8_DIR` and
`RETRORE_PH2_ATARI8_DIR` to directories containing `phantasie1-side-{a,b}.atr` and
`phantasie2-side-{a,b}.atr` respectively. Set `RETRORE_PH3_MSX2_DIR` to the directory containing
the Phantasie III MSX2 Scenario Disk `.dsk` image. Set `RETRORE_PH3_PC88_DIR` to the directory
containing the Phantasie III PC-88 Program and Utility Disk `.d88` images. Set
`RETRORE_PH3_PC98_DIR` to the directory containing the Phantasie III PC-98 Program and Utility Disk
`.d88` images. The Ghidra tests use
`GHIDRA_HOME` and include synthetic programs for all supported platforms. Tests skip when their
input variables are unset.
Release CI runs when a tagged GitHub release is published. It builds and installs the wheel and
runs the synthetic suites with the headless tests enabled. [Release workflow](.github/workflows/release-ci.yml)

See the roadmap for upcoming work.
[PLAN.md](PLAN.md)

## License

MIT, see [LICENSE](LICENSE).
