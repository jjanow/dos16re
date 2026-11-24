# retrore

Standalone reverse-engineering tools for 16-bit real-mode DOS programs, AmigaDOS Hunk executables,
Atari ST GEMDOS executables, Commodore 64 PRGs, Apple II binaries, Atari 8-bit executables, MSX2 programs,
NEC PC-88 and PC-98 programs, Sharp X1 programs, Sharp X68000 Human68k executables, Classic
Macintosh 68k applications, NES / Famicom cartridges, and Sega Genesis / Mega Drive cartridges.
The games in [PLAN.md](PLAN.md) are optional validation targets for executable formats and compiler
patterns.

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

The package requires Python 3.12 or newer. The table records the setups used for local
verification and configured for release CI.

| Check | Python | Ghidra | JDK |
|---|---|---|---|
| Local standalone suite | 3.14 | — | — |
| Local suite with headless tests enabled | 3.14 | 12.2 | OpenJDK 25 |
| Release CI configuration for the installed wheel | 3.12 | 12.2 | Temurin 25 |
| Release CI Windows job: worker, MCP, and synthetic Ghidra tests | 3.12 | 12.2 | Temurin 25 |

See the [release workflow](.github/workflows/release-ci.yml) for the exact CI setup. It runs for each
published release and can be started by hand to verify changes, such as Windows worker hosting, that
can't be tested locally.

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

Agents that work better with typed tools can use the [agent adapter](#agent-adapter) instead.

### Agent adapter

`retrore schema --json` prints a JSON Schema (draft 2020-12) of the query contract, generated from
the query registry. `$defs` holds one request schema per query command (`decomp_request`,
`xrefs_request`, …), `request` (any one of them, discriminated by `command`), `batch` (a nonempty
array of requests), `error`, and `error_report` (the `--json` error object). The top-level
`contract` and `commands` keys give the contract version and a summary of each command. Plain
`retrore schema` lists the commands. The schema expresses every check except the combined cap of
256 `functions` lookups, which it records as `x-retrore-max-total-items`.

```sh
.venv/bin/retrore schema --json > retrore-schema.json
```

`retrore mcp` serves the same queries to [MCP](https://modelcontextprotocol.io) clients over stdio.
It offers one tool per query command, `batch`, `where_is`, `relocations`, `lookup`, `bytes`,
`address_map`, `info`, `load`, and `members`. Query tools take the request parameters as arguments, plus `project`,
an optional exact Ghidra `program` name, and an optional `timeout` in seconds. `batch` takes `requests`,
the same array `retrore batch` reads. `where_is` takes `export` and one of `bytes`, `string`, `constant`,
or `pointer`. `bytes` and `address_map` take `export` and `address`. A call runs through the same validation and
functions as the CLI. Its `structuredContent` and text content hold the JSON that `--json` prints.
An error result has `isError: true` and carries the `--json` error object with `code`, `message`,
and `hint`. A batch with failed rows, or a `functions` call with failed lookups, still succeeds
and reports `error` in those rows, although the CLI exits with status 1. The `gaps` tool
always uses the paged form, like `retrore gaps --limit N`.

`info`, `load`, and `members` take `program` and the corresponding CLI options, named as in
the CLI with underscores, such as `base_segment`, `overlay`, `member`, `x1_lsn`, and `entry`.
`load` also requires `output`. Flags are booleans, repeatable options are arrays of strings, and
values use the CLI's text formats, such as `"c000"` and `"OV1.OVR@2000"`. The tool passes them
through the CLI's parser, so the result is the program map that `--json` prints and usage errors
become `invalid_request`. `load` never overwrites an existing `image.bin` or `map.json`. Importing
into Ghidra stays with `retrore ghidra import`.

Add the server to Claude Code with `claude mcp add retrore -- retrore mcp`, or put this entry in an
MCP client's configuration, such as a project's `.mcp.json`. Use the absolute path to
`.venv/bin/retrore` if it is not on `PATH`, and set `GHIDRA_HOME` in the client's environment.

```json
{"mcpServers": {"retrore": {"command": "retrore", "args": ["mcp"]}}}
```

To keep a deployed copy that tracks development, run `tools/deploy.sh --hooks --mcp` from a clone.
It installs the committed tip of `main` (never the working tree) into its own virtual environment
under `~/.local/share/retrore`, writes a `~/.local/bin/retrore` wrapper that defaults `GHIDRA_HOME`
to `/snap/ghidra/current/ghidra`, registers `retrore mcp` with Claude Code at user scope, and
installs `post-commit`, `post-merge`, and `post-rewrite` hooks. The hooks redeploy in the background
whenever `main` moves in that clone (log in `~/.local/share/retrore/deploy.log`; the deployed commit
is in `COMMIT` there). Running MCP servers keep the code they started with, so reconnect `retrore` in
Claude Code's `/mcp` menu, or start a new session, after an update. Rerun the script to deploy by hand.
`RETRORE_DEPLOY_DIR`, `RETRORE_DEPLOY_BRANCH`, `RETRORE_BIN_DIR`, and `GHIDRA_HOME` override the defaults.

The server supports clients that open with `initialize` (MCP 2025-11-25 and earlier) and clients
that send the protocol version with each request (MCP 2026-07-28). Some tool-calling APIs reject
`oneOf`, `anyOf`, and `allOf` at the top level of a tool's input schema. The tool schemas therefore
state those constraints in their descriptions, and retrore still enforces them.

Tool calls run on up to four worker threads and may finish out of order. Ghidra locks a project
while a headless session has it open, so calls on the same project wait for each other; calls on
other projects and the `where_is`, `info`, and `load` tools run alongside them. The server keeps a
[persistent worker](#persistent-query-workers) per project: the first call on a project starts Ghidra
in a few seconds, and later calls take milliseconds. `batch` still saves round trips for independent
queries. A client that sends `notifications/cancelled` for a call in progress stops the project's
Ghidra process group and gets no response for that call; the next call starts a new worker. A
cancelled call that is still waiting for its project never starts. `retrore mcp --no-worker` launches
Ghidra once per call instead.

## Disk and container members

Use `members` to list a catalog before loading. The JSON includes each member's name, type,
selector, and available source metadata. Pass a loadable member's selector or name to `info`
or `load`. IDs are local to the catalog and distinguish duplicate names. `--disk-file` remains
an alias of `--member`.

```sh
retrore members DISK.d64 --json
retrore load DISK.d64 --member MAIN -o out/c64
retrore members SCENARIO.dsk --format fat12 --json
retrore load SCENARIO.dsk --msx2 --member id:file:1 --member 'id:file:2@8000' -o out/msx2
retrore members COLLECTION.d88 --json
retrore load COLLECTION.d88 --pc88 --member id:disk:2 --pc88-sector '0:0:1@c000' -o out/pc88
```

Catalogs cover DOS MZ overlays, D64, Apple DOS and RDOS, ATR boot sectors and Atari DOS, root
FAT12 files, disks in D88/D77 and HDM containers, and Classic Macintosh HFS, Disk Copy 4.2, and
resource fork wrappers. D88/D77 and HDM selection uses the native PC-88, PC-98, or X1 sector options.
Select `id:boot:1` to load the ATR boot payload explicitly. For a standalone Macintosh resource
fork or wrapper, `id:application` loads the complete application and individual resources are
listed for inspection. Repeat `--member` to order co-resident file loads on platforms that
accept multiple files. Use `--format` for ambiguous filenames and `--apple2-disk-order` for
explicit Apple II sector order.

`container_layout` in `map.json` records the selected members in request order and the disk
layout decisions. The per-unit `member_id` identifies the source catalog entry even when a later
load splits a unit. Use the same selector with `address-map --from file --member` to narrow an
offset lookup to that source.

## DOS loader

The loader restores the original load module from EXEPACK, LZEXE 0.90, 0.91, and 0.91e, and supported
PKLITE streams. PKLITE support covers standard small and large streams, recognized XOR- and
ADD-scrambled EXE stubs, and v1.20 streams with encoded match distances and big-endian relocation
offsets. The COM loader can follow recognized copier and decoder pointers when the copyright area
is erased. The loader applies segment relocations and records the original initial `CS:IP` and
`SS:SP`. Unrecognized packed variants produce a coded error.

```sh
.venv/bin/retrore info PROGRAM.EXE
.venv/bin/retrore load PROGRAM.EXE -o out/program --json
.venv/bin/retrore load START.EXE --overlay GAME.OVR -o out/pool
.venv/bin/retrore load PHANTASI.EXE --overlay OV1.OVR --overlay OV2.OVR -o out/phantasie
.venv/bin/retrore load GAME.COM -o out/com
.venv/bin/retrore load CODE.BIN --dos-raw --base-segment 2000 --dos-offset 100 --dos-entry 120 -o out/raw
```

Both commands accept `--json`, `--base-segment HEX` (default `1000`), and repeatable `--overlay FILE`.
For a raw overlay, use `--overlay FILE@SEG` to choose a hexadecimal segment above the root image.
The loader assigns each remaining overlay unit a distinct paragraph-aligned segment above the root's
memory: its file image, its initial stack, and for unpacked programs the header's minimum allocation.
`map.json` records that limit as `memory_end`, and the Ghidra importer backs the root's uninitialized
data and stack below it with an uninitialized `root_bss` block, so globals there get names and references.

DOS COM programs load at offset `0100` above a minimal Program Segment Prefix with an initial stack
at `FFFE`. Use `--dos-com` to select COM explicitly when the extension or header is ambiguous. Raw loads
default to offset `0000` and enter at the first input byte unless `--dos-entry` is supplied. Compare
`dos_format`, `load_offset`, and `file_spans` in the export to identify generated prefixes and input bytes.

Embedded Borland VROOMM, Microsoft LINK, and Microsoft MOVE overlays are discovered from the
executable. Pass each separate Microsoft LINK bank as `--overlay FILE` to `members`, `info`, or
`load`. Supply all banks to resolve the resident directory. Each member keeps the source file
and payload offset from its own bank.

```sh
retrore members GAME.EXE --overlay GAME1.OVL --overlay GAME2.OVL --json
retrore load GAME.EXE --overlay GAME1.OVL --overlay GAME2.OVL --member id:link_0001 -o out/link
retrore members DYNAMIC.EXE --json
retrore load DYNAMIC.EXE --member id:move_0001 --member id:move_0002 -o out/move
```

Repeat `--member` to select a subset in request order when the full analysis image would exceed
1 MiB. The loader exports native file offsets, applies verified fixups, and rewrites resolved
resident stubs.
VROOMM skips empty code descriptors and handles the reserved fixup bit used by Turbo C++ 1.01.
A flagged VROOMM function-pointer fixup resolves two adjacent `MOV reg,imm16` / `PUSH reg` pairs
using the same register to a unique resident stub. Static LINK directories can be recovered from count
fields or adjacent relocation-backed arrays corroborated by member fixups, including when the
resident module is EXEPACK-compressed. Verified members share one runtime window, including any
padding before their first routine. A member's minimum allocation can account for trailing segments
omitted from the file. Only file-backed segment starts appear in
`segment_offsets`, and fixups to omitted segments keep their relocated runtime addresses.
Inspect `diagnostics` in JSON for unmatched trailers, unresolved VROOMM function-pointer offsets,
and unidentified or ambiguous LINK directories.

MOVE verifies its resident directory against member file offsets and allocation sizes. It
applies member-relative fixups using the resident load segment and follows relocated pointers
to resident dispatch stubs. Verified stubs become far jumps to selected members in the analysis
image. Ghidra backs any allocation beyond the file bytes with uninitialized memory. MOVE chooses
physical placements at runtime. Supply segments from a capture with `--runtime-base` and
`--overlay-segment UNIT=HEX`, or describe observed states in a load manifest.
See the [Phase 12 validation notes](PLAN.md#phase-12-loader-depth-on-supported-platforms).

`load` creates `image.bin` and `map.json` in an output directory where both filenames are available.
Byte zero is at the root unit's linear address. The map gives the
image offsets and sizes of initialized units, and the image is zero-padded between them. Stack memory can
extend beyond the image. Turbo Pascal units use their original resident descriptor segment in their names,
such as `tpov_0085`. Their map records include file offsets and exported entries. Direct far calls identified
through relocations target the resident overlay code. Stubs become far jumps for indirect callers. The map
records the bytes replaced at each site.

The optional `relocations` list gives the image-relative offsets of relocated 16-bit words in the root
and overlay units.

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

### Linker maps and signature catalogs

Pass `--linker-map PROGRAM.MAP` to `load` or `info` to import resident public symbols and source-line
tables from segmented Microsoft LINK or Borland TLINK listings. The export records the input digest
and listing line for each accepted symbol. Ghidra imports labels and shows the source lines as listing
comments. The map reports skipped addresses, including unresolved overlay addresses.
[Microsoft LINK manual](https://bitsavers.trailing-edge.com/pdf/microsoft/msdos_3.20/410630013-320-O02-1285_MSDOS_3.20_User_Reference_1986.pdf)
[Borland TLINK manual](https://www.bitsavers.org/pdf/borland/borland_C%2B%2B/Borland_C%2B%2B_Version_3.1_Tools_and_Utilities_1992.pdf)

Pass `--signatures catalog.json` to match exact bytes and `??` wildcards in initialized units.
Each entry can supply a `unit` to limit the search and a `toolchain` to record the origin.
The match report includes candidate bytes. A unique match becomes a symbol available to
`lookup` and the Ghidra importer.

```json
{"version": 1, "signatures": [
  {"name": "runtime_helper", "pattern": "55 8b ec ?? ?? c3", "unit": "root", "toolchain": "local compiler probe"}
]}
```

## Load states

Use `--load-manifest FILE` with `load` or `info` to describe which units occupy memory in each
runtime state. The `loads` array gives load order. Addresses default to each unit's analysis
address. A later load with `"replace": true` takes over the covered bytes while retaining any
uncovered portions of earlier loads. A state omits units that are absent. For flat 8-bit images,
`variants` can add file-backed units from another export of the same platform. Use a free analysis
address for each added unit. Export paths are relative to the manifest.

```json
{
  "version": 1,
  "initial": "first",
  "states": [
    {"name": "first", "loads": [{"unit": "root"}]},
    {"name": "second", "loads": [{"unit": "bank_two", "linear": "c000"}]}
  ],
  "transitions": [{"from": "first", "to": "second", "kind": "bank", "trigger": "bank select write"}],
  "variants": [{"export": "out/other-bank", "unit": "root", "name": "bank_two", "linear": "8000"}]
}
```

```sh
retrore load BANK1.PRG --load-manifest banks.json -o out/banks
retrore address-map c000 --from runtime --all-states --export out/banks --json
retrore ghidra import out/banks out/bank-project --load-views --json
```

Use `address-map --state NAME` or `trace --state NAME` to select a state. The manifest's initial
state is the default. In a structured trace, `{"kind":"bank","state":"second"}` follows a declared
transition. The ordered event record identifies the unit and source at a reused runtime address.
Ghidra's `--load-views` puts the visible portions of each state in its own address space. These
blocks show the exported bytes, including analysis-time relocations. The primary address space
remains the starting point for decompilation and static references.

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

`map.json` identifies resident hunks as `h0`, `h1`, and so on. Units record file spans and memory
allocations, symbols, absolute and PC-relative relocations, and recognized `HUNK_DEBUG` LINE records.
Each branch of a hierarchical `HUNK_OVERLAY` tree has named units, for example `ov1_2_h1`, at distinct
analysis addresses. The tree records table entries, parentage, and source offsets. Its generated
load states describe which hunks can coexist along each branch. Table symbols at the exact end of a
hunk carry `at_boundary` and are excluded from Ghidra entry points. Actual AmigaOS scatter-load
addresses can be supplied in a manifest or recorded in a trace.

Ghidra imports native symbols, supported source maps, and overlay entry points. Amiga queries
accept `unit:offset` or a flat hexadecimal address. Use `call` for CPU-level routine execution and
`trace` to map emulator events onto the exported hunks.
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

## Sharp X1 loader

Pass `--x1` to `info` or `load`. A `.d88` or `.d77` image defaults to the IPL boot entry. This is
the 32-byte header in cylinder 0, head 0, sector ID 1, with attribute `01`, a 13-byte name,
extension `Sys`, and the payload size, load address, and execution address at `+12`, `+14`, and
`+16`. Its 16-bit starting logical sector is at `+1E`. The loader reads the payload from that sector,
truncates it to the header size, and seeds analysis at the execution address. Logical sectors
fill both sides of a cylinder in turn: track = LSN / 16, head = track & 1, cylinder = track / 2,
sector ID = LSN % 16 + 1. For a container with multiple disks, use `--x1-disk INDEX` (1-based).
A raw input needs `--base-address HEX`.
[X Millennium built-in IPL](https://github.com/r-type/xmil-libretro/blob/master/io/defipl.res)

```sh
.venv/bin/retrore info DISK.d88 --x1 --json
.venv/bin/retrore load DISK.d88 --x1 --x1-ipl --x1-lsn 80+112@100 --entry 100 -o out/x1
.venv/bin/retrore ghidra import out/x1 out/x1-project
.venv/bin/retrore decomp 100 --project out/x1-project --json
```

Repeat `--x1-lsn LSN[+COUNT]@HEX` (hexadecimal logical sector, decimal count) or
`--x1-sector C:H:R[+COUNT]@HEX` (decimal cylinder, head, sector ID, and count) to load disk spans.
These options apply in the order given. Explicit spans replace the IPL payload unless you
also pass `--x1-ipl`, which loads the payload first as `root`. `map.json` records the IPL header
under `ipl` and original container offsets in `file_spans`. Use `--x1-copy SRC:SIZE@DEST` to
copy a span of one visible load, then repeat `--x1-unit FILE@HEX` for raw files. Later loads
replace overlapping bytes. Export separate layouts for alternative stages.

At reset, the IPL ROM covers reads below `$8000`, while writes reach RAM. The IPL turns the ROM
off with a write to port `$1E00` before it jumps to the payload. A write to `$1D00` turns it back
on. The default view is RAM. Use `--x1-view ipl-rom` to represent the ROM window as uninitialized
memory. Devices and VRAM are in the 16-bit I/O space, addressed through `OUT (C),r` with the full
`BC` value. Ghidra imports X1 exports with its Z180 language variant. Unlike the plain Z80
variant, which keeps only `C`, it decodes these ports as `BC`. That variant omits the undocumented
Z80 instructions (`IXH`/`IXL`/`IYH`/`IYL` forms, `SLL`, and the `ED 4E`/`ED 6E` mode mirrors), so
code that uses them stops at a bad instruction. Phantasie I's analysis coverage is the same under both variants. The importer maps the whole I/O space and
labels the cartridge ROM, FDC, palette, priority, PCG, CRTC, sub-CPU, PPI, PSG, IPL ROM switch,
CTC, attribute VRAM, text VRAM, and graphics VRAM blocks. For example, the command
`xrefs x1_crtc:0001 --project out/x1-project --json` lists writes to the CRTC data register.
X1turbo bank memory and its additional devices aren't modeled yet.

The Phantasie I Program Disk's IPL entry `PHANTASIE 1` loads 12 sectors from LSN `$370` (C27 H1 R1)
at `$BF80` and runs `$C000`. The example `load` above adds the second stage. The routine at `$C3D8`
reads `$70` sectors from LSN `$80` to `$0100`, and `$C465` jumps there.
[MAME X1 memory and I/O maps](https://github.com/mamedev/mame/blob/master/src/mame/sharp/x1.cpp)

## Sharp X68000 loader

`info` and `load` detect Human68k `.X` executables by their `HU` header. Pass the executable from the
original disk.

```sh
.venv/bin/retrore info P4.X --json
.venv/bin/retrore load P4.X -o out/x68k
.venv/bin/retrore ghidra import out/x68k out/x68k-project
.venv/bin/retrore decomp text:1714 --project out/x68k-project --json
```

The loader places TEXT, DATA, and zero-filled BSS consecutively at `--base-address` (default
`0x10000`, even, 24-bit). It applies the relocation table against the header's link base: 16-bit
deltas, `0x0001` followed by a 32-bit delta, and an odd delta for a 16-bit site. `map.json` keeps
the original values, the entry point from the header, and the linker symbol table. Text, data, and
BSS symbols get section offsets, and common symbols land in BSS. Strings use Shift-JIS (CP932) in
`where-is`. `.X` files inside `.dim` or `.xdf` disk images must be extracted first.

Ghidra imports the program with the MC68020 language, the X68000 address map (main RAM, graphics and
text VRAM, I/O devices, SRAM, CG ROM, and IPL ROM), and register labels such as
`CRTC_MODE_RESOLUTION`, `OPM_DATA`, and `MFP_GPDR`. Human68k programs call DOS (`$FFxx`) and the FLOAT2/FPACK
library (`$FExx`) with line-F words, which Ghidra cannot decode. The importer follows control flow
from the entry and from text symbols and patches each reached line-F word in Ghidra's copy of the
program. The original bytes stay in `image.bin`.

- A call becomes `jsr (sp)` with a call-override reference to a stub function in the
  `human68k_calls` block at `$01000000`, outside the 24-bit bus. Stubs are named `DOS::_OPEN`,
  `FPACK::__CDADD`, and so on. `callers 0100007a` lists every `_OPEN` site. DOS stubs return D0,
  and `_EXIT`, `_KEEPPR`, and `_EXIT2` don't return. The end-of-line comment records the original word.
- XC compiles 32-bit multiply and divide as `movem.l Da/Db,-(sp)`, an FPACK call, and
  `movem.l (sp)+,Da/Db`. The importer rewrites those 10 bytes as the equivalent `muls.l`, `mulu.l`,
  `divs.l`, or `divu.l` and NOPs, so the decompiler shows the arithmetic. The comment keeps the
  original bytes.
- XC enters routines through `bra` to a trailing `link` and `bra` back. The importer rejoins the
  pieces that analysis splits off, so each routine decompiles as one function.

- DOS stubs carry prototypes for about 80 calls, with each word or long argument at its stack
  offset, so the decompiler shows calls such as `DOS::_WRITE(handle,buffer,length)`. Calls whose
  arguments depend on a mode word (`_IOCTRL`, `_CONCTRL`, and others) declare only the fixed leading
  arguments.
- The other stacked FPACK calls (remainder, conversions, float and double arithmetic, and compares)
  write their result over the first stacked argument. Call fixups model each one, so the decompiler shows
  `uVar2 % param_1` or `(dVar2 + dVar1) / 2.0`. Compares set the condition codes.
- `trap #15` calls whose number is loaded into D0 just before the trap become calls to
  `IOCS::_CRTMOD`-style stubs, with the name in the comment. Supported IOCS calls declare their
  register arguments and results.
- For rejoined XC functions, a direct caller whose stack cleanup corroborates the decompiler's
  inferred stack slots lets the importer persist those parameters. Phantasie IV's `_frand` shows
  the call to `_rand(100)`.
- The importer recognizes XC switch tables (`cmpi.l`, `bhi`, `asl.l #2`, a PC-relative `lea`, and an
  indexed `movea.l` / `jmp (a0)`) and adds their targets.

[Human68k DOS, IOCS, and FPACK call numbers, from XEiJ's include files](https://stdkmd.net/xeij/)
[IOCS register arguments, from elf2x68k](https://github.com/yunkya2/elf2x68k/blob/master/src/libx68k/libiocs/iocscall.csv)

## Classic Macintosh loader

`info` and `load` recognize 68k applications stored as raw resource forks, MacBinary, AppleSingle,
AppleDouble, or on unpartitioned HFS disks, including Disk Copy 4.2. Use `--disk-file NAME` to select
an application on disk and `--macintosh` to force format detection.

```sh
.venv/bin/retrore info 'Pool of Radiance v1.1.rsrc' --json
.venv/bin/retrore load 'Secret of the Silver Blade.img' --disk-file Secret -o out/mac
.venv/bin/retrore ghidra import out/mac out/mac-project
.venv/bin/retrore project-summary --project out/mac-project --json
```

The loader places the near-model `CODE` segments and A5 world at a fixed analysis base. It
reconstructs `CODE 0` jump entries and loads supported THINK C `DATA`, `ZERO`, and `STRS` resources
with `CREL` and `DREL` fixups. The export records original fixup values and source offsets, including
noncontiguous HFS spans. Ghidra resolves direct and recognized indexed calls through A5 and names
common A-line Toolbox traps. `where-is --string` searches MacRoman. The current scope is uncompressed
near-model 68k code. Far-model MPW, CFM and PowerPC, partitioned disks, MFS, and HFS+ remain open.

## Nintendo NES / Famicom loader

`info` and `load` recognize iNES and NES 2.0 cartridges with mapper 0 (NROM) or standard mapper 4
(MMC3). Use `--nes` to select the cartridge loader explicitly. NROM maps 32 KiB of PRG ROM at
`$8000`–`$FFFF` or mirrors a 16 KiB PRG ROM at `$C000`. MMC3 maps four 8 KiB windows.
`--nes-r6 HEX` and `--nes-r7 HEX` select banks. `--nes-prg-mode 0` places R6 at `$8000` and the
second-to-last bank at `$C000`. Mode 1 swaps those two windows. R7 stays at `$A000` and the last
bank stays at `$E000`. The default analysis view uses mode 0, R6 bank 0, and R7 bank 1.
[iNES header](https://www.nesdev.org/wiki/INES) · [NES 2.0 header](https://www.nesdev.org/wiki/NES_2.0) · [MMC3 banking](https://www.nesdev.org/wiki/INES_Mapper_004)

```sh
.venv/bin/retrore info GAME.nes --json
.venv/bin/retrore load GAME.nes --nes-prg-mode 1 --nes-r6 2a --nes-r7 12 -o out/nes --json
.venv/bin/retrore ghidra import out/nes out/nes-project
.venv/bin/retrore address-map c000 --export out/nes --json
```

The map records PRG bank numbers, source offsets, cartridge RAM sizes, and the CHR ROM file span.
Legacy iNES headers that omit the MMC3 PRG RAM size use an 8 KiB default. Image bytes cover the
selected CPU view, including an optional trainer at `$7000`. Ghidra uses 6502 analysis, labels the
hardware vectors and common PPU and APU registers, and seeds the reset, NMI, and IRQ targets that
fall in the exported code. Repeat `--entry HEX` to select the seed addresses yourself. Use a
separate export and project for each MMC3 bank configuration. Cross-window references reflect
the selected banks. Runtime mapper changes, CHR mapping, and CPU RAM and PPU register mirror
aliasing remain open.

## Sega Genesis / Mega Drive loader

`info` and `load` recognize raw, big-endian linear cartridges of up to 4 MiB by their Sega header.
Use `--genesis` to select the loader explicitly. The export preserves the complete ROM and
its file offsets in the `vectors`, `header`, and `rom` units. The map records cartridge titles,
ROM bounds, both checksums, the initial supervisor stack pointer, and the 68000 vector table.
Ghidra seeds the mapped vector targets and labels video, audio, controller, and Z80 registers.
Repeat `--entry HEX` to add analysis entry points. [Sega software development manual](https://gendev.spritesmind.net/files/md/tech/Genesis%20Software%20Development%20Manual%20%5BVersion%202.0%5D%20%5B1991-07-09%5D.pdf)

```sh
.venv/bin/retrore info GAME.md --json
.venv/bin/retrore load GAME.md -o out/genesis --json
.venv/bin/retrore ghidra import out/genesis out/genesis-project
.venv/bin/retrore decomp rom:0000 --project out/genesis-project --json
.venv/bin/retrore address-map vectors:0078 --export out/genesis --json
```

The memory map includes work RAM, Z80 RAM, the main I/O registers, and declared parallel
cartridge SRAM outside the linear ROM. Use `--genesis-sram START:END` for an inclusive hex
range when the header omits it. Even/even or odd/odd endpoints select one byte lane.
Even/odd endpoints select both lanes. For example, the U.S./Europe `Countdown to Doomsday`
cartridge uses `--genesis-sram 200001:203fff` for its 8 KiB of odd-lane SRAM.
The map describes canonical address ranges. Cartridge mappers, ROM and device mirrors,
interleaved copier dumps, EEPROM protocols, and runtime analysis remain open.

## Ghidra

Set `GHIDRA_HOME` to your Ghidra installation directory, which contains `support/analyzeHeadless`, and use a JDK
supported by that installation. Set `JAVA_HOME` if your shell defaults to a different JDK. See
[Compatibility](#compatibility) for the tested setup.

```sh
export GHIDRA_HOME=/path/to/ghidra
export JAVA_HOME=/path/to/jdk-25
```

Pass the project path with or without its `.gpr` extension.
Read-only queries can also open an existing Ghidra program with `--program NAME`, using its exact
name at the project root. A name other than `image.bin` uses a one-shot headless session.

For DOS, the importer creates one memory block per unit, names overlay entries and stubs, and runs
Ghidra's auto-analysis.
The importer marks recovered table words as data, adds computed jump references, and disassembles each case
so auto-analysis can discover the routines they call. Recognized switches compare the index against a
bound (`ja`, `jae`, `jbe`, or `jb` over a default jump, optionally after a `sub` bias) or mask it
(`and bx,N`), use word or zero-extended byte indexes, and jump or call through a CS-relative word table.
A root switch is read against the nearest code segment at or below it among the load segment, the entry
segment, and relocated segment words. `map.json` `jump_tables` records give the `kind` (`jump` or `call`)
and `bound` (`compare`, `mask`, or `byte`). `default` is `null` for tables without a default case.

After analysis, the importer recognizes `push cs` followed by a direct near `call` when the callee's return
instructions agree on a far return and stack cleanup. It applies the far calling convention to the callee.
It also names and types runtime signature matches at analyzed function entries. Import JSON reports the
number of far procedures recognized and runtime signatures applied.

After auto-analysis, the importer tracks DS, ES, and SS through recovered control flow. It recognizes the
startup DGROUP assignment, relocation-backed segment words, and register transfers such as
`push ds` / `pop es`. It applies the inferred context in Ghidra and adds typed references to direct memory
operands in the loaded image. The listing uses names like `DGROUP_4433` and `FAR2820_97f0`. Names use the
relocated segment. Ghidra 12.2 may still print some ES-relative accesses as numeric offsets in decompiled C.

Segment values carry across calls. Each function gets a summary of the segment registers it preserves,
sets to a known value, or copies from another register, and of the argument words it removes on return.
Calls apply the summary, and a callee starts with the segment values all its analyzed callers agree on.
The analysis follows the stack and `[BP+n]` slots, so `LES` and `LDS` resolve from relocation-backed far
pointers in memory or from a far pointer every caller passes as the same argument. Indexed operands such
as `[BX+n]` resolve when the registers hold known values. Without a definite summary, DS and SS are
assumed preserved across a call. Functions reached only through unresolved control flow start with the
startup DGROUP. Values are dropped when incoming paths disagree. A jump into the middle of another
function does not pass its segment values to that function, so a shared error or exit tail can't erase
the caller's DS. The import report's `segment_analysis` counts these jumps. A resolved direct write
invalidates any overlapping relocation-backed segment word.

When a segment register is unknown, the analysis records where and why it was lost (`join`, `call`,
`unknown_call`, `interrupt`, `load`, `pop`, `write`, or `entry`). `func` reports this as `segment_losses`.

A later pass handles indirect calls and jumps that Ghidra left unresolved. It honors explicit segment
overrides when reading the table or variable and keeps candidate targets from initial far pointers
whose segment word is relocated and from offset and segment pairs stored into the slot. Each candidate
lists its evidence and any known writer address. The importer adds a data reference from each
candidate's slot. It seeds a function in a gap when a relocated pointer names the entry, which begins
with `push bp; mov bp,sp` and decodes cleanly.

The last pass recovers calling conventions for functions without a signature. It uses `ret n` /
`retf n` immediates, `add sp,n` or `pop` after calls, and argument reads through `[BP+n]` or
`SS:[BX+n]`. Arguments loaded with `les` or `lds` become one far pointer. Each argument gets an explicit stack
offset. The pass skips signatures that would require more than 256 bytes of inferred stack arguments.
`int 21h` sites with AH loaded in the same straight-line code become calls to stubs such as
`DOS::SeekFile` in a `dos_services` block. The carry flag reads as `extraout_CF` after the call.
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

`gaps --classify` scores each range as `code`, `data`, `padding`, or `unknown`. It reports `code_score`,
`data_score`, `conflict` when both readings have support, a suggested `entry`, and `evidence` rows.
Evidence includes references into the range and relocated pointers. A pointer counts toward code only
when a far call or jump targets its segment. Other evidence is relocated words, a `push bp; mov bp,sp`
or `link a6` prologue, a clean linear decode, text, and zero fill.

## Program queries

```sh
.venv/bin/retrore xrefs OV1:20bb --project out/phantasie-project --json
.venv/bin/retrore callers OV1:20bb --project out/phantasie-project
.venv/bin/retrore callees OV1:20bb --project out/phantasie-project
.venv/bin/retrore func OV1:20bb --project out/phantasie-project --json
.venv/bin/retrore where-is --export out/phantasie --bytes 'b8 00 4c'
.venv/bin/retrore where-is --export out/phantasie --string 'Mystic'
.venv/bin/retrore where-is --export out/phantasie --constant 0x1234 --width 2 --json
.venv/bin/retrore where-is --export out/phantasie --pointer 1000:0eae --json
.venv/bin/retrore relocs --export out/phantasie --unit root --limit 20
.venv/bin/retrore lookup --export out/pool --name 'stub_tpov_0085_*'
.venv/bin/retrore lookup --export out/pool --address 1085:0039
```

`xrefs` reports incoming and outgoing references Ghidra recorded at the exact address, including code and
data references. `callers` and `callees` accept any address inside an analyzed function and list individual
resolved call sites. Callers target the function entry. JSON includes the source and target addresses,
reference type, operand index, and enclosing functions when available.

`func` reports the function entry, inclusive body ranges, total body size in bytes, and callers. For DOS
it gives Ghidra's DS, ES, and SS values at the requested address. Unknown values appear as `?` in text
and `null` in JSON. `segment_losses` gives, for each unknown register, the address and reason where its
value was lost, such as `{"ES": {"address": ..., "reason": "call", "detail": "1000:b79c changes ES"}}`.

`where-is` searches relocated, file-backed bytes in the export. Matches can overlap and must fit
within a unit's file-backed span. `--string` tries every text encoding the platform uses unless
`--encoding` picks one:

- DOS: CP437.
- C64: PETSCII and screen codes, in both character sets.
- Apple II: high-bit ASCII, then plain ASCII.
- Atari 8-bit: ATASCII and screen codes.
- PC-98 and X68000: Shift-JIS.
- MSX, PC-88, X1, and Genesis / Mega Drive: ASCII, then Shift-JIS.
- Amiga: Latin-1. Atari ST: ASCII. Classic Macintosh: MacRoman.

`--ignore-case` matches either letter case. When several encodings were tried, or with
`--ignore-case`, each match reports its `encoding` and `bytes`. Use `--bytes` to search for Atari ST
text containing bytes above `0x7f`.

`--pointer ADDR` finds stored pointers to an address:

- DOS: far pointers in any equivalent `segment:offset` form, and near pointers, which are noisy.
- 68k: aligned big-endian longs.
- 6502 and Z80: little-endian words.

Each match reports whether a loader relocation backs it (`relocated`, `null` where the format has none).
`--pointer-kind` also enables `absolute-short` for aligned 68k words or `split` for 6502 low/high
tables whose indexed loads and stores assemble a pointer. The split result includes both bytes
and the instructions that pair them.

`relocs` lists loader relocations from the export, filtered by `--unit`, by site (`--at` and `--size`),
or by `--target`. DOS targets match on segment, and 68k targets on the value range. Results are paged
with `--limit` and `--offset`. `lookup` finds symbols, unit entries, overlay entries and stubs,
runtime signature matches, hardware labels, and memory regions. `--name` takes an exact name or a `*`
and `?` pattern. `--address` gives the nearest symbol at or below the address, the next symbol, and the
containing unit or region. None of these commands needs Ghidra.
`--constant` accepts a decimal or `0x`-prefixed integer and encodes it in the platform's byte order
at the specified width (1, 2, 4, or 8 bytes, default 2).

Text output previews up to ten references or matches. Use `--json` for the full results with
`unit:offset` and linear addresses where available. Ghidra queries also report the address as
displayed by the analyzed project.

### Inspect bytes and source locations

```sh
.venv/bin/retrore bytes root:12a --export out/pool --size 16 --json
.venv/bin/retrore address-map 02b0 --from file --source START.EXE --export out/pool --json
.venv/bin/retrore address-map c002 --from runtime --runtime-load root=c000 --export out/msx2 --json
.venv/bin/retrore disasm root:12a --project out/pool-project --limit 32 --json
```

`bytes` returns up to 4,096 initialized bytes in one unit. `loaded` is the export's byte sequence.
`original` restores the values before recorded relocations and overlay rewrites. For a packed
executable it refers to the unpacked load module. `file_spans` gives available source offsets over
the requested range. `address-map` accepts logical, linear, runtime, image, or file coordinates.
File lookups may return several matches. `--source` and `--member` narrow them where applicable.
D64, Apple DOS/RDOS, Atari ATR, MSX-DOS FAT12, D88/D77, HDM, and Macintosh container exports
preserve available physical spans. Use `--from file --offset-kind container` to search those offsets.
The default file lookup retains its existing coordinates, including member offsets. Early Atari
8-bit maps can recover those offsets from their ordered segment records. For an older unpacked
DOS export, pass `--source-file PROGRAM.EXE` to `bytes` or `address-map` to verify the
original load module and recover its file offsets.

On all platforms, repeat `--runtime-load UNIT=HEX` to describe an observed view using linear
load addresses. Use `UNIT=unmapped` for an absent unit. Other units keep their exported locations
in that view. DOS also supports the existing `--runtime-base` and `--overlay-segment UNIT=HEX`
options, which describe paragraph segments. Use one placement method per lookup.

`disasm` reads up to 512 bytes in one Ghidra block. It returns instructions, defined data, and
undefined or uninitialized bytes, with explicit offcuts if the range splits a code unit. Operand
references carry the target, type, and Ghidra source. Computed transfers with no resolved targets
are flagged. The query includes original file bytes when Ghidra retains a file mapping.

### Indirect control flow and data layouts

```sh
.venv/bin/retrore indirect --project out/pool-project --status candidate --json
.venv/bin/retrore batch --project out/pool-project --evidence --export out/pool --json <<'EOF'
[{"command": "indirect", "status": "candidate", "limit": 5}]
EOF
.venv/bin/retrore layout 2820:e820 --project out/ph3-project
.venv/bin/retrore layout 2820:e820 --project out/ph3-project --name Character --apply
```

`indirect` lists each indirect call and jump as `resolved` (with its `targets`), `candidate`, or
`unresolved` (with a `reason`). When segment analysis recorded where the operand's segment value
became unknown, `segment_loss` reports the address, reason, and detail. Candidate sites give the
`table`, the segment used to read it, `candidates` with their evidence
(`relocated`, `initial`, `stored`, `function_entry`, `prologue`,
`decodes`, `seeded`) and writer addresses, and why the scan `stop`ped (`sentinel`, `next_variable`,
`uninitialized`, and others). Filter by `--unit`, `--at`, or `--status`.

`layout` infers the shape of a global from the code that reads and writes it. It decompiles every function
that references the range or uses an instruction constant inside it. Each access becomes a constant offset
plus scaled index terms, taken from multiplies, shifts, pointer arithmetic, and loop variables that step by a
constant. The result lists the following:

- each access, with its width and offset;
- `strides`, each with the instruction that implies it (for example `root:1f8c INT_MULT by 0x106`);
- count `bounds`, from loop compares;
- record fields, with their widths and read and write counts;
- `conflicts`, such as two widths at one offset;
- a `layout` kind (`record_array`, `array`, `string`, or `record`);
- a C-style `proposal`.

Loops that copy or clear whole records are counted apart from field accesses. The size defaults to
the defined data, or up to the next named symbol. `--stride` overrides the inferred element size.
`--apply` (CLI only) stops the project's worker, creates the proposed structure or array, and saves the
project. The preview lists defined data in the proposed range. Replacing it requires
`--apply --replace`. The import refuses instruction overlaps and partial overlaps with defined data.
The `functions` record reports omitted functions when `--max-functions` limits the analysis.
An explicitly sized or defined table can establish a larger count than a loop that accesses a subset.

`record-writes` checks writes to a byte field in a real-mode x86 project. Pass the address of the
first field byte. Use `--stride` and `--count` to check the same field in consecutive records.

```sh
.venv/bin/retrore record-writes 280a:00ab --stride 12 --count 15 --project out/ph3-project \
    --code-start root:12dc9 --code-end root:12e43 --json
```

The query examines the listing's Ghidra p-code stores, including implicit string and stack
writes. It uses the segment pass's register values at each instruction, including values
propagated from callers. A store is an `overlap` when its tracked destination covers a field
byte. The `hits` list gives those bytes and their values when known. A `possible` store has
an unresolved address component or a possible 20-bit wrap to the field. The query reports
the segment, offset, and copy source when available. A row with `context: false` has no saved
register values for that instruction. Use `--status` to filter the page and
`--code-start` with `--code-end` to limit the instruction range.

The report gives the count of undefined bytes and computed transfers with no listed target in
the selected code range. Results depend on the listing and the segment analysis's caller and
entry assumptions. A project imported before write context was recorded still reports
possible overlaps from the listing. Reimport to use tracked register values.

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
Use `--map-lines N` for a page of C lines and the inclusive instruction ranges that contribute to
each line. `--line-offset N` continues the page. Lines with no mapped instruction have an empty list.

### Batch Ghidra queries

`batch` runs every Ghidra query command against one project in a single read-only headless
session: `decomp`, `xrefs`, `callers`, `callees`, `func`, and the
[bulk queries](#bulk-lookups-inventories-and-call-graphs). Decompilations share one decompiler. The
command works with projects from every supported platform and accepts the same addresses as the
individual commands.

```sh
.venv/bin/retrore batch --project out/phantasie-project --json <<'EOF'
[
  {"command": "decomp", "address": "OV1:20bb"},
  {"command": "decomp", "address": "OV1:20a5", "context": 2, "slice": 12},
  {"command": "callers", "address": "OV1:20bb"},
  {"command": "xrefs", "address": "OV1:20a5", "direction": "outgoing", "limit": 10, "compact": true},
  {"command": "context", "address": "OV1:20bb", "compact": true}
]
EOF
```

Pass a UTF-8 JSON file as the positional argument or pipe the array on stdin. Each request contains
a `command` and that command's required parameters, such as `address` or `unit`. Optional fields
match the individual commands, with underscores in place of dashes. Use the arrays `fields`,
`ref_types`, `addresses`, and `names`, the integers `limit`, `offset`, `context`, `slice`, `depth`,
and `max_nodes`, the booleans `compact`, `ignore_case`, and `generated`, and the strings `direction`, `unit`,
`name`, `prefix`, and `glob` where supported. retrore validates every request before it starts
Ghidra. The JSON response contains `contract` and a `results` array in request order. Each row
echoes `command` and the identifying parameters `address`, `unit`, `name`, `prefix`, or `glob` that
the request contains. It then includes either `result`, with the individual command's JSON, or an `error` object with `code`,
`message`, and `hint`. The CLI writes the whole batch report to stdout and exits with status 1 if
any query fails. An invalid request array or a headless launch failure uses the command's error
stream. A batch launches Ghidra once, so it costs about the same as one single query. See
[benchmarks](docs/benchmarks.md).

`project-summary` reports the program name, language, compiler model, function count, and memory blocks.
`batch --evidence --json` includes a compact project summary and the original requests in a
versioned evidence bundle. Add `--export OUT` to compare each complete `disasm` result with the
corresponding loader range and include its file spans and fixups. For `decomp`, request `map_lines`,
`context`, or `slice` to compare the instructions cited by the returned C lines, focus, or p-code
operations. The `export_evidence.instructions` array records each distinct instruction's Ghidra
address and `project_bytes` alongside its loader bytes, source spans, and fixups. Evidence covers
up to 512 distinct instructions per result and sets `truncated` if it omits any.

For `indirect`, `export_evidence.sites` follows the query's filters and page. It compares the dispatch
instruction, the guard and table of each loader-recovered switch, initialized candidate slots, and
the instructions that construct stored candidate pointers. Each range includes the Ghidra bytes and
available loader source spans and fixups. Loader-recovered switches also compare Ghidra's resolved
target set with the export. A difference reports `target_mismatch`. Evidence is limited to 512 ranges
per result and 4,096 bytes per range. Older imports may record only the first pointer writer, in which
case the comparison reports incomplete coverage. A `consistent` site means its reported evidence
agrees. Pointer candidates still require runtime observation to establish which targets execute.

Each conflicting byte comparison includes a `conflicts` array with codes for address, initialized size,
and byte mismatches, or incomplete coverage when both sources provide the same number of bytes.
A range uninitialized in both sources has an `unavailable` comparison. A `decomp` comparison is
`consistent` when the bundle checks and matches every cited instruction. Any conflicting instruction
makes the result `conflict`. Missing or truncated evidence otherwise makes it `unavailable` with a reason.

### Reuse Ghidra annotations

```sh
.venv/bin/retrore annotations export --project out/old-project --json > annotations.json
.venv/bin/retrore annotations export --project out/old-project --export out/old --json > annotations-with-evidence.json
.venv/bin/retrore annotations import annotations.json --project out/fresh-project --json
.venv/bin/retrore annotations import annotations.json --project out/fresh-project --apply --json
```

The versioned file uses memory unit names and offsets. It carries manually named functions,
global labels, function-local labels at instruction starts, comments, entry points, manually defined
function signatures, and data layouts.
Export includes the Ghidra language and the executable hash when available. Import previews
additions and conflicts, and applies the entire document in one transaction if it has no conflicts.
Replaying it again reports identical annotations as unchanged.

Version 2 documents include a Ghidra data type archive for program-local structures, unions, enums,
typedefs, function definitions, and the dependencies of captured types and signatures. Ghidra stores
manually created and analyzer-created local definitions alike, so both can appear in the archive.
The `data_types.types` list gives the category and name of each definition. The Base64
`data_types.archive` holds the native `.gdt`, including packing, bitfields, and recursive references.
Typed signatures use category-qualified type names. Preview reports type changes in
`data_type_changes`. A different definition at the same path blocks the whole apply. Replay
requires the same Ghidra language and compiler specification, and adds definitions before applying
signatures. Version 1 documents still replay with textual signatures.

Version 3 and later also carry manually defined signatures that use Ghidra's custom variable storage.
The `custom_storage` field records the return and parameter locations, local variables and
their first-use offsets, signature flags, and stack purge size. Storage uses Ghidra's native
address spaces, including ordered register pieces and signed stack offsets. The bundled archive
supplies the variable types. Preview reports incompatible signatures and conflicting locals.
For a different program layout, prepare a transfer with `compare --storage`.

Version 4 carries fixed-size structures, unions, and arrays placed in the Ghidra listing,
including placements from `layout --apply`. Each `data_layout` annotation records the
category-qualified type and byte length at a unit and offset. The data type archive supplies
the definition. Preview reports conflicts for overlaps with instructions, other defined data,
or other placements in the document. Replay installs the types and placements together.

With `--export OUT`, each annotation includes an `export_evidence` comparison of the byte at its
anchor. The comparison includes loader source spans and fixups where available, and the document
records the export image's SHA-256. Replay still uses the document's language and executable
identity checks.

### Compare revisions and ports

```sh
.venv/bin/retrore compare out/old-project out/new-project --json > comparison.json
.venv/bin/retrore annotations transfer annotations.json comparison.json --json > transferred.json
```

`compare` identifies unique normalized instruction bodies on the same Ghidra language. It also
uses stable symbols, matched callers and callees, and referenced data to report changed and cross-port
candidates. JSON includes the match method, shared evidence, and unresolved alternatives. Use
`--limit` and `--offset` to review another page. The result can identify where a routine changed
without establishing that the two routines have identical behavior.

Add `--semantics` to compare unnamed routines across Ghidra languages without shared call or
data anchors. It decompiles the listings and compares arithmetic and comparison operations,
branch degrees, and literal constants in high p-code. Unique profiles yield review-only
`pcode_shape` candidates when they have at least four operations across three operation kinds
and two distinct constants. Duplicate profiles appear among the unresolved alternatives. The
report includes profile coverage for each project. Use `--timeout` to allow more time for large listings.

`annotations transfer` prepares a new annotation document from a comparison report. It carries
names, signatures, and comments at same-body function entries on the comparison page, records
the source and match method for each, and lists skipped entries. Source anchor evidence and the export
identity travel with the source in `provenance`. The data type archive travels with typed signatures
and data layouts. Use `annotations import` to review the transfer against the destination.

`compare --instructions` includes an `instruction_map` for same-body matches with aligned entries.
Transfer uses that map for comments and global or function-local labels at instruction starts,
including when instruction lengths change or a function moves. Local labels keep their function
scope. The transferred annotation records the destination function entry and preserves the source
entry in `provenance`. Preview reports a conflict if the destination instruction or its expected
function is missing. Offcut comments and annotations with no matching instruction are skipped.
Use `--instructions` and `--storage` together when transferring both instruction annotations and
custom storage.

```sh
.venv/bin/retrore compare out/old-project out/new-project --instructions --storage --json > comparison.json
.venv/bin/retrore annotations transfer annotations.json comparison.json --json > transferred.json
.venv/bin/retrore annotations import transferred.json --project out/new-project --json
.venv/bin/retrore annotations import transferred.json --project out/new-project --apply --json
```

With `--storage`, same-body matches on the same language and compiler specification can carry custom
return, parameter, and local storage. Register pieces and stack offsets retain their original order
and values. Local first-use offsets follow the corresponding instructions when their positions change.
Block matches require the same address space, block type, initialization state, and permissions.
A uniquely named block may grow or shrink. A renamed block can match by identical, non-uniform
initialized bytes when that content identifies one compatible block in each project.

`compare --storage` also lets `annotations transfer` carry fixed-size data layouts alongside any
matched function annotations or custom storage. Layouts can transfer regardless of function
pagination. Absolute storage and layouts retain their relative offsets in unchanged blocks,
uninitialized blocks matched by name, and named blocks whose smaller image is an exact prefix
of the larger one.

In other changed initialized blocks, transfer requires the whole storage or data layout range to
fit inside one byte alignment. The comparison extends exact 16-byte anchors that occur once on
each side, trims overlapping extensions, and discards competing anchors. A changed, renamed block requires two disjoint
anchors and a unique compatible pairing in both directions. Range matching reads up to 4 MiB of
block bytes per project. A changed named block with no usable byte evidence has an empty range
list. Transfer lists unmapped data layouts among the skips, and preview reports unmapped storage
pieces as conflicts. Preview checks destination geometry, checks the byte digest for range-based
transfers, and reports listing overlaps before apply. Export the applied destination project before
transferring its custom storage again.

Version 2 comparisons introduced renamed or resized block pairs. In those pairs, `unit` and `size`
describe the source, and `after_unit` and `after_size` describe the destination.
Comparisons with byte ranges use version 3. Each range records the source offset, destination
offset, and length, with the destination block SHA-256 alongside the ranges. Transfers from
version 3 comparisons use annotation document version 8 for custom storage and layouts. Earlier
annotation and comparison versions remain supported.

### Persistent query workers

Every query launches `analyzeHeadless`, which takes 3–4 seconds before a query that itself needs
milliseconds. A worker keeps the project open in one headless session and answers later queries
without that launch. Results, error objects, time budgets, and cancellation stay the same.

```sh
.venv/bin/retrore worker start --project out/pool-project
.venv/bin/retrore callers root:b1bf --project out/pool-project --compact --json
.venv/bin/retrore decomp root:2197 --project out/pool-project --json
.venv/bin/retrore worker status --project out/pool-project --json
.venv/bin/retrore worker stop --project out/pool-project
```

`worker start` runs a background daemon for the project and returns once Ghidra has opened it.
While it runs, every query command on that project (`decomp`, `gaps`, `batch`, the address and
registry queries, and `trace --project`), from any shell, goes through it. A query command takes about
0.1 seconds then, mostly Python startup. The daemon exits after 15 minutes without queries;
`--idle SECONDS` or `RETRORE_WORKER_IDLE` changes that. `worker stop --all` stops every worker of
the current user. `worker serve` runs the daemon in the foreground.

`retrore mcp` hosts its own workers the same way, and query commands in other shells use them too.
`retrore ghidra import` stops a project's worker before it writes the project. A query still running
there fails with `cancelled`, and the import does not wait for it to finish. Each query runs on the
Ghidra installation and `JAVA_HOME` of the command that sent it. When those differ from the running
worker's, the worker restarts with the new settings. A one-shot fallback inside a daemon uses them
too. Set `RETRORE_WORKER=0`
to launch Ghidra for every query. Ghidra locks a project per session, so with workers disabled a query
on a project that a worker holds fails with `project_locked`, and the message names the worker.

When a time budget runs out or a client cancels a request, retrore stops the worker's process group
and reports `timeout` or `cancelled` as before; the next query starts a new worker, and the budget
covers that start. If the worker cannot answer a request the way a one-shot run would, retrore
runs that request in its own launch. If a worker fails to start for a reason other than the project
lock, retrore uses one-shot launches for the next minute.

Daemons listen on a unix socket named after the project path in `$XDG_RUNTIME_DIR/retrore`, or in
`RETRORE_WORKER_DIR` when set, a directory only the current user can write. The worker connects
back to retrore on a loopback port and proves itself with a one-time token. A daemon removes its
socket and lock file when it exits, and its log too when it exits cleanly. A daemon that fails
keeps its log, and when it fails to start, the `worker start` error quotes the log's last lines. On Windows, daemons and
`retrore mcp` listen on a loopback TCP port instead. The port and a random token that every connection
must present are kept in a file in `%LOCALAPPDATA%\retrore\workers` (or `RETRORE_WORKER_DIR`), with
the host's process ID. Clients skip a file whose host has exited instead of waiting for a refused
connection. A Windows daemon sends its output to its log before importing anything, so startup
errors reach the `worker start` error too. Windows support is tested on Linux with the TCP transport
forced, and on Windows by the release CI job.

The `retrore.queries` module defines every query command, its parameters with JSON Schema types,
ranges, and defaults, its selectable fields, and its caps. `query_definitions()` returns them as
plain data. Validation, the CLI, `batch`, `retrore schema`, and the
[agent adapter](#agent-adapter) use the same definitions.

### Bulk lookups, inventories, and call graphs

These queries answer common orientation questions in one launch, or many in one `batch`. Each
accepts `--json`, `--compact`, `--limit N`, and `--offset N`. Text output previews up to ten records
per list. Each one has a default limit and a hard maximum, and always reports `pagination` for its
lists. A `next_offset` other than `null` means more records remain.

```sh
.venv/bin/retrore functions OV1:20bb OV1:20a5 --name main --project out/phantasie-project --json
.venv/bin/retrore symbols --glob 'FAR*' --unit root --project out/phantasie-project
.venv/bin/retrore inventory OV1 --project out/phantasie-project --limit 50
.venv/bin/retrore callgraph OV1:20bb --direction callers --depth 3 --project out/phantasie-project
.venv/bin/retrore context OV1:20bb --project out/phantasie-project --json
.venv/bin/retrore coverage --project out/phantasie-project
.venv/bin/retrore gaps --unit OV1 --limit 20 --project out/phantasie-project --json
```

| Command | Request | Result |
|---|---|---|
| `functions` | `addresses` and `names`, up to 256 in total | One row per address, then one per function matching each exact name |
| `symbols` | One of `name`, `prefix`, or `glob`, with optional `unit`, `ignore_case`, and `generated` | Symbols ordered by address, up to 100 per page by default and at most 1000 |
| `inventory` | `unit` | The unit's bounds, functions, labels, and defined data, each paged separately |
| `callgraph` | `address`, `direction`, `depth`, `max_nodes` | Functions reached from the root and the call edges between them |
| `context` | `address` | Prototype, calling convention, return type, parameters, callees, and referenced data |
| `gaps` | Optional `unit` | Undefined ranges in executable units, as for plain `gaps` |
| `coverage` | Optional `unit` | Per-unit counts of functions, instruction bytes, data bytes, and undefined bytes |
| `record-writes` | Field `address` with optional `stride`, `count`, code range, and `status` | Stores that overlap or may alias a field byte |

`functions` reports each function's name, entry, inclusive body ranges, size, prototype, and
calling convention. Each row starts with `query`, the address or name it answers. A row for an
address outside any function or an unknown name has an `error` object in place of the record, with
the code `no_function` or `address_not_found`, and the CLI then exits with status 1. Lookups use Ghidra's function names, including defaults like `FUN_1000_0015`.

`symbols` matches names exactly, by prefix, or by a glob in which `*` matches any run of characters
and `?` matches one. It covers names stored in the project, such as functions, imported labels, and
the segment-tracking names on DOS. Ghidra generates names such as `LAB_`, `DAT_`, and `SUB_` for
referenced addresses without a stored symbol. Add `generated` (`--generated`) to match those too,
for example to look up a `DAT_` name from decompiled C. Generated names have the source `DEFAULT`.
Records give the name, address, kind, source, and namespace (`null` for global names).

`callgraph` walks callers or callees (the default) from the function containing the address, in
breadth-first order. `depth` is 1 to 4 (default 2). `max_nodes` caps the walk at 1 to 512 functions,
including the root (default 128). Nodes record their depth from the root. Edges always run from
caller to callee and count call sites. `truncated.depth` is true when a function at the depth limit
has unvisited callers or callees. `truncated.nodes` is true when the node cap stopped the walk.
`unresolved` counts calls without an analyzed function at the other end.

`context` lists the routine's callees once per target, with call counts, and its data references
once per target address. Each data reference gives the address, symbol name, defined data type and
size at that address (`null` when the bytes are undefined), the reference types, and
`access_widths`: the byte widths the referencing instructions load or store, taken from their
p-code. Parameters, callees, and data are paged with a default limit of 32 and a maximum of 256.

With `--unit`, `--limit`, `--offset`, or `--fields`, `gaps` uses the shared paging contract.
`undefined_bytes` then totals the ranges that match the filter. Plain `gaps` keeps its original
output. `coverage` counts undefined bytes in initialized units only.

`--fields` selects top-level result fields for `inventory`, `callgraph`, and `context`, such as
`--fields functions,data`. Lists that are not selected are not computed. For `functions`, `symbols`,
`gaps`, and `coverage`, `--fields` selects fields within each record. `functions` rows keep `query`
and any `error`.

### Errors, exit statuses, and time budgets

`ghidra import`, `decomp`, `gaps`, `batch`, `xrefs`, `callers`, `callees`, `func`, `functions`,
`symbols`, `inventory`, `callgraph`, `context`, `coverage`, and `trace` accept `--timeout SECONDS`.
Imports default to 3600 seconds and single queries to 600. A batch defaults to
600 seconds or 60 seconds per query, whichever is larger. `0` disables the limit. `trace` applies
the budget to its `--project` comparison.
When the budget runs out, retrore stops the whole `analyzeHeadless` process group, JVM included.
It sends SIGTERM first so Ghidra can release the project lock, then SIGKILL after 10 seconds. The
Python functions in `retrore.ghidra` take the same `timeout` keyword. Queries through a
[worker](#persistent-query-workers) follow the same budget, including the worker's start.

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
| `project_locked` | Another Ghidra session holds the project lock; a retrore worker holding it is named in the message |
| `cancelled` | An MCP client cancelled the call (the server sends no response for it) |
| `script_error` | A retrore Ghidra script reported an unclassified failure |
| `invalid_request` | The query or batch request failed validation |
| `address_not_found` | The address is malformed for the project or outside the loaded image |
| `no_function` | No analyzed function or instruction contains the address |
| `project_mismatch` | A trace was compared with a project imported from a different image |
| `query_failed` | Ghidra could not answer the query, for example when decompilation fails |
| `unsupported_packer` | The DOS executable uses a packer retrore cannot unpack; `packer` names it |
| `load_manifest_invalid` | A load state, transition, or bank variant failed validation |
| `toolchain_invalid` | A supplied linker listing or signature catalog failed validation |
| `input_invalid` | The input program or options are invalid for the selected platform |
| `io_error` | A file could not be read or written |

Batch rows and failed `functions` lookup rows use the same `error` object, with the query codes
`address_not_found`, `no_function`, and `query_failed`. An unknown `unit` reports `address_not_found`.

### Versions and compatibility

`map.json` carries an integer major `version`, currently 1. Readers treat a map without `version`
as version 1. They reject a larger version with `unsupported_map_version` and other invalid
values with `export_invalid`. New optional fields do not change the version, and readers ignore
fields they do not know. A change that older readers would misread, such as a changed meaning or
a removed field, increments `version`. The checked-in [unversioned fixtures](tests/fixtures/maps) cover
the DOS, Amiga, C64, MSX2, and PC-98 exporters, and the tests check that current code still reads them.

Ghidra query JSON carries a top-level `contract` integer, currently 1. It is present on single queries
(even with `--fields`), `gaps`, and batch reports. Every `--json` error object from any command carries it too. It is not present inside batch row
results. Adding fields, query commands, or error codes keeps the contract number. Renaming or removing
a field, or changing its type or meaning, increments it.

## Emulator harness

`call` runs a routine from a fresh copy of an exported image. DOS and PC-98 use the x86 backend,
Amiga, Atari ST, X68000, Macintosh, and Genesis use the 68k backend, C64, Apple II, Atari 8-bit, and
NES use the 6502 backend, and MSX2, PC-88, and X1 use the Z80 backend. Each backend starts with the
exported memory layout. Use `--regs` and `--mem` to supply the registers, arguments, and memory
the routine expects. The harness sets up a synthetic return frame. On x86 it uses the configured
`SS:SP` for stack arguments and defaults to a near `RET`. Use `--far` for routines ending in `RETF`.

```sh
.venv/bin/retrore call root:1234 --export out/program --regs ax=10,ds=2000 \
  --mem 2000:0100=3412 --read 2000:0100=2 --json
```

Addresses and register values are hexadecimal. `--mem` writes literal bytes in the order given.
`--read` sizes are decimal or `0x`-prefixed. Repeat these options for additional ranges. JSON returns
the resolved address, final registers as integers, and requested memory bytes as hex strings. The
default instruction limit is one million. Set `--limit N` for another budget.

The DOS `Emulator` Python API supports interrupt handlers, port I/O, and execution hooks. A routine
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

`retrore.dynamic.RoutineBackend.from_export()` provides a shared Python routine interface. Pass a
`RoutineRequest` to the backend's `run` method to get initial and final state and observed service
and hardware events. The backends execute routines in a selected memory layout with scripted
service responses. For a capture involving live bank switches or device emulation, use a machine
emulator and import its events.

## Routine fixtures

A version 1 fixture names a routine and the inputs and outputs to check. Memory locations have
stable labels, so a comparison can use different addresses in two releases. Input and expected
register values accept JSON integers or `0x`-prefixed hexadecimal strings. Addresses follow the
same hexadecimal conventions as `call`.

```json
{
  "version": 1,
  "address": "root:1234",
  "registers": {"ds": "0x2000"},
  "memory": {"output": {"address": "2000:0100", "data": "0000"}},
  "watch": ["ax"],
  "expect": {"registers": {"ax": 4660}, "memory": {"output": "3412"}},
  "matrix": {"bx": [0, 1]}
}
```

```sh
.venv/bin/retrore fixture routine.json --export out/program --snapshots --json > baseline.json
.venv/bin/retrore fixture baseline.json --export out/program --snapshots --json
.venv/bin/retrore fixture routine.json --export out/program --against-report baseline.json --json
.venv/bin/retrore fixture routine.json --export out/program --against-export out/other \
  --against-fixture other-routine.json --json
```

Each combination of `matrix` register values runs in a fresh image. Optional named `cases` can
override inputs, watched state, and expectations. Set a memory range's `size` to watch existing
bytes, or set `data` to initialize it with hex bytes. Default results include register and memory
changes, observed events, and any failed checks. `watch` selects which registers to report.
Expected registers are always watched. Add `--snapshots` for before and after records and an
embedded fixture that the same command can replay against the original export. A failed
expectation or differential comparison returns an unsuccessful exit status.

Use `services` for scripted OS calls. Each entry names a `kind` and `number`, can `match` input
registers, and can set `registers` or write hex bytes to memory with `writes`. For example,
`{"kind":"interrupt","number":"0x16","registers":{"ax":"0x1c0d"}}` supplies a BIOS key result.
Use `interrupt` for x86, `trap` or `aline` for 68k trap instructions, `fline` for X68000 DOS
calls, and `brk` for 6502 `BRK`. On 68k, 6502, and Z80, `call` identifies a scripted subroutine
by its linear address.
Use `hardware` for scripted reads and writes. An entry names the `space`, `operation`, `address`,
`size` in bytes, and `value`. For example,
`{"space":"port","operation":"read","address":"0x60","size":1,"value":28}` supplies a port byte.
Use `memory` for memory-mapped I/O and `port` for x86 or Z80 port I/O. Each list is consumed in
order. Missing events and mismatched reads or writes fail the case.

Use a saved snapshot report or a reference implementation's JSON as the comparison target.
A reference implementation can supply a `cases` array of `name` and `after` records, with
`registers` keyed by register and `memory` keyed by fixture label. The supplied fields are checked
against the matching case.

## Emulator event traces

`trace` also imports a version 1 JSON document from any supported platform. The `events` array
records events in capture order. Addresses are integers or hexadecimal strings and may use
`seg:off` on DOS or PC-98. Optional top-level `placements` assign exported units to linear
runtime addresses. Set a placement to `null` to mark that unit unmapped.

```json
{
  "version": 1,
  "events": [
    {"kind": "instruction", "address": "0800", "bytes": "201008"},
    {"kind": "edge", "from": "0800", "to": "0810", "flow": "call"},
    {"kind": "memory", "pc": "0810", "access": "write", "address": "2000", "size": 1, "bytes": "2a"},
    {"kind": "snapshot", "name": "after", "pc": "0810", "registers": {"a": 42},
     "memory": [{"address": "2000", "bytes": "2a"}]}
  ]
}
```

Use `bank` or `overlay` events with a `placements` object to update the active layout for
subsequent events. An edge across a layout change can set `from_state` and `to_state` to the
1-based event numbers of the two transitions. State `0` is the initial placement. A snapshot can
also include a `state` object for device state captured by the emulator.

Inspect the mapped coordinates and coverage with `--project`. The report shows observed
addresses that lack instruction starts, edges missing from recovered flow, unobserved branches
from measured sites, and proposed additions. Review the JSON preview before rerunning with
`--apply` to change the project.
When an instruction record includes `bytes`, the preview checks those runtime bytes against the
static instruction before proposing additions.
`--runtime-load UNIT=HEX|unmapped` sets explicit initial placement and `--program NAME` selects
an existing program in the project. For a DOS MZ capture, `--runtime-base HEX` sets the segment
where DOS loaded the root. Applied computed edges are visible in `indirect` and `xrefs`.
Each edge records a successor observed in the capture. Checking the index range requires
inputs that exercise the dispatch.

```sh
.venv/bin/retrore trace capture.json --export out/program --project out/project --json
.venv/bin/retrore trace capture.json --export out/program --project out/project --apply --json
```

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
Add `--classify-gaps` to attach static gap classification and runtime hit evidence to the undefined
ranges that contain executed addresses.

Add `--evidence --json` to include the export identity and byte evidence for each mapped address,
including disassembly misses and the examples in classified gaps. Each `export_evidence` record
contains one byte from the loader image, its original value before loader fixups, and the matching
runtime, image, and available source file coordinates. The bytes describe the export. The debugger
log supplies the observed address and hit count.

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
`.d88` images. Set `RETRORE_PH1_X1_DIR` to the directory containing the Phantasie I X1 Program and
Player Disk `.d88` images. Set `RETRORE_PH4_X68K_DIR` to the directory containing Phantasie IV's
X68000 `P4.X`, extracted from Disk 1. Set `RETRORE_POR_MAC_DIR` to the directory containing
`Pool of Radiance v1.1.rsrc` and `RETRORE_SOTSB_MAC_DIR` to the directory containing
`Secret of the Silver Blade.img`. Set `RETRORE_POR_NES_DIR` and `RETRORE_POR_FAMICOM_DIR` to
directories containing one Pool of Radiance `.nes` cartridge image each, for the U.S. and Japanese
releases respectively. Set `RETRORE_CTD_GENESIS_DIR` to the directory containing one raw
U.S./Europe `Buck Rogers: Countdown to Doomsday` Genesis cartridge image. The Ghidra tests use
`GHIDRA_HOME` and include synthetic programs for all
supported platforms. Tests skip when their input variables are unset.

The Phantasie III DOS tests exercise floating-point arithmetic and register-stack copies in Unicorn.
The Ghidra test replays the observed `FTST`, `FCOM`, and `FCOMP` successors.

Phase 12 has optional checks against original tool outputs and releases.

| Environment variable | Inputs |
|---|---|
| `RETRORE_DOS_LOADER_DIR` | Microsoft LINK 3.65 `TEST2.EXE`, PKLITE 2.01 `PACK201.EXE` and `COM201.COM`, and their unpacked `PACK.EXE` and `testcom.com` counterparts |
| `RETRORE_DOS_LINK_2X_DIR` | Microsoft LINK 2.40 `PAD240.EXE` and 2.45 `PAD245.EXE` with a relocated, padded overlay member. See the [build steps](#microsoft-link-2x-probes). |
| `RETRORE_DOS_LINK_LAYOUT_DIR` | LINK 3.65 `LIVE365.EXE` with a 16-byte uninitialized CODE segment before a page-aligned routine in member 2. The test also checks a copy with the directory counts cleared. |
| `RETRORE_CIV_DOS_DIR` | `CIV.EXE` from Civilization for DOS 474.03 (SHA-256 `31e35b01f4d00df81685dfcb81e6de196a3876bd2afff6e39cbbfd964f5852ad`). Checks EXEPACK and 23 embedded Microsoft LINK members. |
| `RETRORE_NETHACK_30J_DIR` | `NETHACK.EXE`, `NETHACK1.OVL`, and `NETHACK2.OVL` from [NetHack 3.0j for DOS](https://cdimage.debian.org/mirror/archive/ftp.sunet.se/pub/games/nethack/Msdos/NH_older/). Checks the external LINK directory and file provenance. |
| `RETRORE_NETHACK_313_DIR` | `NETHACK.EXE` from [NetHack 3.1.3 for DOS](https://cdimage.debian.org/mirror/archive/ftp.sunet.se/pub/games/nethack/Msdos/NH31/). Checks the MOVE catalog, selected member fixups, and resident stubs. |
| `RETRORE_VROOMM_DIR` | The TLINK 4.0 three-overlay `VROOMM.EXE` probe |
| `RETRORE_DOS_OVERLAY_PROBE_DIR` | LINK 3.65 `PADDED.EXE` with a page-aligned overlay segment and TLINK 3.01 `VROOMM.EXE` and `VROOM86.EXE` function-pointer probes built with Turbo C++ 1.01 |
| `RETRORE_DOS_NATIVE_OVERLAY_DIR` | LINK 3.65 and 5.01.21 `TAIL365.EXE`, `TAIL501.EXE`, `BSS365.EXE`, and `BSS501.EXE` plus TLINK 3.01 and 4.0 `INSEG.EXE` and `INSEG4.EXE`. See the [build steps](#trailing-link-segments-and-flagged-tlink-pointers). |
| `RETRORE_BORLAND_COMPILERS_DIR` | Original `TCC.EXE` from [Turbo C++ 1.01](https://altd.embarcadero.com/download/museum/tcpp101.zip) and `BCC.EXE` from [Borland C++ 2.0](https://winworldpc.com/product/borland-c/20) |
| `RETRORE_PKLITE_TESTEXE_DIR` | The `compress` directory with `t10fr` and `h10fr` EXE and UNC pairs from [testexe](https://github.com/camoto-project/testexe) |
| `RETRORE_PKLITE_SFX_DIR` | The [PKZIP 2.04g installer](https://www.hpcalc.org/details/3882) as `pk204g.exe` and its [Deark](https://github.com/jsummers/deark) reference produced by `deark -m pklite -o pk204g-unpacked pk204g.exe` |
| `RETRORE_AMIGA_OVERLAY_DIR` | An original hierarchical executable named `overlay` |
| `RETRORE_DPAINT_AMIGA_DIR` | `dpaint` from the 1986 DeluxePaint I disk. With Ghidra, the test imports it and decompiles an overlay entry. [Release background](https://computerhistory.org/blog/electronic-arts-deluxepaint-early-source-code/) |

Release CI runs when a tagged GitHub release is published. It builds and installs the wheel and
runs the synthetic suites with the headless tests enabled. [Release workflow](.github/workflows/release-ci.yml)

### Microsoft LINK 2.x probes

Use `PAS1.EXE`, `PAS2.EXE`, `PASCAL.LIB`, and `MATH.LIB` from Microsoft Pascal 3.20 and
`MASM.EXE` from MASM 5.10. Copy the distribution's `LINK.V2` as `LP2.EXE` (2.40) and
`LINK.V1` as `LP1.EXE` (2.45). Save the source files with DOS line endings.
[Microsoft Pascal 3.20 disks](https://www.pcjs.org/software/pcx86/lang/microsoft/pascal/compiler/3.20/)

`RUN.PAS`

```pascal
program run(output);
function one: integer; extern;
function two: integer; extern;
begin
  if (one = 1) and (two = 7) and (one = 1) and (two = 7) then
    writeln('PASS')
  else
    writeln('FAIL')
end.
```

`ONE.PAS`

```pascal
module partone;
function one: integer;
begin
  one := 1
end;
end.
```

`PADDED.ASM`

```asm
lead segment para public 'CODE'
db 10h dup (?)
lead ends
two_code segment page public 'PAGECODE'
assume cs:two_code
public TWO
TWO proc far
    mov dx,seg TWO
    mov ax,cs
    cmp ax,dx
    mov ax,0
    jne done
    mov ax,7
done:
    ret
TWO endp
two_code ends
end
```

Run these commands in DOS. Both executables print `PASS` if overlay switching and relocation work.

```bat
pas1 run;
pas2
pas1 one;
pas2
masm padded,padded;
lp2 run+(one)+(padded),pad240,pad240/map,pascal+math;
lp1 run+(one)+(padded),pad245,pad245/map,pascal+math;
pad240
pad245
```

### Trailing LINK segments and flagged TLINK pointers

Use Microsoft C 5.1 and MASM 5.10 for the LINK probes. Save these files with DOS line endings.
`RUN.C` calls each overlay twice, and the process exits with status zero if both return the expected
values.

```c
/* RUN.C */
extern int ovl1(void), ovlb(void);
int main(void) { return !(ovl1() == 1 && ovlb() == 7 && ovl1() == 1 && ovlb() == 7); }
```

```c
/* OVL1.C */
int ovl1(void) { return 1; }
```

```asm
; TAIL.ASM
public _ovlb
two2 segment para public 'CODE'
assume cs:two2
_ovlb proc far
ifdef BSS_TAIL
    mov ax,seg last_code
endif
    mov dx,seg _ovlb
ifdef BSS_TAIL
    sub ax,dx
    cmp ax,10h
    jne fail
endif
    mov ax,cs
    cmp ax,dx
    mov ax,0
    jne done
    mov ax,7
done:
    ret
ifdef BSS_TAIL
fail:
    xor ax,ax
    ret
endif
_ovlb endp
two2 ends
last_code segment page public 'CODE'
ifdef BSS_TAIL
    db 10h dup (?)
endif
last_code ends
end
```

Run with LINK 3.65 named `LINK365.EXE` and 5.01.21 named `LINK501.EXE`.

```bat
cl /AM /c run.c ovl1.c
masm tail,tail;
masm /DBSS_TAIL tail,tailbss;
link365 run+(ovl1)+(tail),tail365,tail365/map,mlibcr; > tail365.log
link365 run+(ovl1)+(tailbss),bss365,bss365/map,mlibcr; > bss365.log
link501 run+(ovl1)+(tail),tail501,tail501/map,mlibcr; > tail501.log
link501 run+(ovl1)+(tailbss),bss501,bss501/map,mlibcr; > bss501.log
```

For the TLINK probes, use Turbo C++ 1.01 and MASM 5.10. Save the two C translation units separately
so the resident check compares the received pointer with the linker's own reference.

```c
/* MAIN.C */
extern int ovla(void);
int main(void) { return ovla() == 7 ? 0 : 1; }
```

```c
/* CHECK.C */
extern int ovlb(void);
int check(int (*fn)(void)) { return fn == ovlb ? fn() : 1; }
```

```asm
; INSEG.ASM
extrn _check:far
external_refs segment para public 'CODE'
assume cs:external_refs
public _ovla
_ovla proc far
    push bp
    mov bp,sp
    mov ax,seg _ovlb
    push ax
    db 0b8h
    dw _ovlb-_ovla
    push ax
    call _check
    mov sp,bp
    pop bp
    ret
_ovla endp
public _ovlb
_ovlb proc far
    mov ax,7
    ret
_ovlb endp
external_refs ends
end
```

The `dw` emits the function's offset without an OMF offset relocation. TLINK flags the segment
fixup so the overlay manager can substitute the resident stub at runtime. Use `TLINK.EXE` 3.01
and `TLINK4.EXE` 4.0. Both programs exit with status zero when the pointer comparison and call succeed.

```bat
tcc -mm -Y -c main.c check.c
masm inseg,inseg;
tlink /m c0m+main+check+/o+inseg+/o-,inseg,inseg,overlay+emu+mathm+cm
tlink4 /m c0m+main+check+/o+inseg+/o-,inseg4,inseg4,overlay+emu+mathm+cm
```

The roadmap tracks upcoming work. [PLAN.md](PLAN.md)

## License

MIT, see [LICENSE](LICENSE).
