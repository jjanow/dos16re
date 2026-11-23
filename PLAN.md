# retrore plan

A reverse-engineering toolkit for retro executables, starting with 16-bit real-mode DOS programs (MZ executables,
packers and overlay systems), AmigaDOS Hunk executables, Atari ST GEMDOS executables, Commodore 64 PRGs, Apple II
binaries, Atari 8-bit executables, MSX2 programs, NEC PC-88 and PC-98 programs, and Sharp X1 disks. It handles formats and compiler
patterns shared across 1980s and early 1990s games and uses those games to validate support. It gives
Ghidra's decompiler and agents driving it one whole-program image to work on.

The primary goal is to help LLMs reverse 16-bit binaries faster and with fewer tokens. Prioritize the
work Ghidra leaves to the analyst: recovering the runtime layout, resolving segmented and indirect
references, and returning compact evidence that an agent can verify against the original bytes.

## Last session

On 2026-11-22 (second session), fixed automatic overlay placement (Phase 1) and added the persistent
query worker (Phase 8). Overlay units now start above the root's stack and minimum allocation, and the
importer adds an uninitialized `root_bss` block, so PoR's `DGROUP_4433` keeps its name. Through a warm
worker, a PoR question that took 8 to 12 s batched now answers in about 0.1 s, and a CLI query through
the daemon in about 0.11 s. `tools/deploy.sh --hooks --mcp` deploys committed `main` to
`~/.local/share/retrore`, registers `retrore mcp` with Claude Code at user scope, and redeploys from git
hooks when `main` moves. With Ghidra 12.2 and the PoR and Phantasie I/III inputs, 327 tests passed with
23 skipped; the standalone suite passed 302 with 48 skipped.

Resume with the worker follow-ups under Phase 8, then Sharp X68000 and Phase 9.

## Why

Recurring failures from the Gold Box (Pool of Radiance) and Phantasie remaster projects:

| Problem | Seen as |
|---|---|
| Overlays all load at segment 0 | Phantasie OV1/OV2 code appears as `FUN_0000_xxxx`; addresses collide between overlays; a table query script was built on a wrong segment delta |
| Overlay stubs break cross-references | PoR `GAME.OVR` (Turbo Pascal `FBOV`, 35 units) is reached through INT 3Fh stubs; every doc resolves `lcall 0085:0039`-style calls by hand |
| Jump-table targets dropped | Ghidra removes switch targets as "unreachable" (Phantasie Mystic SCORE had to be recovered with raw capstone) |
| Segment values not tracked | Phantasie III state lives in far segment `0x1820`, reached through segment words stored in DGROUP (`mov es,[0x2aaa]`); data references stay anonymous |
| Packed executables | EXEPACK unpacked by hand in each project |
| Runtime library noise | Turbo Pascal 6 runtime (Real48, strings, sets, I/O) decompiles as clutter instead of named calls |
| Emulator harness is one-off | PoR's unicorn harness and ~4,500 lines of per-routine oracle scripts only work for that one game |

The initial scope was 16-bit real-mode x86 for DOS. The post-DOS roadmap now covers original source
platforms used by the remaster projects, starting with AmigaDOS.

## Design

- **Python 3 package + CLI** (`retrore`), standard library plus `capstone` and `unicorn`. Every command can print
  JSON (`--json`) so agents can call it cheaply. The package and its default test suite run independently of
  sibling projects. Game-specific addresses and expectations belong in opt-in validation tests.
- **Ghidra integration through headless scripts**, not a full Ghidra extension at first: the loader writes a flat
  image + a JSON "program map" (segments, units, symbols, segment-register assumptions, functions, jump tables),
  and a Ghidra headless script imports it into a project. A real Ghidra loader
  extension can come later if the script route turns out to be limiting.
- **DOS addresses:** `seg:off` with a stable segment per unit, plus a linear address. Overlay code is
  always named `unit:offset` too (e.g. `OV2:34aa`), so notes from different tools line up.
- **No game data in this repo.** Tests that need real game files read them from paths in environment variables and
  skip when unset. Expected values (addresses, names) may be checked in; the binaries may not.

## Phases

### Phase 1: whole-program loader (the main win)

1. **Implemented.** Parse the header and relocation table, relocate the module
   at a fixed base segment, and report the initial CS:IP and SS:SP. See the
   [MS-DOS Encyclopedia](https://www.pcjs.org/documents/books/mspl13/msdos/encyclopedia/section2/#article-4-structure-of-an-application-program).
2. **Implemented.** Unpack EXEPACK and LZEXE 0.90/0.91/0.91e, restore the original entry and stack, and apply the
   recovered relocations. Report recognized unsupported packers and variants. Implement PKLITE as targets need it.
3. **Implemented for the validation targets.** Load Turbo Pascal `FBOV`/`TPOV` banks from resident descriptors
   and relocate their unit code. Place flat overlays at supplied or automatically assigned segments above the
   root. Later formats include Borland VROOMM, Microsoft LINK overlays, and `.COM` programs.
4. **Implemented.** Rewrite direct far calls identified by relocations. Convert each overlay stub to a far jump
   for indirect callers. Preserve original bytes and targets in the map.
5. **Implemented.** `retrore load PROGRAM -o OUT/` exports `image.bin` and `map.json`. Both `load` and `info`
   accept repeatable `--overlay` and support `--json`.

**Validated.** PoR `START.EXE` and `GAME.OVR` load 35 distinct overlay units and resolve all 406 stubs.
The documented stub `0085:0039` resolves to `GAME.OVR` file offset `0x21AED`. Phantasie I's LZEXE-packed
`PHANTASI.EXE` loads alongside both flat overlays at distinct segments.

**Fixed 2026-11-22.** Automatic overlay placement used to start right after the root's file image, so in
PoR `tpov_0016` and later units covered DGROUP's uninitialized data and stack (`DGROUP_4433` resolved to
`tpov_0016:0003`). Automatic units now start above the image end, the initial stack top, and `min_alloc`
for unpacked headers (`memory_end` in `map.json`). The importer creates an uninitialized `root_bss` block
up to that limit. In PoR the first overlay unit moved from `0x20BF0` to `0x28F20`.

### Phase 2: Ghidra import

1. **Implemented.** A headless pre-script creates memory blocks per unit, sets entry points, and seeds
   disassembly before auto-analysis.
2. **Implemented.** Name stubs and unit entries and comment rewritten sites with the original bytes.
3. **Implemented.** `retrore ghidra import OUT/ PROJECT` wraps `analyzeHeadless`. To decompile an analyzed
   function, run `retrore decomp ADDR --project PROJECT` with a `unit:offset` or `seg:off` address.

**Validated on Ghidra 12.2.** The Pool of Radiance loot handler decompiles with its View call named
`tpov_0085_0ab3` directly after import.

The first remaster check used Pool of Radiance's LOADPIECES handler at `GAME.OVR:0x19BA`. In the ordinary
branch a 255 operand invalidates the two slot words without clearing the wall buffer. With both area flags
set, the handler instead passes operands 1 and 3 straight to the wall-set loader at `GAME.OVR:0x2F6FF`,
including 255. The decompiler resolved the overlay calls. Its remaining anonymous data operands give
Phase 3 a second validation case alongside Phantasie III.

### Phase 3: segment-register tracking

1. **Implemented.** Track DS, ES, and SS through recovered control flow, using the startup DGROUP, the
   initial stack segment, relocated segment words loaded from memory, and transfers such as
   `push ds / pop es`. Drop conflicting values at control-flow joins.
2. **Implemented.** Persist segment context in Ghidra and add references and width-based types for
   direct data operands. Name globals by their resolved segment and offset.

**Validated on Ghidra 12.2.** Phantasie III's save-game load and store now reference the typed word
`FAR2820_97f0` in the Ghidra listing. File-relative segment `0x1820` loads as `0x2820` at the default
base. Pool of Radiance's `LOADPIECES` decompilation names DGROUP flags at `0x4433` and `0x4434`.

### Phase 4: code recovery

1. **Implemented for bounded CS-relative word tables.** Recover case targets from a preceding `cmp` and
   `ja` or `jae` and a scaled 16-bit register index. Infer the runtime offset of adjacent tables in flat
   overlays. The Ghidra importer disassembles case blocks and adds computed jump references, allowing
   auto-analysis to find the routines those blocks call.
2. **Implemented.** Recognize `push cs` + direct near call when the analyzed callee returns with `RETF` and
   its returns agree on stack cleanup. Assign the 16-bit far calling convention in Ghidra.
3. **Implemented.** `retrore gaps --project PROJECT` reports undefined ranges per loaded unit. These are
   candidates for further analysis and may contain code, data, or padding.

**Validated on Ghidra 12.2.** The Phantasie I Mystic dispatcher at `OV1:20a5` has seven computed jump
targets. Auto-analysis finds Mystic SCORE at `OV1:20bb` through a call in one of those cases, and
`retrore decomp OV1:20bb` returns the function.

### Phase 5: runtime signatures

1. **Implemented.** Masked byte patterns cover selected Turbo Pascal 5.5, 6.0, and 7.0 routines and
   small-model Turbo C 2.01, Turbo C++ 1.01, Borland C++ 2.0, and Microsoft C 5.1 and 6.0a routines.
2. **Implemented.** Ghidra names and types matches at analyzed function entries. The Pascal catalog includes
   Real48 addition, string copy and concatenation, set union, `Write` for strings, `WriteLn`, `GetMem`,
   `FreeMem`, and `OvrInit`. The C catalog covers selected string, output, and heap routines.
3. **Implemented.** `retrore info` identifies runtimes from startup code and corroborating runtime strings or
   a recognized Turbo Pascal overlay directory. JSON records the evidence and any identified version.

**Validated.** The signatures come from original toolchains and purpose-built DOS probes. The Pascal probe
uses `Overlay`, adds two `Real` values, copies and concatenates short strings, unions two `set of byte`
values, writes text, and allocates and frees a block. The C probe calls `strcpy`, `strlen`, `puts`, `printf`,
`malloc`, and `free` and uses linker map symbols to verify matches. The Microsoft 6.0a probe links a 5.1
object against its 6.0a DOS runtime library.
[Turbo Pascal 5.5](https://altd.embarcadero.com/download/museum/tp55.zip),
[Turbo Pascal 6.0](https://sources.ru/pascal/museum/tp60.htm), [Turbo Pascal 7.0](https://winworldpc.com/product/turbo-pascal/7x),
[Turbo C 2.01](https://altd.embarcadero.com/download/museum/tc201.zip),
[Turbo C++ 1.01](https://altd.embarcadero.com/download/museum/tcpp101.zip), [Borland C++ 2.0](https://winworldpc.com/product/borland-c/20),
[Microsoft C 5.x](https://winworldpc.com/product/microsoft-c-c/5x), [Microsoft C 6.x](https://winworldpc.com/product/microsoft-c-c/6x).

### Phase 6: emulator harness

1. **Implemented.** The Unicorn harness loads the exported image and runs near or far routines with
   caller-supplied registers and memory. Calls start from a fresh image and stop at the synthetic return frame
   or the instruction limit.
2. **Implemented.** Python hooks handle interrupts, port I/O, and execution at specific addresses.
   INT 3Fh at a known Turbo Pascal stub redirects to the resident unit.
3. **Implemented.** `retrore call ADDR --export OUT --regs ... --mem ... --read ...` reports register
   and memory results, with `--json` for scripts.
4. **Implemented.** `retrore trace LOGCPU.TXT --export OUT` maps DOSBox-X debugger CS:IP logs to the
   exported image using the runtime root and overlay segments. Add `--project PROJECT` to report
   executed functions and traced addresses missed by static disassembly.

**Validated.** Synthetic tests cover near and far calls, nested calls, overlay dispatch, and I/O hooks.
The Phantasie I revive routine runs from a loaded overlay and updates a caller-supplied character record.

### Phase 7: agent-facing queries

1. **Implemented.** `xrefs` reports references to and from an address in an analyzed Ghidra project.
   `callers` and `callees` list resolved call sites. `func` reports the function body ranges, segment
   context at the requested address, and callers.
2. **Implemented.** `where-is` searches an exported image for hexadecimal bytes, DOS CP437 strings,
   or little-endian integer constants. Matches stay within individual loaded units.
3. **Implemented.** Every query supports `--json`. Text output previews up to ten references or matches.

**Validated.** Synthetic DOS programs cover code and data references, incoming and outgoing calls
including a far overlay call, function bounds and segment context in Ghidra 12.2, and byte searches
across separated overlay units.

## Test targets

| Target | Format | Checks |
|---|---|---|
| Pool of Radiance (DOS v1.3) | TP6, EXEPACK, `FBOV` overlays | Unit table, stub resolution, addresses listed in the Gold Box RE docs |
| Phantasie I (DOS) | LZEXE 0.90 MZ + program-loaded `OV1.OVR`/`OV2.OVR` | Distinct overlay segments, jump-table recovery (Mystic SCORE) |
| Phantasie III (DOS) | MZ, far data segment `0x1820` | Segment tracking, far globals |
| Phantasie I (Amiga) | AmigaDOS Hunk, 240 resident hunks | Cross-hunk relocation and palette routine callers |
| Phantasie III (Amiga) | AmigaDOS Hunk, CODE/DATA/BSS | Flat memory layout, main-loop decompilation and global reference |
| Phantasie II (Atari ST v1.0) | GEMDOS PRG, resident TEXT/DATA/BSS | Longword fixups, DRI symbols, startup decompilation and references |
| Phantasie I (Commodore 64) | D64 disk, PRGs with 16-bit load addresses | Co-resident helpers, RAM under BASIC ROM, alternative program loads, 6510 code and VIC references |
| Phantasie I and III (Apple II) | RDOS 2.1 and 3.3 sector disks | Native binary load addresses, alternative helper loads, 6502 calls and soft-switch references |
| Phantasie I and II (Atari 8-bit) | Atari DOS boot disks and segmented executables in ATR images | Boot and RUNAD entry points, alternative helper loads, 6502 calls and ANTIC references |
| Phantasie III (MSX2) | FAT12 Scenario Disk, MSX-DOS `.COM` and `.OVR` files | Resident code copy, alternative overlays, Z80 decompilation and cross-unit transfers |
| Phantasie III (NEC PC-88) | D88 Program and Utility Disks | IPL, alternative Z80 payloads, cross-unit transfers and hardware port references |
| Phantasie III (NEC PC-98) | D88 Program and Utility Disks | Real-mode IPL, alternative payloads, cross-unit far jumps and segment context |
| Phantasie I (Sharp X1) | D88 Program and Player Disks | IPL header boot, logical-sector second stage, cross-unit transfer and 16-bit I/O port references |

The opt-in DOS tests use `RETRORE_POR_DIR`, `RETRORE_PH1_DIR`, and `RETRORE_PH3_DIR`.
The opt-in Amiga tests use `RETRORE_PH1_AMIGA_DIR` and `RETRORE_PH3_AMIGA_DIR`. The opt-in Atari ST
tests use `RETRORE_PH2_ST_DIR`. The opt-in C64 tests use `RETRORE_PH1_C64_DIR`. The opt-in Apple II tests use
`RETRORE_PH1_APPLE2_DIR` and `RETRORE_PH3_APPLE2_DIR`. The opt-in Atari 8-bit tests use
`RETRORE_PH1_ATARI8_DIR` and `RETRORE_PH2_ATARI8_DIR`. The opt-in MSX2 tests use `RETRORE_PH3_MSX2_DIR`.
The opt-in PC-88 and PC-98 tests use `RETRORE_PH3_PC88_DIR` and `RETRORE_PH3_PC98_DIR`.
The opt-in X1 tests use `RETRORE_PH1_X1_DIR`.
Headless tests also use `GHIDRA_HOME`.
Tests skip when their inputs are unset. The default suite uses synthetic files.

## Setup

- Python 3.12+, `pip install capstone unicorn` (in a venv, `.venv/`, gitignored).
- Ghidra 12.x (installed as a snap on the dev machine; `analyzeHeadless` path configurable via `GHIDRA_HOME`).
- `pytest` for tests.

## Order of work

Phases 1–7 are implemented for the initial DOS scope, including the optional DOSBox-X trace import.
The Commodore Amiga, Atari ST, Commodore 64, Apple II, Atari 8-bit, MSX2, NEC PC-88, NEC PC-98, and
Sharp X1 milestones are complete for the validated releases. X1turbo validation waits for a copy of
the Gold Box release. Sharp X68000 is the next platform milestone.
The analysis backlog below applies to existing and future platforms.

## Analysis backlog

### Phase 8: faster queries and reproducible releases

- **Implemented.** Publication of a tagged GitHub release builds a wheel, installs it in a clean
  environment, and runs the standalone and synthetic Ghidra suites against the installed package.
- **Implemented.** `retrore batch` runs decompilation and address queries against one project in
  one read-only headless session. It shares the decompiler, preserves request order, and returns
  individual failures alongside successful results.
- **Implemented.** Single and batch Ghidra address queries support field selection. Reference lists
  support paging with filtered totals and next offsets, exact reference type filters, direction selection
  for `xrefs`, and compact address records.
- **Implemented.** Single and batch `decomp` queries return address-linked C excerpts and bounded
  backward p-code slices for calls, branches, and memory accesses. The results identify the containing
  function and the instruction addresses that support the excerpt and slice.
- **Implemented.** One query registry (`queries.py`) defines every Ghidra query's parameters,
  fields, and caps for validation, the CLI, and `batch`. Bounded `functions`, `symbols`, `inventory`,
  `callgraph`, `context`, `gaps`, and `coverage` queries run alone or in a batch with paging and
  explicit truncation. `context` pages parameters too, and `symbols --generated` matches Ghidra's
  generated `DAT_`, `LAB_`, and `SUB_` names.
- **Implemented.** Headless runs have time budgets (`--timeout`) that stop the whole JVM process
  group. Failures carry stable error codes with hints and documented exit statuses.
  `trace --project` has a budget too. `tools/bench.py` measures import and query latency, launch
  counts, output size, and the steps that reversing questions take ([results](docs/benchmarks.md)).
  On Pool of Radiance (36 units) a launch costs about 4.1 s and a batched query about 18 ms. Real
  questions need two or three dependent steps, so even batched they take 8 to 12 s.
- **Implemented.** A persistent query worker keeps one project open across dependent steps
  (`retrore.worker`). RetroreQuery.java's serve mode answers newline-delimited JSON requests over a
  loopback connection with a one-time token. `retrore mcp` hosts a worker per project.
  `retrore worker start|stop|status` runs a daemon on a unix socket that later CLI queries use.
  Results, error codes, time budgets, and cancellation match one-shot runs: an expired or cancelled
  request stops the worker's process group, and a request the worker cannot answer runs one-shot.
  `ghidra import` stops the project's worker first, and `RETRORE_WORKER=0` opts out. Workers exit
  after 15 idle minutes. Measured against the PoR questions in [benchmarks](docs/benchmarks.md).
- **Open.** Worker follow-ups: `ghidra import` waits only about 60 s for a running worker query and
  then reports `project_locked` instead of cancelling it. A daemon keeps the environment and
  `GHIDRA_HOME` of whoever started it. Empty `.lock` and small `.log` files remain in the runtime
  directory after daemons exit. In-process hosting on Windows is untested, and Windows has no daemon.
- **Implemented.** The README's [synthetic walkthrough](README.md#try-a-synthetic-program) generates
  a C64 PRG and runs inspection, export, headless import, and batch queries.
- **Documented.** The README's [compatibility table](README.md#compatibility) records locally tested
  Python, Ghidra, and JDK combinations and the release CI configuration. Update it as verification changes.
- **Implemented.** `map.json` `version` is enforced (missing reads as 1) and query results carry
  `contract`. Unversioned fixture maps for several formats test compatibility with older exports.
- **Implemented.** `retrore schema` emits a JSON Schema generated from the query registry, and
  `retrore mcp` is a standard-library MCP stdio server whose tools share the CLI's validation and
  entry points. Its `info` and `load` tools pass their arguments through the CLI's own parser. Calls
  run concurrently except on the same project, because Ghidra locks a project per session. A
  cancelled call stops its headless run. Lock failures report `project_locked`.

### Phase 9: better code and data recovery

- Extend DOS segment analysis to track CS, DS, ES, and SS across call boundaries with per-function
  summaries. Recover `LDS`/`LES`, stack-relative pointers, segment aliases, and far pointers built
  from relocation-backed words and offset arithmetic. Track selective memory effects and show
  where joined paths or unknown calls caused loss of precision.
- Recover more compiler switch patterns, near and far indirect calls, callback tables, tail calls,
  and dispatch through writable tables. Keep candidate targets and their evidence when a target
  cannot be proved. Apply equivalent recovery to banked and position-independent code as available.
- Improve calling-convention recovery for Pascal, C, and assembly, including segmented pointer
  arguments, stack cleanup, register parameters, and return locations. Expand runtime signatures
  with synthetic probes and match known OS calls and hardware interfaces per platform.
- Detect likely code in undefined ranges, flag conflicting code and data interpretations, and
  corroborate candidates with call targets, relocations, and traces.
- Recover typed arrays, packed records, globals, strings, and table layouts from access patterns.
  Explain widths, strides, and conflicting observations. Add platform-aware string search,
  relocation and pointer searches, and entry-point and symbol lookup across units.

### Phase 10: inspectable evidence and reusable analysis

- Add bounded disassembly and bytes queries with unit offsets, file offsets, resolved operands,
  and original versus relocated bytes. Map logical, linear, runtime, and file addresses in both
  directions. Make decompiler statements traceable to instruction ranges.
- Report why a claim exists, such as a loader fixup, instruction, Ghidra reference, heuristic,
  user annotation, or trace observation. Expose unresolved targets and conflicting evidence
  explicitly in JSON.
- Import and export names, types, signatures, comments, entry points, and layout hints in a
  versioned, diffable file. Preview changes, apply them transactionally, and preserve manual
  Ghidra work across re-imports.
- Identify matching functions and changed behavior across revisions or ports with normalized
  signatures, call graphs, and referenced data. Transfer annotations with provenance and a
  reviewable match report.
- Support read-only queries on compatible existing Ghidra programs where possible. Provide a
  compact project summary and an export of selected evidence for handing work to another agent.

### Phase 11: repeatable dynamic analysis

- Add declarative routine fixtures for register inputs, memory, expected outputs, OS calls, and I/O.
  Report only relevant register and memory changes by default. Support input matrices, repeatable
  snapshots, and differential comparisons with a reimplementation or another release.
- Import emulator snapshots, executed edges, memory accesses, and overlay or bank changes. Correlate
  them with static addresses and show gaps between observed and recovered control flow. Let an
  analyst preview trace-backed additions before applying them to Ghidra.
- Extend routine execution, trace mapping, and coverage queries through platform-specific backends.
  Use a shared request and result shape for common operations, with machine-specific registers, OS
  services, and hardware state available where they matter.

### Phase 12: loader depth on supported platforms

- Add DOS `.COM` and raw loads, PKLITE variants, and Borland VROOMM and Microsoft LINK overlays
  as representative inputs become available. Improve diagnostics for partial and ambiguous loads.
- Add Amiga Hunk overlay trees and broader relocation coverage. Add usable symbols and signatures
  from supported original toolchains, linker maps, and debug records where available.
- Describe load order, mutually exclusive overlays, and bank transitions in reusable manifests.
  Support viewing alternative states together where Ghidra permits, and preserve source provenance
  when runtime addresses overlap.
- Give disk and container loaders a uniform way to enumerate members, select inputs, and record
  layout decisions. Validate expanded format coverage with synthetic fixtures and optional original
  releases.

## Platform capability parity

Aim for the same agent workflows on every supported platform. CLI verbs, address and evidence
records, result limits, and failure behavior should be shared. Provide equivalent platform
capabilities for layout reconstruction, code and data recovery, and dynamic validation. The
underlying analysis uses each machine's conventions and available emulator or trace backend.

| Capability | DOS | Amiga and Atari ST | C64, Apple II, Atari 8-bit, MSX2, PC-88, and X1 | PC-98 |
|---|---|---|---|---|
| Load, export, and byte search | Implemented | Implemented | Implemented | Implemented |
| Ghidra import, decompile, references, and function queries | Implemented | Implemented | Implemented | Implemented |
| Batch Ghidra address queries | Implemented | Implemented | Implemented | Implemented |
| Bulk lookups, inventories, call graphs, and routine context | Implemented | Implemented | Implemented | Implemented |
| Ghidra address query field selection and reference pagination | Implemented | Implemented | Implemented | Implemented |
| Focused C excerpts and backward p-code slices | Implemented | Implemented | Implemented | Implemented |
| Runtime layout | MZ relocation and supported overlays | Resident sections and relocations | One selected bank or overlay snapshot per export | One selected real-mode RAM layout per export |
| Calling conventions, runtime signatures, and indirect control flow | Selected patterns implemented | Extend for relevant targets | Extend for relevant targets | Real-mode segment context and selected far-call conventions |
| Routine emulation and trace coverage | Implemented for the DOS harness and DOSBox-X | Planned | Planned | Planned |

For each new capability, use shared synthetic contract checks where possible and add fixtures for
platform-specific behavior. Track missing capabilities so a platform's loader milestone is distinct
from its analysis coverage.

## Post-DOS stretch goals

For each source platform, validate the executable or ROM loader, memory map, applicable bank or overlay
handling, and analysis on a representative release before starting the next platform. Keep original media
outside this repository and platform-specific game expectations in opt-in validation.

| Order | Original source platform | Phantasie remaster | Gold Box remaster |
|---|---|---|---|
| 1 | Commodore Amiga | Yes | Yes |
| 2 | Atari ST | Yes | Yes |
| 3 | Commodore 64 | Yes | Yes |
| 4 | Apple II | Yes | Yes |
| 5 | Atari 8-bit | Yes | |
| 6 | MSX2 | Yes | |
| 7 | NEC PC-88 | Yes | Yes |
| 8 | NEC PC-98 | Yes | Yes |
| 9 | Sharp X1 / X1turbo | X1 | X1turbo |
| 10 | Sharp X68000 | Yes | |
| 11 | Classic Macintosh | | Yes |
| 12 | Nintendo NES / Famicom | | Yes |
| 13 | Sega Genesis / Mega Drive | | Yes |

The matrix follows OpenPhantasie's supported copies and planned source platforms, and the Gold Box
remaster's port matrix. Gold Box PC-88 and X1turbo validation depends on finding copies of the releases.
The Phantasie project also tracks FM-7 and additional ports on platforms already in the table as research
candidates pending release confirmation. [OpenPhantasie source-platform roadmap](https://github.com/jjanow/OpenPhantasie#planned-source-platform-support)

### Commodore Amiga

**Implemented and validated on Ghidra 12.2.** `info` and `load` detect AmigaDOS Hunk executables,
place their resident CODE, DATA, and BSS at stable addresses, and apply absolute long and compact
relocations. The headless importer restores that layout for 68k analysis and makes the DOS
toolkit's existing decompilation and reference queries available at `hN:offset` addresses.

The SSI Phantasie I and III Amiga disk images from the Phantasie remaster supplied the validation
executables. Ghidra recovered Phantasie I's call from `h20:018c` to the palette routine at
`h77:0466`. For Phantasie III, a zero-based export placed DATA at `0x21890`, and Ghidra
decompiled the main loop at `h0:736c` and resolved its write to `h1:286c`.
Both releases keep their hunks resident. The loader diagnoses AmigaDOS overlay trees as unsupported.

### Atari ST

**Implemented and validated on Ghidra 12.2.** `info` and `load` detect GEMDOS executables, place TEXT,
DATA, and BSS consecutively, and apply the delta-encoded longword relocations. The shared 68k importer
restores this layout and imports available DRI/GST symbols. Analysis queries use `text:offset`,
`data:offset`, `bss:offset`, or a flat address.

Phantasie II v1.0 uses a resident `PHANT.PRG` with 6,485 fixups. Ghidra decompiled the startup routine at
`text:ec36`, found its call from `text:ec8e` to the title-music wait at `text:b8f2`, and resolved a relocated
pointer from `data:02ec` to `data:0718`. The separate `UTILIT2.PRG` validated DRI symbols in all three
sections. The release runs its loader, game, and utility as separate GEMDOS programs.

### Commodore 64

**Implemented and validated on Ghidra 12.2.** `info` and `load` read standalone PRGs and named PRG
members from D64 disks. The loader places co-resident files in one selected 6510 memory view and
records RAM, ROM, and I/O ranges. The Ghidra importer uses the 6502 language and seeds analysis
from an identified BASIC `SYS` stub or explicit entries. Queries use `unit:offset` or a flat address.

The English SSI Phantasie I side A disk supplied the validation programs. `TOWNR` and `OUTDOORS`
both load at `$0801` and can be exported as separate layouts. `RTL-64` can be placed at its runtime
address of `$A000` with BASIC ROM banked out. With BASIC ROM and I/O visible, Ghidra decompiled
the `UTIL-3.O` routine at `$C5C3`, recovered its call to `$C0CC` and a write to the VIC at `$D017`,
and decompiled the co-resident `FAST` install routine at `$CC00`.

### Apple II

**Implemented and validated on Ghidra 12.2.** `info` and `load` accept standalone binaries, raw loads with
explicit addresses, and binary files from Apple DOS 3.3 and SSI RDOS 2.1/3.3 sector images. Each export
places co-resident binaries in one Apple II Plus memory view with a selected Language Card state. The
shared 6502 importer creates blocks for RAM, ROM, and soft switches and seeds analysis at explicit entries.

Phantasie I's RDOS 2.1 boot disk supplied `INFO` at `$0302` and `SHAPES` at `$451F`. Phantasie III's RDOS 3.3
disk supplied `INFO` with two alternative text helpers, `IMPTEXT` and `IMPREVERSE`, both at `$1828`.
Ghidra decompiled the routine at `$0320` with the cross-unit call from `$0328` to `IMPTEXT` and resolved
the speaker soft-switch read at `$C030` from `$0302`.

### Atari 8-bit

**Implemented and validated on Ghidra 12.2.** `info` and `load` read standalone XEX files and
Atari DOS 2.x members from ATR disks, or export the initial sectors specified by the OS boot header.
Segments and explicit additional files apply in load order. Each export captures one XL/XE PORTB
state for OS ROM, BASIC ROM, Self-Test, and the 130XE extended RAM window. The shared 6502 importer
uses the recovered boot or XEX entry points to seed analysis.

The SSI Phantasie I and II disks boot at `$0706`. Their `AUTORUN.SYS` files contain a write to
`PORTB` and have RUNAD entries at `$349F` and `$32DA` respectively. Both `DNG.COM` files run at
`$A7BD`. Ghidra decompiled that entry in Phantasie I, resolving the call from `$A7F4` to the block
containing `$4702` and a write from `$A892` to the ANTIC register `NMIEN` at `$D40E`.
`CAST.COM` and `LOOK.COM` supply two alternative overlays at `$A7C0` in both releases.

### MSX2

**Implemented and validated on Ghidra 12.2.** `info` and `load` accept MSX-DOS `.COM` files, raw
files at explicit addresses, and root-directory members from raw FAT12 disk images. Exports represent
one MSX-DOS RAM layout with declared resident copies and explicit overlay load order. The Z80 importer
creates the unit blocks, seeds entries, and labels the BDOS entry and selected I/O ports.

Phantasie III's `PM3.COM` starts at `$0100` and copies `$5F13` bytes to `$7000`. The `INIT1.OVR` and
`INIT2.OVR` snapshots place each overlay at `$0100` with the same resident copy. Ghidra resolves the
resident transfer from `$B684` to each overlay entry and decompiles the overlay bodies at `$0103` and
`$01A5`. Cartridge formats and slot or mapper transition analysis are future loader work.

### NEC PC-88

**Implemented and validated on Ghidra 12.2.** `info` and `load` read the IPL or caller-selected sectors
from D88/D77 disks, including containers with multiple disks. Raw files and explicit resident copies
can share the selected Z80 address space. The map records sector payload offsets and the selected
ROM and VRAM banks. The Z80 importer seeds entry points and labels memory control, graphics, interrupt,
and floppy interface ports.

The Phantasie III Program and Utility Disks both boot at `$C000` and pass control through `$C100`.
Their second stages load different programs at `$0100`, reaching routines at `$0523` and `$0161`
respectively. Ghidra recovered both transfers and the IPL's write to port `$31`. The loader represents
each stage with a caller-selected memory layout. Future loader work includes filesystem member
selection and additional PC-88 memory modes.

### NEC PC-98

**Implemented and validated on Ghidra 12.2.** `info` and `load` read the IPL or explicit sectors
from D88/D77 and 1232 KiB HDM floppies. Raw files and selected disk spans load at explicit real-mode
segments. The export records original sector offsets and the PC-9801 memory map. The shared x86
importer tracks segment context and represents text VRAM, graphics VRAM, and IPL ROM.

The Phantasie III Program and Utility Disks both start at `1fc0:0000` and load a second stage at
`3f00:0000`. Ghidra decompiled both loaders and recovered their direct far jumps to `0200:035f`.
The startup routines there lead to `0412:0006` on the Program Disk and `03ca:000f` on the Utility
Disk. The Phantasie IV HDM boot sector also imported into Ghidra. Future loader work includes FAT12
member selection for PC-98 DOS floppies and additional machine-specific ROM and graphics views.

### Sharp X1

**Implemented and validated on Ghidra 12.2.** `info` and `load` read the IPL boot entry from D88/D77
disks or caller-selected spans by logical sector or cylinder, head, and sector ID. They also accept raw
files at explicit addresses. Explicit resident copies can share the Z80 address space. The map records
the IPL header, sector payload offsets, and the selected RAM or IPL ROM view below `$8000`. X1 devices
and VRAM are in the 16-bit I/O space. The importer uses Ghidra's Z180 variant so `OUT (C),r` ports
resolve through `BC`. It maps the I/O space and labels the FDC, palette, PCG, CRTC, PPI, PSG, IPL
ROM switch, CTC, and VRAM ranges. The Z180 variant does not decode undocumented Z80 instructions.

The Phantasie I Program Disk boots `PHANTASIE 1` from LSN `$370` at `$BF80` and runs `$C000`. The
routine at `$C3D8` reads `$70` sectors from LSN `$80` to `$0100`, and `$C465` passes control there.
Ghidra recovered that transfer, decompiled the loader and the second stage's main routine at `$3D7F`,
and resolved the CRTC write at `$C04F`, the PPI control write at `$C05B`, and the second stage's FDC
control write at `$011D`. The Player Disk has no IPL entry, and neither disk has a filesystem. Future
loader work includes X1turbo bank memory and devices, filesystem member selection, and runtime-computed
disk loads.
