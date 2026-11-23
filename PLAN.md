# retrore plan

A reverse-engineering toolkit for retro executables, starting with 16-bit real-mode DOS programs (MZ executables,
packers and overlay systems), AmigaDOS Hunk executables, Atari ST GEMDOS executables, Commodore 64 PRGs, Apple II
binaries, Atari 8-bit executables, MSX2 programs, NEC PC-88 and PC-98 programs, Sharp X1 disks, Sharp X68000
Human68k executables, Classic Macintosh 68k applications, NES / Famicom cartridges, and Sega
Genesis / Mega Drive cartridges. It handles formats and compiler patterns shared across 1980s and
early 1990s games and uses those games to validate support. It gives Ghidra's decompiler and agents
driving it one whole-program image to work on.

The primary goal is to help LLMs reverse 16-bit binaries faster and with fewer tokens. Prioritize the
work Ghidra leaves to the analyst: recovering the runtime layout, resolving segmented and indirect
references, and returning compact evidence that an agent can verify against the original bytes.

## Last session

On 2026-11-23, `compare --storage` gained matches for resized blocks by unique name and for
renamed blocks by unique, identical initialized content. Version 7 transfer documents carry the
destination name and size. Replay checks the destination geometry and requires each storage or
data layout range to fit within both blocks. The standalone suite passed 424 tests with 97 skipped.
The comparison, evidence, and layout suites on Ghidra 12.2 passed 31 tests with 2 skipped.

Resume Phase 10 with locating data that moved within a memory block.

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
| Phantasie IV (Sharp X68000) | Human68k `HU` executable with XC symbols | Relocations and symbols, line-F DOS and FPACK calls, XC arithmetic and split entries, save routine decompilation |
| Pool of Radiance (NES and Famicom) | U.S. and Japanese NES 2.0 cartridges | MMC3 bank placement and file provenance, hardware vectors, Ghidra startup and IRQ analysis |
| Buck Rogers: Countdown to Doomsday (Genesis) | U.S./Europe linear Mega Drive ROM, odd-lane cartridge SRAM | ROM and vector provenance, startup and VBlank analysis, video and SRAM references |

The opt-in DOS tests use `RETRORE_POR_DIR`, `RETRORE_PH1_DIR`, and `RETRORE_PH3_DIR`.
The opt-in Amiga tests use `RETRORE_PH1_AMIGA_DIR` and `RETRORE_PH3_AMIGA_DIR`. The opt-in Atari ST
tests use `RETRORE_PH2_ST_DIR`. The opt-in C64 tests use `RETRORE_PH1_C64_DIR`. The opt-in Apple II tests use
`RETRORE_PH1_APPLE2_DIR` and `RETRORE_PH3_APPLE2_DIR`. The opt-in Atari 8-bit tests use
`RETRORE_PH1_ATARI8_DIR` and `RETRORE_PH2_ATARI8_DIR`. The opt-in MSX2 tests use `RETRORE_PH3_MSX2_DIR`.
The opt-in PC-88 and PC-98 tests use `RETRORE_PH3_PC88_DIR` and `RETRORE_PH3_PC98_DIR`.
The opt-in X1 tests use `RETRORE_PH1_X1_DIR`. The opt-in X68000 tests use `RETRORE_PH4_X68K_DIR`.
The opt-in Macintosh tests use `RETRORE_POR_MAC_DIR` and `RETRORE_SOTSB_MAC_DIR`.
The opt-in NES / Famicom tests use `RETRORE_POR_NES_DIR` and `RETRORE_POR_FAMICOM_DIR`.
The opt-in Genesis tests use `RETRORE_CTD_GENESIS_DIR`.
Headless tests also use `GHIDRA_HOME`.
Tests skip when their inputs are unset. The default suite uses synthetic files.

## Setup

- Python 3.12+, `pip install capstone unicorn` (in a venv, `.venv/`, gitignored).
- Ghidra 12.x (installed as a snap on the dev machine; `analyzeHeadless` path configurable via `GHIDRA_HOME`).
- `pytest` for tests.

## Order of work

Phases 1–7 are implemented for the initial DOS scope, including the optional DOSBox-X trace import.
The Commodore Amiga, Atari ST, Commodore 64, Apple II, Atari 8-bit, MSX2, NEC PC-88, NEC PC-98,
Sharp X1, Sharp X68000, Classic Macintosh, Nintendo NES / Famicom, and Sega Genesis / Mega Drive
milestones are complete for the validated releases. X1turbo validation waits for a copy of the Gold Box
release. Continue with the analysis backlog below.

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
- **Implemented.** Stopping a worker host (`ghidra import`, `worker stop`, idle exit) cancels the
  request in progress with `cancelled` instead of waiting for it. Each request carries the caller's
  analyzeHeadless path and `JAVA_HOME`, and the host restarts its JVM when they change. One-shot
  fallbacks inside a daemon use the requesting caller's launcher and `JAVA_HOME` too. Hosts remove
  their lock files, and daemons remove their logs on a clean exit.
- **Implemented and verified on Windows.** Python on Windows has no unix sockets, so hosts there
  listen on a loopback TCP port and write the port, a random token, and their process ID to an endpoint
  file in `%LOCALAPPDATA%\retrore\workers`; every connection must present the token. Clients skip
  a file whose host process has exited, so a crashed host no longer costs a refused connect. Locks use
  `msvcrt.locking`. The daemon runs detached without a console window and sends its output to its log
  before importing anything, so startup errors reach `worker start`. The worker tests run on both
  transports on Linux. The release workflow has a Windows job (worker, MCP, and synthetic Ghidra tests
  with Ghidra 12.2) and a manual trigger. A manual run on 2026-11-23 passed it on the final code (run 45121304418).
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

- **Implemented for DOS.** Segment values carry across calls through per-function summaries (registers
  preserved, set, or copied, and argument words popped), with contextual summaries for agreeing callers
  and at most 4 rounds. The analysis follows the stack and `[BP+n]` slots, resolves `LES`/`LDS` from
  relocated far pointers in memory or from a far pointer every caller passes, and resolves `[BX/SI/DI+n]`
  operands with known registers. `func` reports `segment_losses` (where and why each unknown segment
  register was lost). A jump into another function's middle no longer passes its segment state there,
  which is not strictly sound for shared runtime tails; the import counts these jumps.
  **Validated:** with all Phase 9 passes, Phantasie III's import adds 3,027 data references (was 1,903).
  Functions entering with DS known went from 247 of 380 to 423 of 448, and with ES known from 0 to 94. `1000:1274` references `FAR2820_aa30`, and `int86` at
  `1000:5276` resolves `LDS DI,[BP+8]` to `FAR2820_b7f6` from all 5 callers. Pool of Radiance
  `root:852f` resolves `LES DI,ES:[DI]` to `root_bss:114e`.
  Known BP indexes update frame slots. Unknown writes with evidence that they address SS invalidate
  the affected stack state. Detached MZ functions can inherit the loader SS when the analyzed code never
  changes it. The pass removes Ghidra analysis-only data references on operands that use unknown ES.
  Open: unknown-segment aliases, detached functions when analyzed code can change SS, and dynamic
  heap pointers such as Pool of Radiance's.
- **Implemented.** More switch patterns: `jbe`/`jb` bounds, `sub` bias, mask bounds, byte indexes, and
  near call tables. A root switch is read against the nearest relocated code segment. The XC 68k switch is
  recognized on X68000. A pass after segment analysis keeps candidate targets for unresolved indirect calls
  and jumps, with evidence and the writer's address (`indirect` query). `gaps --classify` scores gaps as
  code, data, or padding with evidence. A gap whose entry a relocated pointer names, that has a prologue,
  and that decodes cleanly is seeded as a function. Ghidra already treats tail jumps to function entries as calls.
  **Validated:** Phantasie III recovers 22 tables (was 0), including the sound driver's call table
  at `218f:0bcc`, and has 448 functions (was 380). `root:532c`, reached only through a relocated far
  pointer, is now a function. Phantasie I has 17 tables (was 15), and Mystic SCORE still decompiles.
  P4.X resolves all 41 computed jumps (was 32). In Pool of Radiance, `tpov_0096:0d70 CALLF [0x6b84]` gets
  candidates `root:0994` and `root:06e6`, written at `tpov_0035:006f` and `:008b`.
  Far CS jump and call tables use relocated selector words for destination evidence. Amiga
  Phantasie I and III each recover 22 switches, and Atari ST Phantasie II recovers 15 in `PHANT.PRG`
  and 3 in `UTILIT2.PRG`. `trace --classify-gaps` attaches runtime hit evidence to static gaps.
  The DOS indirect pass reads segment override prefixes from the instruction bytes and recognizes
  indexed memory operands without a displacement. `indirect` reports `segment_loss` with the origin
  and reason when the operand's segment is genuinely unknown. In Phantasie III, `root:42df` reads
  `SS:[2624]` and finds the relocation-backed candidate `root:11914`.
  Open: genuinely unknown segment values and Phantasie III's dispatch at `root:13721`. Its
  zero-extended index allows 256 values, and the available bytes do not corroborate a table of that size.
- **Implemented.** A conventions pass sizes stack arguments from `ret n`, caller cleanup, and frame reads.
  It makes `les`/`lds` arguments far pointers and names `int 21h` services as `DOS::` stubs, with carry
  as a result. X68000 DOS stubs have prototypes for about 80 calls. Call fixups model stacked FPACK
  remainder, conversion, float, double, and compare helpers. `trap #15` IOCS calls are named.
  **Validated:** P4.X shows `DOS::_WRITE(handle,buffer,length)` in `_write` at `text:3c2dc`,
  `uVar2 % param_1 + 1` in `_rand`, and `(dVar2 + dVar1) / local_24` in `_avg_attr`. Pool of Radiance
  names 35 `int 21h` sites. It recovers 491 callee-cleanup functions and 356 far pointer arguments, and
  Seek at `root:c4e3` tests `extraout_CF` instead of a multiply's carry.
  MSC 5.1 medium-model signatures recognized eight routines in a compiler probe, including the
  DX:AX `lseek` return. The Phantasie III export matches four, and Ghidra applies three to analyzed
  functions. X68000 IOCS stubs have register prototypes for 32 services, covering 25 sites in
  `P4.X`. Caller-validated XC stack parameters restore the `_rand(100)` argument in `_frand`.
  Open: additional runtimes and generic DX:AX, Real48, and register-argument recovery; the
  separate `swi(0x21)` in Ghidra's p-code; and more IOCS prototypes.
- **Implemented.** Searches without Ghidra: `where-is --string` tries each platform's encodings
  (PETSCII and screen codes, high-bit Apple II, ATASCII, Shift-JIS, and others), `--pointer` finds
  stored near, far, or absolute pointers and marks relocated ones, `relocs` filters relocations, and
  `lookup` finds symbols by name pattern or nearest address. The `layout` query infers arrays, records,
  and strings from accesses. It reports strides with their evidence, count bounds, fields, conflicts,
  and a C proposal. `--apply` creates the type.
  **Validated:** P4.X `_gmb` at `88f9c` is 10 × 190-byte records (stride from `text:1754`). Phantasie III's
  roster at `2820:e820` is 20 × 262 bytes (stride from `root:1f8c`). Atari 8-bit Phantasie I's
  copy-protection quiz is found in screen codes at `9f5c`, and C64 "Minotaur" in PETSCII at `TOWNR:0187`.
  Apple II high-bit strings were also validated on original input. Pointer search supports opt-in
  aligned 68k short addresses and 6502 split tables with file-backed low and high bytes. `layout`
  reports omitted functions and previews defined data in the proposal range. Replacing defined data
  requires `--apply --replace`. Runtime-generated split tables such as Apple II PICPLOT still need traces.

### Phase 10: inspectable evidence and reusable analysis

- **Implemented.** `bytes` reports export bytes, original values, source spans, and recorded fixups.
  `address-map` maps logical, linear, runtime, image, and available source file coordinates.
  `disasm` reads a bounded Ghidra range with resolved references and flags unresolved computed flow.
  `decomp --map-lines` maps C lines to contributing instruction ranges. Open: source offsets for
  older maps and formats with incomplete provenance, and generalized runtime placement.
- **Implemented.** `batch --evidence` bundles selected results and their requests. It can
  attach loader evidence to disassembly and the distinct instructions cited by returned decompiler
  fields. Both comparisons report address, initialized size, and byte mismatches, plus incomplete
  coverage when both sources provide equal byte counts. The decompiler comparison records each
  instruction's bytes and source spans and flags missing or truncated evidence. A disassembly
  range uninitialized in both sources reports an unavailable byte comparison. Indirect flow bundles
  compare instructions, loader-recovered tables and targets, initial candidate slots, and stored
  pointer writers. `trace --evidence` attaches the export identity and a byte at each mapped DOSBox-X
  address to the report, including disassembly misses and observed gap examples. The evidence
  includes the original byte before loader fixups and source coordinates where available.
- **Partly implemented.** `annotations` exports names, global labels, function-local instruction
  labels, signatures, comments, and entry points. An optional loader export adds byte and source
  evidence at each anchor. Transfer preserves the source evidence. Replay previews conflicts and
  applies changes in one transaction.
  Version 2 bundles program-local structures, unions, enums, typedefs, function definitions, and
  required dependencies as a Ghidra data type archive. It previews definitions by category and
  name and installs them before replaying signatures that use them. Version 3 also replays custom
  return, parameter, and local storage, with stack purge size and local first-use offsets. Version 4
  replays fixed-size record and array placements, including `layout --apply` results, with overlap
  checks before applying. Version 5 transfer documents use `compare --storage` to remap custom
  storage within matching memory blocks and align local first-use positions by instruction.
  Preview reports unmapped storage as a conflict. Version 6 uses the same block matches to transfer
  fixed-size data layouts at their original block-relative offsets. Preview checks the destination
  block geometry and listing overlaps before replay. Version 7 extends both transfers to uniquely
  named blocks that grew or shrank and to renamed blocks with unique, identical non-uniform bytes.
  Replay checks each range against both block sizes. Older documents remain supported. Open work
  includes locating data that moved within a block and matching renamed blocks with changed bytes.
- **Implemented for review.** `compare` matches normalized bodies in the same language and uses
  names, call graphs, and referenced data to suggest changed and cross-port matches. The result
  shows unresolved alternatives. `annotations transfer` preserves provenance when preparing replay
  at a matched same-body entry. `compare --instructions` also maps instruction starts so interior
  comments and global and function-local labels follow the matched instructions. Preview checks
  that each destination instruction belongs to the expected function. Open: matching unnamed
  cross-port routines without shared call or data anchors.
- **Implemented.** Read-only queries accept an exact name for a compatible existing Ghidra program
  at the project root. `project-summary` and `batch --evidence` support review and handoff.

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

| Capability | DOS | Amiga, Atari ST, X68000, Macintosh, and Genesis | C64, Apple II, Atari 8-bit, MSX2, PC-88, X1, and NES | PC-98 |
|---|---|---|---|---|
| Load, export, byte, string, pointer, relocation, and symbol search | Implemented | Implemented | Implemented | Implemented |
| Ghidra import, decompile, references, and function queries | Implemented | Implemented | Implemented | Implemented |
| Batch Ghidra address queries | Implemented | Implemented | Implemented | Implemented |
| Bulk lookups, inventories, call graphs, and routine context | Implemented | Implemented | Implemented | Implemented |
| Ghidra address query field selection and reference pagination | Implemented | Implemented | Implemented | Implemented |
| Focused C excerpts and backward p-code slices | Implemented | Implemented | Implemented | Implemented |
| Runtime layout | MZ relocation and supported overlays | Resident sections and relocations, a fixed Macintosh A5 world, and a linear Genesis cartridge view | One selected bank or overlay snapshot per export | One selected real-mode RAM layout per export |
| Calling conventions, runtime signatures, and indirect control flow | Stack conventions, `int 21h` services, switch patterns, and indirect-call candidates | X68000 DOS and FPACK, Amiga and Atari ST switch recovery, and Macintosh A5 jump targets and named Toolbox traps | Extend for relevant targets | Real-mode segment context and selected far-call conventions |
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

### Sharp X68000

**Implemented and validated on Ghidra 12.2.** `info` and `load` detect Human68k `HU` executables, place
TEXT, DATA, and BSS consecutively, apply the relocation table (word deltas, long escapes, and word
sites) against the link base, and import the linker symbol table. The importer adds the X68000
address map and register labels. It patches the line-F DOS (`$FFxx`) and FPACK (`$FExx`) calls that
control flow reaches into calls to named stubs outside the 24-bit bus, keeping the original bytes in
`image.bin` and in comments. XC's stacked 32-bit multiply and divide calls become 68020 `muls.l` and
`divs.l`, and routines entered through a `bra` to a trailing `link` are rejoined.

Phantasie IV's `P4.X` (Star Craft, 1991) has 11,122 relocations and 1,015 symbols. Ghidra reached
2,222 line-F sites, including all 1,521 `__CLMUL` and 133 `__CFTOD` calls that a linear sweep finds in
code, without touching the `$FFFF` words in data embedded in TEXT. `_save` at `text:1714` decompiles
with the 190-byte character stride and the 314-, 1,900-, 1,330-, and 308-byte save file writes, and the
callers of `DOS::_OPEN` resolve to `text:3c094`. The decompiler uses DOS stack prototypes and FPACK
remainder and floating-point call fixups. Future loader work includes `.dim`/`.xdf` Human68k disk
members and `.Z`/`.R` programs.

### Classic Macintosh

**Implemented for near-model 68k.** The loader reads resource forks, MacBinary, AppleSingle and
AppleDouble, unpartitioned HFS, and Disk Copy 4.2. It maps `CODE` segments and `CODE 0` jump entries,
builds the A5 world from THINK C `DATA`, `ZERO`, and `STRS`, and applies `CREL` and `DREL` fixups.
Ghidra recovers direct and recognized indexed A5 calls and names common A-line Toolbox traps.

**Validated on Ghidra 12.2.** Pool of Radiance v1.1 has 14 CODE segments and 582 jump entries.
Its startup at `code1:003c` resolves an indexed A5 transfer. Secret of the Silver Blades has 15
segments and 859 jump entries. The imports applied 1,345 and 1,601 THINK C fixups respectively.
Open: compressed CODE, split STRS heaps, MPW far-model code, CFM and PowerPC, partitioned media,
MFS and HFS+, full Toolbox prototypes, and dynamic analysis.

### Nintendo NES / Famicom

**Implemented for NROM and standard MMC3.** The loader reads iNES and NES 2.0 cartridges, includes
optional trainers, and preserves file offsets for every selected PRG window. It maps the NROM
16 KiB mirror and either MMC3 PRG mode with explicit R6 and R7 selections. Ghidra imports one
CPU view with hardware labels, named vectors, and entries for mapped vector targets.

**Validated on Ghidra 12.2.** The U.S. and Japanese Pool of Radiance releases each have 64 PRG banks,
128 KiB of CHR ROM, and 8 KiB of battery-backed PRG RAM. Both default views recover startup calls
and decompile the IRQ handler. An alternate MMC3 mode maps the selected banks to the expected
source offsets in each cartridge. Synthetic analysis verifies a cross-bank call and a PPU write.

Open work includes more mappers, CHR banking, analysis of runtime bank changes and RAM and I/O
mirrors, and an NES trace and emulation backend.

### Sega Genesis / Mega Drive

**Implemented for raw linear cartridges.** The loader preserves ROM bytes and source offsets
and records the cartridge header, initial supervisor stack pointer, and vector table. It maps canonical
work RAM, Z80 RAM, and I/O, with supported parallel SRAM declared by the header or set by
`--genesis-sram`. Ghidra seeds mapped vector targets and labels and types common hardware registers.

**Validated on Ghidra 12.2.** The 1 MiB U.S./Europe `Countdown to Doomsday` ROM starts at
`$000200` and has HBlank and VBlank entries at `$0F1B64` and `$00DE8C`. The reset routine calls
`$019CCA`, where a read resolves to the odd-lane cartridge SRAM at `$200001` using the explicit
range. Ghidra resolves VDP writes in the startup code and decompiles the VBlank handler.

Open work includes banked cartridges, SRAM that shares the ROM address range, ROM and device
mirrors, 24-bit address aliases in Ghidra, interleaved copier dumps, EEPROM protocols, and Genesis
trace and emulation backends.
