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

On 2026-11-25, published [retrore 1.0.0](https://github.com/jjanow/retrore/releases/tag/v1.0.0).
[Release CI](https://github.com/jjanow/retrore/actions/runs/45638059673) built one wheel and passed
the Linux and Windows suites with Python 3.12 and Ghidra 12.2. The release and local deployment use
that wheel. Builds are reserved for releases and testing blockers that require a build.

Resume validation when original X1turbo media or a new compiler runtime is available. The
[platform parity table](#platform-capability-parity) and milestones track the remaining extensions.

## Why

Packed executables and overlays need a reconstructed memory map before analysis can resolve
addresses. Segment tracking and jump-table recovery improve cross-references. Runtime signatures
identify compiler helpers, and routine emulation verifies behavior against the loaded image.

## Design

- **Python 3 package + CLI** (`retrore`), with Capstone for disassembly and Unicorn, py65, and z80 for
  routine execution. Every command can print JSON (`--json`) so agents can call it cheaply. The
  package and its default test suite are self-contained. Game-specific addresses and expectations
  belong in opt-in validation tests.
- **Ghidra integration through headless scripts**, not a full Ghidra extension at first: the loader writes a flat
  image + a JSON "program map" (segments, units, symbols, segment-register assumptions, functions, jump tables),
  and a Ghidra headless script imports it into a project. A real Ghidra loader
  extension can come later if the script route turns out to be limiting.
- **DOS addresses:** `seg:off` with a stable segment per unit, plus a linear address. Overlay code is
  always named `unit:offset` too (e.g. `OV2:34aa`), so notes from different tools line up.
- **No game data in this repo.** Tests that need real game files read them from paths in environment variables and
  skip when unset. Expected values (addresses, names) may be checked in; the binaries may not.

## Phases

### Phase 1: whole-program loader

1. **Implemented.** Parse the header and relocation table, relocate the module
   at a fixed base segment, and report the initial CS:IP and SS:SP. See the
   [MS-DOS Encyclopedia](https://www.pcjs.org/documents/books/mspl13/msdos/encyclopedia/section2/#article-4-structure-of-an-application-program).
2. **Implemented.** Unpack EXEPACK, LZEXE 0.90/0.91/0.91e, and supported PKLITE streams. Restore the
   original entry and stack, apply recovered relocations, and diagnose unrecognized packed variants.
3. **Implemented for the validation targets.** Load Turbo Pascal `FBOV`/`TPOV` banks from resident descriptors
   and relocate their unit code. Place flat overlays at supplied or automatically assigned segments above the
   root. Phase 12 adds DOS COM and raw loads, Borland VROOMM banks, and Microsoft LINK members.
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

Ghidra also resolved the overlay calls in Pool of Radiance's LOADPIECES handler at
`GAME.OVR:0x19BA`, including the wall-set loader at `GAME.OVR:0x2F6FF`.

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
| Pool of Radiance (DOS v1.3) | TP6, EXEPACK, `FBOV` overlays | Unit table, stub resolution, overlay cross-references |
| Phantasie I (DOS) | LZEXE 0.90 MZ + program-loaded `OV1.OVR`/`OV2.OVR` | Distinct overlay segments, jump-table recovery (Mystic SCORE) |
| Phantasie III (DOS) | EXEPACK MZ, four LINK overlays, far data segment `0x1820` | Segment tracking, far globals, traced floating-point dispatch |
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

- Python 3.12+, `pip install -e .` (in a venv, `.venv/`, gitignored).
- Ghidra 12.x (installed as a snap on the dev machine; `analyzeHeadless` path configurable via `GHIDRA_HOME`).
- `pytest` for tests.

## Order of work

Phases 1–7 are implemented for the initial DOS scope, including the optional DOSBox-X trace import.
The Commodore Amiga, Atari ST, Commodore 64, Apple II, Atari 8-bit, MSX2, NEC PC-88, NEC PC-98,
Sharp X1, Sharp X68000, Classic Macintosh, Nintendo NES / Famicom, and Sega Genesis / Mega Drive
milestones are complete for the validated releases. X1turbo validation awaits original media.
Phase 9 is implemented and validated on the releases documented below.
Additional platform capabilities are listed in the parity table and platform milestones below.

## Analysis backlog

### Phase 8: faster queries and reproducible releases

- **Implemented.** Before a GitHub release, run Release CI on the candidate commit. It builds one
  wheel and tests the installed package on Linux and Windows. Publish the wheel from that run.
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
  Write audits also follow shared tails, discard uncertain segment values through calls, and seed detached
  entries with unknown segments. The alias check includes real-mode selector aliases and 20-bit wrap.
- **Implemented.** More switch patterns: `jbe`/`jb` bounds, `sub` bias, mask bounds, byte indexes, and
  near call tables. A root switch is read against the nearest relocated code segment. The XC 68k switch is
  recognized on X68000. A pass after segment analysis keeps candidate targets for unresolved indirect calls
  and jumps, with evidence and the writer's address (`indirect` query). `gaps --classify` scores gaps as
  code, data, or padding with evidence. A gap whose entry a relocated pointer names, that has a prologue,
  and that decodes cleanly is seeded as a function. Ghidra already treats tail jumps to function entries as calls.
  **Validated:** Phantasie III recovers 22 root tables (was 0), including the call table at
  `218f:0bcc`. The root-only import recovered 448 functions (was 380) and seeded `root:532c` from
  a relocated far pointer. With all four LINK overlays loaded, Ghidra finds 528 functions and
  reaches `root:532c` through a direct call. Phantasie I has 17 tables (was 15), and Mystic SCORE
  still decompiles.
  P4.X resolves all 41 computed jumps (was 32). In Pool of Radiance, `tpov_0096:0d70 CALLF [0x6b84]` gets
  candidates `root:0994` and `root:06e6`, written at `tpov_0035:006f` and `:008b`.
  Far CS jump and call tables use relocated selector words for destination evidence. Amiga
  Phantasie I and III each recover 22 switches, and Atari ST Phantasie II recovers 15 in `PHANT.PRG`
  and 3 in `UTILIT2.PRG`. `trace --classify-gaps` attaches runtime hit evidence to static gaps.
  The DOS indirect pass reads segment override prefixes from the instruction bytes and recognizes
  indexed memory operands without a displacement. `indirect` reports `segment_loss` with the origin
  and reason when the operand's segment is genuinely unknown. In Phantasie III, `root:42df` reads
  `SS:[2624]` and finds the relocation-backed candidate `root:11914`.
- **Validated with traces.** Phantasie III's `FTST` at `root:13721` uses `class(SI)`.
  `FCOM` and `FCOMP` at `root:1366d` use `4 * class(SI) + class(DI)` for class values 0–3.
  Traces covered all four `FTST` slots and all 16 comparison slots. The Ghidra regression test
  replays their four and eight distinct successors.
  The class is byte 11 of a 12-byte record. Input converters and arithmetic write the class or
  copy a record. Unicorn tests exercise six arithmetic forms, extended-precision overflow and
  underflow, and stack duplication, exchange, and store paths.
  The `record-writes` query reports overlapping stores and potential segment aliases for a byte
  field, with known byte values and copy sources. The Phantasie III audit checks the class
  bytes in all 15 slots in the runtime allocation. The `FST` word stores at `root:12e40` and
  `root:12e43` use caller-derived `ES:DI` while reading the live record through `DS:SI`.
  The runtime's DOS vector installer assigns INT 34h–3Bh to `root:1241c`, INT 3Ch to the
  segment-override entry at `root:123db`, and INT 3Dh to the WAIT patch handler at
  `root:123be`. The real-mode harness runs them via the interrupt table. Structured traces
  can add observed interrupt edges to Ghidra. Tests exercise both `FST` and the original
  ES-prefixed `FSTP` with a separate buffer and with a segment alias that overwrites a
  class byte with `0x7f`.
- **Validated shipped store paths.** `root:6815` supplies DGROUP:`2582` to the parser's
  8-byte stores at `root:60f4` and `root:6254`. The first store was reached with a
  base-16 argument. The formatter's 10-byte stores at
  `root:6504` and `root:6560` write to DGROUP:`2538`. Probes also cover control and
  status word stores, the integer conversion's `SS:[BP-0xc]`, and all four single-precision
  store sites in LINK member 2, each at `SS:[BP-8]`. The member runs in its original overlay
  window and the probes check physical write intervals against the full record allocation.
  The startup initializer loop at `root:4405` calls `root:6017` through the relocated far
  pointer at DGROUP:`2630`. The installer copies a five-entry table into DGROUP, placing
  `root:6a12` in DGROUP:`1dd6` from the relocated template at `root:2b0d4`. The callback
  decodes the caller's output pointer through two `LES` instructions before the store at
  `root:6a5b`. Its other path copies eight bytes to that pointer at `root:6a38`.
  Direct entry probes supply the output pointer and check both converted values. Ghidra's
  root and four LINK members have no incoming references to the callback slot or entry, the
  alternate parser entry at `root:6383`, or the comparison entry at `root:68a4`. A search of
  the five file-backed units found no stored near or far pointer to either of the latter
  entries. The call at `root:60e4` reaches the integer parser at `root:6349`. Direct probes of
  the alternate entries verify the double through `DS:[DI]` and status through `SS:[BP-2]`.
  A Unicorn run with DOS and BIOS shims booted the game with `NO87=` and rolled characters
  of all five selectable races in Pendragon. The computed menu call at `root:721d` reached
  the Guild handler at `root:ac21`. The game loaded LINK member 2 and reached
  `link_0002:22a7`, `:269b`, `:26c7`, and `:2708`. All four stored at DGROUP:`764c`,
  and the control word and integer stores used DGROUP:`761e` and `7614`. The detached entries
  had zero hits in those runs. The direct probes establish each routine's pointer or stack contract.
- **Audited computed callers in the shipped DOS release.** Ghidra's `indirect` inventory of the
  root and all four LINK members lists no target or candidate for `root:6a12`, `root:6383`, or
  `root:68a4`. Unicorn traces through startup, Pendragon menus, the town archives, and
  ordinary quit logged zero hits at those entries and zero reads of the installed callback table.
  Startup calls at `root:42df` and `root:42f5` and shutdown at `root:43d3` reach
  `root:11914`. Its table call at `root:1191c` selects `root:1192a`, `root:11a2a`, and
  `root:119f9` for services 0, 3, and 2 respectively. The startup jump at `root:4621` returns
  to `root:4264` through the address saved by the argument builder. The call at `root:52c2`
  executes the `INT` thunk built on its own stack.
  In Pendragon, `root:724f` reads five far pointers from the Bank, Mystic, Exit, Armor, and Inn
  descriptors. Their handlers at `link_0002:4112`, `:4152`, `:4192`, `:4259`, and `:4308`
  survive the load of member 3 into the same window. At base `1000`, both members load at
  `23d5:0000`. An ordered load manifest preserves member 2's visible tail and Ghidra 12.2
  replays all five calls against the member's analysis block. In the town archives, member 4
  entered at `link_0004:062d` and its tile dispatch at `:05c1` reached `:05c6` and `:05e9`.
  The DOS read shim invalidates Unicorn's translation cache for the overlay window when it writes
  a member, so execution uses the newly loaded code.
- **Audited the 11 unresolved transfers in the Ghidra 12.2 listing.** Eight were far.
  The initializer, argument return, interrupt thunk, and two menu calls have observed targets.
  The argument builder writes DGROUP:`1d9e` at `root:447e` and `:4482`. The live jump at
  `root:4621` uses that slot to return to `root:4264`. Probes confirm that the error callback
  at `root:441d` skips a null slot at DGROUP:`1d94` and the stack-check jump at `root:4454`
  skips the `ffff:ffff` sentinel at DGROUP:`1d98`. The listing identifies reads of those
  slots and no direct writers. The floating-point exception call at `root:11e86` reads the
  pointer in `280a:0000`; probes confirm its far return frame on entry to `root:602b`.
  The other three listed sites, `root:1191c`, `root:126cf`, and `root:13721`, transfer
  within the floating-point runtime's CS `218f`, above the three detached entries. A scan
  at every byte alignment of the five loaded units, including segment aliases and 20-bit wrap,
  found only the relocated template pointer at `root:2b0d4`. The observed menu selections
  and initialized pointers cover the audited paths.
- **Traced an archives event and combat in the shipped DOS release.** An opt-in Unicorn
  playthrough creates and adds a fighter in Pendragon, loads the first `DNGS.DAT` record, keeps
  the scroll in the west room, and completes a round against a wandering group. Member 4
  replaces the overlay window prefix previously occupied by members 2 and 3. The ordered load
  manifest retains member 2's tail, and the trace maps the executions in member 4 to their
  original file offsets. The tile dispatch at `link_0004:05c1` visits seven targets from
  `:05c6` through `:05f0`. The event interpreter jumps from `link_0004:1534` to `:156e`,
  the item handler. Ghidra 12.2 adds the previously unresolved call from `root:721d` to
  `root:10424` and confirms the jumps from `root:d5c4` to `root:d631` and from `root:1046a`
  to `root:104b9`. The played dungeon path, including the combat round, makes zero software
  FPU operand dispatches and writes no record class bytes. The full run has zero reads of the
  five installed far pointers at DGROUP:`1dce` and no hits at the three detached entries.
- **Traced Fireflash I and a one-time gold event in the shipped DOS release.** A second
  archives playthrough creates a wizard and starts a round in the west passage. The first
  cast reaches `root:caac`, takes the jump at `root:c3ea` to `root:c3ef`, and calls
  `root:b42e`. The wizard's magic drops from 7 to 6. In a third run, the party finds
  256 gold at (12, 13). The event dispatch at `link_0004:1534` reaches `:15e7` once.
  A return to the square finds the event byte changed from `0x81` to `0xff` and the gold
  total still at 256. The two routes capture the overlay and root edges and show zero
  FPU operand dispatches or class-byte writes after archive entry. The full runs record
  zero callback-table reads and zero hits at the detached entries.
- **Traced wilderness events in the shipped DOS release.** With LINK member 3 covering the
  start of member 2's window, `link_0003:02f3` calls the travel-time update at `root:14a9`
  on ten road steps. The party arrives at the Jolly Inn at (24, 32) after five thirds of a day.
  Its empty treasury takes `link_0003:08e1` to the refusal at `:08fb`. After ten steps the
  party returns to Pendragon with no gold spent. With a different DOS clock seed, the first
  northbound step at (24, 36) calls `root:de54` from `link_0003:0239`. Declining the sleeping
  monsters prompt sets the refusal flag and jumps from `root:e020` to `root:e0a3`, bypassing
  combat. Both runs map the executed member 3 edges to their original file offsets. They record
  zero callback-table reads and zero hits at the three detached entries. After wilderness
  entry, both observe zero software FPU operand dispatches and zero class-byte writes.
- **Traced the wilderness combat menu pointer.** Accepting the same road encounter starts
  combat at `root:104c0` and completes one round. Stores at `root:103ac` and `:103b3`
  build the current selection at `2820:b5a8` with the value DGROUP:`0834`. The two `LES`
  instructions before `root:721d` follow that selection to the descriptor at DGROUP:`095e`.
  Its relocated far pointer at DGROUP:`0962` supplies the observed call to `root:10424`.
  This route makes zero reads of the installed callback table and reaches none of the three
  detached entries.
- **Validated arithmetic dispatch slots.** `root:12524` and `root:1253f` use the same
  eight-word table at `root:1205e`. The `0x0e` mask and optional XOR with 2 keep BX
  on those slots. At `root:126cf`, arithmetic uses three 16-word tables at `root:12106`,
  `root:12126`, and `root:12146`, indexed by `4 * class(DI) + class(SI)`. The probes
  exercise all 16 pairs for FADD, FMUL, FSUB, FSUBR, FDIV, and FDIVR. They watch the
  class byte in every allocated slot and see writes of 0–3 only. The single, double, and
  extended loaders write a class through DH at `root:12d47`, `root:12f6d`, and
  `root:134f3`. Their classification branches set DH to 0, 1, or 2, or set bit 0 to
  produce 1 or 3. The six-word copies and exchanges propagate their source class. The 11
  templates copied as full records have classes 0–3. The memory division probe writes class 1
  into the temporary in the next slot. Unmasked division by zero reports `0x83` and substitutes
  class 3. An invalid empty-stack store reports `0x8b`. The following `FTST` reads the class
  below the initial top. A constant push at the stack limit reports `0x8a` and writes class 0
  one record past the limit. A supplied returning exception callback lets the probes observe
  these results. The game's startup at `root:42f5` selects service 3 of the `root:11914`
  dispatcher, which registers the handler at `root:602b`. That handler reaches DOS process
  termination with exit codes `0x83`, `0x8b`, and `0x8a` for these cases.
- **Traced FPU output destinations and class-copy sources.** The software output probes cover
  `FSTP` to single, double, and extended formats for all four record classes, plus integer,
  control-word, and status-word stores. The traces check each word's physical destination against
  the caller buffer and the entire 15-slot allocation. The extended output copies its significand from the
  active `DS:SI` record with `MOVSW`. Double subnormal output uses the four stores from
  `root:1315d` to `:13166`. The single round-toward-zero overflow path emits `7f7f` then
  `ffff` at `root:12e94` and `:12e99`. The traces observe classes 1–3 from arithmetic
  templates at `root:12726` and classes 0 and 1 from constant loads at `root:1376b`.
  The register copy at `root:1273c` and both writes of the exchange at `root:137ac` and
  `:137ad` propagate all four source classes.
- **Replayed shipped FPU interrupt edges.** The saved interrupt frames and live vector table
  identify seven call sites across `root:1241c`, `root:123db`, and `root:123be`. Observed
  interrupt continuations at `root:6887`, `:688a`, and `:688d` recover the `INT 39h` at
  `root:688d` and skip its inline operands. Ghidra 12.2 replays all seven edges. The write
  audit refreshes its context after replay and propagates registers into the observed handlers.
  `record-writes` reports the two single-precision output words, both copies, and both exchange
  writes as possible overlaps. Unicorn shows the exchange uses `280a` for ES and DS.
  Archives playthroughs check the live CS-relative table entries for tile, event, combat,
  and spell dispatch against the export and the observed successors.
- **Implemented.** A conventions pass sizes stack arguments from `ret n`, caller cleanup, and frame reads.
  It treats 16-bit frame displacements as signed and skips inferred argument areas over 256 bytes.
  It makes `les`/`lds` arguments far pointers and names `int 21h` services as `DOS::` stubs, with carry
  as a result. X68000 DOS stubs have prototypes for about 80 calls. Call fixups model stacked FPACK
  remainder, conversion, float, double, and compare helpers. `trap #15` IOCS calls are named.
  **Validated:** P4.X shows `DOS::_WRITE(handle,buffer,length)` in `_write` at `text:3c2dc`,
  `uVar2 % param_1 + 1` in `_rand`, and `(dVar2 + dVar1) / local_24` in `_avg_attr`. Pool of Radiance
  names 35 `int 21h` sites. It recovers 564 callee-cleanup functions and 445 far pointer arguments, and
  Seek at `root:c4e3` tests `extraout_CF` instead of a multiply's carry.
  Microsoft C signatures cover the medium-model DX:AX `lseek` return and the near and far variants
  of `memcpy` and `isatty` from the compiler probes. Short straight-line routines can infer register
  parameters and `DX:AX` or `DX:BX:AX` return storage from direct callers. Real48 signatures retain
  their type. X68000 IOCS stubs have register prototypes for 43 services. Caller-validated XC stack
  parameters restore the `_rand(100)` argument in `_frand`. The `_brkctl`, `_fmalloc`, and `_ffree`
  signatures match the Microsoft C 5.1 libraries and the shipped Phantasie III routines. `_brkctl`
  includes the four-byte increment and far block argument. It and `_fmalloc` return a far pointer
  in `DX:AX`. `_ffree` takes a far pointer. Phantasie IV's 13 OPMDRV wrappers use a constant in
  `D1` to select the subcall. Each typed stub declares the
  `D2` and `A1` inputs used by that wrapper. A bypassable selector load falls back to `_OPMDRV`.
  Ghidra's call fixup elides the separate `swi(0x21)` at recognized DOS sites while retaining the
  service call and its carry result. Unrecognized DOS services and BIOS interrupts retain their
  ordinary vector lookup. The disassembly retains the original interrupt bytes.
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
  requires `--apply --replace`. Apple II Phantasie III's PICPLOT combines two table bytes at index
  `$60` to write `$2228` into its screen-store operand. Pointer search finds both bytes even though
  the high-byte operand base is outside the export. The original routine copies the first two rows
  of a supplied panel into the predicted HGR locations in py65.

- **Traced runtime-only heap pointers.** Phantasie III's `_brkctl` receives the allocated DOS
  selector in AX at `root:4f05`. The runtime stores it in DGROUP:`1dc6` at `root:4cf4` and
  returns the map allocation from `_fmalloc` in `DX:AX` at `root:4cbc`. Archives member 4's `LES` at
  `link_0004:1316` loads the pointer from `2820:b63c` and the next instruction reads a tile byte.
  The same sequence uses heap selectors `6000` and `6200` in separate runs. `trace --evidence`
  identifies the reader's file offset and records the heap location as runtime-only.
- **Verified remaining output cases.** The single subnormal and double saturation paths write
  the expected words to the caller's buffer. Masked invalid `FISTP` writes the indefinite integer
  at each of the 16-, 32-, and 64-bit destinations. Packed BCD, environment, and state stores
  terminate the software runtime with DOS exit `0x87` before writing the destination. Direct calls
  to `root:68a4` preserve AX and transfer each ordered comparison result from `SS:[BP-2]` to FLAGS.
  Static `possible` overlaps remain conditional on runtime selectors and offsets.
- **Identified the conversion callback's library caller.** A Microsoft C 5.1 `/AL` probe linked
  with `LLIBCR`, `LLIBFP`, `EM`, and `LIBH` runs in DOSBox and Unicorn with `NO87=1`. Its `sscanf`
  call parses `%lf %f` as `2.5` and `3.25`. Unicorn observes the third far pointer in
  `__cfltcvt_tab` taking both scanner calls to `__fassign`, the library equivalent of `root:6a12`.
  The library ASCII converter also falls through to the equivalent of `root:6383` after a status check.
  Linking `__fcompp` from `LLIBFP`'s `87fcmp.asm` object reproduces all 25 bytes at `root:68a4`.
  The shipped Phantasie III routes make no reads of the installed callback table
  and observe no calls to the three entries.

### Phase 10: inspectable evidence and reusable analysis

- **Implemented.** `bytes` reports export bytes, original values, source spans, and recorded fixups.
  `address-map` maps logical, linear, runtime, image, and available source file coordinates.
  `disasm` reads a bounded Ghidra range with resolved references and flags unresolved computed flow.
  `decomp --map-lines` maps C lines to contributing instruction ranges. `--source-file` recovers
  verified DOS root offsets for older unpacked exports, and early Atari 8-bit maps recover offsets
  from their ordered segment records. D64, Apple DOS/RDOS, Atari DOS ATR, and MSX-DOS FAT12
  exports preserve both member and physical disk offsets. `address-map --runtime-load` accepts
  explicit linear placements and unmapped units on each supported platform.
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
- **Implemented.** `annotations` exports names, global labels, function-local instruction
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
  Replay checks each range against both block sizes. Version 8 uses unique byte alignments for
  data and storage that moved inside changed initialized blocks. Renamed, changed blocks require
  two disjoint unique anchors and an unambiguous pairing. Replay verifies the destination block
  digest and requires each layout or storage piece to fit one alignment. Older documents remain
  supported.
- **Implemented for review.** `compare` matches normalized bodies in the same language and uses
  names, call graphs, and referenced data to suggest changed and cross-port matches. The result
  shows unresolved alternatives. `annotations transfer` preserves provenance when preparing replay
  at a matched same-body entry. `compare --instructions` also maps instruction starts so interior
  comments and global and function-local labels follow the matched instructions. Preview checks
  that each destination instruction belongs to the expected function. `compare --semantics` uses
  decompiled p-code operation counts, branch degrees, and constants to suggest unnamed cross-port
  candidates without shared call or data anchors. Duplicate profiles remain unresolved.
- **Implemented.** Read-only queries accept an exact name for a compatible existing Ghidra program
  at the project root. `project-summary` and `batch --evidence` support review and handoff.

### Phase 11: repeatable dynamic analysis

- **Implemented.** `fixture` accepts declarative register and memory inputs, expected outputs,
  scripted OS calls, and I/O. It runs input matrices from fresh state, reports relevant changes,
  and captures repeatable snapshots. Compare with another export or a reference report.
- **Implemented.** `trace` maps versioned emulator snapshots, executed edges, memory accesses, and
  overlay or bank changes to exported units. Ghidra coverage reports gaps between observed and
  recovered flow and previews trace-backed additions before explicit application.
- **Implemented.** Routine execution uses a common request and result across x86, 68k, 6502, and
  Z80 backends. CPU-specific registers and scripted service and I/O hooks are exposed through
  fixtures. Structured traces provide static mapping and coverage across the supported exports.
  Use a machine emulator for captures that require live banking or device behavior.

### Phase 12: loader depth on supported platforms

**Complete for the validated formats.**

- **Implemented.** DOS COM and raw loads record the input byte range and initial segment registers.
  PKLITE recognizes additional XOR- and ADD-scrambled EXE stubs and COM decoder pointers. V1.20
  decoding handles encoded match distances and the ADD variant's big-endian relocation offsets.
  Microsoft LINK, Microsoft MOVE, and Borland VROOMM overlays retain their source offsets and
  recovered fixups. DOS catalogs expose member selectors for exports that exceed the first MiB.
  LINK recovers the shared runtime window from counted directories and adjacent arrays with matching
  member fixups, including from EXEPACK-compressed resident modules and separate OVL files. It validates
  trailing segments using the member allocation and exports file-backed segment starts. MOVE reads
  member-relative fixups and resolves resident dispatch stubs using its segment and member tables.
  MOVE directories can have unused slots. Exports preserve the native member IDs across gaps.
  Ghidra backs the rest of each MOVE allocation with uninitialized memory. VROOMM skips header-only
  descriptors for empty code segments and resolves flagged pointer pushes to verified resident stubs.
  Partial layouts and unmapped trailers appear as diagnostics.
- **Implemented.** Amiga Hunk overlay trees retain each node and its ancestry, active segment indices,
  table entries, and source offsets. The loader supports additional narrow absolute and PC-relative
  fixups, recognized LINE records, and the THOR 1.2 manager signature. DOS exports accept LINK and
  TLINK public and source-line listings. Reusable masked signatures can name unique byte matches.
- **Implemented.** Versioned load manifests describe ordered placement, replacement, and transitions.
  Address evidence and traces map reused runtime addresses to the active source. Ghidra can display
  manifest states in separate overlay address spaces alongside the analysis image. Add separately
  selected banks from flat 8-bit exports using the manifest.
- **Implemented.** `members` and `--member` share selectors for supported disk and container inputs.
  Exports preserve selection order, layout decisions, and member and file offsets. Synthetic tests
  cover these workflows. Original-tool outputs and releases use optional `RETRORE_*_DIR` inputs.

**Validated with original tools.** PKLITE 1.15 registered small and large XOR outputs match their
unpacked references. The PKZIP 2.04g installer exercises the ADD decoder and matches Deark on
its image, entry, stack, and 24 relocations. The PKLITE 2.01 COM probe still decodes after its
copyright fields are cleared. LINK 2.40, 2.45, 3.01, 3.05, 3.65, and 5.01.21 probes produced counted
directories. The LINK 2.40 and 2.45 probes have 32 and 4 selectors respectively. Both list the
leading empty CODE segment at the window start and execute the padded member successfully in DOSBox.
The opt-in tests check the window, relocated bytes, and original file offset for both executables.
In the runnable LINK 3.65 and 5.01.21 probes, the shared window begins at image offset `0xB00`.
Member 2 begins with an uninitialized segment, and its first routine is page-aligned at `0xC00`.
Both probes returned the expected values on alternating calls to the two members in DOSBox. The
opt-in LINK 3.65 test checks the padding, relocation, and source offset with the native directory
and with its count words cleared. Ghidra 12.2 kept the full padded member in the runtime view and
decompiled `link_0002:0100` to a routine returning 7. [Microsoft LINK overlay placement](https://www.infania.net/misc/kbarchive/kb/032/Q32003/index.html)

LINK 3.65 and 5.01.21 also list a page-aligned trailing selector at `0xC00` when member 2 ends
on disk before that address. The probe with an empty trailing segment has 16 file bytes. The
probe with a 16-byte uninitialized segment has 29 file bytes and compares the relocated segment
with CS in DOSBox. Retrore keeps the two initialized payload sizes and retains the native runtime
address for the trailing segment's fixup. Ghidra's runtime view replaces only the member's file bytes.

**Validated with shipped static LINK executables.** Civilization for DOS 474.03, Railroad Tycoon
455.00 and 455.02, and Silent Service II use EXEPACK-compressed resident modules with counted
directories. At base segment `0x1000`, Civilization's 23 members share runtime address `0x32F30`
and have 2,915 fixups. Ghidra 12.2 imported the root and all 23 overlay states. The opt-in test
checks the window, fixup count, and original file offsets and bytes.
[Civilization 474.03 archived executable](https://archive.org/details/msdos_Sid_Meiers_Civilization_1991)

NetHack 3.0j for DOS exports 63 LINK members and 6,127 fixups from its two original OVL files.
Its resident directory has 162 selectors and a physical overlay count of 64 including the root.
Every member's first listed selector is `0x07BA`, the link-time window. The last file has an
unmapped 330-byte trailer. The opt-in test clears the two count words in a temporary copy
of the release and recovers the same window, fixup count, and file provenance. In separate
probes, LINK 3.65 and 5.01.21 both wrote the `$$CGSN`
and `$$COVL` words even with a custom `$$OVLINIT` that only returns. Both link maps placed the
paragraph-aligned and page-aligned first segments at `OVERLAY_AREA`. The count-free directory
and delayed first selector have synthetic coverage, including in combination with EXEPACK.
The shipped static releases inspected so far have native counts and their first listed selectors
start at the window. An unmodified release with either edge case would extend that coverage.
Older DOS releases of NetHack 2.3a and 2.3e and PC Hack 3.51 and 3.60 had no appended members
or separate overlay files. The original all-member NetHack 3.0j import exceeded a 420-second
headless budget. A JVM recording found that Ghidra spent 99% of the calling-convention
script samples checking parameter storage conflicts. The script had mistaken signed locals
for large positive argument offsets and inferred thousands of stack words from stray
instructions. With the signed displacements and bounded inference, Ghidra 12.2 imported the
root, all 63 members, and all 64 runtime views in 52 seconds.
[NetHack 3.0j release archive](https://cdimage.debian.org/mirror/archive/ftp.sunet.se/pub/games/nethack/Msdos/NH_older/),
[Microsoft KB Q32003](https://www.infania.net/misc/kbarchive/kb/032/Q32003/index.html)

**Validated with Microsoft MOVE.** NetHack 3.1.3 uses Microsoft C 7 and `/DYNAMIC`. Retrore
catalogs its 63 members and 18,119 member-relative fixups. An export of members 1 and 2 recovers
126 dispatch stubs and imports in Ghidra 12.2. The full analysis image requires more than 1 MiB,
so use `--member` to select overlays.
[NetHack 3.1.3 DOS release archive](https://cdimage.debian.org/mirror/archive/ftp.sunet.se/pub/games/nethack/Msdos/NH31/),
[NetHack 3.1.3 source archive](https://ftp.zx.net.nz/pub/mirror/ftp.funet.fi/pub/unix/games/nethack/)

The NetHack 3.2.2 real-mode executables have 184 and 209 populated MOVE slots. Both segment
directories include records for empty slots whose file offsets and allocation sizes are zero.
NetHack 3.3.1 has 366 populated slots out of 392, with 28,475 fixups and 2,090 resolved stubs.
Ghidra 12.2 imported selected members 392 and 60. [NetHack 3.3.1 DOS release](https://www.nethack.org/v331/ports/download-msdos.html)

LINK 5.30 and the Microsoft C 7 MOVE library produced runnable probes with two overlays,
including two C code segments in one member. Ghidra decompiled the first member's calls to both
members. A probe linked with `/OV:62` had 12 file bytes in member 2 and a 288-byte allocation.
Ghidra imported the tail as a 276-byte uninitialized block. A DOSBox capture placed two members
at the same segment in different states. A load manifest mapped each state to its original
file offsets, and Ghidra imported both runtime views into separate address spaces.
A three-member LINK 5.30 probe used Microsoft's MOVE TRACE utility in DOSBox. With a 19-paragraph
heap, members 1 and 2 initially coexisted. Member 3 took over member 2's segment, and members 1
and 2 later reloaded from XMS at different segments. The opt-in test maps all five loads back to
their source offsets and verifies the coexisting pairs in Ghidra 12.2. In a 96-paragraph heap,
all three stayed loaded. [Probe build steps](README.md#microsoft-move-heap-probe)
[Microsoft C 7 distribution](https://www.pcjs.org/software/pcx86/lang/microsoft/c/7.00/),
[Microsoft C 7 Environment and Tools, chapter 15](https://bitsavers.trailing-edge.com/pdf/microsoft/msdos_c/Microsoft_C_7.0_1991/24778_Environment_and_Tools_199112.pdf)

Turbo C++ 1.01 with TLINK 3.01 and Borland C++ 2.0 with TLINK 4.0 emitted resident stub offsets
for the C far-pointer probes. Both linkers set the pointer-offset flag for an assembly probe that
passes the in-segment function offset as a constant and relocates the segment immediate. The DOSBox
probe compares the pointer with the resident stub and calls through it. Modified probes tested the
manager's instruction checks. The pointer comparison failed with flagged immediate pushes and
with `MOV`/`PUSH` pairs using different registers. Retrore reports those flagged offsets as unresolved.

**Validated with shipped Borland executables.** Turbo C++ 1.01 `TCC.EXE` and Borland C++ 2.0
`BCC.EXE` each export 122 nonempty overlays. `TCC.EXE` has 4 empty descriptors, 894 stubs, and
7,282 fixups. Its overlay manager discards bit 2 of a fixup word before indexing the segment table
and tests bit 0 for pointer-offset rewriting. `BCC.EXE` has 5 empty descriptors, 914 stubs, and
7,612 fixups. DOSBox compiled the same simple C program with both executables. TLINK 3.01 and
4.0 also emitted resident stub offsets in C pointer initializers and return values, and MASM
segment/offset pairs and in-code far pointers.

**Validated with an original Amiga release.** The 1986 DeluxePaint I executable has eight overlay
nodes, including two children of `ov1_6`, and 66 table entries. Ghidra 12.2 imported 6,360
relocations and seeded 63 overlay entries. The other three entries mark exact hunk boundaries.
Amiga overlay trees establish coexistence. Captured placements supply physical scatter-load
addresses for a run. [DeluxePaint release background](https://computerhistory.org/blog/electronic-arts-deluxepaint-early-source-code/)

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
| Runtime layout | MZ, COM, raw loads, and supported overlays | Resident sections and relocations, hierarchical Amiga overlays, a fixed Macintosh A5 world, and a linear Genesis cartridge view | Selected bank snapshots and manifest states | Selected real-mode RAM loads and manifest states |
| Calling conventions, runtime signatures, and indirect control flow | Stack conventions, `int 21h` services, switch patterns, and indirect-call candidates | X68000 DOS and FPACK, Amiga and Atari ST switch recovery, and Macintosh A5 jump targets and named Toolbox traps | Extend for relevant targets | Real-mode segment context and selected far-call conventions |
| Routine emulation and trace coverage | x86 routines, structured emulator traces, and DOSBox-X | 68k routines and structured emulator traces | 6502 or Z80 routines and structured emulator traces | Real-mode x86 routines and structured emulator traces |

For each new capability, use shared synthetic contract checks where possible and add fixtures for
platform-specific behavior. Track missing capabilities so a platform's loader milestone is distinct
from its analysis coverage.

## Post-DOS platform milestones

For each source platform, validate the executable or ROM loader, memory map, applicable bank or overlay
handling, and analysis on a representative release before starting the next platform. Keep original media
outside this repository and platform-specific game expectations in opt-in validation.

### Commodore Amiga

**Implemented and validated on Ghidra 12.2.** `info` and `load` detect AmigaDOS Hunk executables,
place their resident CODE, DATA, and BSS at stable addresses, and apply absolute long and compact
relocations. The headless importer restores that layout for 68k analysis and makes the DOS
toolkit's existing decompilation and reference queries available at `hN:offset` addresses.

Ghidra recovered Phantasie I's call from `h20:018c` to the palette routine at `h77:0466`.
For Phantasie III, a zero-based export placed DATA at `0x21890`, and Ghidra
decompiled the main loop at `h0:736c` and resolved its write to `h1:286c`.
Both Phantasie releases keep their hunks resident. DeluxePaint I validates hierarchical AmigaDOS
overlays on an original release. Ghidra decompiled `ov1_1_h160:01d8` and recovered its call to
`_SetMenuStrip`. Set `RETRORE_DPAINT_AMIGA_DIR` for the DeluxePaint I check or
`RETRORE_AMIGA_OVERLAY_DIR` for another original executable named `overlay`.

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
