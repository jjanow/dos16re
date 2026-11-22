# dos16re plan

A reverse-engineering toolkit for 16-bit real-mode DOS programs: MZ executables, packers and overlay systems, as
used by 1980s–early–1990s games. It handles formats and compiler patterns shared across projects and uses games
to validate that support. It gives Ghidra's decompiler and agents driving it one whole-program image to work on.

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

The initial scope is 16-bit real-mode x86 for DOS. The remaster projects' other source platforms are stretch
goals after the DOS roadmap.

## Design

- **Python 3 package + CLI** (`dos16re`), standard library plus `capstone` and `unicorn`. Every command can print
  JSON (`--json`) so agents can call it cheaply. The package and its default test suite run independently of
  sibling projects. Game-specific addresses and expectations belong in opt-in validation tests.
- **Ghidra integration through headless scripts**, not a full Ghidra extension at first: the loader writes a flat
  image + a JSON "program map" (segments, units, symbols, segment-register assumptions, functions, jump tables),
  and a Ghidra post-script (Java or PyGhidra on Ghidra 12.x) imports it into a project. A real Ghidra loader
  extension can come later if the script route turns out to be limiting.
- **One canonical address form:** `seg:off` with a stable segment per unit, plus a linear address. Overlay code is
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
5. **Implemented.** `dos16re load PROGRAM -o OUT/` exports `image.bin` and `map.json`. Both `load` and `info`
   accept repeatable `--overlay` and support `--json`.

**Validated.** PoR `START.EXE` and `GAME.OVR` load 35 distinct overlay units and resolve all 406 stubs.
The documented stub `0085:0039` resolves to `GAME.OVR` file offset `0x21AED`. Phantasie I's LZEXE-packed
`PHANTASI.EXE` loads alongside both flat overlays at distinct segments.

### Phase 2: Ghidra import

1. **Implemented.** A headless pre-script creates memory blocks per unit, sets entry points, and seeds
   disassembly before auto-analysis.
2. **Implemented.** Name stubs and unit entries and comment rewritten sites with the original bytes.
3. **Implemented.** `dos16re ghidra import OUT/ PROJECT` wraps `analyzeHeadless`. To decompile an analyzed
   function, run `dos16re decomp ADDR --project PROJECT` with a `unit:offset` or `seg:off` address.

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
3. **Implemented.** `dos16re gaps --project PROJECT` reports undefined ranges per loaded unit. These are
   candidates for further analysis and may contain code, data, or padding.

**Validated on Ghidra 12.2.** The Phantasie I Mystic dispatcher at `OV1:20a5` has seven computed jump
targets. Auto-analysis finds Mystic SCORE at `OV1:20bb` through a call in one of those cases, and
`dos16re decomp OV1:20bb` returns the function.

### Phase 5: runtime signatures

1. **Implemented.** Masked byte patterns cover selected Turbo Pascal 5.5, 6.0, and 7.0 routines and
   small-model Turbo C 2.01, Turbo C++ 1.01, Borland C++ 2.0, and Microsoft C 5.1 and 6.0a routines.
2. **Implemented.** Ghidra names and types matches at analyzed function entries. The Pascal catalog includes
   Real48 addition, string copy and concatenation, set union, `Write` for strings, `WriteLn`, `GetMem`,
   `FreeMem`, and `OvrInit`. The C catalog covers selected string, output, and heap routines.
3. **Implemented.** `dos16re info` identifies runtimes from startup code and corroborating runtime strings or
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
3. **Implemented.** `dos16re call ADDR --export OUT --regs ... --mem ... --read ...` reports register
   and memory results, with `--json` for scripts.
4. **Implemented.** `dos16re trace LOGCPU.TXT --export OUT` maps DOSBox-X debugger CS:IP logs to the
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

Game files are found through `DOS16RE_POR_DIR` and `DOS16RE_PH1_DIR`. The headless integration test also
uses `GHIDRA_HOME`. The Phase 3 Phantasie III test uses `DOS16RE_PH3_DIR`. Tests skip when their inputs are unset.
Unit tests on hand-built tiny MZ/overlay files run everywhere (CI).

## Setup

- Python 3.12+, `pip install capstone unicorn` (in a venv, `.venv/`, gitignored).
- Ghidra 12.x (installed as a snap on the dev machine; `analyzeHeadless` path configurable via `GHIDRA_HOME`).
- `pytest` for tests.

## Order of work

Phases 1–7 are implemented for the initial DOS scope, including the optional DOSBox-X trace import.
Work through the post-DOS platforms below in order, one at a time, beginning with Commodore Amiga.

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
