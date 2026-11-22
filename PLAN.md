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

Real-mode x86 only. 68000 (Amiga, Atari ST, X68000) and 6502 (C64, Apple II) targets are out of scope; Ghidra
handles them well enough.

## Design

- **Python 3 package + CLI** (`dos16re`), standard library plus `capstone` and `unicorn`. Every command can print
  JSON (`--json`) so agents can call it cheaply.
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

1. Per-function DS/ES/SS inference: DS from the startup code (DGROUP), segment words loaded from DGROUP globals
   (`mov es,[x]` where `[x]` holds a constant segment after init), `push ds / pop es` patterns.
2. Write the results into Ghidra's segment-register context so memory operands resolve to the right far data
   segment, and name far globals by segment (`FAR1820_97f0`).

**Done when:** Phantasie III references to segment `0x1820` resolve to typed globals in Ghidra.

### Phase 4: code recovery

1. **Implemented for bounded CS-relative word tables.** Recover case targets from a preceding `cmp` and
   `ja` or `jae` and a scaled 16-bit register index. Infer the runtime offset of adjacent tables in flat
   overlays. The Ghidra importer disassembles case blocks and adds computed jump references, allowing
   auto-analysis to find the routines those blocks call.
2. Far procedures called as `push cs` + near call (seen in Borland C/C++ code).
3. Report code no analysis reached (`dos16re gaps`), so nothing is silently dropped.

**Validated on Ghidra 12.2.** The Phantasie I Mystic dispatcher at `OV1:20a5` has seven computed jump
targets. Auto-analysis finds Mystic SCORE at `OV1:20bb` through a call in one of those cases, and
`dos16re decomp OV1:20bb` returns the function.

### Phase 5: runtime signatures

1. Fingerprints for Turbo Pascal 5.5/6/7, Turbo C 2 / Turbo C++, Borland C++, Microsoft C 5/6 runtime routines
   (byte patterns with wildcards over relocated bytes; learned from known binaries where we have them).
2. Name and type them in Ghidra (Real48 math, string/set helpers, `Write`/`WriteLn`, heap, overlay manager).
3. Compiler detection in `dos16re info`.

### Phase 6: emulator harness

1. Generalize the PoR unicorn harness into a library: load the phase-1 image, call any routine by address with
   registers/memory set up by the caller, run to return, read results back.
2. Traps for INT 10h/16h/21h/1Ah, port I/O (video, sound, timer), and per-address hooks; stub INT 3Fh overlay loads
   since every unit is resident.
3. CLI: `dos16re call ADDR --regs ... --mem ...` for quick oracle checks.
4. Optional: import DOSBox-X debugger traces (CS:IP logs) and map them onto the static image, marking which
   functions ran and listing reached code the static analysis missed.

### Phase 7: agent-facing queries

`xrefs`, `callers`, `callees`, `where-is` (find a byte/string/constant across all units), `func` (bounds, segment
context, callers), all with `--json`. Keep outputs short by default so they fit in an agent's context.

## Test targets

| Target | Format | Checks |
|---|---|---|
| Pool of Radiance (DOS v1.3) | TP6, EXEPACK, `FBOV` overlays | Unit table, stub resolution, addresses listed in the Gold Box RE docs |
| Phantasie I (DOS) | LZEXE 0.90 MZ + program-loaded `OV1.OVR`/`OV2.OVR` | Distinct overlay segments, jump-table recovery (Mystic SCORE) |
| Phantasie III (DOS) | MZ, far data segment `0x1820` | Segment tracking, far globals |

Game files are found through `DOS16RE_POR_DIR` and `DOS16RE_PH1_DIR`. The headless integration test also
uses `GHIDRA_HOME`. The Phase 3 Phantasie III test will use `DOS16RE_PH3_DIR`. Tests skip when their inputs are unset.
Unit tests on hand-built tiny MZ/overlay files run everywhere (CI).

## Setup

- Python 3.12+, `pip install capstone unicorn` (in a venv, `.venv/`, gitignored).
- Ghidra 12.x (installed as a snap on the dev machine; `analyzeHeadless` path configurable via `GHIDRA_HOME`).
- `pytest` for tests.

## Order of work

Phases 1 and 2 are complete for the initial targets, and Phase 4 jump-table recovery is validated on Mystic
SCORE. Next is Phase 3 segment tracking for Phantasie III and the Pool of Radiance LOADPIECES data references.
Then continue with Phase 6 for emulator reuse and Phases 5 and 7 for signatures and queries.
