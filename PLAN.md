# dos16re plan

A reverse-engineering toolkit for 16-bit real-mode DOS programs: MZ executables, packers and overlay systems, as
used by 1980s–early-1990s games. It doesn't replace Ghidra's decompiler. It does the parts Ghidra gets wrong or
skips for these programs, then gives Ghidra (and agents driving it) one correct, whole-program image to work on.

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

1. MZ parsing: header, relocations, load at a fixed base segment, entry CS:IP and SS:SP.
2. Unpackers: EXEPACK (Microsoft, documented scheme), then LZEXE 0.91/0.90 and PKLITE as targets need them. Detect
   unknown packers and say so instead of guessing.
3. Overlay systems, each placed at its own segment above the root image:
   - Turbo Pascal overlays (`FBOV`/`TPOV` header, INT 3Fh stubs in the root, stub table → unit file offset, size,
     entry list). Target: PoR `GAME.EXE` + `GAME.OVR`.
   - Plain `.OVR` files loaded by the program itself (INT 21h AX=4B03 or read into a buffer). The user supplies the
     load segment or the loader finds the load call. Target: Phantasie I `OV1.OVR` / `OV2.OVR`.
   - Later, as needed: Borland VROOMM (`FBOV` with C++ stubs), Microsoft LINK overlays (INT 3Fh MS variant),
     .COM programs.
4. Stub rewriting: in the exported image, each overlay stub call becomes a direct far call to the unit's resolved
   segment (the original bytes are kept in the map), so cross-references flow across the root and all overlays.
5. `dos16re load PROGRAM [OVERLAYS...] -o OUT/` writes `image.bin` + `map.json`; `dos16re info` prints the
   segment/unit table.

**Done when:** PoR loads with all 35 units at distinct segments; every stub resolves; addresses hand-resolved in
the Gold Box docs (e.g. stub `0085:0039` → `0x21AED`) come out the same.

### Phase 2: Ghidra import

1. Headless post-script that creates memory blocks per segment/unit, applies `map.json` names, sets entry points,
   and disassembles from them.
2. Name stubs and unit entries; mark rewritten stubs with comments showing the original bytes.
3. `dos16re ghidra import OUT/ PROJECT` wraps `analyzeHeadless`; `dos16re decomp ADDR` prints the decompiled
   function from that project (unit:offset or seg:off accepted).

**Done when:** a PoR or Phantasie function that calls into an overlay shows the callee by name in Ghidra's
decompiler, with no manual fix-ups.

### Phase 3: segment-register tracking

1. Per-function DS/ES/SS inference: DS from the startup code (DGROUP), segment words loaded from DGROUP globals
   (`mov es,[x]` where `[x]` holds a constant segment after init), `push ds / pop es` patterns.
2. Write the results into Ghidra's segment-register context so memory operands resolve to the right far data
   segment, and name far globals by segment (`FAR1820_97f0`).

**Done when:** Phantasie III references to segment `0x1820` resolve to typed globals in Ghidra.

### Phase 4: code recovery

1. Jump-table recovery: CS-relative word tables (`jmp cs:[bx+tbl]`, `shl bx,1` patterns, Turbo Pascal `case`, MSC
   switch). Bounds from the preceding `cmp`/`ja`. Create the target functions and add the references Ghidra lost.
2. Far procedures called as `push cs` + near call (seen in Borland C/C++ code).
3. Report code no analysis reached (`dos16re gaps`), so nothing is silently dropped.

**Done when:** Phantasie Mystic SCORE (OV1 `0x20bb..0x225a`) appears as a function without manual work.

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
| Phantasie I (DOS) | MZ + program-loaded `OV1.OVR`/`OV2.OVR` | Distinct overlay segments, jump-table recovery (Mystic SCORE) |
| Phantasie III (DOS) | MZ, far data segment `0x1820` | Segment tracking, far globals |

Game files are found through `DOS16RE_POR_DIR`, `DOS16RE_PH1_DIR`, `DOS16RE_PH3_DIR`; tests skip when unset.
Unit tests on hand-built tiny MZ/overlay files run everywhere (CI).

## Setup

- Python 3.12+, `pip install capstone unicorn` (in a venv, `.venv/`, gitignored).
- Ghidra 12.x (installed as a snap on the dev machine; `analyzeHeadless` path configurable via `GHIDRA_HOME`).
- `pytest` for tests.

## Order of work

Phase 1 → 2 first: they remove most of the manual address work. Then 4 and 3 (they unblock the Phantasie
targets), then 6 (reuse in the remaster projects), then 5 and 7. After phase 2, try it on a real open question in
one of the remaster projects before going further, and adjust this plan from what that shows.
