# dos16re

Standalone reverse-engineering tools for 16-bit real-mode DOS programs. Install and run `dos16re` independently
of any game or remaster project. The games in [PLAN.md](PLAN.md) are optional validation targets for particular
executable formats and compiler patterns.

## DOS loader

The loader restores the original load module from EXEPACK and LZEXE 0.90, 0.91, and 0.91e executables.
It applies segment relocations and records the original initial `CS:IP` and `SS:SP`. Recognized unsupported
packers such as PKLITE produce a diagnostic.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e . pytest
.venv/bin/dos16re info PROGRAM.EXE
.venv/bin/dos16re load PROGRAM.EXE -o out/program --json
.venv/bin/dos16re load START.EXE --overlay GAME.OVR -o out/pool
.venv/bin/dos16re load PHANTASI.EXE --overlay OV1.OVR --overlay OV2.OVR -o out/phantasie
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

## Ghidra

Set `GHIDRA_HOME` to your Ghidra installation directory, which contains `support/analyzeHeadless`, and use a JDK
supported by that installation. The importer creates one memory block per unit, names overlay entries and
stubs, and runs Ghidra's auto-analysis. Pass the project path with or without its `.gpr` extension.
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
.venv/bin/dos16re ghidra import out/pool out/pool-project
.venv/bin/dos16re decomp tpov_0025:1036 --project out/pool-project --json
.venv/bin/dos16re ghidra import out/phantasie out/phantasie-project
.venv/bin/dos16re decomp OV1:20bb --project out/phantasie-project --json
.venv/bin/dos16re gaps --project out/phantasie-project --json
```

`decomp` accepts a `unit:offset` or `seg:off` address in an analyzed function. Offset and segment values
are hexadecimal. The JSON response includes the function's entry address and decompiled C.

`gaps` reports ranges of undefined bytes in the initialized image blocks. These ranges may contain code,
data, or padding. Text output shows the total and the first ten ranges. JSON includes all ranges with
inclusive `unit:offset` endpoints, the starting linear address, and byte counts.

## Emulator harness

`call` runs a routine from an exported image with Unicorn. Each call starts with a fresh copy of the
image and the exported `SS:SP`, which you can override through `--regs`. Supply the data segments,
arguments, and memory the routine expects. The harness pushes a synthetic return frame below the
configured `SP`, so stack arguments start at the configured `SS:SP`. Use `--far` for a routine that
ends in `RETF`. The default is a near `RET`.

```sh
.venv/bin/dos16re call root:1234 --export out/program --regs ax=10,ds=2000 \
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

from dos16re.emulator import Emulator


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

## Tests

Run tests with `.venv/bin/python -m pytest`. The real-game tests read Pool of Radiance DOS v1.3 from
`DOS16RE_POR_DIR`, the Phantasie I DOS MZ edition from `DOS16RE_PH1_DIR`, and Phantasie III's
`MAIN.EXE` from `DOS16RE_PH3_DIR`. The Ghidra tests use `GHIDRA_HOME` and include a synthetic DOS
executable. Tests skip when their input variables are unset. See the roadmap for upcoming work.
[PLAN.md](PLAN.md)

## License

MIT, see [LICENSE](LICENSE).
