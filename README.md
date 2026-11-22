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

## Ghidra

Set `GHIDRA_HOME` to your Ghidra installation directory, which contains `support/analyzeHeadless`, and use a JDK
supported by that installation. The importer creates one memory block per unit, names overlay entries and
stubs, and runs Ghidra's auto-analysis. Pass the project path with or without its `.gpr` extension.
The importer marks recovered table words as data, adds computed jump references, and disassembles each case
so auto-analysis can discover the routines they call.

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
```

`decomp` accepts a `unit:offset` or `seg:off` address in an analyzed function. Offset and segment values
are hexadecimal. The JSON response includes the function's entry address and decompiled C.

Run tests with `.venv/bin/python -m pytest`. The real-game tests read Pool of Radiance DOS v1.3 from
`DOS16RE_POR_DIR`, the Phantasie I DOS MZ edition from `DOS16RE_PH1_DIR`, and Phantasie III's
`MAIN.EXE` from `DOS16RE_PH3_DIR`. The Ghidra tests use `GHIDRA_HOME` and include a synthetic DOS
executable. Tests skip when their input variables are unset. See the roadmap for upcoming work.
[PLAN.md](PLAN.md)

## License

MIT, see [LICENSE](LICENSE).
