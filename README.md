# dos16re

Reverse-engineering tools for 16-bit real-mode DOS programs. The toolkit is designed for any project in that
scope. The games in [PLAN.md](PLAN.md) are validation targets for particular executable formats and compiler
patterns.

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

When the loader finds a bounded CS-relative word jump table, `map.json` records the dispatch, table,
default branch, and case targets in index order. It uses the `cmp` and `ja` or `jae` guard to size the table.
For adjacent tables in flat overlays, it can infer the original runtime offset from the table's file position.

## Ghidra

Set `GHIDRA_HOME` to your Ghidra installation directory, which contains `support/analyzeHeadless`, and use a JDK
supported by that installation. The importer creates one memory block per unit, names overlay entries and
stubs, and runs Ghidra's auto-analysis. Pass the project path with or without its `.gpr` extension.
The importer marks recovered table words as data, adds computed jump references, and disassembles each case
so auto-analysis can discover the routines they call.

```sh
.venv/bin/dos16re ghidra import out/pool out/pool-project
.venv/bin/dos16re decomp tpov_0025:1036 --project out/pool-project --json
.venv/bin/dos16re ghidra import out/phantasie out/phantasie-project
.venv/bin/dos16re decomp OV1:20bb --project out/phantasie-project --json
```

`decomp` accepts a `unit:offset` or `seg:off` address in an analyzed function. Offset and segment values
are hexadecimal. The JSON response includes the function's entry address and decompiled C.

Run tests with `.venv/bin/python -m pytest`. The real-game tests read Pool of Radiance DOS v1.3 from
`DOS16RE_POR_DIR` and the Phantasie I DOS MZ edition from `DOS16RE_PH1_DIR`. The Ghidra tests also use
`GHIDRA_HOME`. Tests skip when their input variables are unset. See the roadmap for upcoming work.
[PLAN.md](PLAN.md)

## License

MIT, see [LICENSE](LICENSE).
