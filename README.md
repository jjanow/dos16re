# retrore

Standalone reverse-engineering tools for 16-bit real-mode DOS programs, AmigaDOS Hunk executables,
Atari ST GEMDOS executables, Commodore 64 PRGs, Apple II binaries, and Atari 8-bit executables.
Install and run `retrore` independently of any game or remaster project. The games in [PLAN.md](PLAN.md)
are optional validation targets for particular executable formats and compiler patterns.

## DOS loader

The loader restores the original load module from EXEPACK and LZEXE 0.90, 0.91, and 0.91e executables.
It applies segment relocations and records the original initial `CS:IP` and `SS:SP`. Recognized unsupported
packers such as PKLITE produce a diagnostic.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e . pytest
.venv/bin/retrore info PROGRAM.EXE
.venv/bin/retrore load PROGRAM.EXE -o out/program --json
.venv/bin/retrore load START.EXE --overlay GAME.OVR -o out/pool
.venv/bin/retrore load PHANTASI.EXE --overlay OV1.OVR --overlay OV2.OVR -o out/phantasie
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

`map.json` identifies hunks as `h0`, `h1`, and so on. Each unit records its file span and memory
allocation, symbols, and applied absolute 32-bit relocations, including the compact variant. Ghidra
uses its big-endian 68k language, imports the symbols, and analyzes from the executable's entry in
`h0`. Amiga Ghidra queries accept `hN:offset` or a flat hexadecimal address. `HUNK_OVERLAY` files
produce an unsupported-format diagnostic. The `call` and `trace` commands are DOS-specific.
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

## Ghidra

Set `GHIDRA_HOME` to your Ghidra installation directory, which contains `support/analyzeHeadless`, and use a JDK
supported by that installation. Pass the project path with or without its `.gpr` extension.

For DOS, the importer creates one memory block per unit, names overlay entries and stubs, and runs
Ghidra's auto-analysis.
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

## Program queries

```sh
.venv/bin/retrore xrefs OV1:20bb --project out/phantasie-project --json
.venv/bin/retrore callers OV1:20bb --project out/phantasie-project
.venv/bin/retrore callees OV1:20bb --project out/phantasie-project
.venv/bin/retrore func OV1:20bb --project out/phantasie-project --json
.venv/bin/retrore where-is --export out/phantasie --bytes 'b8 00 4c'
.venv/bin/retrore where-is --export out/phantasie --string 'Mystic'
.venv/bin/retrore where-is --export out/phantasie --constant 0x1234 --width 2 --json
```

`xrefs` reports incoming and outgoing references Ghidra recorded at the exact address, including code and
data references. `callers` and `callees` accept any address inside an analyzed function and list individual
resolved call sites. Callers target the function entry. JSON includes the source and target addresses,
reference type, operand index, and enclosing functions when available.

`func` reports the function entry, inclusive body ranges, total body size in bytes, and callers. For DOS
it gives Ghidra's DS, ES, and SS values at the requested address. Unknown values appear as `?` in text
and `null` in JSON.

`where-is` searches relocated, file-backed bytes in the export. Matches can overlap and must fit
within a unit's file-backed span. `--string` uses DOS CP437, Amiga Latin-1, or Atari ST ASCII. Use
`--bytes` to search for Atari ST text containing bytes above `0x7f`.
`--constant` accepts a decimal or `0x`-prefixed integer and encodes it in the platform's byte order
at the specified width (1, 2, 4, or 8 bytes, default 2).

Text output previews up to ten references or matches. Use `--json` for the full results with
`unit:offset` and linear addresses where available. Ghidra queries also report the address as
displayed by the analyzed project.

## Emulator harness

`call` runs a routine from an exported image with Unicorn. Each call starts with a fresh copy of the
image and the exported `SS:SP`, which you can override through `--regs`. Supply the data segments,
arguments, and memory the routine expects. The harness pushes a synthetic return frame below the
configured `SP`, so stack arguments start at the configured `SS:SP`. Use `--far` for a routine that
ends in `RETF`. The default is a near `RET`.

```sh
.venv/bin/retrore call root:1234 --export out/program --regs ax=10,ds=2000 \
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

## Tests

Run tests with `.venv/bin/python -m pytest`. The real-game tests read Pool of Radiance DOS v1.3 from
`RETRORE_POR_DIR`, the Phantasie I DOS MZ edition from `RETRORE_PH1_DIR`, and Phantasie III's
`MAIN.EXE` from `RETRORE_PH3_DIR`. Point `RETRORE_PH1_AMIGA_DIR` and `RETRORE_PH3_AMIGA_DIR` to
the extracted Amiga directories containing `game` and `PhantasieIII` respectively. Set
`RETRORE_PH2_ST_DIR` to the extracted Phantasie II v1.0 Atari ST disk directory with `PHANT.PRG` and
`UTILIT2.PRG`. Set `RETRORE_PH1_C64_DIR` to the directory containing
`Phantasie_I_1986_SSI_Side_A.d64`. Set `RETRORE_PH1_APPLE2_DIR` to the directory containing
`phantasie1-4am-side-a-boot.dsk` and `RETRORE_PH3_APPLE2_DIR` to the directory containing
`Phantasie_III_1987_SSI_cr_Disk_1_of_3_Side_A.dsk`. Point `RETRORE_PH1_ATARI8_DIR` and
`RETRORE_PH2_ATARI8_DIR` to directories containing `phantasie1-side-{a,b}.atr` and
`phantasie2-side-{a,b}.atr` respectively. The Ghidra tests use `GHIDRA_HOME` and include synthetic
DOS, Amiga, Atari ST, C64, Apple II, and Atari 8-bit programs. Tests skip when their input variables are unset.
See the roadmap for upcoming work.
[PLAN.md](PLAN.md)

## License

MIT, see [LICENSE](LICENSE).
