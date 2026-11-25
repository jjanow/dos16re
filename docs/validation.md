# Validation reference

The default suite uses synthetic inputs. The [README test instructions](../README.md#tests) name
the inputs and environment variables for opt-in validation. Original media and captures stay
outside the repository. See the [roadmap](../PLAN.md) for current deliverables.

## Representative releases

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
| Pool of Radiance v1.1 and Secret of the Silver Blades (Classic Macintosh) | Near-model 68k, CODE segments and THINK C A5 world | A5 jump entries, runtime fixups, indexed startup transfer |
| Pool of Radiance (NES and Famicom) | U.S. and Japanese NES 2.0 cartridges | MMC3 bank placement and file provenance, hardware vectors, Ghidra startup and IRQ analysis |
| Buck Rogers: Countdown to Doomsday (Genesis) | U.S./Europe linear Mega Drive ROM, odd-lane cartridge SRAM | ROM and vector provenance, startup and VBlank analysis, video and SRAM references |

## DOS reversing checks

- Pool of Radiance DOS v1.3 exports 35 Turbo Pascal overlay units and resolves 406 stubs.
  The loot handler's call at `GAME.OVR` file offset `0x65b4` reaches `tpov_0085:0ab3`
  at file offset `0x21aed`. Ghidra decompiles the call after import.
  [Regression checks](../tests/test_targets.py)
- Phantasie I DOS loads two flat overlays at distinct analysis addresses. Ghidra recovers seven
  switch targets at `OV1:20a5` and decompiles Mystic SCORE at `OV1:20bb`. The routine harness
  executes the revive routine with a supplied character record.
  [Regression checks](../tests/test_targets.py)
- Phantasie III DOS checks segment context for far globals and reports possible stores to 12-byte
  software FPU records. Original execution probes exercise arithmetic, comparisons, stores, and
  software interrupt continuations. Opt-in playthroughs record menu, archives, and wilderness
  transfers and check file offsets after a LINK member replaces the previous member's window.
  The heap probe verifies that a tile reader's instruction has file provenance while the heap
  address exists only at runtime.
  [Segment checks](../tests/test_segments.py) · [Playthrough and heap checks](../tests/test_phantasie_iii_dungeon.py)

## Runtime signature validation

The signatures come from original toolchains and purpose-built DOS probes. The Pascal probe
uses `Overlay`, adds two `Real` values, copies and concatenates short strings, unions two `set of byte`
values, writes text, and allocates and frees a block. The C probe calls `strcpy`, `strlen`, `puts`, `printf`,
`malloc`, and `free` and uses linker map symbols to verify matches. The Microsoft 6.0a probe links a 5.1
object against its 6.0a DOS runtime library.
[Turbo Pascal 5.5](https://altd.embarcadero.com/download/museum/tp55.zip),
[Turbo Pascal 6.0](https://sources.ru/pascal/museum/tp60.htm), [Turbo Pascal 7.0](https://winworldpc.com/product/turbo-pascal/7x),
[Turbo C 2.01](https://altd.embarcadero.com/download/museum/tc201.zip),
[Turbo C++ 1.01](https://altd.embarcadero.com/download/museum/tcpp101.zip), [Borland C++ 2.0](https://winworldpc.com/product/borland-c/20),
[Microsoft C 5.x](https://winworldpc.com/product/microsoft-c-c/5x), [Microsoft C 6.x](https://winworldpc.com/product/microsoft-c-c/6x).

**Validated with Microsoft Pascal 3.20.** LINK 2.40 and 2.45 place all three helpers at different
addresses. Both builds print `VALUE 42` in DOSBox, and Ghidra 12.2 decompiles the main routine
with calls to file initialization, heap allocation, and newline output under their original names.
The relocation-backed `ENTXQQ` entry identifies the runtime family. The overlay probes reach it
through a relocated far jump. The loader reports the fixed DGROUP copy bounds, selector bias,
maximal shift, and new stack offset. Unicorn verified the resulting DS and SS and the relocated
string literal under two DOS allocation limits per build. Ghidra preserves frame-helper calls and
marks their inline local size words as data, with fall-through at the following instruction.
A call fixup uses each inline size to model BP and SP on the normal return path. The decompiler
recovers the heap routine's argument and local stack slot on both LINK builds. With an explicit
capture, Ghidra maps the copied bytes at their runtime addresses and propagates DS and SS from
the recognized startup switch. The LINK 2.40 probe validated overlapping source and destination
ranges, and the LINK 2.45 probe validated the capped shift. The relocated DGROUP copy
corroborates version 3.20. An `ENTXQQ` prefix with no matching copy reports only the family.
[Probe build steps](../README.md#microsoft-pascal-runtime-probe)

**Validated with Microsoft Pascal 3.30.** LINK 3.02 maps the entry to `__astart`. Its relocated
DGROUP selector and stack setup, Pascal initializer table loop, and far calls distinguish it
from 3.20. The same evidence identifies the empty program and a build linked with `LVARSTCK.OBJ`.
The 3.20 DGROUP copy and inline frame size handling remain specific to their original patterns.
[Probe build steps](../README.md#microsoft-pascal-330-probes)

## Loader and overlay validation

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
start at the window.
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
all three stayed loaded. [Probe build steps](../README.md#microsoft-move-heap-probe)
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

## Earlier development notes

The pre-refocus plan remains available in Git with detailed code recovery audits, measurements,
and per-platform import results.

```sh
git show 790f410:PLAN.md
```
