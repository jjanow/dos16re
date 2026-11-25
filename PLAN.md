# retrore roadmap

Help LLMs reverse 16-bit real-mode binaries faster and with fewer tokens. Start with a DOS
executable and its overlays, reconstruct the memory layout Ghidra needs, and give the agent a
short answer it can verify at the instruction and, where available, the original file offset.
Mark unknown targets and unavailable source coordinates explicitly. Keep results machine-readable
through the existing JSON CLI and MCP tools.

## Completion target

A shell-capable agent can reproduce the two DOS answers below from a fresh export. Both answers
carry enough evidence for a reviewer to check them against the input. A single benchmark measures
the cost of answering the static question. All three deliverables met their acceptance checks
on 2026-11-25, and the project moved to maintenance.

The loader, Ghidra import, structured traces, evidence queries, and persistent worker already
shipped in [1.0.0](https://github.com/jjanow/retrore/releases/tag/v1.0.0). Use those entry points.
The [README](README.md) documents current capabilities, and the
[validation reference](docs/validation.md) records tested formats and original releases.

## Deliverables

| ID | Deliverable | State | Depends on |
|---|---|---|---|
| DOS-1 | [Reproduce one static cross-overlay call](docs/dos-overlay-call.md) | Complete | None |
| DOS-2 | [Reproduce one observed call from a reused overlay window](docs/dos-overlay-trace.md) | Complete | None |
| DOS-3 | [Measure the cost of the DOS-1 answer](docs/benchmarks.md#static-overlay-call-dos-3) | Complete | DOS-1 |

### DOS-1 · Static cross-overlay call

**Question.** Which routine does the Pool of Radiance DOS v1.3 loot handler call at
`GAME.OVR` file offset `0x65b4`?

**Deliver.** A runnable walkthrough in `docs/dos-overlay-call.md` from `load` through Ghidra import,
a focused JSON query, and `retrore bytes`. Reuse the
[Pool of Radiance tests](tests/test_targets.py) and `RETRORE_POR_DIR`.

**Done when.** The query identifies `tpov_0085:0ab3` at `GAME.OVR` offset `0x21aed`,
and the walkthrough shows how to check the call instruction and its loader rewrite against
the original overlay bytes. Validate the walkthrough from a fresh project on the opt-in release.

### DOS-2 · Observed call from a reused overlay window

**Question.** Which LINK member issues the wilderness encounter call in Phantasie III DOS,
and where is the call instruction in `MAIN.EXE`?

**Deliver.** A runnable walkthrough in `docs/dos-overlay-trace.md` using the decline case of
the [wilderness encounter trace test](tests/test_phantasie_iii_dungeon.py) with `RETRORE_PH3_DIR`.
Use its ordered load manifest and `trace --evidence --json`.

**Done when.** The report shows the observed `link_0003:0239` → `root:de54` call after member 3
replaces the prefix of member 2's window. The caller's reported file offset falls in member 3's
span, and reading `MAIN.EXE` at that offset confirms the original byte. The walkthrough uses the
active trace state and cites the observed edge as evidence.

### DOS-3 · Cost of the static answer

**Deliver.** One reproducible measurement of DOS-1 on its imported Pool of Radiance project.
Compare full, one-shot JSON queries with focused queries on a persistent worker. Reuse
[`tools/bench.py`](tools/bench.py) where it fits.

**Done when.** Both paths return the same callee and the same instruction and file evidence.
Record the exact requests, median query time over three runs per path, Ghidra launch counts, and
total JSON bytes read by the agent. Record worker startup separately. With the worker warm, the
focused path has lower median query time, fewer JSON bytes, and zero Ghidra launches.
Use JSON bytes as a proxy for context size and report them as bytes.

## Maintenance and new work

Maintain documented behavior and shared JSON contracts for supported platforms. Keep the default
suite self-contained and keep original media and anything extracted from it out of the repository.
Add a new deliverable only when a named reversing question has a reproducible blocker and one
check can show that it is resolved. X1turbo bank and device support, PC-98 FAT12 member loading,
and platform-wide feature parity are deferred.

## Last session

2026-11-25. Verified the maintenance baseline with the default suite (522 passed, 156 skipped)
and confirmed that the installed deployment matched the tested commit. DOS-1 through DOS-3
remain complete. Resume with the next reproducible blocker in a named reversing question.
