# Headless Ghidra benchmarks

`tools/bench.py` generates the README's [synthetic C64 program](../README.md#try-a-synthetic-program),
imports it into a fresh project, and times the CLI entry points in process. It counts
`analyzeHeadless` launches, records JSON output sizes, and prints a JSON summary.

```sh
GHIDRA_HOME=/path/to/ghidra .venv/bin/python tools/bench.py --repeat 3 --batch-sizes 1,5,20
```

It also answers question scenarios. A scenario is a reversing question split into dependent steps.
Each step's queries need only earlier results, so one batch can run them together. Every scenario
runs twice, once with one launch per query and once with one batch per step. `--project` and
`--scenarios FILE` measure an existing analyzed project with questions written for it:

```sh
.venv/bin/python tools/bench.py --project out/por-project --scenarios questions.json --repeat 3
```

## Results, 2026-11-22

Linux, 16 cores, Ghidra 12.2 (snap), Python 3.14. Medians of 3 runs. Other agents were running
headless Ghidra on the same machine at the time (load average about 3), so expect some noise.

| Measurement | Wall time | Launches | JSON output |
|---|---|---|---|
| Cold import and analysis | 4.84 s | 1 | 83 B |
| Single `callees` query | 3.54 s | 1 | 651 B |
| Single `decomp` query | 3.69 s | 1 | 191 B |
| Single `xrefs` query | 3.43 s | 1 | 519 B |
| Single `func` query | 3.55 s | 1 | 410 B |
| Single `callers` query | 3.58 s | 1 | 561 B |
| Batch of 1 | 3.39 s | 1 | 719 B |
| Batch of 5 | 3.68 s | 1 | 2,550 B |
| Batch of 20 | 3.68 s | 1 | 10,113 B |

- Each launch costs about 3.4 s before any query runs. That covers JVM and Ghidra startup, opening
  the project, and loading the query script. Ghidra caches compiled scripts, so only the first
  launch after a script changes pays to compile it.
- Within a launch, queries are warm: each extra query in a batch costs about 15 ms,
  (3.677 s − 3.390 s) / 19. Every separate command is a cold start that pays the full launch cost again.
- Running the 20 batched queries as separate commands would take about 71 s and 20 launches.
  The batch takes 3.7 s and 1 launch.
- Batch output is about 500 bytes per query here. It grows with decompiled C size and reference
  counts. Use `fields`, `limit`, and `compact` to cut it down.

The built-in scenarios on the synthetic program, 2026-11-22, medians of 3:

| Question | Queries | Steps | One launch per query | One batch per step |
|---|---|---|---|---|
| What does the entry routine do, and what does its callee do? | 3 | 2 | 10.7 s | 7.2 s |
| Which routine writes the VIC border color, and how is it reached? | 3 | 2 | 10.1 s | 6.8 s |

## Large overlay project, 2026-11-22

Pool of Radiance `START.EXE` with `GAME.OVR`: 266 KiB image, 36 units (root and 35 overlay units),
406 stubs, 1,454 stored symbols. Import and analysis took 16 s. Same machine and Ghidra, load average
about 2, medians of 3 runs.

| Measurement | Wall time | Launches | JSON output |
|---|---|---|---|
| Batch of 1 | 4.13 s | 1 | 4,251 B |
| Batch of 5 | 4.37 s | 1 | 12,059 B |
| Batch of 20 | 4.48 s | 1 | 44,625 B |

A launch on this project costs about 4.1 s, against 3.4 s for the 13-byte program, and each extra
query in a batch about 18 ms. Opening a much larger project adds little to the launch cost.

The three questions below use real PoR addresses. The question file stays outside the repository
with the game.

| Question | Queries | Steps | One launch per query | One batch per step |
|---|---|---|---|---|
| What does the overlay View routine do, and what does one caller do around the call? | 4 | 2 | 16.3 s, 4 launches | 8.4 s, 2 launches |
| What does overlay unit `tpov_0085` contain, and which units reach its entry? | 3 | 2 | 11.7 s, 3 launches | 7.9 s, 2 launches |
| Which routines allocate heap blocks, and what do the first two callers do? | 4 | 3 | 16.1 s, 4 launches | 11.9 s, 3 launches |

Batching halves the time at best, but it cannot remove the dependent steps. Each question still
needs two or three launches, and the analysis inside them takes about 0.1 s. Output size is the
same either way, about 2–3 KB per query here.

## Is a persistent worker justified?

Yes, for dependent questions. Batching already amortizes the fixed cost for independent queries,
and it stays the right shape for the queries within one step. But typical questions need two or
three dependent steps, where each answer picks the next address. Each step pays about 4 s to launch
Ghidra for about 0.1 s of work.

The first synthetic measurement left two conditions for reconsidering a worker. The first one now
holds: the PoR questions are chains of steps that batching cannot merge. The second does not:
opening a 36-unit project costs only about 0.7 s more than the 13-byte program. Launch overhead
dominates either way. A worker that keeps a project open would cut a three-step question from about
12 s to one 4 s open plus well under a second, and later questions would skip the open as well.
