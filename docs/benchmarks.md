# Headless Ghidra benchmarks

`tools/bench.py` generates the README's [synthetic C64 program](../README.md#try-a-synthetic-program),
imports it into a fresh project, and times the CLI entry points in process. It counts
`analyzeHeadless` launches, records JSON output sizes, and prints a JSON summary.

```sh
GHIDRA_HOME=/path/to/ghidra .venv/bin/python tools/bench.py --repeat 3 --batch-sizes 1,5,20
```

It also answers question scenarios. A scenario is a reversing question split into dependent steps.
Each step's queries need only earlier results, so one batch can run them together. Every scenario
runs with one launch per query and with one batch per step. It then runs through a
[persistent worker](../README.md#persistent-query-workers): cold, where the question starts the
worker, and warm, both with one batch per step and with one call per query. Worker starts count as
launches. The `cli` entry times separate `retrore` processes, one-shot and through a
`retrore worker start` daemon. `--project` and `--scenarios FILE` measure an existing analyzed
project with questions written for it:

```sh
.venv/bin/python tools/bench.py --project out/por-project --scenarios questions.json --repeat 3
```

## Results, 2026-11-22

Linux, 16 cores, Ghidra 12.2 (snap), Python 3.14. Medians of 3 runs at a system load of about 3.

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

## Persistent worker, 2026-11-22

Same machine and Ghidra, load average about 1.5–2, medians of 3 runs. The worker columns use
`retrore.worker` in process, as `retrore mcp` does. Cold starts the worker inside the question, and
warm reuses a running one.

Synthetic program:

| Question | One launch per query | One batch per step | Worker, cold | Worker, warm (batch per step) | Worker, warm (call per query) |
|---|---|---|---|---|---|
| Entry routine and its callee (3 queries, 2 steps) | 10.1 s, 3 launches | 6.9 s, 2 launches | 3.46 s, 1 launch | 5 ms | 4 ms |
| VIC border writer and how it is reached (3 queries, 2 steps) | 9.6 s, 3 launches | 6.4 s, 2 launches | 3.21 s, 1 launch | 2 ms | 2 ms |

A single query through a warm worker takes 6–8 ms, against 3.2–3.5 s with its own launch.

Pool of Radiance (36 units), with query addresses from the tested export.

| Question | One launch per query | One batch per step | Worker, cold | Worker, warm (batch per step) | Worker, warm (call per query) |
|---|---|---|---|---|---|
| Heap allocation: callers of `System_GetMem`, then decompilation and call context of two callers (5 queries, 3 steps) | 18.7 s, 5 launches | 11.1 s, 3 launches | 3.94 s, 1 launch | 26 ms | 20 ms |
| Overlay unit `tpov_0085`: inventory, then one routine's decompilation and callers graph (3 queries, 2 steps) | 11.2 s, 3 launches | 7.7 s, 2 launches | 4.08 s, 1 launch | 104 ms | 99 ms |
| `Overlay_OvrInit`: decompilation and callers, then the caller's context and decompilation (4 queries, 2 steps) | 15.2 s, 4 launches | 7.9 s, 2 launches | 4.03 s, 1 launch | 112 ms | 65 ms |

Output is the same JSON whichever way the queries run. A cold question costs one launch, about 4 s.
After that a question costs its analysis time, 20–110 ms here, mostly decompilation. Per-query calls
through a warm worker are as fast as batches, so an agent can ask one query at a time without paying
for it.

Separate CLI processes, as a shell user or a coding agent issuing commands runs them:

| Project | One-shot `retrore` query | `retrore worker start` | Query through the daemon |
|---|---|---|---|
| Synthetic | 3.28 s | 3.41 s | 0.096 s |
| Pool of Radiance | 3.76 s | 3.81 s | 0.110 s |

Through the daemon a CLI query costs Python startup plus the query, about 0.1 s.

## Persistent worker impact

The worker reuses one Ghidra session across dependent steps. The Pool of Radiance scenarios took
11–19 s with a launch per query, 8–11 s with a launch per batch, about 4 s with a cold worker, and
0.03–0.11 s with a warm worker.
