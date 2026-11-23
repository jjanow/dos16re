# Headless Ghidra benchmarks

`tools/bench.py` generates the README's [synthetic C64 program](../README.md#try-a-synthetic-program),
imports it into a fresh project, and times the CLI entry points in process. It counts
`analyzeHeadless` launches, records JSON output sizes, and prints a JSON summary.

```sh
GHIDRA_HOME=/path/to/ghidra .venv/bin/python tools/bench.py --repeat 3 --batch-sizes 1,5,20
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

## Is a persistent worker justified?

A persistent worker isn't needed while queries can be batched. Batching already amortizes almost
all of the fixed cost.

A worker would help in one case: an agent that asks one dependent question at a time, where each
answer picks the next address. There, every step pays about 3.4 s of launch overhead for 15 to
100 ms of work.

Reconsider a worker, or a cache keyed on project and request, if these conditions hold:

- traces show long chains of single queries that cannot be batched;
- the per-launch cost on real projects is much higher than for this 13-byte program.

Large DOS projects with many overlays take longer to open. Measure one with `tools/bench.py`
adapted to that export before deciding.
