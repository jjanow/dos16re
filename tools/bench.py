#!/usr/bin/env python3
"""Benchmark headless Ghidra import and query latency on the README's synthetic C64 program.

Requires GHIDRA_HOME. Prints a JSON summary on stdout and progress on stderr.

    .venv/bin/python tools/bench.py --repeat 3 --batch-sizes 1,5,20
"""

import argparse
import contextlib
import io
import json
import statistics
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from retrore import ghidra
from retrore.cli import main

# The README walkthrough program: JSR $C004, RTS; LDA #$07; STA $D020; RTS.
PROGRAM = bytes.fromhex("00c0 2004c060 a907 8d20d060")
QUERIES = [
    {"command": "callees", "address": "c000", "limit": 1},
    {"command": "decomp", "address": "c004"},
    {"command": "xrefs", "address": "c006", "direction": "outgoing", "ref_types": ["WRITE"], "limit": 1},
    {"command": "func", "address": "c000"},
    {"command": "callers", "address": "c004"},
]


class Counter:
    """Count and time analyzeHeadless launches made through retrore.ghidra."""

    def __init__(self) -> None:
        self.launches = 0
        self.headless_seconds = 0.0
        self._launch = ghidra._launch

    def __call__(self, *args, **kwargs):
        self.launches += 1
        started = time.perf_counter()
        try:
            return self._launch(*args, **kwargs)
        finally:
            self.headless_seconds += time.perf_counter() - started


def run(counter: Counter, argv: list[str], stdin: str | None = None) -> dict:
    out, err = io.StringIO(), io.StringIO()
    before = counter.launches, counter.headless_seconds
    started = time.perf_counter()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        saved = sys.stdin
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            status = main(argv)
        finally:
            sys.stdin = saved
    seconds = time.perf_counter() - started
    if status != 0:
        raise SystemExit(f"retrore {' '.join(argv)} failed with {status}: {err.getvalue() or out.getvalue()}")
    return {
        "seconds": seconds,
        "launches": counter.launches - before[0],
        "headless_seconds": counter.headless_seconds - before[1],
        "output_bytes": len(out.getvalue().encode()),
    }


def summarize(samples: list[dict]) -> dict:
    return {
        "median_seconds": round(statistics.median(sample["seconds"] for sample in samples), 3),
        "min_seconds": round(min(sample["seconds"] for sample in samples), 3),
        "launches": samples[0]["launches"],
        "output_bytes": samples[0]["output_bytes"],
    }


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def benchmark(work: Path, repeat: int, batch_sizes: list[int]) -> dict:
    counter = Counter()
    ghidra._launch = counter
    source, export, project = work / "demo.prg", work / "export", work / "project"
    source.write_bytes(PROGRAM)
    run(counter, ["load", str(source), "--entry", "c000", "-o", str(export), "--json"])

    log("cold import")
    cold_import = run(counter, ["ghidra", "import", str(export), str(project), "--json"])

    log(f"single queries x{repeat}")
    single = {}
    for query in QUERIES:
        argv = [query["command"], query["address"], "--project", str(project), "--json"]
        for name in ("limit", "direction"):
            if name in query:
                argv += [f"--{name}", str(query[name])]
        for kind in query.get("ref_types", ()):
            argv += ["--ref-type", kind]
        single[query["command"]] = summarize([run(counter, argv) for _ in range(repeat)])
    single_median = statistics.median(entry["median_seconds"] for entry in single.values())

    batches = {}
    for size in batch_sizes:
        log(f"batch of {size} x{repeat}")
        requests = json.dumps([QUERIES[index % len(QUERIES)] for index in range(size)])
        batches[str(size)] = summarize([
            run(counter, ["batch", "--project", str(project), "--json"], stdin=requests) for _ in range(repeat)
        ])
    smallest, largest = min(batch_sizes), max(batch_sizes)
    marginal = None
    if largest > smallest:
        marginal = round(
            (batches[str(largest)]["median_seconds"] - batches[str(smallest)]["median_seconds"])
            / (largest - smallest), 3)

    return {
        "program": "README synthetic C64 PRG (13 bytes)",
        "repeat": repeat,
        "cold_import": {key: round(value, 3) if isinstance(value, float) else value for key, value in cold_import.items()},
        "single_query": single,
        "single_query_median_seconds": round(single_median, 3),
        "batch": batches,
        "batch_marginal_seconds_per_query": marginal,
        "separate_launches_for_largest_batch": {
            "launches": largest,
            "estimated_seconds": round(largest * single_median, 3),
        },
    }


def main_bench() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeat", type=int, default=3, help="runs per measurement (default 3)")
    parser.add_argument("--batch-sizes", default="1,5,20", help="comma-separated batch sizes (default 1,5,20)")
    parser.add_argument("--work", type=Path, help="keep the export and project in this new directory")
    args = parser.parse_args()
    sizes = sorted({int(size) for size in args.batch_sizes.split(",")})
    if args.work:
        args.work.mkdir(parents=True)
        report = benchmark(args.work, args.repeat, sizes)
    else:
        with TemporaryDirectory(prefix="retrore-bench-") as temp:
            report = benchmark(Path(temp), args.repeat, sizes)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main_bench()
