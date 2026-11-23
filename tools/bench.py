#!/usr/bin/env python3
"""Benchmark headless Ghidra import and query latency, and the launches reversing questions need.

By default the benchmark generates the README's synthetic C64 program, imports it, and times single
queries, batches, and the built-in question scenarios. With --project and --scenarios it measures an
existing analyzed project instead, such as a large DOS overlay program, without importing anything.

A scenario is a question answered in dependent steps. Each step lists queries that need only the
results of earlier steps, so one batch can run them together:

    [{"question": "...", "steps": [[{"command": "decomp", "address": "c000"}, ...], [...]]}]

Each scenario runs with one launch per query, as an agent issuing single commands would, with one
batch per step, and through a persistent worker (retrore.worker): cold (the first question starts the
worker), warm with one batch per step, and warm with one call per query. The CLI measurement times
separate `retrore` processes, with and without a `retrore worker start` daemon.

Requires GHIDRA_HOME. Prints a JSON summary on stdout and progress on stderr.

    .venv/bin/python tools/bench.py --repeat 3 --batch-sizes 1,5,20
    .venv/bin/python tools/bench.py --project PROJECT --scenarios questions.json --repeat 1
"""

import argparse
import contextlib
import io
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from retrore import ghidra, worker
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

# Questions about the synthetic program, answered in dependent steps.
SCENARIOS = [
    {
        "question": "What does the entry routine do, and what does its callee do?",
        "steps": [
            [{"command": "decomp", "address": "c000"}, {"command": "callees", "address": "c000", "compact": True}],
            [{"command": "decomp", "address": "c004"}],
        ],
    },
    {
        "question": "Which routine writes the VIC border color, and how is it reached?",
        "steps": [
            [{"command": "xrefs", "address": "d020", "direction": "incoming", "ref_types": ["WRITE"],
              "compact": True}],
            [{"command": "context", "address": "c006", "compact": True},
             {"command": "callgraph", "address": "c006", "direction": "callers", "compact": True}],
        ],
    },
]


@contextlib.contextmanager
def one_shot():
    """Run queries with one analyzeHeadless launch each, even if a worker is running for the project."""
    saved = os.environ.get("RETRORE_WORKER")
    os.environ["RETRORE_WORKER"] = "0"
    try:
        yield
    finally:
        if saved is None:
            del os.environ["RETRORE_WORKER"]
        else:
            os.environ["RETRORE_WORKER"] = saved


class Counter:
    """Count and time analyzeHeadless launches made through retrore.ghidra, including worker starts."""

    def __init__(self) -> None:
        self._launches = 0
        self.headless_seconds = 0.0
        self._launch = ghidra._launch

    @property
    def launches(self) -> int:
        return self._launches + worker.STARTS

    def __call__(self, *args, **kwargs):
        self._launches += 1
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


def _timed(counter: Counter, call) -> dict:
    before = counter.launches
    started = time.perf_counter()
    report = call()
    return {"seconds": time.perf_counter() - started, "launches": counter.launches - before,
            "output_bytes": len(json.dumps(report).encode())}


def _total(samples: list[dict]) -> dict:
    return {key: sum(sample[key] for sample in samples) for key in ("seconds", "launches", "output_bytes")}


def scenarios(counter: Counter, project: Path, questions: list[dict], repeat: int) -> list[dict]:
    """Answer each question with one launch per query, then with one batch per step."""
    results = []
    for question in questions:
        steps = question["steps"]
        log(f"scenario x{repeat}: {question['question']}")

        def separate() -> dict:
            return _total([_timed(counter, lambda request=request: ghidra.query(project, request))
                           for step in steps for request in step])

        def batched() -> dict:
            return _total([_timed(counter, lambda step=step: ghidra.query_batch(project, step)) for step in steps])

        with one_shot():
            one_shot_separate = [separate() for _ in range(repeat)]
            one_shot_batched = [batched() for _ in range(repeat)]
        with worker.hosting("bench"):
            cold = []
            for _ in range(repeat):
                worker.close_all()
                cold.append(batched())
            warm = [batched() for _ in range(repeat)]
            warm_separate = [separate() for _ in range(repeat)]
        results.append({
            "question": question["question"],
            "queries": sum(map(len, steps)),
            "steps": len(steps),
            "separate": summarize(one_shot_separate),
            "batched": summarize(one_shot_batched),
            "worker_cold": summarize(cold),
            "worker_warm": summarize(warm),
            "worker_warm_separate": summarize(warm_separate),
        })
    return results


def cli_processes(project: Path, requests: list[dict], repeat: int) -> dict:
    """Time separate `retrore` processes per query, one-shot and through a worker daemon."""
    def argv(request: dict) -> list[str]:
        command = [sys.executable, "-m", "retrore", request["command"], request["address"], "--project",
                   str(project), "--json"]
        return command + (["--compact"] if request.get("compact") else [])

    def timed(request: dict, **environment: str) -> dict:
        started = time.perf_counter()
        process = subprocess.run(argv(request), capture_output=True, env={**os.environ, **environment})
        if process.returncode:
            raise SystemExit(f"retrore failed: {process.stderr.decode(errors='replace')}")
        return {"seconds": time.perf_counter() - started, "launches": 0, "output_bytes": len(process.stdout)}

    requests = [request for request in requests if request["command"] in ("decomp", "func", "callers", "callees")]
    log(f"CLI processes x{repeat}")
    report = {"one_shot": summarize([timed(requests[0], RETRORE_WORKER="0") for _ in range(repeat)])}
    started = time.perf_counter()
    worker.start(project)
    report["worker_start_seconds"] = round(time.perf_counter() - started, 3)
    try:
        report["through_daemon"] = summarize([timed(request) for _ in range(repeat) for request in requests])
    finally:
        worker.stop(project)
    return report


def measure_project(project: Path, questions: list[dict], repeat: int, batch_sizes: list[int]) -> dict:
    """Measure scenarios and batch sizes on an existing analyzed project."""
    worker.stop(project)  # A running worker would lock the project against one-shot launches.
    counter = Counter()
    ghidra._launch = counter
    requests = [request for question in questions for step in question["steps"] for request in step]
    batches = {}
    with one_shot():
        for size in batch_sizes:
            log(f"batch of {size} x{repeat}")
            batch = [requests[index % len(requests)] for index in range(size)]
            batches[str(size)] = summarize([_timed(counter, lambda: ghidra.query_batch(project, batch))
                                            for _ in range(repeat)])
    return {"project": project.name, "repeat": repeat, "batch": batches,
            "scenarios": scenarios(counter, project, questions, repeat),
            "cli": cli_processes(project, requests, repeat)}


def benchmark(work: Path, repeat: int, batch_sizes: list[int]) -> dict:
    counter = Counter()
    ghidra._launch = counter
    source, export, project = work / "demo.prg", work / "export", work / "project"
    source.write_bytes(PROGRAM)
    run(counter, ["load", str(source), "--entry", "c000", "-o", str(export), "--json"])

    log("cold import")
    cold_import = run(counter, ["ghidra", "import", str(export), str(project), "--json"])

    log(f"single queries x{repeat}")
    single, warm_single = {}, {}
    for query in QUERIES:
        argv = [query["command"], query["address"], "--project", str(project), "--json"]
        for name in ("limit", "direction"):
            if name in query:
                argv += [f"--{name}", str(query[name])]
        for kind in query.get("ref_types", ()):
            argv += ["--ref-type", kind]
        with one_shot():
            single[query["command"]] = summarize([run(counter, argv) for _ in range(repeat)])
        with worker.hosting("bench"):
            run(counter, argv)  # Start the worker.
            warm_single[query["command"]] = summarize([run(counter, argv) for _ in range(repeat)])
    single_median = statistics.median(entry["median_seconds"] for entry in single.values())

    batches = {}
    with one_shot():
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
        "worker_warm_single_query": warm_single,
        "batch": batches,
        "batch_marginal_seconds_per_query": marginal,
        "separate_launches_for_largest_batch": {
            "launches": largest,
            "estimated_seconds": round(largest * single_median, 3),
        },
        "scenarios": scenarios(counter, project, SCENARIOS, repeat),
        "cli": cli_processes(project, QUERIES, repeat),
    }


def main_bench() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeat", type=int, default=3, help="runs per measurement (default 3)")
    parser.add_argument("--batch-sizes", default="1,5,20", help="comma-separated batch sizes (default 1,5,20)")
    parser.add_argument("--work", type=Path, help="keep the export and project in this new directory")
    parser.add_argument("--project", type=Path, help="measure this existing analyzed project (needs --scenarios)")
    parser.add_argument("--scenarios", type=Path, help="JSON file of questions for --project")
    args = parser.parse_args()
    sizes = sorted({int(size) for size in args.batch_sizes.split(",")})
    if bool(args.project) != bool(args.scenarios):
        parser.error("--project and --scenarios go together")
    if args.project:
        questions = json.loads(args.scenarios.read_text(encoding="utf-8"))
        report = measure_project(args.project, questions, args.repeat, sizes)
    elif args.work:
        args.work.mkdir(parents=True)
        report = benchmark(args.work, args.repeat, sizes)
    else:
        with TemporaryDirectory(prefix="retrore-bench-") as temp:
            report = benchmark(Path(temp), args.repeat, sizes)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main_bench()
