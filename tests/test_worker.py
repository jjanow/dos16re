"""Persistent query workers, using a fake analyzeHeadless that speaks the serve protocol."""

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from retrore import ghidra, worker
from retrore.cli import main
from retrore.errors import CONTRACT_VERSION
from retrore.ghidra import GhidraError, cancellable
from test_errors import _wait_dead

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the fake launcher is a POSIX script")

PACKAGE_PATH = Path(ghidra.__file__).resolve().parents[1]

# Every launch appends its kind to FAKE_LAUNCHES. Serve launches connect back to the worker manager and
# answer requests; the address selects a behavior. One-shot launches write a result marked "oneshot".
_FAKE = """#!{python}
import json, os, socket, sys, time
args = sys.argv[1:]
serve = "serve" in args
with open(os.environ["FAKE_LAUNCHES"], "a") as launches:
    launches.write(("serve" if serve else "oneshot") + "\\n")
if not serve:
    if "RetroreGaps.java" in args:
        report = {{"program": "image.bin", "ranges": [], "undefined_bytes": 0, "oneshot": True}}
    else:
        mode, request = args[-3], json.load(open(args[-2]))
        if mode == "batch":
            report = {{"results": [{{"result": {{"echo": item, "oneshot": True}}}} for item in request]}}
        else:
            report = {{"echo": request, "oneshot": True}}
    with open(args[-1], "w") as result:
        json.dump(report, result)
    sys.exit(0)
behavior = os.environ.get("FAKE_WORKER", "ok")
with open(os.environ["FAKE_WORKER_PID"], "w") as pid_file:
    pid_file.write(str(os.getpid()))
if behavior == "locked":
    print("ERROR Abort due to error: ghidra.framework.store.LockException: Unable to lock project!")
    sys.exit(1)
if behavior == "broken":
    print("ERROR serve mode is broken")
    sys.exit(1)
if behavior == "hang":
    time.sleep(300)
print("INFO starting", flush=True)
channel = socket.create_connection(("127.0.0.1", int(args[args.index("serve") + 1])))
stream = channel.makefile("rw", encoding="utf-8")
stream.write(json.dumps({{"token": os.environ["RETRORE_WORKER_TOKEN"], "program": "image.bin"}}) + "\\n")
stream.flush()
for line in stream:
    request = json.loads(line)
    mode, payload = request["mode"], request.get("input")
    if mode == "shutdown":
        break
    address = payload.get("address") if isinstance(payload, dict) else None
    response = {{"id": request["id"]}}
    if address == "aaaa":
        time.sleep(300)
    elif address == "dddd":
        os._exit(3)
    elif address == "cccc":
        response["crash"] = "NullPointerException"
    elif address == "bad":
        response["report"] = {{"error": {{"code": "address_not_found", "message": "unknown unit bad"}}}}
    elif mode == "gaps":
        response["report"] = {{"program": "image.bin", "ranges": [], "undefined_bytes": 0, "pid": os.getpid()}}
    elif mode == "batch":
        response["report"] = {{"results": [{{"result": {{"echo": item, "pid": os.getpid()}}}} for item in payload]}}
    else:
        response["report"] = {{"echo": payload, "pid": os.getpid()}}
    stream.write(json.dumps(response) + "\\n")
    stream.flush()
"""


class Fake:
    def __init__(self, tmp_path: Path, monkeypatch) -> None:
        support = tmp_path / "ghidra" / "support"
        support.mkdir(parents=True)
        launcher = support / "analyzeHeadless"
        launcher.write_text(_FAKE.format(python=sys.executable), encoding="utf-8")
        launcher.chmod(0o755)
        self.launch_log = tmp_path / "launches.txt"
        self.pid_file = tmp_path / "worker.pid"
        self.project = tmp_path / "demo.gpr"
        self.project.write_text("", encoding="utf-8")
        self.monkeypatch = monkeypatch
        monkeypatch.setenv("GHIDRA_HOME", str(tmp_path / "ghidra"))
        monkeypatch.setenv("FAKE_LAUNCHES", str(self.launch_log))
        monkeypatch.setenv("FAKE_WORKER_PID", str(self.pid_file))
        monkeypatch.setattr(ghidra, "_KILL_GRACE", 1)
        monkeypatch.setattr(worker, "STOP_GRACE", 2)

    def behave(self, behavior: str) -> None:
        self.monkeypatch.setenv("FAKE_WORKER", behavior)

    @property
    def launches(self) -> list[str]:
        return self.launch_log.read_text().split() if self.launch_log.exists() else []

    def worker_pid(self) -> int:
        deadline = time.monotonic() + 15
        while not (self.pid_file.exists() and self.pid_file.read_text()):
            assert time.monotonic() < deadline, "the fake worker did not start"
            time.sleep(0.05)
        return int(self.pid_file.read_text())


@pytest.fixture
def fake(tmp_path, monkeypatch):
    fake = Fake(tmp_path, monkeypatch)
    yield fake
    worker.stop_all()


@pytest.fixture
def hosted(fake):
    with worker.hosting("test"):
        yield fake


def test_one_launch_answers_every_mode_with_the_one_shot_contract(hosted):
    request = {"command": "func", "address": "c000"}
    single = ghidra.query(hosted.project, request)
    assert single["contract"] == CONTRACT_VERSION and single["echo"]["command"] == "func"
    batch = ghidra.query_batch(hosted.project, [request, {"command": "callers", "address": "c004", "limit": 2}])
    assert batch["contract"] == CONTRACT_VERSION
    assert [row["command"] for row in batch["results"]] == ["func", "callers"]
    assert batch["results"][1]["address"] == "c004" and "pid" in batch["results"][1]["result"]
    gaps = ghidra.analysis_gaps(hosted.project)
    assert gaps == {"contract": CONTRACT_VERSION, "program": "image.bin", "ranges": [], "undefined_bytes": 0,
                    "pid": single["pid"]}
    trace = ghidra.trace_coverage(hosted.project, {"sha256": "00", "units": []})
    assert "contract" not in trace and trace["echo"] == {"sha256": "00", "units": []}
    assert hosted.launches == ["serve"]
    record = worker.status(hosted.project)
    assert record["ghidra"] == "ready" and record["requests"] == 4 and record["owner"] == "test"


def test_script_errors_keep_their_codes_and_the_worker(hosted):
    with pytest.raises(GhidraError) as caught:
        ghidra.query(hosted.project, {"command": "func", "address": "bad"})
    assert caught.value.code == "address_not_found" and str(caught.value) == "unknown unit bad"
    ghidra.query(hosted.project, {"command": "func", "address": "c000"})
    assert hosted.launches == ["serve"]


def test_timeout_stops_the_worker_and_the_next_request_restarts_it(hosted):
    ghidra.query(hosted.project, {"command": "func", "address": "c000"})
    first = hosted.worker_pid()
    started = time.monotonic()
    with pytest.raises(GhidraError) as caught:
        ghidra.query(hosted.project, {"command": "func", "address": "aaaa"}, timeout=2)
    assert time.monotonic() - started < 15
    assert caught.value.code == "timeout"
    assert str(caught.value).startswith("Ghidra RetroreQuery.java exceeded the 2 second time budget after ")
    assert str(caught.value).endswith("; the headless process group was stopped")
    _wait_dead(first)
    hosted.pid_file.unlink()
    assert ghidra.query(hosted.project, {"command": "func", "address": "c000"})["pid"] == hosted.worker_pid()
    assert hosted.launches == ["serve", "serve"]


def test_budget_covers_the_worker_start(hosted):
    hosted.behave("hang")
    with pytest.raises(GhidraError) as caught:
        ghidra.query(hosted.project, {"command": "func", "address": "c000"}, timeout=1)
    assert caught.value.code == "timeout"
    _wait_dead(hosted.worker_pid())


def test_cancellation_stops_the_worker(hosted):
    ghidra.query(hosted.project, {"command": "func", "address": "c000"})
    event = threading.Event()
    threading.Timer(1, event.set).start()
    with cancellable(event), pytest.raises(GhidraError) as caught:
        ghidra.query(hosted.project, {"command": "func", "address": "aaaa"})
    assert caught.value.code == "cancelled"
    _wait_dead(hosted.worker_pid())


@pytest.mark.parametrize("address", ["cccc", "dddd"])
def test_a_request_the_worker_cannot_answer_runs_one_shot(hosted, address):
    report = ghidra.query(hosted.project, {"command": "func", "address": address})
    assert report["oneshot"] is True and report["echo"]["address"] == address
    assert hosted.launches == ["serve", "oneshot"]
    ghidra.query(hosted.project, {"command": "func", "address": "c000"})
    assert hosted.launches == ["serve", "oneshot", "serve"]


def test_a_worker_that_cannot_start_falls_back_to_one_shot(hosted):
    hosted.behave("broken")
    for _ in range(2):
        assert ghidra.query(hosted.project, {"command": "func", "address": "c000"})["oneshot"] is True
    # The failed start pauses worker launches instead of paying for them on every request.
    assert hosted.launches == ["serve", "oneshot", "oneshot"]


def test_a_locked_project_is_reported_without_a_second_launch(hosted):
    hosted.behave("locked")
    with pytest.raises(GhidraError) as caught:
        ghidra.query(hosted.project, {"command": "func", "address": "c000"})
    assert caught.value.code == "project_locked"
    assert hosted.launches == ["serve"]


def test_retrore_worker_0_disables_workers(hosted, monkeypatch):
    monkeypatch.setenv("RETRORE_WORKER", "0")
    assert ghidra.query(hosted.project, {"command": "func", "address": "c000"})["oneshot"] is True
    assert hosted.launches == ["oneshot"]


def test_idle_timeout_stops_the_worker(fake):
    host = worker.Host(fake.project, owner="test", idle=1)
    try:
        host.warm()
        pid = fake.worker_pid()
        assert host.closed.wait(15)
        _wait_dead(pid)
        assert not worker._paths(worker.project_key(fake.project))["sock"].exists()
    finally:
        host.close()


def _environment(**extra: str) -> dict:
    return {**os.environ, "PYTHONPATH": str(PACKAGE_PATH), **extra}


def test_cli_queries_reuse_a_daemon_and_import_stops_it(fake, capsys):
    project = str(fake.project)
    assert main(["worker", "status", "--project", project, "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"contract": CONTRACT_VERSION, "running": False}
    assert main(["worker", "start", "--project", project, "--json"]) == 0
    started = json.loads(capsys.readouterr().out)
    assert started["running"] and started["started"] and started["owner"] == "daemon"
    daemon, jvm = started["pid"], fake.worker_pid()
    assert started["ghidra_pid"] == jvm

    for _ in range(2):
        assert main(["func", "c000", "--project", project, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["pid"] == jvm
    # A separate process reaches the same worker.
    child = subprocess.run([sys.executable, "-m", "retrore", "gaps", "--project", project, "--json"],
                           capture_output=True, text=True, env=_environment(), check=True, timeout=60)
    assert json.loads(child.stdout)["pid"] == jvm
    assert main(["worker", "start", "--project", project, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["started"] is False
    assert fake.launches == ["serve"]

    # A budget that expires stops the daemon's Ghidra process, and the daemon starts a new one.
    assert main(["func", "aaaa", "--project", project, "--timeout", "2", "--json"]) == 1
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "timeout"
    _wait_dead(jvm)
    fake.pid_file.unlink()
    assert main(["func", "c000", "--project", project, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["pid"] == fake.worker_pid()

    # One-shot queries name the worker that holds the project.
    assert worker.holder_note(fake.project).startswith(f"\nA retrore worker (process {daemon}, daemon)")

    with pytest.raises(GhidraError):
        ghidra.import_program(fake.project.parent / "missing-export", fake.project)
    _wait_dead(daemon)
    assert worker.status(fake.project) is None


def test_a_closed_client_connection_cancels_the_daemon_request(fake):
    assert worker.start(fake.project)["started"]
    jvm = fake.worker_pid()
    event = threading.Event()
    threading.Timer(1, event.set).start()
    with cancellable(event), pytest.raises(GhidraError) as caught:
        ghidra.query(fake.project, {"command": "func", "address": "aaaa"})
    assert caught.value.code == "cancelled"
    _wait_dead(jvm)
    assert worker.status(fake.project)["ghidra"] == "stopped"
    assert worker.stop_all() == [str(worker.project_key(fake.project))]


def test_cli_queries_reach_a_hosting_process(hosted):
    # The MCP server hosts its workers this way; CLI commands on the same project go through them.
    jvm = ghidra.query(hosted.project, {"command": "func", "address": "c000"})["pid"]
    child = subprocess.run([sys.executable, "-m", "retrore", "func", "c000", "--project", str(hosted.project),
                            "--json"], capture_output=True, text=True, env=_environment(), check=True, timeout=60)
    assert json.loads(child.stdout)["pid"] == jvm
    child = subprocess.run([sys.executable, "-m", "retrore", "worker", "stop", "--project", str(hosted.project),
                            "--json"], capture_output=True, text=True, env=_environment(), check=True, timeout=60)
    assert json.loads(child.stdout)["stopped"] == [str(worker.project_key(hosted.project))]
    _wait_dead(jvm)
    # The next query in the hosting process starts a new worker.
    hosted.pid_file.unlink()
    assert ghidra.query(hosted.project, {"command": "func", "address": "c000"})["pid"] == hosted.worker_pid()


def test_worker_stop_needs_a_project_or_all(capsys):
    assert main(["worker", "stop", "--json"]) == 1
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "invalid_request"


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test")
def test_real_worker_matches_one_shot_queries(tmp_path, monkeypatch, capsys):
    # The README walkthrough program: JSR $C004, RTS; LDA #$07; STA $D020; RTS.
    source, export, project = tmp_path / "demo.prg", tmp_path / "export", tmp_path / "project"
    source.write_bytes(bytes.fromhex("00c0 2004c060 a907 8d20d060"))
    assert main(["load", str(source), "--entry", "c000", "-o", str(export)]) == 0
    assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0
    capsys.readouterr()
    requests = [
        {"command": "decomp", "address": "c004", "context": 1},
        {"command": "callers", "address": "c004"},
        {"command": "xrefs", "address": "d020", "direction": "incoming", "compact": True},
        {"command": "func", "address": "ffff"},
    ]

    def answers() -> list:
        rows = [ghidra.query_batch(project, requests), ghidra.analysis_gaps(project)]
        for request in requests:
            try:
                rows.append(ghidra.query(project, request))
            except GhidraError as error:
                rows.append({"code": error.code, "message": str(error)})
        return rows

    monkeypatch.setenv("RETRORE_WORKER", "0")
    expected = answers()
    monkeypatch.delenv("RETRORE_WORKER")
    starts = worker.STARTS
    with worker.hosting("test"):
        assert answers() == expected
        started = time.monotonic()
        ghidra.query(project, requests[0])
        assert time.monotonic() - started < 2
        assert worker.STARTS == starts + 1
        record = worker.status(project)
        assert record["requests"] == len(requests) + 3 and record["fallbacks"] == 0
        # A timeout or cancellation kills the process group; the next request reopens the project at once.
        host = worker._local_host(worker.project_key(project), create=False)
        host.worker.kill()
        assert ghidra.query(project, requests[0]) == expected[2]
        assert worker.STARTS == starts + 2
        record = worker.status(project)
        assert record["fallbacks"] == 0
        # Re-importing stops the worker first instead of failing on the project lock.
        with pytest.raises(GhidraError) as caught:
            ghidra.import_program(export, project)
        assert caught.value.code == "headless_failed" and "conflicting program file" in str(caught.value)
        _wait_dead(record["ghidra_pid"])
        assert worker.status(project) is None

    # A daemon whose worker is killed by a budget that expires while it opens the project recovers too.
    assert main(["worker", "start", "--project", str(project), "--json"]) == 0
    capsys.readouterr()
    try:
        record = worker.status(project)
        host_pid = record["pid"]
        # Stop the daemon's Ghidra the way an expired budget does, then give requests too little time to
        # reopen the project, so each one kills a worker that is still starting.
        os.killpg(record["ghidra_pid"], signal.SIGTERM)
        _wait_dead(record["ghidra_pid"])
        for budget in ("0.5", "2", "3.5"):
            main(["callers", "c004", "--project", str(project), "--timeout", budget, "--json"])
            capsys.readouterr()
        assert main(["callers", "c004", "--project", str(project), "--json"]) == 0
        assert json.loads(capsys.readouterr().out) == expected[3]
        assert worker.status(project)["pid"] == host_pid
    finally:
        worker.stop(project)
