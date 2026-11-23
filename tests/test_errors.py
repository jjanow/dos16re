"""Coded errors, exit statuses, and time budgets for headless Ghidra, using a fake analyzeHeadless."""

import json
import os
import sys
import time
from io import StringIO

import pytest

from retrore import ghidra
from retrore.cli import main
from retrore.errors import HINTS
from retrore.ghidra import GhidraError

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the fake launcher is a POSIX script")

# The fake launcher reads its behavior from FAKE_GHIDRA_MODE; the last argument is the result file.
_FAKE = """#!{python}
import json, os, subprocess, sys, time
mode = os.environ["FAKE_GHIDRA_MODE"]
result = sys.argv[-1]
if mode == "hang":
    # A grandchild that ignores SIGTERM and holds the output pipe, like a JVM under a shell launcher.
    child = subprocess.Popen(
        [sys.executable, "-c", "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)"],
    )
    with open(os.environ["FAKE_GHIDRA_PID"], "w") as pid_file:
        pid_file.write(str(child.pid))
    time.sleep(300)
elif mode == "crash":
    print("INFO starting")
    print("ERROR Exception in thread main: something broke")
    sys.exit(1)
elif mode == "write":
    with open(result, "w") as output:
        output.write(os.environ["FAKE_GHIDRA_RESULT"])
"""


@pytest.fixture
def fake_ghidra(tmp_path, monkeypatch):
    support = tmp_path / "ghidra" / "support"
    support.mkdir(parents=True)
    launcher = support / "analyzeHeadless"
    launcher.write_text(_FAKE.format(python=sys.executable), encoding="utf-8")
    launcher.chmod(0o755)
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path / "ghidra"))
    project = tmp_path / "demo.gpr"
    project.write_text("", encoding="utf-8")

    def configure(mode, result=None):
        monkeypatch.setenv("FAKE_GHIDRA_MODE", mode)
        if result is not None:
            monkeypatch.setenv("FAKE_GHIDRA_RESULT", json.dumps(result))
        return project
    return configure


def _error(capsys):
    captured = capsys.readouterr()
    assert not captured.out
    report = json.loads(captured.err)
    assert report["contract"] == 1
    assert set(report["error"]) == {"code", "message", "hint"}
    assert report["error"]["hint"] == HINTS[report["error"]["code"]]
    return report["error"]


def test_timeout_kills_the_whole_process_group(fake_ghidra, tmp_path, monkeypatch, capsys):
    project = fake_ghidra("hang")
    pid_file = tmp_path / "grandchild.pid"
    monkeypatch.setenv("FAKE_GHIDRA_PID", str(pid_file))
    monkeypatch.setattr(ghidra, "_KILL_GRACE", 1)
    started = time.monotonic()
    assert main(["decomp", "1000", "--project", str(project), "--timeout", "2", "--json"]) == 1
    assert time.monotonic() - started < 20
    error = _error(capsys)
    assert error["code"] == "timeout"
    assert "2 second time budget" in error["message"]

    grandchild = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        with open(f"/proc/{grandchild}/stat") if os.path.exists(f"/proc/{grandchild}/stat") else StringIO("") as stat:
            if ") Z " in stat.read():  # A zombie waiting for its new parent to reap it is already dead.
                break
        time.sleep(0.1)
    else:
        os.kill(grandchild, 9)
        pytest.fail("the grandchild survived the time budget")


def test_timeout_validation_and_disabled_budget(fake_ghidra, capsys):
    project = fake_ghidra("write", {"function": {"name": "f"}, "callers": []})
    with pytest.raises(SystemExit) as caught:
        main(["callers", "1000", "--project", str(project), "--timeout", "-1"])
    assert caught.value.code == 2
    capsys.readouterr()
    assert main(["callers", "1000", "--project", str(project), "--timeout", "0", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"contract": 1, "function": {"name": "f"}, "callers": []}


def test_ghidra_not_found(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path))
    (tmp_path / "demo.gpr").write_text("", encoding="utf-8")
    assert main(["gaps", "--project", str(tmp_path / "demo"), "--json"]) == 1
    assert _error(capsys)["code"] == "ghidra_not_found"


def test_project_and_export_not_found(fake_ghidra, tmp_path, capsys):
    fake_ghidra("write", {})
    assert main(["func", "1000", "--project", str(tmp_path / "missing"), "--json"]) == 1
    assert _error(capsys)["code"] == "project_not_found"
    assert main(["ghidra", "import", str(tmp_path / "nothing"), str(tmp_path / "new"), "--json"]) == 1
    assert _error(capsys)["code"] == "export_invalid"


def test_headless_failure_includes_the_log_tail(fake_ghidra, capsys):
    project = fake_ghidra("crash")
    assert main(["xrefs", "1000", "--project", str(project), "--json"]) == 1
    error = _error(capsys)
    assert error["code"] == "headless_failed"
    assert "something broke" in error["message"] and "exit status 1" in error["message"]


@pytest.mark.parametrize(("reported", "code"), [
    ({"code": "no_function", "message": "no analyzed function contains 1000"}, "no_function"),
    ("java.lang.IllegalStateException: boom", "script_error"),
])
def test_script_errors_carry_codes(fake_ghidra, capsys, reported, code):
    project = fake_ghidra("write", {"error": reported})
    assert main(["decomp", "1000", "--project", str(project), "--json"]) == 1
    error = _error(capsys)
    assert error["code"] == code
    assert error["message"] == (reported["message"] if isinstance(reported, dict) else reported)


def test_invalid_requests(fake_ghidra, monkeypatch, capsys):
    project = fake_ghidra("write", {})
    assert main(["xrefs", "nothex", "--project", str(project), "--json"]) == 1
    assert _error(capsys)["code"] == "invalid_request"
    monkeypatch.setattr("sys.stdin", StringIO("[{"))
    assert main(["batch", "--project", str(project), "--json"]) == 1
    assert _error(capsys)["code"] == "invalid_request"


def test_batch_rows_carry_codes(fake_ghidra, monkeypatch, capsys):
    rows = [
        {"command": "func", "address": "1000", "result": {"size": 1}},
        {"command": "func", "address": "2000", "error": {"code": "address_not_found", "message": "outside"}},
        {"command": "func", "address": "3000", "error": "legacy message"},
    ]
    project = fake_ghidra("write", {"results": rows})
    requests = [{"command": row["command"], "address": row["address"]} for row in rows]
    monkeypatch.setattr("sys.stdin", StringIO(json.dumps(requests)))
    assert main(["batch", "--project", str(project), "--json"]) == 1
    captured = capsys.readouterr()
    assert not captured.err
    report = json.loads(captured.out)
    assert report["contract"] == 1
    results = report["results"]
    assert results[0] == rows[0]
    assert results[1]["error"] == {"code": "address_not_found", "message": "outside", "hint": HINTS["address_not_found"]}
    assert results[2]["error"] == {"code": "query_failed", "message": "legacy message", "hint": HINTS["query_failed"]}

    monkeypatch.setattr("sys.stdin", StringIO(json.dumps(requests)))
    assert main(["batch", "--project", str(project)]) == 1
    assert "address_not_found: outside" in capsys.readouterr().out


def test_python_api_raises_coded_errors(fake_ghidra):
    project = fake_ghidra("crash")
    with pytest.raises(GhidraError) as caught:
        ghidra.query_batch(project, [{"command": "func", "address": "1000"}], timeout=30)
    assert caught.value.code == "headless_failed"
