"""Run Ghidra's headless importer and analysis queries."""

import json
import os
from contextlib import contextmanager
from contextvars import ContextVar
import signal
import subprocess
import threading
import time
from importlib.resources import as_file, files
from pathlib import Path
from tempfile import TemporaryDirectory

from .errors import CONTRACT_VERSION, CodedError, coded
from .image import (
    FLAT16_FORMATS, M68K_FORMATS, MAC68K_FORMAT, PC98_FORMAT, X1_FORMAT, X68K_FORMAT, Z80_FORMATS, image_units, read_map,
)
from .queries import QueryError, echo, normalize_query


# Default time budgets in seconds for one analyzeHeadless launch. None or 0 disables the limit.
IMPORT_TIMEOUT = 3600
QUERY_TIMEOUT = 600
BATCH_SECONDS_PER_QUERY = 60
_KILL_GRACE = 10


class GhidraError(CodedError):
    """A headless Ghidra command could not complete."""

    default_code = "invalid_request"


# A caller such as the MCP server sets this event to stop the headless run started in its context.
_cancel: ContextVar[threading.Event | None] = ContextVar("retrore_cancel", default=None)
_CANCEL_POLL = 0.2


@contextmanager
def cancellable(event: threading.Event):
    """Stop headless runs started in this context, and fail them with code `cancelled`, once event is set."""
    token = _cancel.set(event)
    try:
        yield
    finally:
        _cancel.reset(token)


def check_cancelled(label: str = "request") -> None:
    """Raise GhidraError with code `cancelled` if the current context's request was cancelled."""
    event = _cancel.get()
    if event is not None and event.is_set():
        raise GhidraError(f"Ghidra {label} was cancelled", code="cancelled")


def check_timeout(seconds: object) -> float | None:
    """Return a valid time budget in seconds: a nonnegative number, or None for the default."""
    if seconds is None:
        return None
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not seconds >= 0:
        raise GhidraError("expected a nonnegative number of seconds")
    return float(seconds)


def _headless() -> Path:
    home = os.environ.get("GHIDRA_HOME", "/snap/ghidra/current/ghidra")
    command = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    launcher = Path(home).expanduser().resolve() / "support" / command
    if not launcher.is_file():
        raise GhidraError(
            f"analyzeHeadless not found at {launcher}. Set GHIDRA_HOME to Ghidra's install directory.",
            code="ghidra_not_found",
        )
    return launcher


def _project_parts(project: Path) -> tuple[str, str]:
    project = project.resolve()
    return str(project.parent), project.name.removesuffix(".gpr")


def launch_environment(java_home: str | None) -> dict:
    """This process's environment with JAVA_HOME replaced by java_home, or removed when it is None."""
    environment = dict(os.environ)
    environment.pop("JAVA_HOME", None)
    if java_home:
        environment["JAVA_HOME"] = java_home
    return environment


def _run(
    project: Path, options: list[str], script: str | tuple[str, ...] | None, *arguments: str,
    pre_script: str | None = None, timeout: float | None = QUERY_TIMEOUT, setup: dict | None = None,
) -> dict:
    """Run analyzeHeadless once. setup is a worker.launch_setup() record of another process's launcher and
    JAVA_HOME to use instead of this process's, for a worker host answering that process. Several post
    scripts run in order with the same arguments; each later one may extend the result file."""
    launcher = setup["launcher"] if setup else _headless()
    scripts = files("retrore").joinpath("ghidra_scripts")
    post_scripts = (script,) if isinstance(script, str) else tuple(script or ())
    label = post_scripts[0] if post_scripts else pre_script
    with as_file(scripts) as script_dir, TemporaryDirectory() as temp:
        result_file = Path(temp) / "result.json"
        script_args = [*arguments, str(result_file)]
        script_options = [option for name in post_scripts for option in ("-postScript", name, *script_args)]
        if pre_script:
            script_options = ["-preScript", pre_script, *script_args, *script_options]
        command = [str(launcher), *_project_parts(project), *options, "-scriptPath", str(script_dir), *script_options]
        environment = launch_environment(setup.get("java_home")) if setup else None
        returncode, output = _launch(command, timeout, label, environment)
        if result_file.is_file():
            try:
                report = json.loads(result_file.read_text(encoding="utf-8"))
            except (UnicodeError, ValueError) as error:
                raise GhidraError(f"Ghidra {label} wrote an unreadable result: {error}", code="script_error") from error
            report = _checked(report, label)
            if not returncode:
                return report
        error = _failure(label, returncode, output)
        if error.code == "project_locked":
            from . import worker
            error.args = (str(error) + worker.holder_note(project),)
        raise error


def _checked(report: object, label: str | None) -> object:
    """Raise the error object a script reported instead of a result."""
    if isinstance(report, dict) and "error" in report:
        record = coded(report["error"])
        raise GhidraError(record["message"], code=record["code"])
    return report


def _failure(label: str | None, returncode: int | None, output: str) -> GhidraError:
    """The error for a headless run that exited without a result, from its log output."""
    lines = output.splitlines()
    errors = [line for line in lines if "ERROR" in line or "Exception" in line]
    detail = "\n".join((errors or lines)[-8:])
    code = "project_locked" if "LockException" in output else "headless_failed"
    return GhidraError(f"Ghidra {label} failed (exit status {returncode})\n{detail}", code=code)


def _launch(command: list[str], timeout: float | None, label: str | None,
            environment: dict | None = None) -> tuple[int, str]:
    """Run analyzeHeadless in its own process group and kill the whole group when the budget expires."""
    check_cancelled(label)
    windows = os.name == "nt"
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", env=environment,
        **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if windows else {"start_new_session": True}),
    )
    started = time.monotonic()
    deadline = started + timeout if timeout else None
    cancel = _cancel.get()
    previous = _forward_termination()
    try:
        while True:
            wait = None if deadline is None else max(0.0, deadline - time.monotonic())
            if cancel is not None:
                wait = _CANCEL_POLL if wait is None else min(wait, _CANCEL_POLL)
            try:
                output, _ = process.communicate(timeout=wait)
                return process.returncode, output
            except subprocess.TimeoutExpired:
                if cancel is not None and cancel.is_set():
                    _kill_group(process, windows)
                    raise GhidraError(f"Ghidra {label} was cancelled; the headless process group was stopped",
                                      code="cancelled") from None
                if deadline is not None and time.monotonic() >= deadline:
                    _kill_group(process, windows)
                    raise GhidraError(
                        f"Ghidra {label} exceeded the {timeout:g} second time budget after "
                        f"{time.monotonic() - started:.1f} seconds; the headless process group was stopped",
                        code="timeout",
                    ) from None
    except GhidraError:
        raise
    except BaseException:
        _kill_group(process, windows)
        raise
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _exit_on_signal(number: int, frame: object) -> None:
    raise SystemExit(128 + number)


def _forward_termination() -> dict:
    """Turn SIGTERM and SIGHUP into SystemExit so the new session's JVM is stopped with retrore."""
    if os.name == "nt" or threading.current_thread() is not threading.main_thread():
        return {}
    previous = {}
    for number in (signal.SIGTERM, signal.SIGHUP):
        if signal.getsignal(number) is signal.SIG_DFL:
            previous[number] = signal.signal(number, _exit_on_signal)
    return previous


def _kill_group(process: subprocess.Popen, windows: bool) -> None:
    _stop_group(process, windows)
    try:
        process.communicate(timeout=_KILL_GRACE)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()


def _stop_group(process: subprocess.Popen, windows: bool) -> None:
    """Terminate a process group started with _launch's flags, then kill whatever outlives the grace period."""
    if windows:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)], check=False, capture_output=True)
    else:
        # SIGTERM first lets the JVM release the project lock; SIGKILL whatever is left after the grace period.
        for sent, grace in ((signal.SIGTERM, _KILL_GRACE), (signal.SIGKILL, None)):
            try:
                os.killpg(process.pid, sent)
            except ProcessLookupError:
                break
            if grace is None:
                break
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline and _group_alive(process):
                time.sleep(0.1)
            if not _group_alive(process):
                break


def _group_alive(process: subprocess.Popen) -> bool:
    process.poll()  # Reap the launcher so a zombie leader does not keep the group visible.
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def import_program(export: Path, project: Path, *, timeout: float | None = IMPORT_TIMEOUT) -> dict:
    export = export.resolve()
    from . import worker
    worker.stop(project)  # A worker's read-only session would lock the project and serve the old program.
    manifest = export / "map.json"
    image = export / "image.bin"
    if not manifest.is_file() or not image.is_file():
        raise GhidraError(f"expected map.json and image.bin in {export}", code="export_invalid")
    program = read_map(export)
    options = ["-import", str(image), "-loader", "BinaryLoader", "-processor"]
    if program.get("format") in M68K_FORMATS:
        image_units(program, image.stat().st_size)
        post_script = {
            X68K_FORMAT: "RetroreM68kImport.java", MAC68K_FORMAT: "RetroreMacintosh.java",
        }.get(program["format"])
        report = _run(
            project, [*options, "68000:BE:32:MC68020"], post_script, str(manifest),
            pre_script="RetroreM68kImport.java", timeout=timeout,
        )
        if program["format"] == MAC68K_FORMAT and "macintosh" not in report:
            raise GhidraError("Ghidra RetroreMacintosh.java did not run", code="script_error")
        return report
    if program.get("format") in FLAT16_FORMATS:
        image_units(program, image.stat().st_size)
        language = "z80:LE:16:default" if program["format"] in Z80_FORMATS else "6502:LE:16:default"
        if program["format"] == X1_FORMAT:
            # The Z180 variant decodes IN/OUT (C) ports as BC; the plain Z80 variant keeps only C.
            language = "z180:LE:16:default"
        return _run(
            project, [*options, language], None, str(manifest), pre_script="Retrore8BitImport.java",
            timeout=timeout,
        )
    if program.get("format") == PC98_FORMAT:
        image_units(program, image.stat().st_size)
    report = _run(
        project, [*options, "x86:LE:16:Real Mode"],
        ("RetroreSegments.java", "RetroreIndirect.java", "RetroreConventions.java"), str(manifest),
        pre_script="RetroreImport.java", timeout=timeout,
    )
    # A post script that fails to compile leaves no result of its own.
    for key, script in (("indirect", "RetroreIndirect.java"), ("calling_conventions", "RetroreConventions.java")):
        if key not in report:
            raise GhidraError(f"Ghidra {script} did not run", code="script_error")
    return report


def decompile(address: str, project: Path, *, timeout: float | None = QUERY_TIMEOUT,
              program: str | None = None, **options: object) -> dict:
    return query_address("decomp", address, project, timeout=timeout, program=program, **options)


def query_address(
    command: str, address: str, project: Path, *, timeout: float | None = QUERY_TIMEOUT,
    program: str | None = None, **options: object,
) -> dict:
    return query(project, dict(command=command, address=address, **options), timeout=timeout, program=program)


def query(project: Path, request: object, *, timeout: float | None = QUERY_TIMEOUT,
          program: str | None = None) -> dict:
    """Run one query from the registry in a read-only Ghidra session."""
    return _code_row_errors(_query_json(project, "single", _normalize(request), timeout=timeout, program=program))


def _code_row_errors(result: dict) -> dict:
    # Lookup rows that fail individually carry the same error objects as batch rows.
    for row in result.get("functions", ()):
        if "error" in row:
            row["error"] = coded(row["error"], "query_failed")
    return result


def _normalize(request: object) -> dict:
    try:
        return normalize_query(request)
    except QueryError as error:
        raise GhidraError(str(error)) from error


def query_batch(project: Path, requests: object, *, timeout: float | None = None,
                program: str | None = None, _instruction_bytes: bool = False) -> dict:
    """Run an ordered array of queries in one read-only Ghidra session.

    The default budget is QUERY_TIMEOUT or BATCH_SECONDS_PER_QUERY per request, whichever is larger.
    Pass 0 to disable the limit.
    """
    if not isinstance(requests, list) or not requests:
        raise GhidraError("expected a nonempty JSON array of queries")
    normalized = []
    for index, request in enumerate(requests, 1):
        try:
            entry = _normalize(request)
        except GhidraError as error:
            raise GhidraError(f"query {index}: {error}") from error
        if _instruction_bytes and entry["command"] == "decomp":
            entry["_instruction_bytes"] = True
        normalized.append(entry)

    if timeout is None:
        timeout = max(QUERY_TIMEOUT, BATCH_SECONDS_PER_QUERY * len(requests))
    report = _query_json(project, "batch", normalized, timeout=timeout, program=program)
    report["results"] = [
        {"command": request["command"], **echo(request), **row}
        for request, row in zip(requests, report["results"], strict=True)
    ]
    for row in report["results"]:
        if "result" in row:
            _code_row_errors(row["result"])
    return report


def analysis_gaps(project: Path, *, timeout: float | None = QUERY_TIMEOUT) -> dict:
    return {"contract": CONTRACT_VERSION, **_report(project, "gaps", None, timeout)}


def trace_coverage(project: Path, coverage: dict, *, timeout: float | None = QUERY_TIMEOUT) -> dict:
    return _query_json(project, "trace", coverage, timeout=timeout)


def _query_json(project: Path, mode: str, request: object, *, timeout: float | None = QUERY_TIMEOUT,
                program: str | None = None) -> dict:
    if program is not None and program != "image.bin":
        _check_program_name(program)
        report = _oneshot(project, mode, request, timeout, program=program)
    else:
        report = _report(project, mode, request, timeout)
    if mode == "trace":
        return report
    if mode == "batch":
        for row in report.get("results", ()):
            if "error" in row:
                row["error"] = coded(row["error"], "query_failed")
    return {"contract": CONTRACT_VERSION, **report}


def _check_program_name(program: str) -> None:
    if (not isinstance(program, str) or not program.strip() or program.startswith("-")
            or any(char in program for char in "/\\*?\0\r\n") or program in (".", "..")):
        raise GhidraError("program must be the exact name of a program at the project root")


def _report(project: Path, mode: str, request: object, timeout: float | None) -> dict:
    """Run a RetroreQuery.java mode, or RetroreGaps.java for mode `gaps`, and return the script's report.

    The project's persistent worker answers when one is running or this process hosts workers;
    otherwise analyzeHeadless runs once for the request.
    """
    from . import worker
    _require_project(project)
    report = worker.route(project, mode, request, timeout)
    return _oneshot(project, mode, request, timeout) if report is None else report


def _oneshot(project: Path, mode: str, request: object, timeout: float | None, setup: dict | None = None,
             *, program: str = "image.bin") -> dict:
    """Run one query mode in its own analyzeHeadless launch, with another process's setup if given."""
    if mode == "gaps":
        return _query(project, "RetroreGaps.java", timeout=timeout, setup=setup)
    with TemporaryDirectory() as temp:
        input_file = Path(temp) / "input.json"
        input_file.write_text(json.dumps(request), encoding="utf-8")
        return _query(project, "RetroreQuery.java", mode, str(input_file), timeout=timeout, setup=setup, program=program)


def _require_project(project: Path) -> None:
    project_dir, project_name = _project_parts(project)
    if not Path(project_dir, project_name + ".gpr").is_file():
        raise GhidraError(
            f"Ghidra project not found at {Path(project_dir, project_name + '.gpr')}", code="project_not_found",
        )


def _query(project: Path, script: str, *arguments: str, timeout: float | None = QUERY_TIMEOUT,
           setup: dict | None = None, program: str = "image.bin") -> dict:
    _require_project(project)
    return _run(
        project, ["-process", program, "-noanalysis", "-readOnly"],
        script, *arguments, timeout=timeout, setup=setup,
    )
