"""Run Ghidra's headless importer and analysis queries."""

import json
import os
import re
import signal
import subprocess
import threading
import time
from importlib.resources import as_file, files
from pathlib import Path
from tempfile import TemporaryDirectory

from .errors import CONTRACT_VERSION, CodedError, coded
from .image import FLAT16_FORMATS, M68K_FORMATS, PC98_FORMAT, Z80_FORMATS, image_units, read_map

_QUERY_FIELDS = {
    "decomp": {"address", "unit_address", "linear", "name", "decompilation"},
    "xrefs": {"address", "incoming", "outgoing"},
    "callers": {"function", "callers"},
    "callees": {"function", "callees"},
    "func": {"function", "ranges", "size", "address", "segments", "callers"},
}
_REFERENCE_OPTIONS = {"limit", "offset", "ref_types", "compact"}
_DECOMP_LIMITS = {"context": (0, 20), "slice": (1, 128)}


# Default time budgets in seconds for one analyzeHeadless launch. None or 0 disables the limit.
IMPORT_TIMEOUT = 3600
QUERY_TIMEOUT = 600
BATCH_SECONDS_PER_QUERY = 60
_KILL_GRACE = 10


class GhidraError(CodedError):
    """A headless Ghidra command could not complete."""

    default_code = "invalid_request"


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


def _run(
    project: Path, options: list[str], script: str | None, *arguments: str, pre_script: str | None = None,
    timeout: float | None = QUERY_TIMEOUT,
) -> dict:
    launcher = _headless()
    scripts = files("retrore").joinpath("ghidra_scripts")
    label = script or pre_script
    with as_file(scripts) as script_dir, TemporaryDirectory() as temp:
        result_file = Path(temp) / "result.json"
        script_args = [*arguments, str(result_file)]
        script_options = ["-postScript", script, *script_args] if script else []
        if pre_script:
            script_options = ["-preScript", pre_script, *script_args, *script_options]
        command = [str(launcher), *_project_parts(project), *options, "-scriptPath", str(script_dir), *script_options]
        returncode, output = _launch(command, timeout, label)
        if result_file.is_file():
            try:
                report = json.loads(result_file.read_text(encoding="utf-8"))
            except (UnicodeError, ValueError) as error:
                raise GhidraError(f"Ghidra {label} wrote an unreadable result: {error}", code="script_error") from error
            if isinstance(report, dict) and "error" in report:
                record = coded(report["error"])
                raise GhidraError(record["message"], code=record["code"])
            if not returncode:
                return report
        lines = output.splitlines()
        errors = [line for line in lines if "ERROR" in line or "Exception" in line]
        detail = "\n".join((errors or lines)[-8:])
        raise GhidraError(f"Ghidra {label} failed (exit status {returncode})\n{detail}", code="headless_failed")


def _launch(command: list[str], timeout: float | None, label: str | None) -> tuple[int, str]:
    """Run analyzeHeadless in its own process group and kill the whole group when the budget expires."""
    windows = os.name == "nt"
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace",
        **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if windows else {"start_new_session": True}),
    )
    started = time.monotonic()
    previous = _forward_termination()
    try:
        output, _ = process.communicate(timeout=timeout or None)
        return process.returncode, output
    except subprocess.TimeoutExpired:
        _kill_group(process, windows)
        raise GhidraError(
            f"Ghidra {label} exceeded the {timeout:g} second time budget after "
            f"{time.monotonic() - started:.1f} seconds; the headless process group was stopped",
            code="timeout",
        ) from None
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
    try:
        process.communicate(timeout=_KILL_GRACE)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()


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
    manifest = export / "map.json"
    image = export / "image.bin"
    if not manifest.is_file() or not image.is_file():
        raise GhidraError(f"expected map.json and image.bin in {export}", code="export_invalid")
    program = read_map(export)
    options = ["-import", str(image), "-loader", "BinaryLoader", "-processor"]
    if program.get("format") in M68K_FORMATS:
        image_units(program, image.stat().st_size)
        return _run(
            project, [*options, "68000:BE:32:MC68020"], None, str(manifest), pre_script="RetroreM68kImport.java",
            timeout=timeout,
        )
    if program.get("format") in FLAT16_FORMATS:
        image_units(program, image.stat().st_size)
        language = "z80:LE:16:default" if program["format"] in Z80_FORMATS else "6502:LE:16:default"
        return _run(
            project, [*options, language], None, str(manifest), pre_script="Retrore8BitImport.java",
            timeout=timeout,
        )
    if program.get("format") == PC98_FORMAT:
        image_units(program, image.stat().st_size)
    return _run(
        project, [*options, "x86:LE:16:Real Mode"],
        "RetroreSegments.java", str(manifest), pre_script="RetroreImport.java", timeout=timeout,
    )


def decompile(address: str, project: Path, *, timeout: float | None = QUERY_TIMEOUT, **options: object) -> dict:
    return query_address("decomp", address, project, timeout=timeout, **options)


def query_address(
    command: str, address: str, project: Path, *, timeout: float | None = QUERY_TIMEOUT, **options: object,
) -> dict:
    request = dict(command=command, address=address, **options)
    _validate_query(request)
    return _query_json(project, "single", request, timeout=timeout)


def _validate_query(request: object) -> None:
    if not isinstance(request, dict) or not {"command", "address"} <= request.keys():
        raise GhidraError("expected a query object with command and address")
    command, address = request["command"], request["address"]
    if not isinstance(command, str) or command not in _QUERY_FIELDS:
        raise GhidraError("command must use decomp, xrefs, callers, callees, or func")
    if not isinstance(address, str):
        raise GhidraError("address must be a string")
    if not re.fullmatch(r"(?:[^:]+:)?[0-9a-fA-F]{1,8}", address):
        raise GhidraError("expected a hexadecimal unit:offset, seg:off, or flat address")
    allowed = {"command", "address", "fields"}
    fields_allowed = _QUERY_FIELDS[command].copy()
    if command == "decomp":
        allowed.update(_DECOMP_LIMITS)
        for name, (minimum, maximum) in _DECOMP_LIMITS.items():
            if name in request and (type(request[name]) is not int or not minimum <= request[name] <= maximum):
                raise GhidraError(f"{name} must be an integer between {minimum} and {maximum}")
        if "context" in request:
            fields_allowed.add("excerpt")
        if "slice" in request:
            fields_allowed.add("slice")
        if "context" in request or "slice" in request:
            fields_allowed.add("focus")
    else:
        allowed.update(_REFERENCE_OPTIONS)
    if command == "xrefs":
        allowed.add("direction")
    unknown = request.keys() - allowed
    if unknown:
        raise GhidraError(f"unsupported options for {command}: {', '.join(sorted(unknown))}")
    if "fields" in request:
        fields = request["fields"]
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(field, str) or field not in fields_allowed for field in fields)):
            raise GhidraError(f"fields for {command} must be a nonempty list chosen from {', '.join(sorted(fields_allowed))}")
    if "direction" in request and request["direction"] not in ("incoming", "outgoing", "both"):
        raise GhidraError("direction must be incoming, outgoing, or both")
    if "ref_types" in request:
        types = request["ref_types"]
        if (not isinstance(types, list) or not types
                or any(not isinstance(kind, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", kind) for kind in types)):
            raise GhidraError("ref_types must be a nonempty list of Ghidra reference type names")
    if "compact" in request and type(request["compact"]) is not bool:
        raise GhidraError("compact must be a boolean")
    for name, minimum in (("offset", 0), ("limit", 1)):
        if name in request and (type(request[name]) is not int or not minimum <= request[name] <= 0x7FFFFFFF):
            raise GhidraError(f"{name} must be an integer between {minimum} and 2147483647")


def query_batch(project: Path, requests: object, *, timeout: float | None = None) -> dict:
    """Run an ordered array of address queries in one read-only Ghidra session.

    The default budget is QUERY_TIMEOUT or BATCH_SECONDS_PER_QUERY per request, whichever is larger.
    Pass 0 to disable the limit.
    """
    if not isinstance(requests, list) or not requests:
        raise GhidraError("expected a nonempty JSON array of queries")
    for index, request in enumerate(requests, 1):
        try:
            _validate_query(request)
        except GhidraError as error:
            raise GhidraError(f"query {index}: {error}") from error

    if timeout is None:
        timeout = max(QUERY_TIMEOUT, BATCH_SECONDS_PER_QUERY * len(requests))
    return _query_json(project, "batch", requests, timeout=timeout)


def analysis_gaps(project: Path, *, timeout: float | None = QUERY_TIMEOUT) -> dict:
    return {"contract": CONTRACT_VERSION, **_query(project, "RetroreGaps.java", timeout=timeout)}


def trace_coverage(project: Path, coverage: dict, *, timeout: float | None = QUERY_TIMEOUT) -> dict:
    return _query_json(project, "trace", coverage, timeout=timeout)


def _query_json(project: Path, mode: str, request: object, *, timeout: float | None = QUERY_TIMEOUT) -> dict:
    with TemporaryDirectory() as temp:
        input_file = Path(temp) / "input.json"
        input_file.write_text(json.dumps(request), encoding="utf-8")
        report = _query(project, "RetroreQuery.java", mode, str(input_file), timeout=timeout)
    if mode == "trace":
        return report
    if mode == "batch":
        for row in report.get("results", ()):
            if "error" in row:
                row["error"] = coded(row["error"], "query_failed")
    return {"contract": CONTRACT_VERSION, **report}


def _query(project: Path, script: str, *arguments: str, timeout: float | None = QUERY_TIMEOUT) -> dict:
    project_dir, project_name = _project_parts(project)
    if not Path(project_dir, project_name + ".gpr").is_file():
        raise GhidraError(
            f"Ghidra project not found at {Path(project_dir, project_name + '.gpr')}", code="project_not_found",
        )
    return _run(
        project, ["-process", "image.bin", "-noanalysis", "-readOnly"],
        script, *arguments, timeout=timeout,
    )
