"""Persistent headless Ghidra query workers.

A worker is one analyzeHeadless process that keeps a project open read-only and answers queries
through RetroreQuery.java's serve mode. It saves the 3–4 second launch that every one-shot query pays.

Ghidra locks a project per session, so each project has at most one worker, owned by a host. A host
is either a `retrore worker serve` daemon or a long-lived process such as `retrore mcp`. On POSIX
systems the host also listens on a unix socket in the runtime directory, so other retrore processes
on the same project send their queries through it instead of failing with `project_locked`, and
`retrore ghidra import` can stop it before writing the project.

The channel between a host and its JVM is a loopback TCP connection that the JVM opens back to the
host; it proves itself with a one-time token passed in the environment. Requests and responses are
newline-delimited JSON. The host's unix socket carries one request and one response per connection.

Requests keep the one-shot contract: the same reports, error codes, time budgets, and cancellation.
A request that outlives its budget, or is cancelled, stops the worker's process group; the next
request starts a new worker. A request the worker cannot answer the way a one-shot run would runs
as a one-shot launch instead.
"""

import atexit
import contextlib
import hashlib
import json
import os
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from importlib.resources import as_file, files
from pathlib import Path

from . import ghidra
from .ghidra import GhidraError

LABEL = "RetroreQuery.java"
IDLE_TIMEOUT = 900  # seconds without requests before a host stops its worker and exits
START_FAILURE_COOLDOWN = 60  # seconds of one-shot launches after a worker failed to start
STOP_GRACE = 10  # seconds a worker gets to close the project after a shutdown request
TOKEN_ENV = "RETRORE_WORKER_TOKEN"
_POLL = 0.2
_SOCKET_LIMIT = 100  # bytes; sun_path holds 104 to 108 depending on the system
_MAX_LINE = 1 << 30

# Counts worker launches in this process, for benchmarks.
STARTS = 0


def enabled() -> bool:
    """Whether queries may use workers. RETRORE_WORKER=0 makes every query a one-shot launch."""
    return os.environ.get("RETRORE_WORKER", "1").strip().lower() not in ("0", "off", "no", "false")


def idle_timeout() -> float:
    value = os.environ.get("RETRORE_WORKER_IDLE")
    if value:
        try:
            seconds = float(value)
        except ValueError:
            raise GhidraError(f"RETRORE_WORKER_IDLE must be a number of seconds, not {value!r}") from None
        if seconds > 0:
            return seconds
    return IDLE_TIMEOUT


def sockets_supported() -> bool:
    return os.name != "nt" and hasattr(socket, "AF_UNIX")


def project_key(project: Path) -> Path:
    """The project's resolved path without the .gpr suffix, which names it for workers."""
    project = Path(project).expanduser().resolve()
    return project.with_name(project.name.removesuffix(".gpr"))


def runtime_dir() -> Path:
    """The private directory for worker sockets, locks, and daemon logs."""
    configured = os.environ.get("RETRORE_WORKER_DIR")
    if configured:
        path = Path(configured)
    elif os.environ.get("XDG_RUNTIME_DIR"):
        path = Path(os.environ["XDG_RUNTIME_DIR"]) / "retrore"
    else:
        path = Path(tempfile.gettempdir()) / f"retrore-{os.getuid() if hasattr(os, 'getuid') else 'user'}"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if hasattr(os, "getuid"):
        info = path.stat()
        if info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise GhidraError(f"worker directory {path} must be owned by this user and not writable by others",
                              code="io_error")
    return path


def _paths(key: Path) -> dict[str, Path]:
    digest = hashlib.sha256(str(key).encode()).hexdigest()[:16]
    base = runtime_dir() / digest
    return {suffix: base.with_suffix("." + suffix) for suffix in ("sock", "lock", "log")}


class WorkerCrash(Exception):
    """The worker failed a request in a way a one-shot launch reports differently, or died."""


class _Budget:
    """One request's time budget and cancellation event."""

    def __init__(self, timeout: float | None, cancel: threading.Event | None) -> None:
        self.timeout = timeout or None
        self.started = time.monotonic()
        self.deadline = self.started + timeout if timeout else None
        self.cancel = cancel

    def wait(self, cap: float = _POLL) -> float:
        if self.deadline is None:
            return cap
        return max(0.0, min(cap, self.deadline - time.monotonic()))

    def remaining(self) -> float | None:
        if self.deadline is None:
            return None
        return self.deadline - time.monotonic()

    def cancelled(self) -> bool:
        return self.cancel is not None and self.cancel.is_set()

    def expired(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline

    def error(self, stopped: bool = True) -> GhidraError | None:
        """The error to raise once the request is cancelled or out of time, or None while it may continue."""
        suffix = "; the headless process group was stopped" if stopped else " waiting for the project's worker"
        if self.cancelled():
            if stopped:
                return GhidraError(f"Ghidra {LABEL} was cancelled{suffix}", code="cancelled")
            return GhidraError(f"Ghidra {LABEL} was cancelled", code="cancelled")
        if self.expired():
            return GhidraError(
                f"Ghidra {LABEL} exceeded the {self.timeout:g} second time budget after "
                f"{time.monotonic() - self.started:.1f} seconds{suffix}", code="timeout")
        return None


class Worker:
    """One analyzeHeadless process serving RetroreQuery.java requests for one project."""

    def __init__(self, project: Path) -> None:
        self.project = project
        self.process: subprocess.Popen | None = None
        self.log: deque[str] = deque(maxlen=400)
        self._channel: socket.socket | None = None
        self._buffer = bytearray()
        self._scripts = contextlib.ExitStack()
        self._next_id = 0
        self.started_at: float | None = None
        self.requests = 0

    def running(self) -> bool:
        return self._channel is not None and self.process is not None and self.process.poll() is None

    def start(self, budget: _Budget) -> None:
        """Launch analyzeHeadless and wait for the script to connect back, within the request's budget."""
        global STARTS
        self.kill()
        launcher = ghidra._headless()
        token = secrets.token_hex(16)
        listener = socket.create_server(("127.0.0.1", 0))
        try:
            script_dir = self._scripts.enter_context(as_file(files("retrore").joinpath("ghidra_scripts")))
            command = [
                str(launcher), *ghidra._project_parts(self.project), "-process", "image.bin", "-noanalysis",
                "-readOnly", "-scriptPath", str(script_dir), "-postScript", LABEL, "serve",
                str(listener.getsockname()[1]),
            ]
            ghidra.check_cancelled(LABEL)
            windows = os.name == "nt"
            self.log.clear()
            self.process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                encoding="utf-8", errors="replace", env={**os.environ, TOKEN_ENV: token},
                **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if windows else {"start_new_session": True}),
            )
            STARTS += 1
            self.started_at = time.monotonic()
            self.requests = 0
            drain = threading.Thread(target=self._drain, args=(self.process,), name="retrore-worker-log",
                                     daemon=True)
            drain.start()
            while True:
                error = budget.error()
                if error is not None:
                    self.kill()
                    raise error
                if self.process.poll() is not None:
                    drain.join(5)
                    returncode = self.process.returncode
                    self.kill()
                    raise ghidra._failure(LABEL, returncode, "".join(self.log))
                ready, _, _ = select.select([listener], [], [], budget.wait())
                if not ready:
                    continue
                channel, _ = listener.accept()
                self._channel, self._buffer = channel, bytearray()
                try:
                    hello = json.loads(self._read_line(budget, hello=True))
                except (WorkerCrash, ValueError, UnicodeError):
                    hello = None
                if isinstance(hello, dict) and secrets.compare_digest(str(hello.get("token", "")), token):
                    return
                channel.close()
                self._channel = None
        except BaseException:
            self.kill()
            raise
        finally:
            listener.close()

    def _drain(self, process: subprocess.Popen) -> None:
        with contextlib.suppress(OSError, ValueError):
            for line in process.stdout:
                self.log.append(line)

    def request(self, mode: str, payload: object, budget: _Budget) -> object:
        """Send one request and return the script's report."""
        if not self.running():
            self.start(budget)
        self._next_id += 1
        identifier = self._next_id
        line = json.dumps({"id": identifier, "mode": mode, "input": payload}, separators=(",", ":")) + "\n"
        try:
            self._channel.sendall(line.encode("utf-8"))
        except OSError as error:
            self.kill()
            raise WorkerCrash(f"the worker closed its connection: {error}") from None
        try:
            response = json.loads(self._read_line(budget))
        except (ValueError, UnicodeError) as error:
            self.kill()
            raise WorkerCrash(f"the worker sent an unreadable response: {error}") from None
        self.requests += 1
        if not isinstance(response, dict) or response.get("id") != identifier:
            self.kill()
            raise WorkerCrash("the worker answered a different request")
        if "crash" in response:
            raise WorkerCrash(str(response["crash"]))
        return response.get("report")

    def _read_line(self, budget: _Budget, *, hello: bool = False) -> str:
        """Read one line from the JVM, stopping it when the budget runs out or the request is cancelled."""
        hello_deadline = time.monotonic() + 30 if hello else None
        while True:
            end = self._buffer.find(b"\n")
            if end >= 0:
                line = bytes(self._buffer[:end])
                del self._buffer[:end + 1]
                return line.decode("utf-8")
            error = budget.error()
            if error is not None:
                self.kill()
                raise error
            if hello_deadline is not None and time.monotonic() >= hello_deadline:
                raise WorkerCrash("the worker did not identify itself")
            ready, _, _ = select.select([self._channel], [], [], budget.wait())
            if not ready:
                continue
            try:
                chunk = self._channel.recv(1 << 16)
            except OSError:
                chunk = b""
            if not chunk:
                if hello:
                    raise WorkerCrash("the connection closed before the worker identified itself")
                excerpt = "".join(list(self.log)[-8:])
                self.kill()
                raise WorkerCrash(f"the worker exited during the request\n{excerpt}")
            self._buffer += chunk
            if len(self._buffer) > _MAX_LINE:
                self.kill()
                raise WorkerCrash("the worker sent an oversized response")

    def stop(self) -> None:
        """Ask the script to close the project, then stop the process group if it does not exit in time."""
        if self.running():
            with contextlib.suppress(OSError):
                self._channel.sendall(b'{"id":0,"mode":"shutdown"}\n')
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.process.wait(STOP_GRACE)
        self.kill()

    def kill(self) -> None:
        """Stop the whole process group and release the channel."""
        if self._channel is not None:
            with contextlib.suppress(OSError):
                self._channel.close()
            self._channel = None
        process, self.process = self.process, None
        if process is not None:
            ghidra._stop_group(process, os.name == "nt")
            try:
                process.wait(ghidra._KILL_GRACE)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            if process.stdout is not None:
                with contextlib.suppress(OSError):
                    process.stdout.close()
        self._scripts.close()
        self.started_at = None


_RETRY = object()


class Host:
    """Owns a project's worker, serializes its requests, and serves other processes on a unix socket."""

    def __init__(self, project: Path, *, owner: str, idle: float | None = None, listen: bool = True,
                 on_close=None) -> None:
        self.project = project_key(project)
        self.owner = owner
        self.idle = idle or idle_timeout()
        self.worker = Worker(self.project)
        self.closed = threading.Event()
        self.finished = threading.Event()
        self._clients: set[threading.Thread] = set()
        self.requests = 0
        self.fallbacks = 0
        self._lock = threading.Lock()
        self._state = threading.Lock()
        self._busy = 0
        self._last_used = time.monotonic()
        self._disabled_until = 0.0
        self._on_close = on_close
        self._server: socket.socket | None = None
        self._lock_file = None
        self.socket_path: Path | None = None
        if listen and sockets_supported():
            self._listen()
        threading.Thread(target=self._reap, name="retrore-worker-idle", daemon=True).start()

    # Unix socket hosting.

    def _listen(self) -> None:
        import fcntl
        try:
            paths = _paths(self.project)
        except (GhidraError, OSError):
            return  # Serve this process only.
        if len(os.fsencode(paths["sock"])) > _SOCKET_LIMIT:
            return
        handle = open(paths["lock"], "a+")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            raise HostExists(self.project) from None
        self._lock_file = handle
        with contextlib.suppress(FileNotFoundError):
            paths["sock"].unlink()  # stale: its host released the lock
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(paths["sock"]))
            os.chmod(paths["sock"], 0o600)
            server.listen(16)
        except OSError:
            server.close()
            return
        self._server, self.socket_path = server, paths["sock"]
        threading.Thread(target=self._accept, name="retrore-worker-accept", daemon=True).start()

    def _accept(self) -> None:
        server = self._server
        while not self.closed.is_set():
            try:
                ready, _, _ = select.select([server], [], [], _POLL)
                if not ready:
                    continue
                connection, _ = server.accept()
            except (OSError, ValueError):
                return
            thread = threading.Thread(target=self._client, args=(connection,), name="retrore-worker-client",
                                      daemon=True)
            with self._state:
                self._clients.add(thread)
            thread.start()

    def join_clients(self, timeout: float) -> None:
        """Wait for connections in progress to send their replies, such as the reply to `stop`."""
        deadline = time.monotonic() + timeout
        with self._state:
            clients = list(self._clients)
        for thread in clients:
            if thread is not threading.current_thread():
                thread.join(max(0.0, deadline - time.monotonic()))

    def _client(self, connection: socket.socket) -> None:
        try:
            self._serve_client(connection)
        finally:
            with self._state:
                self._clients.discard(threading.current_thread())

    def _serve_client(self, connection: socket.socket) -> None:
        with connection:
            try:
                message = json.loads(_receive_line(connection, time.monotonic() + 30))
                op = message.get("op") if isinstance(message, dict) else None
            except (OSError, ValueError, UnicodeError, TimeoutError):
                return
            if op == "status":
                reply = {"status": self.status()}
            elif op == "stop":
                self.close()
                reply = {"stopped": True}
            elif op == "query":
                reply = self._remote_query(connection, message)
            else:
                reply = {"error": {"code": "invalid_request", "message": f"unknown worker operation {op!r}"}}
            with contextlib.suppress(OSError):
                connection.sendall((json.dumps(reply) + "\n").encode("utf-8"))

    def _remote_query(self, connection: socket.socket, message: dict) -> dict:
        cancel, done = threading.Event(), threading.Event()

        def watch() -> None:
            # The client sends nothing after its request, so readability means it hung up.
            while not done.is_set():
                try:
                    ready, _, _ = select.select([connection], [], [], _POLL)
                    if ready and not connection.recv(1, socket.MSG_PEEK):
                        cancel.set()
                        return
                except OSError:
                    cancel.set()
                    return

        watcher = threading.Thread(target=watch, name="retrore-worker-watch", daemon=True)
        watcher.start()
        try:
            timeout = message.get("timeout")
            report = self.query(str(message.get("mode")), message.get("input"),
                                float(timeout) if timeout else None, cancel)
            return {"retry": True} if report is _RETRY else {"report": report}
        except GhidraError as error:
            return {"error": {"code": error.code, "message": str(error)}}
        except Exception as error:  # Report the failure to the client instead of dropping the connection.
            return {"error": {"code": "headless_failed", "message": f"the retrore worker failed: {error}"}}
        finally:
            done.set()

    # Requests.

    def query(self, mode: str, payload: object, timeout: float | None, cancel: threading.Event | None) -> object:
        """Return the script's report for one request, raise GhidraError, or return _RETRY once closed."""
        budget = _Budget(timeout, cancel)
        with self._state:
            if self.closed.is_set():
                return _RETRY
            self._busy += 1
        try:
            while not self._lock.acquire(timeout=budget.wait()):
                error = budget.error(stopped=False)
                if error is not None:
                    raise error
            try:
                if self.closed.is_set():
                    return _RETRY
                error = budget.error(stopped=False)
                if error is not None:
                    raise error
                self.requests += 1
                return self._answer(mode, payload, budget)
            finally:
                self._lock.release()
        finally:
            with self._state:
                self._busy -= 1
                self._last_used = time.monotonic()

    def _answer(self, mode: str, payload: object, budget: _Budget) -> object:
        if time.monotonic() >= self._disabled_until:
            try:
                return ghidra._checked(self.worker.request(mode, payload, budget), LABEL)
            except WorkerCrash:
                self.worker.kill()
            except GhidraError as error:
                if error.code != "headless_failed" or self.worker.requests:
                    raise
                # The worker did not start; one-shot launches may still work.
                self._disabled_until = time.monotonic() + START_FAILURE_COOLDOWN
        self.fallbacks += 1
        remaining = budget.remaining()
        if remaining is not None and remaining <= 0:
            raise budget.error()
        with contextlib.ExitStack() as stack:
            if budget.cancel is not None:
                stack.enter_context(ghidra.cancellable(budget.cancel))
            return ghidra._oneshot(self.project, mode, payload, remaining)

    def warm(self, timeout: float | None = ghidra.QUERY_TIMEOUT) -> None:
        """Start the worker now so the first query does not wait for it."""
        budget = _Budget(timeout, None)
        with self._lock:
            if not self.closed.is_set() and not self.worker.running():
                self.worker.start(budget)

    def status(self) -> dict:
        worker = self.worker
        with self._state:
            idle = time.monotonic() - self._last_used if not self._busy else 0.0
        return {
            "project": str(self.project), "owner": self.owner, "pid": os.getpid(),
            "ghidra": "ready" if worker.running() else "stopped",
            "ghidra_pid": worker.process.pid if worker.process is not None else None,
            "uptime_seconds": round(time.monotonic() - worker.started_at, 1) if worker.started_at else None,
            "requests": self.requests, "fallbacks": self.fallbacks,
            "idle_seconds": round(idle, 1), "idle_timeout": self.idle,
            "socket": str(self.socket_path) if self.socket_path else None,
        }

    # Lifetime.

    def _reap(self) -> None:
        while not self.closed.wait(min(self.idle, 5.0)):
            with self._state:
                idle = not self._busy and time.monotonic() - self._last_used >= self.idle
            if idle:
                self.close()

    def close(self) -> None:
        """Stop the worker, stop listening, and release the project. Waits for a request in progress."""
        with self._state:
            closing = self.closed.is_set()
            self.closed.set()
        if closing:
            self.finished.wait()
            return
        if self._server is not None:
            with contextlib.suppress(OSError):
                self._server.close()
            if self.socket_path is not None:
                with contextlib.suppress(OSError):
                    self.socket_path.unlink()
        with self._lock:
            self.worker.stop()
        if self._lock_file is not None:
            self._lock_file.close()
        if self._on_close is not None:
            self._on_close(self)
        self.finished.set()


class HostExists(Exception):
    """Another process hosts the project's worker."""


def _receive_line(connection: socket.socket, deadline: float | None, cancel: threading.Event | None = None) -> str:
    buffer = bytearray()
    while True:
        end = buffer.find(b"\n")
        if end >= 0:
            return bytes(buffer[:end]).decode("utf-8")
        if cancel is not None and cancel.is_set():
            raise InterruptedError
        wait = _POLL if deadline is None else max(0.0, min(_POLL, deadline - time.monotonic()))
        if deadline is not None and wait <= 0:
            raise TimeoutError
        ready, _, _ = select.select([connection], [], [], wait)
        if ready:
            chunk = connection.recv(1 << 16)
            if not chunk:
                raise ConnectionError("the worker host closed the connection")
            buffer += chunk
            if len(buffer) > _MAX_LINE:
                raise ConnectionError("oversized response")


def _call(key: Path, message: dict, *, deadline: float | None = None,
          cancel: threading.Event | None = None) -> dict | None:
    """Send one operation to the project's host socket. Returns None when no host is listening."""
    if not sockets_supported():
        return None
    try:
        path = _paths(key)["sock"]
    except (GhidraError, OSError):
        return None
    if not path.exists():
        return None
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with connection:
        try:
            connection.connect(str(path))
        except (FileNotFoundError, ConnectionRefusedError):
            return None
        connection.sendall((json.dumps(message) + "\n").encode("utf-8"))
        reply = json.loads(_receive_line(connection, deadline, cancel))
    return reply if isinstance(reply, dict) else None


# Hosts in this process.

_hosts: dict[Path, Host] = {}
_hosts_guard = threading.Lock()
_hosting = 0
_hosting_owner = "retrore"


@contextlib.contextmanager
def hosting(owner: str):
    """Start workers on demand in this process, for long-lived callers such as the MCP server."""
    global _hosting, _hosting_owner
    with _hosts_guard:
        _hosting += 1
        _hosting_owner = owner
    try:
        yield
    finally:
        with _hosts_guard:
            _hosting -= 1
            last = not _hosting
        if last:
            close_all()


def close_all() -> None:
    with _hosts_guard:
        hosts = list(_hosts.values())
    for host in hosts:
        host.close()


atexit.register(close_all)


def _forget(host: Host) -> None:
    with _hosts_guard:
        if _hosts.get(host.project) is host:
            del _hosts[host.project]


def _local_host(key: Path, create: bool) -> Host | None:
    with _hosts_guard:
        host = _hosts.get(key)
        if host is not None and not host.closed.is_set():
            return host
        if not create or not _hosting:
            return None
        try:
            host = Host(key, owner=_hosting_owner, on_close=_forget)
        except HostExists:
            return None
        _hosts[key] = host
        return host


def route(project: Path, mode: str, payload: object, timeout: float | None) -> object:
    """Answer a query through a worker and return the script's report, or None to run it one-shot."""
    if not enabled():
        return None
    key = project_key(project)
    cancel = ghidra._cancel.get()
    for attempt in range(20):
        host = _local_host(key, create=False)
        if host is not None:
            report = host.query(mode, payload, timeout, cancel)
            if report is not _RETRY:
                return report
            continue
        report = _remote(key, mode, payload, timeout, cancel)
        if report is not _RETRY:
            return report
        host = _local_host(key, create=True)
        if host is None:
            if not _hosting:
                return None
            time.sleep(0.1 * min(attempt + 1, 5))  # Another process is setting up its host.
            continue
        report = host.query(mode, payload, timeout, cancel)
        if report is not _RETRY:
            return report
    return None


def _remote(key: Path, mode: str, payload: object, timeout: float | None, cancel: threading.Event | None) -> object:
    """Send a query to another process's host. Returns _RETRY when none answers."""
    budget = _Budget(timeout, cancel)
    # The host enforces the budget; this deadline only guards against a host that stopped responding.
    deadline = None if budget.deadline is None else budget.deadline + 2 * ghidra._KILL_GRACE + STOP_GRACE + 5
    try:
        reply = _call(key, {"op": "query", "mode": mode, "input": payload, "timeout": timeout},
                      deadline=deadline, cancel=cancel)
    except InterruptedError:
        raise GhidraError(f"Ghidra {LABEL} was cancelled; the headless process group was stopped",
                          code="cancelled") from None
    except TimeoutError:
        raise budget.error() or GhidraError(f"the retrore worker for {key} stopped responding",
                                            code="timeout") from None
    except (OSError, ValueError, UnicodeError):
        return _RETRY
    if reply is None or reply.get("retry"):
        return _RETRY
    if "error" in reply:
        error = reply["error"] if isinstance(reply["error"], dict) else {}
        raise GhidraError(str(error.get("message", "the retrore worker failed")),
                          code=str(error.get("code", "headless_failed")))
    return reply.get("report")


# Management for the CLI.

def status(project: Path) -> dict | None:
    """Report the project's worker host, in this process or another, or None if there is none."""
    key = project_key(project)
    host = _local_host(key, create=False)
    if host is not None:
        return host.status()
    try:
        reply = _call(key, {"op": "status"}, deadline=time.monotonic() + 10)
    except (OSError, ValueError, UnicodeError, TimeoutError, InterruptedError):
        return None
    return reply.get("status") if reply else None


def stop(project: Path) -> bool:
    """Stop the project's worker host and wait until it releases the project. Returns whether one ran."""
    key = project_key(project)
    stopped = False
    host = _local_host(key, create=False)
    if host is not None:
        host.close()
        stopped = True
    try:
        reply = _call(key, {"op": "stop"}, deadline=time.monotonic() + 2 * ghidra._KILL_GRACE + STOP_GRACE + 30)
    except (OSError, ValueError, UnicodeError, TimeoutError, InterruptedError):
        reply = None
    return stopped or bool(reply and reply.get("stopped"))


def stop_all() -> list[str]:
    """Stop every worker host listening in the runtime directory. Returns their projects."""
    close_all()
    projects = []
    if not sockets_supported():
        return projects
    for path in sorted(runtime_dir().glob("*.sock")):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        with connection:
            try:
                connection.connect(str(path))
                connection.sendall(b'{"op":"status"}\n')
                project = json.loads(_receive_line(connection, time.monotonic() + 10))["status"]["project"]
            except (OSError, ValueError, KeyError, TypeError, TimeoutError):
                continue
        if stop(Path(project)):
            projects.append(project)
    return projects


def holder_note(project: Path) -> str:
    """A sentence naming the worker that holds the project, or an empty string."""
    try:
        record = status(project)
    except GhidraError:
        return ""
    if not record:
        return ""
    return (f"\nA retrore worker (process {record['pid']}, {record['owner']}) holds the project. "
            f"Stop it with `retrore worker stop --project {record['project']}`, or leave RETRORE_WORKER unset "
            "to send queries through it.")


def _require_sockets() -> None:
    if not sockets_supported():
        raise GhidraError("worker daemons need unix domain sockets, which this platform's Python lacks",
                          code="invalid_request")


def serve(project: Path, idle: float | None = None, *, warm: bool = True) -> int:
    """Run a worker daemon for the project in the foreground until it is stopped or idle."""
    _require_sockets()
    ghidra._require_project(project)
    try:
        host = Host(project, owner="daemon", idle=idle)
    except HostExists:
        print(f"retrore: a worker already serves {project_key(project)}", file=sys.stderr)
        return 1
    if host.socket_path is None:
        host.close()
        raise GhidraError(f"the worker socket path for {project} is too long; set RETRORE_WORKER_DIR to a "
                          "shorter directory", code="io_error")

    def finish(number: int, frame: object) -> None:
        threading.Thread(target=host.close, daemon=True).start()

    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(number, finish)
    print(f"retrore worker {os.getpid()} serving {host.project} on {host.socket_path}", file=sys.stderr, flush=True)
    if warm:
        try:
            host.warm()
        except GhidraError as error:
            print(f"retrore: {error}", file=sys.stderr, flush=True)
            host.close()
            return 1
    while not host.finished.wait(1):
        pass
    host.join_clients(10)
    print(f"retrore worker {os.getpid()} stopped", file=sys.stderr, flush=True)
    return 0


def start(project: Path, idle: float | None = None, timeout: float | None = ghidra.QUERY_TIMEOUT) -> dict:
    """Start a detached worker daemon for the project and wait until its Ghidra session is ready."""
    _require_sockets()
    ghidra._require_project(project)
    key = project_key(project)
    record = status(key)
    if record is not None:
        return {**record, "started": False}
    log = _paths(key)["log"]
    package = str(Path(__file__).resolve().parents[1])
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, (package, os.environ.get("PYTHONPATH"))))}
    environment.pop(TOKEN_ENV, None)
    command = [sys.executable, "-m", "retrore", "worker", "serve", "--project", str(key)]
    if idle:
        command += ["--idle", f"{idle:g}"]
    with open(log, "w", encoding="utf-8") as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                   env=environment, start_new_session=True, cwd=str(runtime_dir()))
    deadline = None if not timeout else time.monotonic() + timeout
    while True:
        if process.poll() is not None:
            lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
            detail = "\n".join(lines[-8:])
            locked = "project_locked" in detail or "LockException" in detail
            raise GhidraError(f"the retrore worker exited with status {process.returncode}\n{detail}",
                              code="project_locked" if locked else "headless_failed")
        record = status(key)
        if record is not None and record.get("ghidra") == "ready":
            return {**record, "started": True, "log": str(log)}
        if deadline is not None and time.monotonic() >= deadline:
            stop(key)
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            raise GhidraError(f"the retrore worker did not become ready within {timeout:g} seconds", code="timeout")
        time.sleep(_POLL)
