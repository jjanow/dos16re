import os

# A Windows worker daemon starts with no output handle (see worker._adopt_log). Send its output to
# the log `worker start` named before importing anything, so import and startup errors reach it too.
if os.name == "nt" and os.environ.get("RETRORE_WORKER_LOG"):
    try:
        _log = os.open(os.environ["RETRORE_WORKER_LOG"], os.O_WRONLY | os.O_APPEND | os.O_CREAT)
    except OSError:
        pass
    else:
        for _target in (1, 2):
            os.dup2(_log, _target)
        os.close(_log)

from .cli import main  # noqa: E402

raise SystemExit(main())
