# dos16re

Toolkit for reverse engineering 16-bit real-mode DOS programs and their overlays. See `PLAN.md` for the roadmap.

- Python 3.12+, dependencies in a `.venv/` (`capstone`, `unicorn`, `pytest`). Ghidra 12.x via `GHIDRA_HOME`.
- Never commit game files or anything extracted from them. Real-game tests read paths from `DOS16RE_*_DIR`
  environment variables and skip when unset.
- Every CLI command supports `--json`; keep default output short.
- Keep `README.md` and `PLAN.md` current as phases land.
