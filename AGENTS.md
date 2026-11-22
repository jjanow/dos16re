# retrore

Toolkit for reverse engineering retro executables: 16-bit real-mode DOS programs and their overlays,
AmigaDOS Hunk executables, and other platforms as they are added. See `PLAN.md` for the roadmap.

- Python 3.12+, dependencies in a `.venv/` (`capstone`, `unicorn`, `pytest`). Ghidra 12.x via `GHIDRA_HOME`.
- Keep `retrore` standalone. Runtime code and the default test suite must work without sibling projects,
  their scripts, or their data. Keep game-specific assumptions in opt-in validation tests.
- Never commit game files or anything extracted from them. Real-game tests read paths from `RETRORE_*_DIR`
  environment variables and skip when unset.
- Every CLI command supports `--json`; keep default output short.
- Keep `README.md` and `PLAN.md` current as phases land.
- **“wrap it”** is a session command. Update `PLAN.md` with open items and a short “Last session”
  entry covering completed work, verification, and where to resume. Remove stale session notes and
  markers. Verify the changes, commit and push the session’s retrore work, and prune merged agent
  worktrees that are clean and unused. Keep unrelated changes and private game inputs out of the commit.
