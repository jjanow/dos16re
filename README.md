# dos16re

Reverse-engineering tools for 16-bit real-mode DOS programs. The toolkit is designed for any project in that
scope. The games in [PLAN.md](PLAN.md) are validation targets for particular executable formats and compiler
patterns.

## MZ loader

Phase 1 starts with the DOS MZ load module. The loader applies segment relocations and records the initial
`CS:IP` and `SS:SP`. See [PLAN.md](PLAN.md) for the unpacking, overlay and Ghidra milestones.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e . pytest
.venv/bin/dos16re info PROGRAM.EXE
.venv/bin/dos16re load PROGRAM.EXE -o out/program --json
.venv/bin/python -m pytest
```

Both commands accept `--json` and `--base-segment HEX`. The default load segment is `1000` hex. `load` writes
`image.bin` and `map.json` and requires those filenames to be free in the output directory. Byte zero of
`image.bin` is at the root unit's linear address in the map. The image contains the initialized bytes from
the DOS load module. The initial stack can point into memory beyond the image.

Tests use synthetic executables. Tests that use real programs read them from paths you set in environment
variables.

## License

MIT, see [LICENSE](LICENSE).
