# dos16re

Reverse-engineering tools for 16-bit real-mode DOS programs: MZ executables, EXEPACK/LZEXE-style packers and
overlay systems (Turbo Pascal, program-loaded `.OVR` files and more). It builds one correct whole-program image,
with every overlay at its own segment and overlay stubs resolved, and imports it into Ghidra so cross-references,
segment registers and jump tables come out right.

Status: planning. See [PLAN.md](PLAN.md) for the design and phases.

No game files are included or needed to build. Tests that use real programs read them from paths you set in
environment variables.

## License

MIT, see [LICENSE](LICENSE).
