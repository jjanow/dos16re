"""Run Ghidra's headless importer and analysis queries."""

import json
import os
import re
import subprocess
from importlib.resources import as_file, files
from pathlib import Path
from tempfile import TemporaryDirectory

from .image import M68K_FORMATS, MOS6502_FORMATS, image_units, read_map


class GhidraError(ValueError):
    """A headless Ghidra command could not complete."""


def _headless() -> Path:
    home = os.environ.get("GHIDRA_HOME", "/snap/ghidra/current/ghidra")
    command = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    launcher = Path(home).expanduser().resolve() / "support" / command
    if not launcher.is_file():
        raise GhidraError(
            f"analyzeHeadless not found at {launcher}. Set GHIDRA_HOME to Ghidra's install directory."
        )
    return launcher


def _project_parts(project: Path) -> tuple[str, str]:
    project = project.resolve()
    return str(project.parent), project.name.removesuffix(".gpr")


def _run(
    project: Path, options: list[str], script: str | None, *arguments: str, pre_script: str | None = None,
) -> dict:
    launcher = _headless()
    scripts = files("retrore").joinpath("ghidra_scripts")
    with as_file(scripts) as script_dir, TemporaryDirectory() as temp:
        result_file = Path(temp) / "result.json"
        script_args = [*arguments, str(result_file)]
        script_options = ["-postScript", script, *script_args] if script else []
        if pre_script:
            script_options = ["-preScript", pre_script, *script_args, *script_options]
        result = subprocess.run(
            [str(launcher), *_project_parts(project), *options,
             "-scriptPath", str(script_dir), *script_options],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace",
        )
        if result.returncode or not result_file.is_file():
            lines = result.stdout.splitlines()
            errors = [line for line in lines if "ERROR" in line or "Exception" in line]
            detail = "\n".join((errors or lines)[-8:])
            raise GhidraError(f"Ghidra {script or pre_script} failed\n{detail}")
        report = json.loads(result_file.read_text(encoding="utf-8"))
        if "error" in report:
            raise GhidraError(report["error"])
        return report


def import_program(export: Path, project: Path) -> dict:
    export = export.resolve()
    manifest = export / "map.json"
    image = export / "image.bin"
    if not manifest.is_file() or not image.is_file():
        raise GhidraError(f"expected map.json and image.bin in {export}")
    program = read_map(export)
    options = ["-import", str(image), "-loader", "BinaryLoader", "-processor"]
    if program.get("format") in M68K_FORMATS:
        image_units(program, image.stat().st_size)
        return _run(
            project, [*options, "68000:BE:32:MC68020"], None, str(manifest), pre_script="RetroreM68kImport.java",
        )
    if program.get("format") in MOS6502_FORMATS:
        image_units(program, image.stat().st_size)
        return _run(
            project, [*options, "6502:LE:16:default"], None, str(manifest), pre_script="Retrore6502Import.java",
        )
    return _run(
        project, [*options, "x86:LE:16:Real Mode"],
        "RetroreSegments.java", str(manifest), pre_script="RetroreImport.java",
    )


def decompile(address: str, project: Path) -> dict:
    return query_address("decomp", address, project)


def query_address(command: str, address: str, project: Path) -> dict:
    if not re.fullmatch(r"(?:[^:]+:)?[0-9a-fA-F]{1,8}", address):
        raise GhidraError("expected a hexadecimal unit:offset, DOS seg:off, or flat address")
    return _query(project, "RetroreQuery.java", command, address)


def analysis_gaps(project: Path) -> dict:
    return _query(project, "RetroreGaps.java")


def trace_coverage(project: Path, coverage: dict) -> dict:
    with TemporaryDirectory() as temp:
        positions = Path(temp) / "positions.json"
        positions.write_text(json.dumps(coverage), encoding="utf-8")
        return _query(project, "RetroreQuery.java", "trace", str(positions))


def _query(project: Path, script: str, *arguments: str) -> dict:
    project_dir, project_name = _project_parts(project)
    if not Path(project_dir, project_name + ".gpr").is_file():
        raise GhidraError(f"Ghidra project not found at {Path(project_dir, project_name + '.gpr')}")
    return _run(
        project, ["-process", "image.bin", "-noanalysis", "-readOnly"],
        script, *arguments,
    )
