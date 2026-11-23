"""Run Ghidra's headless importer and analysis queries."""

import json
import os
import subprocess
from importlib.resources import as_file, files
from pathlib import Path
from tempfile import TemporaryDirectory

from .image import FLAT16_FORMATS, M68K_FORMATS, PC98_FORMAT, Z80_FORMATS, image_units, read_map
from .queries import QueryError, echo, normalize_query

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
    if program.get("format") in FLAT16_FORMATS:
        image_units(program, image.stat().st_size)
        language = "z80:LE:16:default" if program["format"] in Z80_FORMATS else "6502:LE:16:default"
        return _run(
            project, [*options, language], None, str(manifest), pre_script="Retrore8BitImport.java",
        )
    if program.get("format") == PC98_FORMAT:
        image_units(program, image.stat().st_size)
    return _run(
        project, [*options, "x86:LE:16:Real Mode"],
        "RetroreSegments.java", str(manifest), pre_script="RetroreImport.java",
    )


def decompile(address: str, project: Path, **options: object) -> dict:
    return query_address("decomp", address, project, **options)


def query_address(command: str, address: str, project: Path, **options: object) -> dict:
    return query(project, dict(command=command, address=address, **options))


def query(project: Path, request: object) -> dict:
    """Run one query from the registry in a read-only Ghidra session."""
    return _query_json(project, "single", _normalize(request))


def _normalize(request: object) -> dict:
    try:
        return normalize_query(request)
    except QueryError as error:
        raise GhidraError(str(error)) from error


def query_batch(project: Path, requests: object) -> dict:
    """Run an ordered array of queries in one read-only Ghidra session."""
    if not isinstance(requests, list) or not requests:
        raise GhidraError("expected a nonempty JSON array of queries")
    normalized = []
    for index, request in enumerate(requests, 1):
        try:
            normalized.append(_normalize(request))
        except GhidraError as error:
            raise GhidraError(f"query {index}: {error}") from error

    report = _query_json(project, "batch", normalized)
    report["results"] = [
        {"command": request["command"], **echo(request), **row}
        for request, row in zip(requests, report["results"], strict=True)
    ]
    return report


def analysis_gaps(project: Path) -> dict:
    return _query(project, "RetroreGaps.java")


def trace_coverage(project: Path, coverage: dict) -> dict:
    return _query_json(project, "trace", coverage)


def _query_json(project: Path, mode: str, request: object) -> dict:
    with TemporaryDirectory() as temp:
        input_file = Path(temp) / "input.json"
        input_file.write_text(json.dumps(request), encoding="utf-8")
        return _query(project, "RetroreQuery.java", mode, str(input_file))


def _query(project: Path, script: str, *arguments: str) -> dict:
    project_dir, project_name = _project_parts(project)
    if not Path(project_dir, project_name + ".gpr").is_file():
        raise GhidraError(f"Ghidra project not found at {Path(project_dir, project_name + '.gpr')}")
    return _run(
        project, ["-process", "image.bin", "-noanalysis", "-readOnly"],
        script, *arguments,
    )
