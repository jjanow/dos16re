"""Run Ghidra's headless importer and analysis queries."""

import json
import os
import re
import subprocess
from importlib.resources import as_file, files
from pathlib import Path
from tempfile import TemporaryDirectory


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
    project: Path, options: list[str], script: str, *arguments: str, pre_script: str | None = None,
) -> dict:
    launcher = _headless()
    scripts = files("dos16re").joinpath("ghidra_scripts")
    with as_file(scripts) as script_dir, TemporaryDirectory() as temp:
        result_file = Path(temp) / "result.json"
        script_args = [*arguments, str(result_file)]
        script_options = ["-postScript", script, *script_args]
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
            raise GhidraError(f"Ghidra {script} failed\n{detail}")
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
    return _run(
        project,
        ["-import", str(image), "-loader", "BinaryLoader", "-processor", "x86:LE:16:Real Mode"],
        "Dos16reSegments.java", str(manifest), pre_script="Dos16reImport.java",
    )


def decompile(address: str, project: Path) -> dict:
    if not re.fullmatch(r"[^:]+:[0-9a-fA-F]{1,8}", address):
        raise GhidraError("expected a hexadecimal seg:off or unit:offset address")
    return _query(project, "Dos16reDecompile.java", address)


def analysis_gaps(project: Path) -> dict:
    return _query(project, "Dos16reGaps.java")


def _query(project: Path, script: str, *arguments: str) -> dict:
    project_dir, project_name = _project_parts(project)
    if not Path(project_dir, project_name + ".gpr").is_file():
        raise GhidraError(f"Ghidra project not found at {Path(project_dir, project_name + '.gpr')}")
    return _run(
        project, ["-process", "image.bin", "-noanalysis", "-readOnly"],
        script, *arguments,
    )
