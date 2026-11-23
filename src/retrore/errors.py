"""Stable error codes, hints, and exit statuses shared by the CLI and the Ghidra wrapper."""

# Version of the JSON query contract: result shapes, the batch envelope, and error objects.
CONTRACT_VERSION = 1

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

HINTS = {
    "ghidra_not_found": "Set GHIDRA_HOME to the Ghidra install directory that contains support/analyzeHeadless.",
    "project_not_found": "Check the --project path, or create the project with `retrore ghidra import`.",
    "export_invalid": "Re-export the program with `retrore load PROGRAM -o OUT`.",
    "unsupported_map_version": "The export was written by a newer retrore. Upgrade retrore or re-export the program.",
    "timeout": "Raise --timeout (0 disables the limit) or split the work into smaller batches.",
    "headless_failed": "Read the log excerpt in the message. Check JAVA_HOME and that no other process holds the "
                       "project lock.",
    "project_locked": "Another Ghidra session has the project open. Close it, or wait for the other query to "
                      "finish; one project serves one headless session at a time.",
    "cancelled": "The client cancelled the request.",
    "script_error": "A retrore Ghidra script failed. Re-import the export with the current retrore if the project "
                    "is old, then report the message if it persists.",
    "invalid_request": "Fix the request. See `retrore COMMAND --help` and the README's query documentation.",
    "address_not_found": "Use a hexadecimal unit:offset, seg:off, or flat address inside the loaded image.",
    "no_function": "No analyzed function or instruction covers the address. Query a function entry, or check "
                   "`retrore gaps` for unanalyzed code.",
    "project_mismatch": "Re-import the current export, or pass the export the project was built from.",
    "query_failed": "The query failed inside Ghidra. Read the message for details.",
    "unsupported_packer": "Unpack the program with an external tool, then load the unpacked file.",
    "input_invalid": "Check the input file and options against the README section for its platform.",
    "io_error": "Check that the path exists and is readable or writable.",
}


class CodedError(ValueError):
    """An error with a stable machine-readable code and an actionable hint."""

    default_code = "input_invalid"

    def __init__(self, message: str, *, code: str | None = None, hint: str | None = None) -> None:
        super().__init__(message)
        self.code = code or self.default_code
        self.hint = hint


def error_record(error: BaseException) -> dict:
    """Return the `{code, message, hint}` object for an error."""
    code = getattr(error, "code", None)
    if not isinstance(code, str):
        if isinstance(error, OSError):
            code = "io_error"
        elif hasattr(error, "packer"):
            code = "unsupported_packer"
        else:
            code = "input_invalid"
    return {"code": code, "message": str(error), "hint": getattr(error, "hint", None) or HINTS.get(code)}


def coded(error: object, default: str = "script_error") -> dict:
    """Normalize an error reported by a Ghidra script into a `{code, message, hint}` object."""
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        code = error.get("code") if isinstance(error.get("code"), str) else default
        return {"code": code, "message": error["message"], "hint": HINTS.get(code)}
    return {"code": default, "message": str(error), "hint": HINTS.get(default)}
