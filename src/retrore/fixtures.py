"""Run declarative routine fixtures and compare their observable state."""

import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from itertools import groupby, product
from pathlib import Path

from .dynamic import HardwareIO, RoutineBackend, RoutineRequest, Service
from .emulator import DEFAULT_INSTRUCTION_LIMIT, EmulatorError

_VERSION = 1
_REPORT = "retrore-fixture-report"
_OPTIONS = {"address", "registers", "memory", "watch", "expect", "services", "hardware", "far", "limit"}
_IMPLICIT_REGISTERS = {
    "x86": {"cs", "ip"},
    "m68k": {"pc"},
    "6502": {"pc"},
    "z80": {"pc", "af", "bc", "de", "hl", "r"},
}


class FixtureError(ValueError):
    """An invalid fixture or an incompatible comparison request."""


@dataclass(frozen=True)
class _Case:
    name: str
    request: RoutineRequest
    memory_names: tuple[str, ...]
    watch: tuple[str, ...] | None
    expected: dict


def _object(value, field: str, allowed: set[str] | None = None) -> Mapping:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) or not key for key in value):
        raise FixtureError(f"{field} must be an object with nonempty string keys")
    if allowed is not None and (unknown := value.keys() - allowed):
        raise FixtureError(f"unknown {field} field: {', '.join(sorted(unknown))}")
    return value


def _array(value, field: str) -> list:
    if not isinstance(value, list):
        raise FixtureError(f"{field} must be an array")
    return value


def _uint(value, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError:
            pass
    if type(value) is not int or value < minimum:
        raise FixtureError(f"{field} must be an integer of at least {minimum}")
    return value


def _address(value, field: str) -> str | int:
    if (isinstance(value, str) and value.strip()) or (type(value) is int and value >= 0):
        return value
    raise FixtureError(f"{field} must be a nonempty address string or an unsigned integer")


def _bytes(value, field: str) -> bytes:
    if isinstance(value, str):
        try:
            if data := bytes.fromhex(value):
                return data
        except ValueError:
            pass
    raise FixtureError(f"{field} must contain hexadecimal bytes")


def _register_names(value, field: str) -> tuple[str, ...]:
    if any(not isinstance(name, str) or not name.strip() for name in value):
        raise FixtureError(f"{field} must use nonempty register names")
    names = tuple(name.lower() for name in value)
    if len(set(names)) != len(names):
        raise FixtureError(f"{field} contains duplicate registers")
    return names


def _registers(value, field: str) -> dict[str, int]:
    values = _object(value, field)
    names = _register_names(values, field)
    return {name: _uint(value, f"{field}.{name}") for name, value in zip(names, values.values(), strict=True)}


def _services(value) -> tuple[Service, ...]:
    services = []
    for index, entry in enumerate(_array(value, "services")):
        field = f"services[{index}]"
        record = _object(entry, field, {"number", "kind", "match", "registers", "writes"})
        kind = record.get("kind", "interrupt")
        if not isinstance(kind, str) or not kind:
            raise FixtureError(f"{field}.kind must be a nonempty string")
        writes = _object(record.get("writes", {}), f"{field}.writes")
        services.append(Service(
            number=_uint(record.get("number"), f"{field}.number"),
            kind=kind,
            match=_registers(record.get("match", {}), f"{field}.match"),
            registers=_registers(record.get("registers", {}), f"{field}.registers"),
            writes=tuple((where, _bytes(data, f"{field}.writes.{where}")) for where, data in writes.items()),
        ))
    return tuple(services)


def _hardware(value) -> tuple[HardwareIO, ...]:
    hardware = []
    for index, entry in enumerate(_array(value, "hardware")):
        field = f"hardware[{index}]"
        record = _object(entry, field, {"operation", "address", "size", "value", "space"})
        operation, space = record.get("operation"), record.get("space", "port")
        if operation not in ("read", "write"):
            raise FixtureError(f"{field}.operation must be read or write")
        if space not in ("port", "memory", "mmio"):
            raise FixtureError(f"{field}.space must be port or memory")
        hardware.append(HardwareIO(
            operation=operation,
            address=_uint(record.get("address"), f"{field}.address"),
            size=_uint(record.get("size", 1), f"{field}.size", minimum=1),
            value=_uint(record.get("value"), f"{field}.value"),
            space="memory" if space == "mmio" else space,
        ))
    return tuple(hardware)


def _memory(value) -> tuple[tuple[str, ...], tuple, tuple]:
    memory = _object(value, "memory")
    writes, reads = [], []
    for name, entry in memory.items():
        field = f"memory.{name}"
        record = _object(entry, field, {"address", "data", "size"})
        where = _address(record.get("address"), f"{field}.address")
        data = _bytes(record["data"], f"{field}.data") if "data" in record else b""
        size = _uint(record.get("size", len(data)), f"{field}.size", minimum=1)
        if len(data) > size:
            raise FixtureError(f"{field}.data exceeds its watched size")
        if data:
            writes.append((where, data))
        reads.append((where, size))
    return tuple(memory), tuple(writes), tuple(reads)


def _case(name: str, options: Mapping, inputs: dict[str, int]) -> _Case:
    labels, writes, reads = _memory(options.get("memory", {}))
    expect = _object(options.get("expect", {}), "expect", {"registers", "memory"})
    expected_memory = _object(expect.get("memory", {}), "expect.memory", set(labels))
    expected_bytes = {label: _bytes(value, f"expect.memory.{label}") for label, value in expected_memory.items()}
    for label, (_, size) in zip(labels, reads, strict=True):
        if label in expected_bytes and len(expected_bytes[label]) != size:
            raise FixtureError(f"expect.memory.{label} must contain {size} bytes")
    far = options.get("far", False)
    if type(far) is not bool:
        raise FixtureError("far must be a boolean")
    watch = _register_names(_array(options["watch"], "watch"), "watch") if "watch" in options else None
    return _Case(name, RoutineRequest(
        address=_address(options.get("address"), "address"),
        registers=_registers(options.get("registers", {}), "registers") | inputs,
        writes=writes, reads=reads, far=far,
        limit=_uint(options.get("limit", DEFAULT_INSTRUCTION_LIMIT), "limit", minimum=1),
        services=_services(options.get("services", [])), hardware=_hardware(options.get("hardware", [])),
    ), labels, watch, {
        "registers": _registers(expect.get("registers", {}), "expect.registers"),
        "memory": {label: data.hex() for label, data in expected_bytes.items()},
    })


def _merge_case(base: dict, overrides: Mapping) -> dict:
    options = base | overrides
    if "registers" in overrides:
        options["registers"] = (_registers(base.get("registers", {}), "registers") |
                                _registers(overrides["registers"], "registers"))
    if "memory" in overrides:
        memory = dict(_object(base.get("memory", {}), "memory"))
        for name, entry in _object(overrides["memory"], "memory").items():
            memory[name] = dict(_object(memory.get(name, {}), f"memory.{name}")) | _object(entry, f"memory.{name}")
        options["memory"] = memory
    if "expect" in overrides:
        allowed = {"registers", "memory"}
        first = _object(base.get("expect", {}), "expect", allowed)
        second = _object(overrides["expect"], "expect", allowed)
        options["expect"] = {
            "registers": (_registers(first.get("registers", {}), "expect.registers") |
                          _registers(second.get("registers", {}), "expect.registers")),
            "memory": dict(_object(first.get("memory", {}), "expect.memory")) |
                      _object(second.get("memory", {}), "expect.memory"),
        }
    return options


def _cases(fixture: Mapping) -> list[_Case]:
    fields = _OPTIONS | {"version", "cases", "matrix"}
    fixture = _object(fixture, "fixture", fields)
    version = fixture.get("version", _VERSION)
    if type(version) is not int or version != _VERSION:
        raise FixtureError(f"unsupported fixture version: {version}")
    base = {key: value for key, value in fixture.items() if key in _OPTIONS}
    matrix = _object(fixture.get("matrix", {}), "matrix")
    axes = {}
    matrix = dict(zip(_register_names(matrix, "matrix"), matrix.values(), strict=True))
    for name, axis in sorted(matrix.items()):
        values = [_uint(value, f"matrix.{name}") for value in _array(axis, f"matrix.{name}")]
        if not values or len(set(values)) != len(values):
            raise FixtureError(f"matrix.{name} must contain distinct input values")
        axes[name] = values
    records = _array(fixture.get("cases", [{"name": "default"}]), "cases")
    if not records:
        raise FixtureError("cases must contain at least one case")
    cases = []
    names = set()
    for record in records:
        record = dict(_object(record, "case", _OPTIONS | {"name"}))
        name = record.pop("name", None)
        if not isinstance(name, str) or not name.strip() or name in names:
            raise FixtureError("case names must be nonempty and distinct")
        names.add(name)
        options = _merge_case(base, record)
        for values in product(*axes.values()):
            inputs = dict(zip(axes, values, strict=True))
            suffix = ", ".join(f"{key}=0x{value:x}" for key, value in inputs.items())
            case_name = f"{name} [{suffix}]" if suffix else name
            try:
                cases.append(_case(case_name, options, inputs))
            except FixtureError as error:
                raise FixtureError(f"{case_name}: {error}") from error
    return cases


def _read_json(path: Path, field: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise FixtureError(f"could not read {field} {path}: {error}") from error
    return dict(_object(value, field))


def load_fixture(path: Path) -> dict:
    """Read a fixture or a fixture report that includes a replayable snapshot."""
    return _read_json(path, "fixture")


def load_report(path: Path) -> dict:
    """Read a snapshot report or reference implementation results."""
    return _read_json(path, "comparison report")


def _definition(fixture: Mapping, identity: Mapping) -> Mapping:
    fixture = _object(fixture, "fixture")
    if fixture.get("type") != _REPORT:
        return fixture
    if type(fixture.get("version")) is not int or fixture["version"] != _VERSION or "fixture" not in fixture:
        raise FixtureError("expected a version 1 report with a replayable fixture")
    if fixture.get("export") != identity:
        raise FixtureError("snapshot was recorded with a different export")
    return _object(fixture["fixture"], "fixture")


def _memory_changes(before: bytes, after: bytes) -> list[dict]:
    changes = []
    changed = (index for index, (old, new) in enumerate(zip(before, after, strict=True)) if old != new)
    for _, group in groupby(enumerate(changed), lambda pair: pair[1] - pair[0]):
        _, start = next(group)
        end = start + sum(1 for _ in group) + 1
        changes.append({"offset": start, "before": before[start:end].hex(), "after": after[start:end].hex()})
    return changes


def _run_case(backend: RoutineBackend, case: _Case) -> dict:
    report = {"name": case.name, "passed": False, "changes": {"registers": {}, "memory": {}}, "failures": []}
    try:
        result = backend.run(case.request)
    except EmulatorError as error:
        report["failures"].append({"kind": "execution", "message": str(error)})
        return report
    report["address"] = backend.location(result.address)
    report["events"] = list(result.events)
    report["_registers"] = result.after.registers

    selected = set(case.watch or ()) | case.expected["registers"].keys()
    if unknown := selected - result.after.registers.keys():
        raise FixtureError(f"{case.name}: unknown watched register: {', '.join(sorted(unknown))}")
    names = selected
    if case.watch is None:
        names = selected | (result.after.registers.keys() - _IMPLICIT_REGISTERS.get(backend.architecture, {"pc"}))
    states = {}
    for label, state in (("before", result.before), ("after", result.after)):
        states[label] = {
            "registers": {name: state.registers[name] for name in sorted(names)},
            "memory": {name: data.hex() for name, (_, data) in zip(case.memory_names, state.memory, strict=True)},
        }
    report.update(states)
    report["watch"] = sorted(selected)
    before, after = states["before"]["registers"], states["after"]["registers"]
    report["changes"]["registers"] = {name: {"before": before[name], "after": value}
                                      for name, value in after.items() if before[name] != value}
    for name, (_, old), (where, new) in zip(case.memory_names, result.before.memory, result.after.memory, strict=True):
        if old != new:
            report["changes"]["memory"][name] = {"address": backend.location(where), "ranges": _memory_changes(old, new)}

    for field, kind in (("registers", "register"), ("memory", "memory")):
        for name, expected in case.expected[field].items():
            actual = states["after"][field][name]
            if expected != actual:
                report["failures"].append({"kind": kind, "name": name, "expected": expected, "actual": actual})
    report["passed"] = not report["failures"]
    return report


def _reference_cases(report: Mapping) -> list[dict]:
    report = _object(report, "comparison report")
    recorded = report.get("type") == _REPORT
    if recorded and (type(report.get("version")) is not int or report["version"] != _VERSION):
        raise FixtureError("unsupported fixture report version")
    cases = []
    names = set()
    for record in _array(report.get("cases"), "comparison cases"):
        record = _object(record, "comparison case")
        name = record.get("name")
        if not isinstance(name, str) or not name.strip() or name in names:
            raise FixtureError("comparison case names must be nonempty and distinct")
        names.add(name)
        if recorded and "after" not in record:
            raise FixtureError(f"{name}: comparison requires a successful execution recorded with snapshots")
        case = {"name": name}
        for label in ("before", "after") if recorded else ("after",):
            state = _object(record.get(label), f"{name}.{label}", {"registers", "memory"})
            case[label] = {
                "registers": _registers(state.get("registers", {}), f"{name}.{label}.registers"),
                "memory": {key: _bytes(value, f"{name}.{label}.memory.{key}").hex()
                           for key, value in _object(state.get("memory", {}), f"{name}.{label}.memory").items()},
            }
        if recorded:
            case["watch"] = _register_names(_array(record.get("watch", []), f"{name}.watch"), f"{name}.watch")
            if set(case["watch"]) - case["after"]["registers"].keys():
                raise FixtureError(f"{name}: watched registers are missing from the snapshot")
            for field in ("registers", "memory"):
                if case["before"][field].keys() != case["after"][field].keys():
                    raise FixtureError(f"{name}: snapshot {field} must have matching before and after labels")
            for label, value in case["before"]["memory"].items():
                if len(value) != len(case["after"]["memory"][label]):
                    raise FixtureError(f"{name}: snapshot memory {label} must have the same size before and after")
        cases.append(case)
    if not cases:
        raise FixtureError("comparison report must contain at least one case")
    return cases


def _compared_registers(case: dict) -> set[str]:
    after = case["after"]["registers"]
    before = case["before"]["registers"]
    return set(case["watch"]) | {name for name, value in after.items() if value != before.get(name)}


def _differences(cases: list[dict], references: list[dict], *, against_export: bool) -> list[dict]:
    actual_by_name = {case["name"]: case for case in cases}
    reference_by_name = {case["name"]: case for case in references}
    differences = []
    for name in sorted(actual_by_name.keys() | reference_by_name.keys()):
        actual, reference = actual_by_name.get(name), reference_by_name.get(name)
        if actual is None or reference is None:
            differences.append({"case": name, "kind": "missing_case", "missing_from": "fixture" if actual is None else "reference"})
            continue
        if against_export and reference["failures"]:
            differences.append({"case": name, "kind": "reference_failure", "failures": reference["failures"]})
        if "after" not in actual or "after" not in reference:
            differences.append({"case": name, "kind": "missing_state",
                                "missing_from": [side for side, case in (("fixture", actual), ("reference", reference))
                                                 if "after" not in case]})
            continue
        for field, kind in (("registers", "register"), ("memory", "memory")):
            values, expected = actual["after"][field], reference["after"][field]
            if field == "registers":
                values = actual["_registers"]
                expected = reference.get("_registers", expected)
            if "before" not in reference:
                keys = expected.keys()
            elif field == "registers":
                keys = _compared_registers(actual) | _compared_registers(reference)
            else:
                keys = values.keys() | expected.keys()
            for key in sorted(keys):
                if values.get(key) != expected.get(key):
                    differences.append({"case": name, "kind": kind, "name": key,
                                        "actual": values.get(key), "reference": expected.get(key)})
    return differences


def run_fixture(
    export: Path, fixture: Mapping, *, against_export: Path | None = None, against_fixture: Mapping | None = None,
    against_report: Mapping | None = None, snapshots: bool = False,
) -> dict:
    """Execute independent cases, optionally comparing final state or recording replayable input."""
    if against_export is not None and against_report is not None:
        raise FixtureError("choose a reference export or a comparison report")
    if against_fixture is not None and against_export is None:
        raise FixtureError("a reference fixture requires a reference export")
    backend = RoutineBackend.from_export(export)
    identity = backend.identity()
    fixture = _definition(fixture, identity)
    cases = [_run_case(backend, case) for case in _cases(fixture)]
    report = {"type": _REPORT, "version": _VERSION, "export": identity, "passed": all(case["passed"] for case in cases),
              "cases": cases}
    if against_export is not None:
        reference_backend = RoutineBackend.from_export(against_export)
        reference_identity = reference_backend.identity()
        reference_fixture = fixture if against_fixture is None else _definition(against_fixture, reference_identity)
        references = [_run_case(reference_backend, case) for case in _cases(reference_fixture)]
    elif against_report is not None:
        references = _reference_cases(against_report)
        reference_identity = against_report.get("export")
    if against_export is not None or against_report is not None:
        differences = _differences(cases, references, against_export=against_export is not None)
        report["comparison"] = {"reference": reference_identity, "passed": not differences, "differences": differences}
        report["passed"] = report["passed"] and not differences
    if snapshots:
        report["fixture"] = deepcopy(dict(fixture))
    for case in cases:
        case.pop("_registers", None)
        if not snapshots:
            for key in ("before", "after", "watch"):
                case.pop(key, None)
    return report
