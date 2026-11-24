import json

import pytest

from retrore.c64 import PrgUnit, build_c64_image
from retrore.fixtures import FixtureError, load_fixture, run_fixture
from retrore.mz import Address, LoadedMZ
from retrore.overlays import build_image


def _export(path, code):
    root = LoadedMZ(0x1001, bytes.fromhex(code), Address(0x1001, 0), Address(0x2345, 0x200))
    return _write_export(path, *build_image(root, "synthetic.exe", []))


def _write_export(path, image, manifest):
    path.mkdir()
    (path / "image.bin").write_bytes(image)
    (path / "map.json").write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_matrix_and_case_overrides_report_only_changed_observations(tmp_path):
    # add ax,bx; mov [0101],ax; ret
    export = _export(tmp_path / "export", "03c3 a30101 c3")
    fixture = {
        "address": "root:0",
        "registers": {"DS": "0x2000", "BX": 1},
        "memory": {
            "output": {"address": "2000:0100", "data": "fefefe00cc"},
            "unchanged": {"address": "2000:0200", "size": 1},
        },
        "watch": ["AX"],
        "matrix": {"ax": [3, 4], "dx": [0, 1]},
        "cases": [{"name": "base"}, {"name": "override", "registers": {"bx": 5},
                                     "memory": {"output": {"data": "fefefe00dd"}}}],
    }
    report = run_fixture(export, fixture)
    assert report["passed"]
    assert len(report["cases"]) == 8
    first, last = report["cases"][0], report["cases"][-1]
    assert first["name"] == "base [ax=0x3, dx=0x0]"
    assert last["name"] == "override [ax=0x4, dx=0x1]"
    assert "before" not in first
    assert "after" not in first
    assert first["changes"]["registers"] == {"ax": {"before": 3, "after": 4}}
    assert set(first["changes"]["memory"]) == {"output"}
    assert first["changes"]["memory"]["output"]["ranges"] == [{"offset": 1, "before": "fefe", "after": "0400"}]
    assert last["changes"]["registers"] == {"ax": {"before": 4, "after": 9}}


def test_services_ports_assertions_and_snapshot_replay(tmp_path):
    export = _export(tmp_path / "export", "cd21 e460 e660 c3")  # int 21h; in al,60h; out 60h,al; ret
    fixture = {
        "address": "root:0", "registers": {"ax": "0x100"},
        "memory": {"result": {"address": "2000:0100", "size": 1}},
        "expect": {"registers": {"ax": "0x1342"}, "memory": {"result": "bf"}},
        "services": [{"number": "0x21", "match": {"ax": "0x100"}, "registers": {"ax": "0x1300"},
                      "writes": {"2000:0100": "bf"}}],
        "hardware": [{"address": "0x60", "operation": "read", "value": "0x42"},
                     {"address": "0x60", "operation": "write", "value": "0x42"}],
    }
    report = run_fixture(export, fixture, snapshots=True)
    assert report["passed"], report
    case, = report["cases"]
    assert case["before"]["memory"] == {"result": "00"}
    assert case["after"]["memory"] == {"result": "bf"}
    assert case["after"]["registers"]["ax"] == 0x1342
    assert "sp" not in case["changes"]["registers"]
    assert [event["kind"] for event in case["events"]] == ["interrupt", "io", "io"]
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(json.dumps(report), encoding="utf-8")
    assert run_fixture(export, load_fixture(snapshot), snapshots=True) == report
    other = _export(tmp_path / "other", "90 cd21 e460 e660 c3")
    with pytest.raises(FixtureError, match="different export"):
        run_fixture(other, load_fixture(snapshot))

    broken = run_fixture(export, fixture | {"expect": {"registers": {"ax": 1}}})
    assert not broken["passed"]
    assert broken["cases"][0]["failures"] == [{"kind": "register", "name": "ax", "actual": 0x1342, "expected": 1}]
    wrong_io = fixture["hardware"] + [{"address": "0x60", "operation": "read", "value": 1}]
    broken = run_fixture(export, fixture | {"hardware": wrong_io})
    assert not broken["passed"]
    assert broken["cases"][0]["failures"][0]["kind"] == "execution"

    map_path = export / "map.json"
    manifest = json.loads(map_path.read_text(encoding="utf-8"))
    manifest["stack"]["offset"] += 2
    map_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(FixtureError, match="different export"):
        run_fixture(export, load_fixture(snapshot))


def test_differential_comparison_uses_case_and_memory_labels(tmp_path):
    export = _export(tmp_path / "export", "40 a30001 c3")                # inc ax; mov [0100],ax; ret
    release = _export(tmp_path / "release", "90 40 a30002 c3")          # nop; inc ax; mov [0200],ax; ret
    changed = _export(tmp_path / "changed", "90 40 40 a30002 c3")       # nop; inc ax; inc ax; mov [0200],ax; ret
    fixture = {
        "address": "root:0", "watch": ["ax"], "registers": {"ax": 5, "ds": "0x2000"},
        "memory": {"result": {"address": "2000:0100", "size": 2}},
    }
    other_fixture = fixture | {
        "address": "root:1", "registers": {"ax": 5, "ds": "0x3000"},
        "memory": {"result": {"address": "3000:0200", "size": 2}},
    }
    equal = run_fixture(export, fixture, against_export=release, against_fixture=other_fixture)
    assert equal["passed"]
    assert not equal["comparison"]["differences"]
    different = run_fixture(export, fixture, against_export=changed, against_fixture=other_fixture)
    assert not different["passed"]
    assert different["comparison"]["differences"] == [
        {"case": "default", "kind": "register", "name": "ax", "actual": 6, "reference": 7},
        {"case": "default", "kind": "memory", "name": "result", "actual": "0600", "reference": "0700"},
    ]
    python_result = 5 + 1
    reference_report = {"cases": [{"name": "default", "after": {"registers": {"ax": python_result}}}]}
    compared = run_fixture(export, fixture | {"watch": []}, against_report=reference_report)
    assert compared["passed"]
    assert not compared["cases"][0]["changes"]["registers"]


def test_compare_across_cpu_architectures_using_only_named_memory(tmp_path):
    dos = _export(tmp_path / "dos", "40 a30001 c3")  # inc ax; mov [0100],ax; ret
    prg = PrgUnit("root", "sample.prg", bytes.fromhex("0008 a906 8d0020 60"))  # LDA #6; STA $2000; RTS
    c64 = _write_export(tmp_path / "c64", *build_c64_image([prg], "sample.prg"))
    fixture = {
        "address": "root:0", "registers": {"ax": 5, "ds": "0x2000"}, "watch": [],
        "memory": {"result": {"address": "2000:0100", "size": 2}},
    }
    reference = {"address": "0800", "watch": [], "memory": {"result": {"address": "2000", "size": 2}}}
    assert run_fixture(dos, fixture, against_export=c64, against_fixture=reference)["passed"]


def test_snapshot_comparison_rejects_inconsistent_state(tmp_path):
    export = _export(tmp_path / "export", "40 c3")
    fixture = {"address": "root:0", "memory": {"area": {"address": "2000:0100", "size": 1}}}
    report = run_fixture(export, fixture, snapshots=True)
    report["cases"][0]["after"]["memory"]["area"] = "0000"
    with pytest.raises(FixtureError, match="same size before and after"):
        run_fixture(export, fixture, against_report=report)


@pytest.mark.parametrize(("fixture", "error"), [
    ({"version": True}, "unsupported fixture version"),
    ({"matrix": {"ax": [1, "0x1"]}}, "distinct input values"),
    ({"cases": [{"name": "one"}, {"name": "one"}]}, "distinct"),
    ({"expect": {"memory": {"unknown": "cc"}}}, "unknown expect.memory field"),
    ({"memory": {"result": {"address": "2000:0100", "size": 1, "data": "0000"}}}, "exceeds its watched size"),
])
def test_invalid_fixture_fails_before_execution(tmp_path, fixture, error):
    export = _export(tmp_path / "export", "c3")
    with pytest.raises(FixtureError, match=error):
        run_fixture(export, {"address": "root:0"} | fixture)
