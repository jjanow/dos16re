import json
import os

import pytest

from retrore import worker
from retrore.cli import main
from retrore.compare import _compare, _storage_blocks


def _listing(language, *functions):
    return {"program": "fixture", "language": language, "sha256": "", "functions": list(functions)}


def _routine(identifier, body, *, name=None, calls=(), data=()):
    return {"id": identifier, "address": identifier, "unit": "text", "offset": int(identifier, 16),
            "name": name or f"FUN_{identifier}", "stable_name": name, "instructions": 3,
            "fingerprint": body, "raw_sha256": body, "calls": list(calls), "external_calls": [], "data": list(data)}


def test_cross_port_uses_named_and_call_data_evidence():
    before = _listing("6502", _routine("10", "old", name="_entry"),
                      _routine("20", "same", calls=("10",), data=("string_sha256:waiting",)),
                      _routine("30", "shared"))
    after = _listing("68000", _routine("110", "new", name="entry"),
                     _routine("120", "same", calls=("110",), data=("string_sha256:waiting",)),
                     _routine("130", "shared"))
    report = _compare(before, after, 100, 0)
    assert [(row["before"]["address"], row["after"]["address"], row["matched_by"], row["status"])
            for row in report["matches"]] == [
        ("10", "110", "symbol", "cross_port_candidate"),
        ("20", "120", "call_graph_and_data", "cross_port_candidate"),
    ]
    shared = report["matches"][1]["evidence"]["shared"]
    assert shared["callees"] == {"count": 1, "examples": ["match:10"]}
    assert shared["data"]["count"] == 1
    assert report["unpaired_before"][0]["candidate_count"] == 0  # ISA fingerprints are separate.


def test_duplicate_bodies_remain_ambiguous_and_paged():
    before = _listing("6502", _routine("10", "duplicate"), _routine("20", "duplicate"))
    after = _listing("6502", _routine("110", "duplicate"), _routine("120", "duplicate"))
    report = _compare(before, after, 1, 0)
    assert report["matches"] == []
    assert report["counts"]["ambiguous_before"] == 2
    assert report["pagination"]["unpaired_before"] == {"offset": 0, "total": 2, "returned": 1, "next_offset": 1}
    unpaired, = report["unpaired_before"]
    assert unpaired["candidate_count"] == 2
    assert [row["address"] for row in unpaired["candidates"]] == ["110", "120"]
    assert unpaired["candidates"][0]["matched_by"] == ["normalized_instructions"]


def test_storage_block_matches_require_unique_names_or_contents():
    def block(unit, start, digest=None, **overrides):
        return {"unit": unit, "start": start, "size": 32, "space": "ram", "type": "DEFAULT",
                "initialized": True, "read": True, "write": True, "execute": False,
                "content_sha256": digest} | overrides

    before = [block("stable", "1000"), block("renamed", "1100", "one"),
              block("shrunk", "1200", "old"), block("changed", "1300", "three"),
              block("padding", "1400"), block("repeated", "1500", "four"),
              block("duplicate", "1600", "five"), block("duplicate", "1700", "six"),
              block("already_matched", "1800", "seven"), block("also_seven", "1900", "seven")]
    after = [block("stable", "2000"), block("new_name", "2100", "one"),
             block("shrunk", "2200", "new", size=16), block("changed", "2300", "three", execute=True),
             block("different_padding", "2400"), block("first_copy", "2500", "four"),
             block("second_copy", "2600", "four"), block("would_match", "2700", "five"),
             block("already_matched", "2800", "seven"), block("new_seven", "2900", "seven")]
    assert _storage_blocks(before, after) == [
        {"unit": "stable", "space": "ram", "size": 32, "before_start": "1000", "after_start": "2000"},
        {"unit": "renamed", "space": "ram", "size": 32, "before_start": "1100", "after_start": "2100",
         "after_unit": "new_name", "after_size": 32},
        {"unit": "shrunk", "space": "ram", "size": 32, "before_start": "1200", "after_start": "2200",
         "after_unit": "shrunk", "after_size": 16},
        {"unit": "already_matched", "space": "ram", "size": 32, "before_start": "1800", "after_start": "2800"},
    ]


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="set GHIDRA_HOME to run the Ghidra integration test")
def test_compare_projects_normalizes_moved_operands_and_flags_changed_body(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv(worker.TRANSPORT_ENV, "tcp")
    projects = []
    for base, value in ((0x2000, 7), (0x3000, 8)):
        suffix = f"{base:04x}"
        source = tmp_path / f"demo-{suffix}.prg"
        export, project = (tmp_path / f"{prefix}-{suffix}" for prefix in ("export", "project"))
        reference = (base + 0x10).to_bytes(2, "little")
        data = (base + 0x40).to_bytes(2, "little")
        image = bytearray(0x42)
        image[:9] = b"\x20" + reference + b"\xad" + data + bytes.fromhex("85 01 60")
        image[0x10:0x15] = bytes([0xA9, value, 0xAA, 0xE8, 0x60])
        image[0x20:0x28] = b"\x20" + reference + bytes.fromhex("e9 01 e6 02 60")
        source.write_bytes(base.to_bytes(2, "little") + image)
        assert main(["load", str(source), "--entry", suffix, "--entry", f"{base + 0x20:04x}",
                     "-o", str(export)]) == 0, capsys.readouterr().err
        assert main(["ghidra", "import", str(export), str(project)]) == 0, capsys.readouterr().err
        capsys.readouterr()
        projects.append(project)
    worker.start(projects[0])
    try:
        assert main(["compare", *map(str, projects), "--instructions", "--json"]) == 0, capsys.readouterr().err
        report = json.loads(capsys.readouterr().out)
        assert worker.status(projects[0])["requests"] == 1
    finally:
        worker.stop(projects[0])
    assert report["counts"]["same_body"] == 2 and report["counts"]["changed_candidate"] == 1
    calls = [row for row in report["matches"] if row["status"] == "same_body"]
    assert all(not row["evidence"]["same_raw_instruction_bytes"] for row in calls)
    main_match = next(row for row in calls if row["before"]["offset"] == 0)
    assert "name:CPU_PORT_DATA" in main_match["evidence"]["shared"]["data"]["examples"]
    assert main_match["instruction_map"][1] == {"before": {"unit": "root", "offset": 3},
                                               "after": {"unit": "root", "offset": 3}}
    changed, = [row for row in report["matches"] if row["status"] == "changed_candidate"]
    assert "instruction_map" not in changed
    assert changed["matched_by"] == "call_graph_and_data"
    assert (changed["before"]["offset"], changed["after"]["offset"]) == (0x10, 0x10)
    assert changed["evidence"]["shared"]["callers"]["count"] == 2
