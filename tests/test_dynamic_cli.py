import json

from retrore.cli import main


def test_fixture_cli_compares_snapshot_and_signals_difference(tmp_path, capsys):
    program, export = tmp_path / "sample.prg", tmp_path / "export"
    program.write_bytes(bytes.fromhex("0008 a92a 8d0020 60"))  # LDA #$2a; STA $2000; RTS
    assert main(["load", str(program), "--c64", "-o", str(export)]) == 0
    capsys.readouterr()

    specification = tmp_path / "routine.json"
    specification.write_text(json.dumps({
        "version": 1, "address": "0800", "watch": ["a"],
        "memory": {"output": {"address": "2000", "size": 1}},
        "expect": {"registers": {"a": 42}, "memory": {"output": "2a"}},
    }), encoding="utf-8")
    command = ["fixture", str(specification), "--export", str(export), "--json"]
    assert main(command[:-1]) == 0
    assert "output+0 00 → 2a" in capsys.readouterr().out
    assert main([*command, "--snapshots"]) == 0, capsys.readouterr().err
    result = json.loads(capsys.readouterr().out)
    assert result["passed"]

    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(result), encoding="utf-8")
    assert main(["fixture", str(baseline), "--export", str(export), "--snapshots", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == result

    assert main([*command, "--against-report", str(baseline)]) == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["passed"]

    result["cases"][0]["after"]["memory"]["output"] = "29"
    baseline.write_text(json.dumps(result), encoding="utf-8")
    assert main([*command, "--against-report", str(baseline)]) == 1
    assert not json.loads(capsys.readouterr().out)["passed"]


def test_call_cli_runs_flat_address_routine(tmp_path, capsys):
    program, export = tmp_path / "sample.prg", tmp_path / "export"
    program.write_bytes(bytes.fromhex("0008 a92a 8d0020 60"))  # LDA #$2a; STA $2000; RTS
    assert main(["load", str(program), "--c64", "-o", str(export)]) == 0
    capsys.readouterr()

    assert main(["call", "0800", "--export", str(export), "--read", "2000=1", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["address"]["linear"] == 0x0800
    assert result["registers"]["a"] == 42
    assert result["memory"][0]["data"] == "2a"
