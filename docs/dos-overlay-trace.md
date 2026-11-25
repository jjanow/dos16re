# Identify a DOS call in a reused overlay window

In the Phantasie III DOS wilderness encounter, LINK member 3 calls `root:de54` from
`link_0003:0239`. The call instruction starts at `MAIN.EXE` file offset `0x21639`.

Run the commands from the retrore checkout with the [test dependencies](../README.md#tests)
installed. Set `RETRORE_PH3_DIR` to the directory containing the original DOS `MAIN.EXE` and
its companion game files. The [decline test](../tests/test_phantasie_iii_dungeon.py) walks north
from Pendragon and declines the encounter. It captures the call from live emulation, checks the
overlay reads, and writes the trace and export into pytest's temporary directory.

```sh
ph3_work=$(mktemp -d)
: "${RETRORE_PH3_DIR:?Set RETRORE_PH3_DIR}"
.venv/bin/python -m pytest -q \
  'tests/test_phantasie_iii_dungeon.py::test_phantasie_iii_wilderness_encounter_trace[decline]' \
  --basetemp "$ph3_work/run"
capture=$(find "$ph3_work/run" -type f -name trace.json -print)
test -f "$capture"
ph3_export="${capture%/*}/export"
.venv/bin/retrore trace "$capture" --export "$ph3_export" --evidence --json > "$ph3_work/report.json"
```

The capture's overlay event activates the manifest's `wilderness` state before execution
records are mapped. Its ordered loads place member 2 in the shared window, then place member 3
at the same address. Member 3 owns the prefix of the resulting state and member 2 still owns the
tail. Use the observed edge and its source file evidence to identify the caller.

```sh
.venv/bin/python - "$ph3_work/report.json" "$ph3_export/map.json" "$RETRORE_PH3_DIR" <<'PY'
import json
import sys
from pathlib import Path

report_path, map_path, game_dir = map(Path, sys.argv[1:])
report = json.loads(report_path.read_text())
program = json.loads(map_path.read_text())
transition, = report["transitions"]
state, = [state for state in program["load_manifest"]["states"] if state["name"] == transition["to"]]
assert transition["kind"] == "overlay" and state["name"] == "wilderness"
town, wilderness = state["loads"][-2:]
assert (town["unit"], wilderness["unit"]) == ("link_0002", "link_0003")
assert town["linear"] == wilderness["linear"] and wilderness["replace"]

edge, = [edge for edge in report["edges"] if edge["from"]["location"]["unit_address"] == "link_0003:0239"]
assert transition["event"] < edge["event"] and edge["flow"] == "call" and edge["count"] == 1
caller, callee = edge["from"], edge["to"]
assert callee["location"]["unit_address"] == "root:de54"
span, = [span for span in state["spans"] if span["unit"] == "link_0003"]
assert span["linear"] <= caller["runtime_linear"] < span["linear"] + span["size"]

proof = caller["export_evidence"]
file = proof["address"]["file"]
member, = [unit for unit in program["units"] if unit["name"] == file["member_id"] == span["unit"]]
offset = file["offset"]
assert file["source"] == "MAIN.EXE" and offset == 0x21639
assert member["file_offset"] <= offset < member["file_offset"] + member["size"]
assert offset == member["file_offset"] + span["offset"] + caller["runtime_linear"] - span["linear"]
source_path, = [path for path in game_dir.iterdir() if path.name.upper() == file["source"]]
with source_path.open("rb") as source:
    source.seek(offset)
    original = source.read(1).hex()
assert original == proof["original"]
hit, = [hit for hit in report["mapped"] if hit["unit_address"] == caller["location"]["unit_address"]]
observed, = hit["observed_bytes"]
assert observed[:2] == proof["loaded"] == original
print(f"Observed {caller['location']['unit_address']} -> {callee['location']['unit_address']}")
print(f"Confirmed the first instruction byte at {file['source']} offset {offset:#x}")
PY
```

The observed successor gives the call target. The active manifest span maps the caller's runtime
address to member 3 and supplies the file coordinate for the byte check.
