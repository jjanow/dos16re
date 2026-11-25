# Resolve a static DOS overlay call

The Pool of Radiance DOS v1.3 loot handler calls `tpov_0085:0ab3`. The call is at
`GAME.OVR` file offset `0x65b4`, and the target is at `0x21aed` in the same file.

Run the commands in Bash from the retrore checkout. Set `RETRORE_POR_DIR` to the
original v1.3 directory and configure [Ghidra](../README.md#ghidra).
The commands use the checkout's virtual environment and `jq`.

```sh
por_work=$(mktemp -d)
por_root="${RETRORE_POR_DIR:?Set RETRORE_POR_DIR}/START.EXE"
[ -f "$por_root" ] || por_root="$RETRORE_POR_DIR/GAME.EXE"
por_bank="$RETRORE_POR_DIR/GAME.OVR"

.venv/bin/retrore load "$por_root" --overlay "$por_bank" -o "$por_work/export" --json > "$por_work/load.json"
.venv/bin/retrore ghidra import "$por_work/export" "$por_work/project" --json > "$por_work/import.json"
caller=$(.venv/bin/retrore address-map 65b4 --from file --source GAME.OVR \
  --export "$por_work/export" --json | jq -er '.matches[0].unit_address')
.venv/bin/retrore disasm "$caller" --limit 5 --fields rows --project "$por_work/project" --json \
  > "$por_work/call.json"
jq '.rows[] | {address, instruction, bytes, references}' "$por_work/call.json"
```

The file lookup gives `tpov_0025:1036`. The disassembly shows a five-byte far call with an
`UNCONDITIONAL_CALL` reference to `tpov_0085:0ab3`. Use the reference's `unit_address` to
identify the callee. Ghidra can display an equivalent segment:offset for the same linear address.

```sh
callee=$(jq -er '.rows[].references[] | select(.type == "UNCONDITIONAL_CALL") | .target.unit_address' \
  "$por_work/call.json")
.venv/bin/retrore bytes "$caller" --size 5 --export "$por_work/export" --json > "$por_work/caller-bytes.json"
.venv/bin/retrore bytes "$callee" --size 1 --export "$por_work/export" --json > "$por_work/callee-bytes.json"

.venv/bin/python - "$por_work" "$por_bank" <<'PY'
import json
import sys
from pathlib import Path
from struct import unpack

work, bank = map(Path, sys.argv[1:])
call, = json.loads((work / "call.json").read_text())["rows"]
caller = json.loads((work / "caller-bytes.json").read_text())
callee = json.loads((work / "callee-bytes.json").read_text())
reference, = [ref for ref in call["references"] if ref["type"] == "UNCONDITIONAL_CALL"]
assert call["kind"] == "instruction" and not call["partial"] and call["size"] == 5
assert call["address"]["unit_address"] == caller["address"]["unit_address"] == "tpov_0025:1036"
assert reference["target"]["unit_address"] == callee["address"]["unit_address"] == "tpov_0085:0ab3"

with bank.open("rb") as source:
    for proof, offset in ((caller, 0x65b4), (callee, 0x21aed)):
        span, = proof["file_spans"]
        assert (span["source"], span["file_offset"]) == ("GAME.OVR", offset)
        source.seek(span["file_offset"])
        assert source.read(proof["size"]).hex() == proof["original"]

relocation, rewrite = caller["evidence"]
assert relocation["kind"] == "relocation" and rewrite["kind"] == "overlay_call"
assert relocation["image_offset"] == caller["address"]["image_offset"] + 3
assert caller["original"][6:] == relocation["before"]
assert rewrite["before"] == caller["original"][:6] + relocation["after"]
assert rewrite["after"] == caller["loaded"] == call["bytes"]
opcode, offset, segment = unpack("<BHH", bytes.fromhex(rewrite["after"]))
assert opcode == 0x9a and segment * 16 + offset == callee["address"]["linear"]
print(f"{callee['address']['unit_address']} at GAME.OVR offset {callee['address']['file']['offset']:#x}")
PY
```

The loader relocates the far pointer's segment word, then rewrites the call from the
resident overlay stub to its overlay body. The byte check follows those two records from
the original file through `image.bin` to Ghidra's instruction.

The [Pool of Radiance regression tests](../tests/test_targets.py) check the same loader target
and confirm that Ghidra decompiles the call. The [benchmark](benchmarks.md#static-overlay-call-dos-3)
uses the project created above.
