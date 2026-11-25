import json
import os
from collections import Counter, deque
from io import BytesIO
from pathlib import Path
from struct import pack, pack_into, unpack_from

import pytest
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, x86_const as x86

from retrore.cli import main
from retrore.emulator import Emulator
from retrore.load_manifest import apply_load_manifest
from retrore.mz import Address


_BIOS_KEYS = {
    "enter": 0x1c0d, "esc": 0x011b, "left": 0x4b00, "right": 0x4d00, "up": 0x4800, "down": 0x5000,
}


class _KeyboardExhausted(Exception):
    pass


class _DosSession:
    """DOS and BIOS services used by this opt-in playthrough."""

    def __init__(self, files, keys, window, window_end, *, clock_dx):
        self.files = files
        self.keys = deque(_BIOS_KEYS[key] if key in _BIOS_KEYS else ord(key) for key in keys)
        self.window = window
        self.window_end = window_end
        self.clock_dx = clock_dx
        self.handles = {}
        self.heap = 0x6000
        self.ports = {}
        self.overlay_reads = []
        self.data_reads = []

    def dos(self, cpu, _number):
        ax, bx, cx, dx, ds = cpu.reg_read_batch((
            x86.UC_X86_REG_AX, x86.UC_X86_REG_BX, x86.UC_X86_REG_CX, x86.UC_X86_REG_DX, x86.UC_X86_REG_DS,
        ))
        service, subfunction = divmod(ax, 0x100)
        carry = 0
        if service == 0x30:
            cpu.reg_write(x86.UC_X86_REG_AX, 0x1606)
        elif service == 0x35:
            offset, segment = unpack_from("<HH", cpu.mem_read(subfunction * 4, 4))
            cpu.reg_write(x86.UC_X86_REG_BX, offset)
            cpu.reg_write(x86.UC_X86_REG_ES, segment)
        elif service == 0x25:
            cpu.mem_write(subfunction * 4, pack("<HH", dx, ds))
        elif service == 0x3d:
            filename = cpu.mem_read(Address(ds, dx).linear, 128).split(b"\0", 1)[0].decode("ascii")
            name = filename.rsplit("\\", 1)[-1].upper()
            path = self.files.get(name)
            if path is None:
                cpu.reg_write(x86.UC_X86_REG_AX, 2)
                carry = 1
            else:
                handle = max(self.handles, default=4) + 1
                self.handles[handle] = name, BytesIO(path.read_bytes())
                cpu.reg_write(x86.UC_X86_REG_AX, handle)
        elif service == 0x42:
            _, stream = self.handles[bx]
            displacement = int.from_bytes(pack("<HH", dx, cx), "little", signed=True)
            position = stream.seek(displacement, subfunction)
            cpu.reg_write(x86.UC_X86_REG_AX, position & 0xffff)
            cpu.reg_write(x86.UC_X86_REG_DX, position >> 16)
        elif service == 0x3f:
            name, stream = self.handles[bx]
            position = stream.tell()
            data = stream.read(cx)
            address = Address(ds, dx).linear
            if data:
                cpu.mem_write(address, data)
            if name == "MAIN.EXE" and self.window <= address < self.window_end:
                self.overlay_reads.append((position, address, len(data)))
                cpu.ctl_remove_cache(self.window, self.window_end)
            elif name in ("DNGS.DAT", "MONSTERS.CGA"):
                self.data_reads.append((name, position, len(data)))
            cpu.reg_write(x86.UC_X86_REG_AX, len(data))
        elif service == 0x3e:
            if bx in self.handles:
                _, stream = self.handles.pop(bx)
                stream.close()
        elif service == 0x19:
            cpu.reg_write(x86.UC_X86_REG_AX, 0x1902)
        elif service == 0x47:
            cpu.mem_write(Address(ds, cpu.reg_read(x86.UC_X86_REG_SI)).linear, b"\0")
        elif service == 0x48:
            cpu.reg_write(x86.UC_X86_REG_AX, self.heap)
            self.heap += bx + 1
        elif service in (0x49, 0x4a):
            pass
        elif ax == 0x4300:
            cpu.reg_write(x86.UC_X86_REG_CX, 0x20)
        elif ax == 0x4400:
            cpu.reg_write(x86.UC_X86_REG_DX, 0x80 if bx < 5 else 0)
        elif service == 0x0b:
            cpu.reg_write(x86.UC_X86_REG_AX, 0x0b00)
        elif service == 0x2a:
            cpu.reg_write(x86.UC_X86_REG_AX, 2)
            cpu.reg_write(x86.UC_X86_REG_CX, 1991)
            cpu.reg_write(x86.UC_X86_REG_DX, 0x0612)
        elif service == 0x2c:
            cpu.reg_write(x86.UC_X86_REG_CX, 0x0c00)
            cpu.reg_write(x86.UC_X86_REG_DX, self.clock_dx)
        elif service == 0x40:
            assert bx < 5  # The route can write to the DOS console.
            cpu.reg_write(x86.UC_X86_REG_AX, cx)
        else:
            pytest.fail(f"unexpected DOS service AX={ax:04x}")
        cpu.reg_write(x86.UC_X86_REG_EFLAGS, cpu.reg_read(x86.UC_X86_REG_EFLAGS) & ~1 | carry)

    def bios(self, cpu, number):
        service = cpu.reg_read(x86.UC_X86_REG_AX) >> 8
        if number == 0x10:
            if service == 0x0f:
                cpu.reg_write(x86.UC_X86_REG_AX, 0x5003)
            else:
                assert service in (0, 1, 2, 0x0b, 0x0c, 0x10, 0x11, 0x12)
        elif number == 0x11:
            cpu.reg_write(x86.UC_X86_REG_AX, 0x21)
        elif number == 0x1a:
            cpu.reg_write(x86.UC_X86_REG_CX, 0)
            cpu.reg_write(x86.UC_X86_REG_DX, 0x1234)
            cpu.reg_write(x86.UC_X86_REG_AX, 0)
        else:
            assert number == 0x16 and service in (0, 1)
            if not self.keys:
                raise _KeyboardExhausted
            if service == 1:
                cpu.reg_write(x86.UC_X86_REG_EFLAGS, cpu.reg_read(x86.UC_X86_REG_EFLAGS) & ~0x40)
            cpu.reg_write(x86.UC_X86_REG_AX, self.keys.popleft() if service == 0 else self.keys[0])

    def port_in(self, _cpu, port, _size):
        value = self.ports.get(port, 0) ^ 9
        self.ports[port] = value
        return value


def _enter_archives_keys(*, wizard=False):
    class_keys = ["down"] * 5 if wizard else []
    return [
        # Create a human in the Guild and add her to the party.
        "y", "left", "enter", "down", "down", "down", "enter", "enter", *class_keys, "enter",
        "left", "enter", "a", "d", "a", "enter", "esc", "enter", "down", "down", "enter", "enter", "esc",
        # Leave Pendragon, enter the archives, and use the original map.
        "left", "left", "left", "enter", "y", "down", "down", "right", "y", "n", "n",
    ]


def _archives_keys():
    return [
        *_enter_archives_keys(),
        # Reach the west room at (2, 10), answer the quiz, and keep the scroll.
        *(["down"] * 6), *(["left"] * 5), *(["down"] * 4), *(["left"] * 4), "down", "enter", "y",
        # Meet a wandering group in the west passage and fight one round.
        *(["right"] * 4), *(["down"] * 4), "enter", "enter", "esc",
    ]


def _fireflash_keys():
    return [
        *_enter_archives_keys(wizard=True),
        # Turn down the west passage and take the wandering encounter.
        *(["down"] * 6), *(["left"] * 5), "down", "down", "enter", "enter",
        # Select the wizard, choose Cast Spell and Fireflash I, and start the round.
        "enter", *(["down"] * 4), "enter", "enter", "enter", "esc",
    ]


def _gold_keys():
    return [
        *_enter_archives_keys(),
        # Circle through the south corridor to the hidden room at (12, 13).
        *(["down"] * 6), *(["left"] * 5), *(["down"] * 10), *(["right"] * 10),
        *(["up"] * 3), *(["left"] * 4), "enter",
        # Leave and reenter the gold square.
        "right", "left",
    ]


@pytest.mark.parametrize(("route", "keys", "clock_dx"), [
    pytest.param("scroll", _archives_keys(), 0x0120, id="scroll"),
    pytest.param("fireflash", _fireflash_keys(), 0x0500, id="fireflash"),
    pytest.param("gold", _gold_keys(), 0x0b00, id="gold"),
])
def test_phantasie_iii_archives_event_trace(tmp_path, capsys, route, keys, clock_dx):
    directory = os.environ.get("RETRORE_PH3_DIR")
    if not directory:
        pytest.skip("set RETRORE_PH3_DIR to the original DOS game directory")
    files = {path.name.upper(): path for path in Path(directory).iterdir() if path.is_file()}
    required = {
        "MAIN.EXE", "CREATURE.DAT", "DNGS.DAT", "DTOWN.CMP", "INITARMS.DAT", "MONSTERS.CGA",
        "PICS.CMP", "SHAPES.CGA", "TOWN.CMP", "WORLD.CGA", "WORLD.DAT",
    }
    if missing := required - files.keys():
        pytest.skip(f"the archives playthrough needs the DOS media files {', '.join(sorted(missing))}")
    files = {name: files[name] for name in required}
    export = tmp_path / "export"
    assert main(["load", str(files["MAIN.EXE"]), "-o", str(export), "--json"]) == 0, capsys.readouterr().err
    capsys.readouterr()
    map_path = export / "map.json"
    program = json.loads(map_path.read_text(encoding="utf-8"))
    image = (export / "image.bin").read_bytes()
    units = {unit["name"]: unit for unit in program["units"]}
    base = units["root"]["segment"]
    origin = units["root"]["linear"]
    dungeon = units["link_0004"]
    window = dungeon["runtime_linear"]
    long_member = units["link_0002"]
    casting = route == "fireflash"
    combat = route != "gold"
    # The DOS clock seeds the encounter and turn order in each playthrough.
    dos = _DosSession(files, keys, window, window + long_member["size"], clock_dx=clock_dx)

    psp, environment = base - 0x10, base - 0x110
    prefix = bytearray(0x100)
    pack_into("<HH", prefix, 0, 0x20cd, 0xa000)
    pack_into("<H", prefix, 0x2c, environment)
    prefix[0x81] = 0x0d
    entry = Address(program["entry"]["segment"], program["entry"]["offset"])

    callbacks = Address(base + 0x28c0, 0x1dce).linear
    magic = Address(base + 0x1820, 0x0254).linear
    party_gold = Address(base + 0x1820, 0x09de).linear
    detached = {origin + offset for offset in (0x6383, 0x68a4, 0x6a12)}
    bottom = Address(base + 0x180a, 0xa0).linear
    record_end = bottom + 15 * 12
    class_values = {False: set(), True: set()}
    fpu_dispatches = Counter()
    installed_callbacks = []
    callback_reads = []
    detached_hits = []
    checkpoints = []
    edges = Counter()
    instruction_bytes = {}
    keep_item, round_return = origin + 0xf421, origin + 0x10783
    round_start, cast_dispatch, fireflash = origin + 0xd8c7, origin + 0xcaac, origin + 0xb42e
    event_lookup = window + 0x12e2
    milestones = {
        "scroll": (keep_item, round_return), "fireflash": (cast_dispatch, fireflash, round_return), "gold": (),
    }[route]
    expected_edges = {}
    if combat:
        expected_edges.update({
            (origin + 0xd5c4, origin + 0xd631): 1,
            (origin + 0x721d, origin + 0x10424): 1,
            (origin + 0x1046a, origin + 0x104b9): 1,
        })
    expected_edges.update({
        "scroll": {(window + 0x1534, window + 0x156e): 1},
        "fireflash": {(origin + 0xc3ea, origin + 0xc3ef): 1},
        "gold": {(window + 0x1534, window + 0x15e7): 1},
    }[route])
    tile_dispatch = window + 0x05c1
    flows = {source: "jump" for source, _ in expected_edges}
    flows[tile_dispatch] = "jump"
    if combat:
        flows[origin + 0x721d] = "call"
    magic_values = []
    gold_visits = []
    entered = False
    prior = None

    def code(cpu, address, size, _data):
        nonlocal entered, prior
        if address == window + 0x062d and dos.overlay_reads and dos.overlay_reads[-1][0] == dungeon["file_offset"]:
            entered = True
        if address == origin + 0x6028:  # The initializer just copied the five far pointers.
            offset, segment = unpack_from("<HH", cpu.mem_read(callbacks + 8, 4))
            installed_callbacks.append(Address(segment, offset).linear)
        if address in detached:
            detached_hits.append(address)
        if address == origin + 0x1249b:
            fpu_dispatches[entered] += 1
        if entered:
            if address in milestones:
                checkpoints.append(address)
            if casting and address in (round_start, cast_dispatch, round_return):
                magic_values.append((address, unpack_from("<H", cpu.mem_read(magic, 2))[0]))
            if route == "gold" and address == event_lookup:
                es, bx, si = cpu.reg_read_batch((x86.UC_X86_REG_ES, x86.UC_X86_REG_BX, x86.UC_X86_REG_SI))
                event_flag = cpu.mem_read(Address(es, (bx + si) & 0xffff).linear, 1)[0]
                gold_visits.append((event_flag, unpack_from("<I", cpu.mem_read(party_gold, 4))[0]))
            if prior is not None:
                edges[prior, address] += 1
                instruction_bytes[address] = cpu.mem_read(address, size).hex()
            prior = address if address in flows else None
            if prior is not None:
                instruction_bytes[address] = cpu.mem_read(address, size).hex()

    def setup(cpu):
        ticks = 0

        def clock(cpu, _access, _address, _size, _value, _data):
            nonlocal ticks
            ticks += 1
            cpu.mem_write(0x46c, pack("<I", ticks // 2))

        def read_callback(_cpu, _access, address, size, _value, _data):
            if address + size > callbacks:
                callback_reads.append(address)

        def write_record(_cpu, _access, address, size, value, _data):
            for field in range(max(address, bottom), min(address + size, record_end)):
                if (field - bottom) % 12 == 11:
                    class_values[entered].add((value >> (8 * (field - address))) & 0xff)

        cpu.hook_add(UC_HOOK_MEM_READ, clock, begin=0x46c, end=0x46f)
        cpu.hook_add(UC_HOOK_MEM_READ, read_callback, begin=callbacks - 15, end=callbacks + 19)
        cpu.hook_add(UC_HOOK_MEM_WRITE, write_record, begin=bottom - 15, end=record_end - 1)
        cpu.hook_add(UC_HOOK_CODE, code)
        return lambda: None

    emulator = Emulator(image, program)
    with pytest.raises(_KeyboardExhausted):
        emulator.call(
            entry, regs={"ds": psp, "es": psp},
            writes=[(Address(psp, 0), bytes(prefix)),
                    (Address(environment, 0), b"NO87=\0\0\x01\0C:\\MAIN.EXE\0")],
            interrupts={0x21: dos.dos, **{number: dos.bios for number in (0x10, 0x11, 0x16, 0x1a)}},
            ivt_interrupts=range(0x32, 0x40), on_in=dos.port_in,
            on_out=lambda _cpu, _port, _size, _value: None, _setup=setup, limit=15_000_000,
        )
    assert entered
    # Member 4 replaces the prefix of the most recent member 2 load, after member 3.
    archive_load = dos.overlay_reads.index((dungeon["file_offset"], window, dungeon["size"]))
    assert archive_load >= 2
    assert dos.overlay_reads[archive_load - 1][0] == units["link_0003"]["file_offset"]
    assert dos.overlay_reads[archive_load - 2][:2] == (long_member["file_offset"] + 0x4000, window + 0x4000)
    assert ("DNGS.DAT", 0, 0x1080) in dos.data_reads
    if combat:
        assert any(name == "MONSTERS.CGA" and size > 0 for name, _, size in dos.data_reads)
    assert checkpoints == list(milestones)
    if casting:
        assert magic_values == [(round_start, 7), (cast_dispatch, 6), (round_return, 6)]
    if route == "gold":
        # The interpreter clears the event after the first award. Reentering finds the cleared byte.
        assert gold_visits == [(0x81, 0), (0xff, 256)]
    assert installed_callbacks == [origin + 0x6a12]
    assert not callback_reads and not detached_hits
    assert fpu_dispatches[False] > 0 and fpu_dispatches[True] == 0
    assert class_values == {False: {0, 1}, True: set()}
    tile_targets = {target - window for source, target in edges if source == tile_dispatch}
    expected_tiles = {0x05c6, 0x05cd, 0x05d4, 0x05db, 0x05e2, 0x05e9, 0x05f0}
    if casting:
        expected_tiles -= {0x05cd, 0x05db}
    assert tile_targets == expected_tiles
    assert {edge: count for edge, count in edges.items() if edge[0] != tile_dispatch} == expected_edges

    loads = [{"unit": "root"}]
    loads.extend({"unit": name, "linear": window, "replace": True} for name in ("link_0002", "link_0004"))
    manifest = tmp_path / "archive-loads.json"
    manifest.write_text(json.dumps({
        "version": 1, "initial": "root",
        "states": [{"name": "root", "loads": [{"unit": "root"}]}, {"name": "archives", "loads": loads}],
        "transitions": [{"from": "root", "to": "archives", "kind": "overlay"}],
    }), encoding="utf-8")
    apply_load_manifest(manifest, image, program)
    map_path.write_text(json.dumps(program), encoding="utf-8")

    events = [{"kind": "overlay", "state": "archives"}]
    events.extend({"kind": "instruction", "address": address, "bytes": data}
                  for address, data in instruction_bytes.items())
    events.extend({"kind": "edge", "from": source, "to": target, "count": count, "flow": flows[source]}
                  for (source, target), count in edges.items())
    trace = tmp_path / "archives.json"
    trace.write_text(json.dumps({"version": 1, "events": events}), encoding="utf-8")
    command = ["trace", str(trace), "--export", str(export), "--evidence", "--json"]
    assert main(command) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert {(edge["from"]["runtime_linear"], edge["to"]["runtime_linear"]): edge["count"]
            for edge in report["edges"]} == edges
    for edge in report["edges"]:
        for where in (edge["from"], edge["to"]):
            address = where["runtime_linear"]
            if window <= address < window + dungeon["size"]:
                offset = address - window
                assert where["location"]["unit_address"] == f"link_0004:{offset:04x}"
                assert where["export_evidence"]["address"]["file"]["offset"] == dungeon["file_offset"] + offset
            else:
                assert where["location"]["unit_address"] == f"root:{address - origin:04x}"
        assert edge["flow"] == flows[edge["from"]["runtime_linear"]]

    if os.environ.get("GHIDRA_HOME"):
        project = tmp_path / "ph3"
        assert main(["ghidra", "import", str(export), str(project), "--json"]) == 0, capsys.readouterr().err
        capsys.readouterr()
        assert main([*command, "--project", str(project), "--apply"]) == 0, capsys.readouterr().err
        analysis = json.loads(capsys.readouterr().out)["analysis"]
        assert analysis["missed"] == []
        assert {row["event"] for row in analysis["edge_gaps"]} == {
            event for row in analysis["applied"] if row["kind"] == "flow" for event in row["events"]
        }
        if combat:
            assert main(["indirect", "--at", "root:721d", "--project", str(project), "--compact", "--json"]) == 0
            menu, = json.loads(capsys.readouterr().out)["sites"]
            assert menu["status"] == "resolved" and "root:10424" in menu["targets"]
