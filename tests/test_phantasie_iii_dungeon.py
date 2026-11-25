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

    def __init__(self, files, keys, window, window_end, *, clock_dx, heap=0x6000):
        self.files = files
        self.keys = deque(_BIOS_KEYS[key] if key in _BIOS_KEYS else ord(key) for key in keys)
        self.window = window
        self.window_end = window_end
        self.clock_dx = clock_dx
        self.handles = {}
        self.heap = heap
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
            elif name in ("DNGS.DAT", "MONSTERS.CGA", "WORLD.DAT"):
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


def _leave_pendragon_keys(*, wizard=False):
    class_keys = ["down"] * 5 if wizard else []
    return [
        # Create a human in the Guild and add her to the party.
        "y", "left", "enter", "down", "down", "down", "enter", "enter", *class_keys, "enter",
        "left", "enter", "a", "d", "a", "enter", "esc", "enter", "down", "down", "enter", "enter", "esc",
        # Leave Pendragon.
        "left", "left", "left", "enter", "y",
    ]


def _enter_archives_keys(*, wizard=False):
    # Enter the archives and use the original map.
    return [*_leave_pendragon_keys(wizard=wizard), "down", "down", "right", "y", "n", "n"]


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


def _load_game(tmp_path, capsys, *additional_files):
    directory = os.environ.get("RETRORE_PH3_DIR")
    if not directory:
        pytest.skip("set RETRORE_PH3_DIR to the original DOS game directory")
    files = {path.name.upper(): path for path in Path(directory).iterdir() if path.is_file()}
    required = {
        "MAIN.EXE", "CREATURE.DAT", "DTOWN.CMP", "INITARMS.DAT", "PICS.CMP", "SHAPES.CGA",
        "TOWN.CMP", "WORLD.CGA", "WORLD.DAT", *additional_files,
    }
    if missing := required - files.keys():
        pytest.skip(f"the Phantasie III playthrough needs the DOS media files {', '.join(sorted(missing))}")
    files = {name: files[name] for name in required}
    export = tmp_path / "export"
    assert main(["load", str(files["MAIN.EXE"]), "-o", str(export), "--json"]) == 0, capsys.readouterr().err
    capsys.readouterr()
    program = json.loads((export / "map.json").read_text(encoding="utf-8"))
    image = (export / "image.bin").read_bytes()
    return files, export, program, image


def _play_game(image, program, dos, active_member, entry_offset, observe, *, observe_startup=False):
    root = program["units"][0]
    base, origin = root["segment"], root["linear"]
    psp, environment = base - 0x10, base - 0x110
    prefix = bytearray(0x100)
    pack_into("<HH", prefix, 0, 0x20cd, 0xa000)
    pack_into("<H", prefix, 0x2c, environment)
    prefix[0x81] = 0x0d
    entry = Address(program["entry"]["segment"], program["entry"]["offset"])

    callbacks = Address(base + 0x28c0, 0x1dce).linear
    detached = {origin + offset for offset in (0x6383, 0x68a4, 0x6a12)}
    bottom = Address(base + 0x180a, 0xa0).linear
    record_end = bottom + 15 * 12
    class_values = {False: set(), True: set()}
    fpu_dispatches = Counter()
    installed_callbacks = []
    callback_reads = []
    detached_hits = []
    argument_returns = []
    entered = False
    route_entry = active_member["runtime_linear"] + entry_offset

    def code(cpu, address, size, _data):
        nonlocal entered
        if address == route_entry and dos.overlay_reads and dos.overlay_reads[-1][0] == active_member["file_offset"]:
            entered = True
        if address == origin + 0x6028:  # The initializer just copied the five far pointers.
            offset, segment = unpack_from("<HH", cpu.mem_read(callbacks + 8, 4))
            installed_callbacks.append(Address(segment, offset).linear)
        if address == origin + 0x4621:  # The argument builder jumps to the far return saved on entry.
            ds = cpu.reg_read(x86.UC_X86_REG_DS)
            assert ds == base + 0x28c0
            offset, segment = unpack_from("<HH", cpu.mem_read(Address(ds, 0x1d9e).linear, 4))
            argument_returns.append(Address(segment, offset).linear)
        if address in detached:
            detached_hits.append(address)
        if address == origin + 0x1249b:
            fpu_dispatches[entered] += 1
        if entered or observe_startup:
            observe(cpu, address, size)

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
    assert argument_returns == [origin + 0x4264]
    assert installed_callbacks == [origin + 0x6a12]
    assert not callback_reads and not detached_hits
    assert fpu_dispatches[False] > 0 and fpu_dispatches[True] == 0
    assert class_values == {False: {0, 1}, True: set()}


class _EdgeTrace:
    def __init__(self, flows):
        self.flows = flows
        self.edges = Counter()
        self.instruction_bytes = {}
        self.prior = None

    def observe(self, cpu, address, size):
        if self.prior is not None:
            self.edges[self.prior, address] += 1
            self.instruction_bytes[address] = cpu.mem_read(address, size).hex()
        self.prior = address if address in self.flows else None
        if self.prior is not None:
            self.instruction_bytes[address] = cpu.mem_read(address, size).hex()


@pytest.mark.parametrize(("route", "keys", "clock_dx"), [
    pytest.param("scroll", _archives_keys(), 0x0120, id="scroll"),
    pytest.param("fireflash", _fireflash_keys(), 0x0500, id="fireflash"),
    pytest.param("gold", _gold_keys(), 0x0b00, id="gold"),
])
def test_phantasie_iii_archives_event_trace(tmp_path, capsys, route, keys, clock_dx):
    files, export, program, image = _load_game(tmp_path, capsys, "DNGS.DAT", "MONSTERS.CGA")
    units = {unit["name"]: unit for unit in program["units"]}
    base, origin = units["root"]["segment"], units["root"]["linear"]
    dungeon = units["link_0004"]
    window = dungeon["runtime_linear"]
    long_member = units["link_0002"]
    casting = route == "fireflash"
    combat = route != "gold"
    dos = _DosSession(files, keys, window, window + long_member["size"], clock_dx=clock_dx)
    magic = Address(base + 0x1820, 0x0254).linear
    party_gold = Address(base + 0x1820, 0x09de).linear
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
    trace = _EdgeTrace(flows)
    tables = {
        tile_dispatch: (dungeon, 0x05f7, 7),
        window + 0x1534: (dungeon, 0x1aea, 27),
        origin + 0xc3ea: (units["root"], 0x15a1, 24),
        origin + 0xd5c4: (units["root"], 0x2563, 15),
        origin + 0x1046a: (units["root"], 0x0ae9, 8),
    }
    table_edges = Counter()
    checkpoints, magic_values, gold_visits = [], [], []

    def observe(cpu, address, size):
        if address in milestones:
            checkpoints.append(address)
        if casting and address in (round_start, cast_dispatch, round_return):
            magic_values.append((address, unpack_from("<H", cpu.mem_read(magic, 2))[0]))
        if route == "gold" and address == event_lookup:
            es, bx, si = cpu.reg_read_batch((x86.UC_X86_REG_ES, x86.UC_X86_REG_BX, x86.UC_X86_REG_SI))
            event_flag = cpu.mem_read(Address(es, (bx + si) & 0xffff).linear, 1)[0]
            gold_visits.append((event_flag, unpack_from("<I", cpu.mem_read(party_gold, 4))[0]))
        if address in tables:
            unit, table, slots = tables[address]
            cs, bx = cpu.reg_read_batch((x86.UC_X86_REG_CS, x86.UC_X86_REG_BX))
            assert bx % 2 == 0 and bx // 2 < slots
            assert cpu.mem_read(address, size) == b"\x2e\xff\xa7" + pack("<H", table)
            slot = Address(cs, table + bx).linear
            unit_start = unit.get("runtime_linear", origin)
            assert unit_start <= slot <= unit_start + unit["size"] - 2
            source = unit["image_offset"] + slot - unit_start
            word = cpu.mem_read(slot, 2)
            assert word == image[source:source + 2]
            target, = unpack_from("<H", word)
            table_edges[address, Address(cs, target).linear] += 1
        trace.observe(cpu, address, size)

    _play_game(image, program, dos, dungeon, 0x062d, observe)
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
    edges = trace.edges
    assert table_edges == {edge: count for edge, count in edges.items() if edge[0] in tables}
    tile_targets = {target - window for source, target in edges if source == tile_dispatch}
    expected_tiles = {0x05c6, 0x05cd, 0x05d4, 0x05db, 0x05e2, 0x05e9, 0x05f0}
    if casting:
        expected_tiles -= {0x05cd, 0x05db}
    assert tile_targets == expected_tiles
    assert {edge: count for edge, count in edges.items() if edge[0] != tile_dispatch} == expected_edges

    project = _check_trace(tmp_path, capsys, export, program, image, "archives", dungeon, trace)
    if project is not None and combat:
        assert main(["indirect", "--at", "root:721d", "--project", str(project), "--compact", "--json"]) == 0
        menu, = json.loads(capsys.readouterr().out)["sites"]
        assert menu["status"] == "resolved" and "root:10424" in menu["targets"]


def test_phantasie_iii_wilderness_inn_trace(tmp_path, capsys):
    files, export, program, image = _load_game(tmp_path, capsys)
    units = {unit["name"]: unit for unit in program["units"]}
    base, origin = units["root"]["segment"], units["root"]["linear"]
    wilderness, town = units["link_0003"], units["link_0002"]
    window = wilderness["runtime_linear"]
    # Walk north to the Jolly Inn, accept the offer, dismiss the refusal, and return to town.
    keys = [*_leave_pendragon_keys(), *(["up"] * 5), "y", "enter", *(["down"] * 5), "y"]
    dos = _DosSession(files, keys, window, window + town["size"], clock_dx=0x0120)
    travel = window + 0x02f3
    encounter = window + 0x0239
    enter_place = window + 0x01bc
    inn_choice = window + 0x0869
    price_check = window + 0x08e1
    trace = _EdgeTrace({
        travel: "call", encounter: "call", enter_place: "call", inn_choice: "jump", price_check: "jump",
    })
    far_data = Address(base + 0x1820, 0).linear
    visits = []
    outcomes = []

    def observe(cpu, address, size):
        trace.observe(cpu, address, size)
        if address == enter_place:
            x, y = unpack_from("<HH", cpu.mem_read(far_data + 0x4882, 4))
            days_out, = unpack_from("<I", cpu.mem_read(far_data + 0x09e2, 4))
            visits.append((x, y, days_out))
        if address == window + 0x091d:
            gold, = unpack_from("<I", cpu.mem_read(far_data + 0x09de, 4))
            outdoors, = unpack_from("<H", cpu.mem_read(far_data + 0x487c, 2))
            in_town, = unpack_from("<H", cpu.mem_read(far_data + 0xe596, 2))
            outcomes.append((gold, outdoors, in_town))

    _play_game(image, program, dos, wilderness, 0x0088, observe)
    assert ("WORLD.DAT", 0, 0x0ea6) in dos.data_reads
    assert dos.overlay_reads[-2][:2] == (town["file_offset"] + 0x4000, window + 0x4000)
    assert dos.overlay_reads[-1][:2] == (wilderness["file_offset"], window)
    assert visits == [(24, 32, 5), (24, 37, 10)]
    assert outcomes == [(0, 1, 0), (0, 0, 1)]
    assert trace.edges == {
        (travel, origin + 0x14a9): 10,
        (encounter, origin + 0xde54): 8,
        (enter_place, window + 0x06c8): 2,
        (inn_choice, window + 0x08cc): 1,
        (price_check, window + 0x08fb): 1,
    }
    _check_trace(tmp_path, capsys, export, program, image, "wilderness", wilderness, trace)


@pytest.mark.parametrize("attack", [False, True], ids=["decline", "attack"])
def test_phantasie_iii_wilderness_encounter_trace(tmp_path, capsys, attack):
    files, export, program, image = _load_game(tmp_path, capsys, *(("MONSTERS.CGA",) if attack else ()))
    units = {unit["name"]: unit for unit in program["units"]}
    base, origin = units["root"]["segment"], units["root"]["linear"]
    wilderness, town = units["link_0003"], units["link_0002"]
    window = wilderness["runtime_linear"]
    # The first road step finds sleeping monsters. The attack route completes one round.
    keys = ["y", "enter", "enter", "esc"] if attack else ["n"]
    dos = _DosSession(files, [*_leave_pendragon_keys(), "up", *keys], window, window + town["size"], clock_dx=0x1700)
    encounter = window + 0x0239
    sleeping_prompt = origin + 0xdf35
    decline = origin + 0xdf3f
    skip_combat = origin + 0xe020
    combat = origin + 0xe062
    menu_call = origin + 0x721d
    round_return = origin + 0x10783
    trace = _EdgeTrace({
        encounter: "call", sleeping_prompt: "call", decline: "jump", skip_combat: "jump", combat: "call",
        menu_call: "call", origin + 0x1046a: "jump",
    })
    far_data = Address(base + 0x1820, 0).linear
    dgroup = base + 0x28c0
    selection = far_data + 0xb5a8
    menu, descriptor = Address(dgroup, 0x0834), Address(dgroup, 0x095e)
    positions = []
    declined = []
    selection_writes = []
    menu_targets = []
    rounds = []

    def read_pointer(cpu, linear):
        offset, segment = unpack_from("<HH", cpu.mem_read(linear, 4))
        return Address(segment, offset)

    def observe(cpu, address, size):
        trace.observe(cpu, address, size)
        if address == sleeping_prompt:
            positions.append(unpack_from("<HH", cpu.mem_read(far_data + 0x4882, 4)))
        if address == skip_combat:
            declined.append(unpack_from("<H", cpu.mem_read(far_data + 0xb578, 2))[0])
        if address in (origin + 0x103b3, origin + 0x103ba):
            # Each instruction executes immediately after one half of the selection pointer is stored.
            assert cpu.reg_read(x86.UC_X86_REG_ES) * 16 == far_data
            word = selection if address == origin + 0x103b3 else selection + 2
            selection_writes.append(unpack_from("<H", cpu.mem_read(word, 2))[0])
        if address == menu_call:
            assert read_pointer(cpu, selection) == menu
            assert read_pointer(cpu, menu.linear + 6) == descriptor
            es, bx = cpu.reg_read_batch((x86.UC_X86_REG_ES, x86.UC_X86_REG_BX))
            assert Address(es, bx) == descriptor
            target = read_pointer(cpu, descriptor.linear + 4)
            template = descriptor.linear + 4 - origin
            assert cpu.mem_read(descriptor.linear + 4, 4) == image[template:template + 4]
            menu_targets.append(target.linear)
        if address == round_return:
            rounds.append(address)

    _play_game(image, program, dos, wilderness, 0x0088, observe)
    assert positions == [(24, 36)]
    town_start, town_tail, wilderness_read = dos.overlay_reads[-3:]
    assert town_start == (town["file_offset"], window, 0x4000)
    assert town_tail[:2] == (town["file_offset"] + 0x4000, window + 0x4000)
    assert wilderness_read[:2] == (wilderness["file_offset"], window)
    assert wilderness["size"] <= wilderness_read[2] < town["size"]
    expected_edges = {
        (encounter, origin + 0xde54): 1,
        (sleeping_prompt, origin + 0xe294): 1,
    }
    if attack:
        assert any(name == "MONSTERS.CGA" and size > 0 for name, _, size in dos.data_reads)
        assert selection_writes == [menu.offset, menu.segment]
        assert menu_targets == [origin + 0x10424]
        assert not declined and rounds == [round_return]
        expected_edges.update({
            (combat, origin + 0x104c0): 1,
            (menu_call, origin + 0x10424): 1,
            (origin + 0x1046a, origin + 0x104b9): 1,
        })
    else:
        assert declined == [1]
        assert not selection_writes and not menu_targets and not rounds
        expected_edges.update({(decline, origin + 0xdff9): 1, (skip_combat, origin + 0xe0a3): 1})
    assert trace.edges == expected_edges
    _check_trace(tmp_path, capsys, export, program, image, "wilderness", wilderness, trace)


@pytest.mark.parametrize("heap", [0x6000, 0x6200], ids=["heap-6000", "heap-6200"])
def test_phantasie_iii_runtime_heap_trace(tmp_path, capsys, heap):
    files, export, program, image = _load_game(tmp_path, capsys, "DNGS.DAT", "MONSTERS.CGA")
    units = {unit["name"]: unit for unit in program["units"]}
    base, origin = units["root"]["segment"], units["root"]["linear"]
    dungeon = units["link_0004"]
    window = dungeon["runtime_linear"]
    far_data = base + 0x1820
    dgroup = base + 0x28c0
    selector_slot = Address(dgroup, 0x1dc6)
    map_pointer = Address(far_data, 0xb63c)
    dos = _DosSession(files, _archives_keys(), window, window + units["link_0002"]["size"],
                      clock_dx=0x0120, heap=heap)
    events = []
    sampled_tile = None
    reading_tiles = tile_checked = False

    def access(kind, pc, address, data):
        events.append({"kind": "memory", "access": kind, "pc": pc, "address": str(address),
                       "size": len(data), "bytes": data.hex()})

    def observe(cpu, address, _size):
        nonlocal sampled_tile, reading_tiles, tile_checked
        if address == origin + 0x4f05:
            # DOS Allocate just returned the segment to _brkctl.
            ax, bx, flags = cpu.reg_read_batch((x86.UC_X86_REG_AX, x86.UC_X86_REG_BX, x86.UC_X86_REG_EFLAGS))
            assert (ax, bx, flags & 1) == (heap, 0xec, 0)
            events.append({"kind": "snapshot", "pc": address, "registers": {"ax": ax, "bx": bx}})
        elif address == origin + 0x4cf7:
            assert cpu.mem_read(selector_slot.linear, 2) == pack("<H", heap)
            access("write", address - 3, selector_slot, pack("<H", heap))
        elif address == origin + 0x4cbc:
            # The far allocator's epilogue preserves the returned pointer in DX:AX.
            ax, dx = cpu.reg_read_batch((x86.UC_X86_REG_AX, x86.UC_X86_REG_DX))
            if (dx, ax) == (heap, 0x1a9c):
                events.append({"kind": "snapshot", "pc": address, "registers": {"ax": ax, "dx": dx}})
        elif address == window + 0x062d and dos.overlay_reads[-1][0] == dungeon["file_offset"]:
            events.append({"kind": "overlay", "state": "archives"})
            reading_tiles = True
        elif reading_tiles and sampled_tile is None and address == window + 0x131b:
            es, bx, si = cpu.reg_read_batch((x86.UC_X86_REG_ES, x86.UC_X86_REG_BX, x86.UC_X86_REG_SI))
            pointer = pack("<HH", si, es)
            assert (es, si) == (heap, 0x1a9c)
            assert cpu.mem_read(map_pointer.linear, 4) == pointer
            access("read", window + 0x1316, map_pointer, pointer)
            tile = Address(es, (bx + si + 1) & 0xffff)
            sampled_tile = bytes(cpu.mem_read(tile.linear, 1))
            access("read", address, tile, sampled_tile)
        elif sampled_tile is not None and not tile_checked and address == window + 0x131f:
            assert cpu.reg_read(x86.UC_X86_REG_AL) == sampled_tile[0]
            events.append({"kind": "instruction", "address": address})
            tile_checked = True

    _play_game(image, program, dos, dungeon, 0x062d, observe, observe_startup=True)
    signatures = {item["name"]: item for item in program["runtime_signatures"]}
    for name, offset in (("_brkctl", 0x4eac), ("_fmalloc", 0x4c83)):
        assert signatures[name]["unit_offset"] == offset and signatures[name]["result_registers"] == ["DX", "AX"]
    assert signatures["_ffree"]["unit_offset"] == 0x4c6e
    assert signatures["_ffree"]["parameters"][0]["type"] == "farptr"
    _route_manifest(tmp_path, export, program, image, "archives", dungeon)
    trace = tmp_path / "heap.json"
    trace.write_text(json.dumps({"version": 1, "events": events}), encoding="utf-8")
    assert main(["trace", str(trace), "--export", str(export), "--evidence", "--json"]) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    allocation, allocated_pointer = report["snapshots"]
    assert allocation["pc"]["location"]["unit_address"] == "root:4f05"
    assert allocated_pointer["pc"]["location"]["unit_address"] == "root:4cbc"
    assert allocated_pointer["registers"] == {"ax": 0x1a9c, "dx": heap}
    write, pointer_read, tile_read = report["memory"]
    assert write["pc"]["location"]["unit_address"] == "root:4cf4"
    assert pointer_read["pc"]["location"]["unit_address"] == "link_0004:1316"
    assert tile_read["location"] is None and tile_read["spans"][0]["location"] is None
    assert heap * 16 + 0x1a9c <= tile_read["runtime_linear"] < heap * 16 + 0x2e4c
    assert tile_read["pc"]["export_evidence"]["address"]["file"]["offset"] == dungeon["file_offset"] + 0x131b
    tile_result, = report["mapped"]
    assert tile_result["unit_address"] == "link_0004:131f"


def _route_manifest(tmp_path, export, program, image, state, active_member):
    window = active_member["runtime_linear"]
    loads = [{"unit": "root"}]
    loads.extend({"unit": name, "linear": window, "replace": True}
                 for name in ("link_0002", active_member["name"]))
    manifest = tmp_path / "loads.json"
    manifest.write_text(json.dumps({
        "version": 1, "initial": "root",
        "states": [{"name": "root", "loads": [{"unit": "root"}]}, {"name": state, "loads": loads}],
        "transitions": [{"from": "root", "to": state, "kind": "overlay"}],
    }), encoding="utf-8")
    apply_load_manifest(manifest, image, program)
    (export / "map.json").write_text(json.dumps(program), encoding="utf-8")


def _check_trace(tmp_path, capsys, export, program, image, state, active_member, trace):
    window = active_member["runtime_linear"]
    origin = program["units"][0]["linear"]
    _route_manifest(tmp_path, export, program, image, state, active_member)
    events = [{"kind": "overlay", "state": state}]
    events.extend({"kind": "instruction", "address": address, "bytes": data}
                  for address, data in trace.instruction_bytes.items())
    events.extend({"kind": "edge", "from": source, "to": target, "count": count, "flow": trace.flows[source]}
                  for (source, target), count in trace.edges.items())
    trace_path = tmp_path / "trace.json"
    trace_path.write_text(json.dumps({"version": 1, "events": events}), encoding="utf-8")
    command = ["trace", str(trace_path), "--export", str(export), "--evidence", "--json"]
    assert main(command) == 0, capsys.readouterr().err
    report = json.loads(capsys.readouterr().out)
    assert {(edge["from"]["runtime_linear"], edge["to"]["runtime_linear"]): edge["count"]
            for edge in report["edges"]} == trace.edges
    for edge in report["edges"]:
        for where in (edge["from"], edge["to"]):
            address = where["runtime_linear"]
            if window <= address < window + active_member["size"]:
                offset = address - window
                assert where["location"]["unit_address"] == f"{active_member['name']}:{offset:04x}"
                assert where["export_evidence"]["address"]["file"]["offset"] == active_member["file_offset"] + offset
            else:
                assert where["location"]["unit_address"] == f"root:{address - origin:04x}"
        assert edge["flow"] == trace.flows[edge["from"]["runtime_linear"]]

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
        return project
    return None
