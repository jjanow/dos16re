import json

import pytest

from retrore.dynamic import HardwareIO, RoutineBackend, RoutineRequest, Service, TraceAddressBackend
from retrore.emulator import EmulatorError
from retrore.evidence import ExportEvidence
from retrore.image import M68K_FORMATS, MOS6502_FORMATS, Z80_FORMATS
from retrore.mz import Address, LoadedMZ
from retrore.overlays import build_image
from retrore.pc98 import Pc98Source, build_pc98_image


def _flat(code, image_format, *, linear=0x100, **metadata):
    image = bytes.fromhex(code)
    unit = {"name": "text", "linear": linear, "image_offset": 0, "size": len(image), "file_size": len(image)}
    return RoutineBackend(image, {"format": image_format, "units": [unit], **metadata})


@pytest.mark.parametrize("image_format", M68K_FORMATS)
def test_68k_shared_call_returns_after_nested_jsr(image_format):
    # JSR sub; ADDQ.L #1,D0; RTS; sub: ADDQ.L #1,D0; RTS
    backend = _flat("4eb90000010a 5280 4e75 5280 4e75", image_format)
    routine = RoutineRequest("TEXT:0000", registers={"d0": 8}, limit=5)
    result = backend.run(routine)
    assert result.before.registers["d0"] == 8
    assert result.after.registers["d0"] == 10
    assert result.after.registers["pc"] == result.before.registers["pc"] == 0x100
    assert result.after.registers["a7"] == result.before.registers["a7"]
    assert backend.run(routine) == result
    with pytest.raises(EmulatorError, match="did not return within 4 instructions"):
        backend.run(RoutineRequest(0x100, limit=4))


@pytest.mark.parametrize("image_format", MOS6502_FORMATS)
def test_6502_shared_call_preserves_stack_across_nested_calls(image_format):
    # JSR sub; INX; RTS; sub: INX; STX $20; RTS
    backend = _flat("200503 e8 60 e8 8620 60", image_format, linear=0x300)
    result = backend.run(RoutineRequest("300", registers={"x": 3, "sp": 0}, reads=((0x20, 1),), limit=6))
    assert result.before.memory == ((0x20, bytes(1)),)
    assert result.after.memory == ((0x20, b"\x04"),)
    assert result.after.registers["x"] == 5
    assert result.after.registers["sp"] == result.before.registers["sp"] == 0


@pytest.mark.parametrize("image_format", Z80_FORMATS)
def test_z80_shared_call_resolves_scripted_os_entry_and_full_io_port(image_format):
    # CALL $0005; OUT ($60),A; LD ($2000),A; RET
    backend = _flat("cd0500 d360 320020 c9", image_format)
    routine = RoutineRequest(
        "text:0", registers={"c": 2}, reads=(("2000", 1),), limit=5,
        services=(Service(5, match={"c": 2}, registers={"a": 7}, kind="call"),),
        hardware=(HardwareIO("write", 0x0760, value=7),),
    )
    result = backend.run(routine)
    assert result.after.registers["a"] == 7
    assert result.before.memory == ((0x2000, b"\x00"),)
    assert result.after.memory == ((0x2000, b"\x07"),)
    assert [event["kind"] for event in result.events] == ["call", "io"]
    assert result.after.registers["sp"] == result.before.registers["sp"]


def test_pc98_call_uses_recorded_stack_and_real_mode_services():
    image, program = build_pc98_image([Pc98Source("boot", "boot.bin", 0x200, bytes.fromhex("cd18 cb"))],
                                      "pc98", [])
    program["stack"] = {"segment": 0x8000, "offset": 0x100}
    backend = RoutineBackend(image, program)
    routine = RoutineRequest("boot:0", far=True, registers={"ax": 1},
                             services=(Service(0x18, match={"ax": 1}, registers={"ax": 2}),))
    result = backend.run(routine)
    assert result.address == Address(0x200, 0)
    assert backend.location(result.address) == {"segment": 0x200, "offset": 0, "linear": 0x2000}
    assert result.before.registers["sp"] == result.after.registers["sp"] == 0x100
    assert result.after.registers["ss"] == 0x8000
    assert result.after.registers["ax"] == 2


def test_nes_uses_binary_arithmetic_even_if_decimal_flag_is_set():
    # SED; LDA #9; CLC; ADC #1; RTS
    routine = RoutineRequest(0x100)
    assert _flat("f8 a909 18 6901 60", "APPLE2").run(routine).after.registers["a"] == 0x10
    assert _flat("f8 a909 18 6901 60", "NES").run(routine).after.registers["a"] == 10


def test_nes_mirrors_internal_ram_and_keeps_mapper_writes_off_rom():
    # LDA $0801; STA $1002; STA $8000; RTS
    backend = _flat("ad0108 8d0210 8d0080 60", "NES", linear=0x8000, memory_map=[
        {"name": "prg_rom", "linear": 0x8000, "size": 0x8000, "read": "rom", "write": "mapper"},
    ])
    result = backend.run(RoutineRequest(
        "text:0", writes=((1, b"\x07"),), reads=((1, 2), (0x1802, 1), (0x8000, 1)),
        hardware=(HardwareIO("write", 0x8000, value=7, space="memory"),),
    ))
    assert result.after.memory == ((1, b"\x07\x07"), (0x1802, b"\x07"), (0x8000, b"\xad"))


def test_z80_prefixed_return_counts_as_one_instruction():
    result = _flat("dd fd c9", "X1").run(RoutineRequest("text:0", limit=1))
    assert result.before.registers["sp"] == result.after.registers["sp"]


def test_macintosh_service_receives_a5_world_and_scripted_mmio():
    # A-line trap; MOVE.B $3000,D0; MOVE.B D0,$3001; RTS
    backend = _flat("a123 103900003000 13c000003001 4e75", "MAC68K", a5={"linear": 0x2000})
    routine = RoutineRequest(
        "text:0", reads=((0x3000, 2),),
        services=(Service(0xA123, match={"a5": 0x2000}, kind="aline"),),
        hardware=(HardwareIO("read", 0x3000, value=7, space="memory"),
                  HardwareIO("write", 0x3001, value=7, space="memory")),
    )
    result = backend.run(routine)
    assert result.after.registers["d0"] == 7
    assert result.before.memory == result.after.memory == ((0x3000, bytes(2)),)
    assert [event["kind"] for event in result.events] == ["aline", "io", "io"]


def test_6502_uses_loader_declared_memory_mapped_hardware():
    backend = _flat("ad0020 8d0120 60", "NES", memory_map=[
        {"name": "ppu", "linear": 0x2000, "size": 8, "read": "io", "write": "io"},
    ])
    with pytest.raises(EmulatorError, match="unhandled memory read at 0x2000"):
        backend.run(RoutineRequest(0x100))
    routine = RoutineRequest(
        0x100, reads=((0x2000, 2),),
        hardware=(HardwareIO("read", 0x2000, value=7, space="memory"),
                  HardwareIO("write", 0x2001, value=7, space="memory")),
    )
    result = backend.run(routine)
    assert result.after.registers["a"] == 7
    assert result.before.memory == result.after.memory == ((0x2000, bytes(2)),)


def test_dos_mmio_and_map_identity(tmp_path):
    root = LoadedMZ(0x1000, bytes.fromhex("a00020 a20120 c3"), Address(0x1000, 0), Address(0x2000, 0x200))
    image, program = build_image(root, "dos.exe", [])
    (tmp_path / "image.bin").write_bytes(image)
    (tmp_path / "map.json").write_text(json.dumps(program), encoding="utf-8")
    backend = RoutineBackend.from_export(tmp_path)
    routine = RoutineRequest(
        "root:0", reads=(("0000:2000", 2),),
        hardware=(HardwareIO("read", 0x2000, value=7, space="memory"),
                  HardwareIO("write", 0x2001, value=7, space="memory")),
    )
    result = backend.run(routine)
    assert result.after.registers["ax"] == 7
    assert result.before.memory == result.after.memory == ((Address(0, 0x2000), bytes(2)),)
    identity_with_stack = RoutineBackend(image, {**program, "stack": {"segment": 0x2000, "offset": 0x300}}).identity()
    assert identity_with_stack["image_sha256"] == backend.identity()["image_sha256"]
    assert identity_with_stack["map_sha256"] != backend.identity()["map_sha256"]

    addresses = TraceAddressBackend(ExportEvidence(tmp_path, runtime_base=0x3000))
    assert addresses.linear("3000:0001") == 0x30001
    unit, offset = addresses.location(0x30001)
    assert (unit.name, offset) == ("root", 1)
    assert addresses.location(0x10001) is None
    assert addresses.location(0x10001, {"root": 0x10000}) == (unit, 1)
