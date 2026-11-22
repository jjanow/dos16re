import json
from struct import pack, pack_into

import pytest
from unicorn.x86_const import UC_X86_REG_AX, UC_X86_REG_CX, UC_X86_REG_DX

from dos16re.cli import main
from dos16re.emulator import Emulator, EmulatorError
from dos16re.mz import Address, LoadedMZ
from dos16re.overlays import Overlay, build_image


def _emulator(code):
    root = LoadedMZ(0x1001, bytes.fromhex(code), Address(0x1001, 0), Address(0x2345, 0x200))
    return Emulator(*build_image(root, "synthetic.exe", []))


def test_cli_calls_non_aligned_entry_and_reads_back_state(tmp_path, capsys):
    # add ax,[bp+2]; add ax,[0100]; mov [0102],ax; ret 2
    code = bytes(19) + bytes.fromhex("89e5 034602 03060001 a30201 c20200")
    header = pack("<2s13H4x", b"MZ", 32 + len(code), 1, 0, 2, 0, 0, 0x400, 0x200, 0, 3, 1, 0, 0)
    program, output = tmp_path / "test.exe", tmp_path / "export"
    program.write_bytes(header + code)
    assert main(["load", str(program), "-o", str(output)]) == 0
    capsys.readouterr()

    assert main([
        "call", "1001:0003", "--export", str(output), "--regs", "ax=7,ds=2222", "--regs", "bx=10",
        "--mem", "1400:0200=0300", "--mem", "2222:0100=0200", "--read", "2222:0102=2",
        "--limit", "5", "--json",
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["address"] == {"segment": 0x1001, "offset": 3, "linear": 0x10013}
    assert report["registers"]["ax"] == 12
    assert report["registers"]["bx"] == 0x10
    assert report["registers"]["sp"] == 0x202
    assert report["memory"] == [
        {"address": {"segment": 0x2222, "offset": 0x102, "linear": 0x22322}, "data": "0c00"}
    ]

    assert main(["call", "root:ffff", "--export", str(output), "--json"]) == 1
    error = json.loads(capsys.readouterr().err)["error"]
    assert "offset outside unit" in error


def test_recursive_near_call_stops_after_consuming_original_frame():
    # dec cx; jz done; call entry; done: inc ax; ret
    emulator = _emulator("49 7403 e8faff 40 c3")
    countdown = []

    result = emulator.call("ROOT:0", regs={"cx": 3}, limit=14, hooks={
        "root:0": lambda cpu: countdown.append(cpu.reg_read(UC_X86_REG_CX)),
    })
    assert countdown == [3, 2, 1]
    assert result.registers["ax"] == 3
    with pytest.raises(EmulatorError, match="did not return within 13 instructions"):
        emulator.call("root:0", regs={"cx": 3}, limit=13)


def test_calls_relocated_overlay_and_redirects_original_interrupt_stub():
    root = bytearray(80)
    pack_into("<BHHB", root, 0, 0x9A, 0x20, 0x1001, 0xC3)
    pack_into("<HHI4H", root, 16, 0x3FCD, 0, 8, 4, 0, 1, 0)
    pack_into("<HHB", root, 48, 0x3FCD, 0, 0)
    bank = pack("<4sI", b"FBOV", 4) + bytes.fromhex("b83412 cb")
    loaded = LoadedMZ(0x1000, root, Address(0x1000, 0), Address(0x2345, 0x200), (Address(0, 3),))
    image, manifest = build_image(loaded, "synthetic.exe", [Overlay("code.ovr", "code", bank)])
    emulator = Emulator(image, manifest)

    assert emulator.call("root:0").registers["ax"] == 0x1234
    assert emulator.call("tpov_0001:0", far=True).registers["ax"] == 0x1234
    assert emulator.call("1001:0020", far=True).registers["ax"] == 0x1234
    stub = manifest["stubs"][0]
    assert emulator.call("1001:0020", far=True, writes=[
        ("1001:0020", bytes.fromhex(stub["original"])),
        ("tpov_0001:1", bytes.fromhex("7856")),
    ]).registers["ax"] == 0x5678
    assert emulator.call("1001:0020", far=True).registers["ax"] == 0x1234


def test_hooks_supply_interrupt_and_port_io():
    emulator = _emulator("cd10 cd16 cd21 cd1a e560 ef c3")
    interrupts, outputs = [], []

    def interrupt(cpu, number):
        interrupts.append(number)
        cpu.reg_write(UC_X86_REG_DX, 0x3D4)

    def port_in(cpu, port, size):
        assert (port, size) == (0x60, 2)
        assert cpu.reg_read(UC_X86_REG_AX) == 0
        return 0x1234

    result = emulator.call("root:0", interrupts=dict.fromkeys((0x10, 0x16, 0x21, 0x1A), interrupt),
                           on_in=port_in, on_out=lambda cpu, *event: outputs.append(event))
    assert interrupts == [0x10, 0x16, 0x21, 0x1A]
    assert outputs == [(0x3D4, 2, 0x1234)]
    assert result.registers["ax"] == 0x1234


@pytest.mark.parametrize(("code", "error"), [
    ("cd21c3", "unhandled interrupt 21h at 1001:0000"),
    ("e460c3", "unhandled IN from port 0060h"),
    ("e660c3", "unhandled OUT to port 0060h"),
    ("ebfe", "did not return within 5 instructions"),
    ("f4", "did not return within 5 instructions"),
])
def test_unhandled_io_and_nonreturning_routines_fail(code, error, capsys):
    with pytest.raises(EmulatorError, match=error):
        _emulator(code).call("root:0", limit=5)
    assert not capsys.readouterr().err
