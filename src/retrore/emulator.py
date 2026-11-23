"""Call routines from a relocated DOS image with Unicorn."""

import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from struct import pack
from sys import maxsize

from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from capstone.x86 import X86_INS_RET, X86_INS_RETF
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_INTR, UC_HOOK_MEM_READ, UC_MODE_16
from unicorn import Uc, UcError, x86_const as x86

from .image import check_map_version
from .mz import Address

DEFAULT_INSTRUCTION_LIMIT = 1_000_000
_IMAGE_LIMIT = 0x100000
_MEMORY_SIZE = 0x110000  # Includes the high-memory area reachable with A20 enabled.
_WORD_MASK = 0xFFFF
_REGISTERS = {
    name.lower(): getattr(x86, f"UC_X86_REG_{name}")
    for name in ("AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP", "CS", "IP", "DS", "ES", "SS", "FS", "GS", "FLAGS")
}
_SETTABLE = _REGISTERS.keys() - {"cs", "ip"}

AddressInput = str | Address
Interrupt = Callable[[Uc, int], None]
PortIn = Callable[[Uc, int, int], int]
PortOut = Callable[[Uc, int, int, int], None]
CodeHook = Callable[[Uc], None]


class EmulatorError(ValueError):
    """An invalid call request or an emulated routine that did not return."""


@dataclass(frozen=True)
class CallResult:
    address: Address
    registers: dict[str, int]
    memory: tuple[tuple[Address, bytes], ...]


def _word(value: int) -> bool:
    return type(value) is int and 0 <= value <= _WORD_MASK


def _map_address(record: dict) -> Address:
    segment, offset = record["segment"], record["offset"]
    if not _word(segment) or not _word(offset):
        raise ValueError("invalid segment or offset")
    return Address(segment, offset)


def _pc(uc: Uc) -> Address:
    return Address(uc.reg_read(x86.UC_X86_REG_CS), uc.reg_read(x86.UC_X86_REG_IP))


class Emulator:
    """Launch independent calls with a copy of an image built by `retrore load`."""

    def __init__(self, image: bytes, program_map: dict) -> None:
        self._image = bytes(image)
        self._units: dict[str, tuple[int, int]] = {}
        check_map_version(program_map)
        try:
            if program_map.get("format", "MZ") != "MZ":
                raise ValueError("routine emulation requires a DOS MZ image")
            units = program_map["units"]
            self._origin = units[0]["linear"]
            if type(self._origin) is not int or not 0 <= self._origin <= self._origin + len(image) <= _IMAGE_LIMIT:
                raise ValueError("image extends past the 1 MiB image limit")
            for unit in units:
                segment, size, name = unit["segment"], unit["size"], unit["name"].casefold()
                start = unit["image_offset"]
                if not _word(segment) or type(start) is not int or segment * 16 != self._origin + start:
                    raise ValueError(f"invalid placement for unit {name}")
                if type(size) is not int or not 0 <= start <= start + size <= len(image):
                    raise ValueError(f"unit {name} extends outside the image")
                self._units[name] = (segment, size)
            self._stack = _map_address(program_map["stack"])
            self._stubs = {
                _map_address(stub["address"]).linear: _map_address(stub["target"])
                for stub in program_map.get("stubs", ())
            }
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as error:
            raise EmulatorError(f"invalid program map: {error}") from error

    @classmethod
    def from_export(cls, export: Path) -> "Emulator":
        try:
            program_map = json.loads((export / "map.json").read_text(encoding="utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise EmulatorError(f"invalid map.json: {error}") from error
        return cls((export / "image.bin").read_bytes(), program_map)

    def resolve(self, address: AddressInput) -> Address:
        """Resolve a 16-bit segment:offset or case-insensitive unit:offset."""
        if isinstance(address, Address) and _word(address.segment) and _word(address.offset):
            return address
        match = re.fullmatch(r"([^:]+):([0-9a-fA-F]{1,4})", address) if isinstance(address, str) else None
        if not match:
            raise EmulatorError(f"expected a 16-bit seg:off or unit:offset address, got {address}")
        name, text = match.groups()
        offset = int(text, 16)
        unit = self._units.get(name.casefold())
        if unit is not None:
            segment, size = unit
            if offset >= size:
                raise EmulatorError(f"offset outside unit {name}: {offset:04x}")
            return Address(segment, offset)
        if not re.fullmatch(r"[0-9a-fA-F]{1,4}", name):
            raise EmulatorError(f"unknown unit or invalid segment: {name}")
        return Address(int(name, 16), offset)

    @staticmethod
    def _check_span(address: Address, size: int) -> None:
        if type(size) is not int or not 0 < size <= _MEMORY_SIZE - address.linear:
            raise EmulatorError(f"invalid memory size at {address}: {size}")

    def call(
        self,
        address: AddressInput,
        *,
        regs: Mapping[str, int] | None = None,
        writes: Iterable[tuple[AddressInput, bytes]] = (),
        reads: Iterable[tuple[AddressInput, int]] = (),
        far: bool = False,
        limit: int = DEFAULT_INSTRUCTION_LIMIT,
        interrupts: Mapping[int, Interrupt] | None = None,
        on_in: PortIn | None = None,
        on_out: PortOut | None = None,
        hooks: Mapping[AddressInput, CodeHook] | None = None,
    ) -> CallResult:
        """Set up state and run to a 16-bit RET or RETF. Hooks receive the live Unicorn CPU."""
        if type(limit) is not int or not 0 < limit < maxsize:
            raise EmulatorError("instruction limit must be a positive supported integer")
        start = self.resolve(address)
        initial = {"ss": self._stack.segment, "sp": self._stack.offset, "flags": 2}
        for name, value in (regs or {}).items():
            register = name.lower()
            if register not in _SETTABLE:
                raise EmulatorError(f"cannot set register {name} through regs")
            if not _word(value):
                raise EmulatorError(f"{name} must be a 16-bit unsigned value")
            initial[register] = value

        patches = [(self.resolve(where), data) for where, data in writes]
        requests = [(self.resolve(where), size) for where, size in reads]
        for where, data in patches:
            self._check_span(where, len(data))
        for where, size in requests:
            self._check_span(where, size)
        if not (
            any(segment * 16 <= start.linear < segment * 16 + size for segment, size in self._units.values())
            or any(where.linear <= start.linear < where.linear + len(data) for where, data in patches)
        ):
            raise EmulatorError(f"routine address {start} is outside initialized memory")

        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, _MEMORY_SIZE)
        if self._image:
            uc.mem_write(self._origin, self._image)
        for where, data in patches:
            uc.mem_write(where.linear, data)
        io_error = self._install_io(uc, interrupts or {}, on_in, on_out)
        returned = self._install_return(uc, start, initial, far, hooks or {})
        for name, value in initial.items():
            uc.reg_write(_REGISTERS[name], value)
        uc.reg_write(x86.UC_X86_REG_CS, start.segment)

        try:
            uc.emu_start(start.linear, _MEMORY_SIZE, count=limit)
        except UcError as error:
            raise EmulatorError(f"emulation failed at {_pc(uc)}: {error}") from error
        if (error := io_error()) is not None:
            raise error
        if not returned() or _pc(uc) != start:
            raise EmulatorError(f"routine did not return within {limit} instructions (stopped at {_pc(uc)})")

        registers = {name: uc.reg_read(register) for name, register in _REGISTERS.items()}
        memory = tuple((where, bytes(uc.mem_read(where.linear, size))) for where, size in requests)
        return CallResult(start, registers, memory)

    def _install_return(
        self, uc: Uc, start: Address, initial: dict[str, int], far: bool, hooks: Mapping[AddressInput, CodeHook],
    ) -> Callable[[], bool]:
        # Use the entry itself as the return address so a near call needs no spare
        # code byte in its segment. Distinguish a return from recursion or a jump
        # back to the entry by watching for RET to consume this specific frame.
        frame = pack("<HH", start.offset, start.segment) if far else pack("<H", start.offset)
        stack = Address(initial["ss"], (initial["sp"] - len(frame)) & _WORD_MASK)
        initial["sp"] = stack.offset
        uc.mem_write(stack.linear, frame)
        decoder = Cs(CS_ARCH_X86, CS_MODE_16)
        return_opcode = X86_INS_RETF if far else X86_INS_RET
        returning = False
        by_linear = {self.resolve(where).linear: hook for where, hook in hooks.items()}
        entry_hook = by_linear.pop(start.linear, None)

        def read_frame(cpu: Uc, _access: int, _address: int, size: int, _value: int, _data: object) -> None:
            nonlocal returning
            if size != 2 or cpu.reg_read(x86.UC_X86_REG_SP) != stack.offset:
                return
            if cpu.reg_read(x86.UC_X86_REG_SS) != stack.segment or cpu.mem_read(stack.linear, len(frame)) != frame:
                return
            pc = _pc(cpu)
            if not far and pc.segment != start.segment:
                return
            instruction = next(decoder.disasm(cpu.mem_read(pc.linear, 15), pc.linear, count=1), None)
            returning = instruction is not None and instruction.id == return_opcode

        def at_entry(cpu: Uc, _address: int, _size: int, _data: object) -> None:
            if returning and _pc(cpu) == start:
                cpu.emu_stop()
            elif entry_hook is not None:
                entry_hook(cpu)

        def on_code(cpu: Uc, _address: int, _size: int, callback: CodeHook) -> None:
            callback(cpu)

        uc.hook_add(UC_HOOK_MEM_READ, read_frame, begin=stack.linear, end=stack.linear)
        uc.hook_add(UC_HOOK_CODE, at_entry, begin=start.linear, end=start.linear)
        for linear, hook in by_linear.items():
            uc.hook_add(UC_HOOK_CODE, on_code, hook, begin=linear, end=linear)
        return lambda: returning

    def _install_io(
        self, uc: Uc, interrupts: Mapping[int, Interrupt], on_in: PortIn | None, on_out: PortOut | None,
    ) -> Callable[[], Exception | None]:
        input_error = None

        def interrupt(cpu: Uc, number: int, _data: object) -> None:
            handler = interrupts.get(number)
            if handler is not None:
                handler(cpu, number)
                return
            pc = _pc(cpu)
            site = Address(pc.segment, (pc.offset - 2) & _WORD_MASK)
            is_int = cpu.mem_read(site.linear, 2) == bytes((0xCD, number))
            target = self._stubs.get(site.linear) if number == 0x3F and is_int else None
            if target is None:
                raise EmulatorError(f"unhandled interrupt {number:02x}h at {site if is_int else pc}")
            cpu.reg_write(x86.UC_X86_REG_CS, target.segment)
            cpu.reg_write(x86.UC_X86_REG_IP, target.offset)

        def port_in(cpu: Uc, port: int, size: int, _data: object) -> int:
            nonlocal input_error
            try:
                if on_in is None:
                    raise EmulatorError(f"unhandled IN from port {port:04x}h at {_pc(cpu)}")
                value = on_in(cpu, port, size)
                if type(value) is not int or not 0 <= value < 1 << (8 * size):
                    raise EmulatorError(f"invalid {size}-byte IN value for port {port:04x}h")
                return value
            except Exception as error:
                # Unicorn's ctypes IN callback must return an integer even after a hook fails.
                input_error = error
                cpu.emu_stop()
                return 0

        def port_out(cpu: Uc, port: int, size: int, value: int, _data: object) -> None:
            if on_out is None:
                raise EmulatorError(f"unhandled OUT to port {port:04x}h at {_pc(cpu)}")
            on_out(cpu, port, size, value)

        uc.hook_add(UC_HOOK_INTR, interrupt)
        uc.hook_add(UC_HOOK_INSN, port_in, None, 1, 0, x86.UC_X86_INS_IN)
        uc.hook_add(UC_HOOK_INSN, port_out, None, 1, 0, x86.UC_X86_INS_OUT)
        return lambda: input_error
