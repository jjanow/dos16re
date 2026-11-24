"""Run isolated routines and interpret runtime addresses from image exports."""

import json
import re
from bisect import bisect_right
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from sys import maxsize

from py65.devices.mpu6502 import MPU
from unicorn import (
    UC_ARCH_M68K, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ,
    UC_MODE_BIG_ENDIAN, Uc, UcError, m68k_const as m68k,
)
from z80 import Z80Machine

from .emulator import DEFAULT_INSTRUCTION_LIMIT, Emulator, EmulatorError, _REGISTERS as _X86_REGISTERS
from .evidence import ExportEvidence
from .image import (
    GENESIS_FORMAT, MAC68K_FORMAT, M68K_ADDRESS_LIMIT, M68K_FORMATS, MOS6502_FORMATS, NES_FORMAT,
    PC98_FORMAT, X68K_FORMAT, Z80_FORMATS, ImageUnit, check_map_version, image_units, read_map, runtime_spans,
)
from .mz import Address

AddressInput = str | Address | int
ResolvedAddress = Address | int
_FORMAT_ARCHITECTURES = (
    (("MZ", PC98_FORMAT), "x86", 0x110000),
    (M68K_FORMATS, "m68k", M68K_ADDRESS_LIMIT),
    (MOS6502_FORMATS, "6502", 0x10000),
    (Z80_FORMATS, "z80", 0x10000),
)
_HEX = re.compile(r"(?:0[xX])?[0-9a-fA-F]+")
_M68K_REGISTERS = {
    name.lower(): getattr(m68k, f"UC_M68K_REG_{name}")
    for name in (*(f"D{i}" for i in range(8)), *(f"A{i}" for i in range(8)), "SR", "PC")
}
_6502_WIDTHS = dict.fromkeys(("a", "x", "y", "sp", "p"), 8) | {"pc": 16}
_Z80_WIDTHS = (
    dict.fromkeys(("a", "f", "b", "c", "d", "e", "h", "l", "i", "r"), 8)
    | dict.fromkeys(("af", "bc", "de", "hl", "ix", "iy", "sp", "pc", "alt_af", "alt_bc", "alt_de", "alt_hl"), 16)
    | dict.fromkeys(("iff1", "iff2"), 1)
)


@dataclass(frozen=True)
class Service:
    number: int
    match: Mapping[str, int] = field(default_factory=dict)
    registers: Mapping[str, int] = field(default_factory=dict)
    writes: tuple[tuple[AddressInput, bytes], ...] = ()
    kind: str = "interrupt"


@dataclass(frozen=True)
class HardwareIO:
    operation: str
    address: int
    size: int = 1
    value: int = 0
    space: str = "port"


@dataclass(frozen=True)
class RoutineRequest:
    address: AddressInput
    registers: Mapping[str, int] = field(default_factory=dict)
    writes: tuple[tuple[AddressInput, bytes], ...] = ()
    reads: tuple[tuple[AddressInput, int], ...] = ()
    far: bool = False
    limit: int = DEFAULT_INSTRUCTION_LIMIT
    services: tuple[Service, ...] = ()
    hardware: tuple[HardwareIO, ...] = ()


@dataclass(frozen=True)
class RoutineState:
    registers: dict[str, int]
    memory: tuple[tuple[ResolvedAddress, bytes], ...]


@dataclass(frozen=True)
class RoutineResult:
    address: ResolvedAddress
    before: RoutineState
    after: RoutineState
    events: tuple[dict, ...]


def _architecture(image_format: str) -> tuple[str, int]:
    for formats, architecture, limit in _FORMAT_ARCHITECTURES:
        if image_format in formats:
            return architecture, limit
    raise EmulatorError(f"unsupported image format {image_format}")


def _linear(address: AddressInput, architecture: str, limit: int) -> int:
    if isinstance(address, Address) and architecture == "x86":
        if type(address.segment) is int and type(address.offset) is int:
            if 0 <= address.segment <= 0xFFFF and 0 <= address.offset <= 0xFFFF:
                return address.linear
    if isinstance(address, str):
        if _HEX.fullmatch(address):
            address = int(address, 16)
        elif architecture == "x86" and re.fullmatch(r"[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}", address):
            segment, offset = address.split(":")
            return int(segment, 16) * 16 + int(offset, 16)
    if type(address) is int and 0 <= address < limit:
        return address
    raise EmulatorError(f"invalid {architecture} runtime address {address!r}")


class TraceAddressBackend:
    """Map CPU addresses to static image units under a selected runtime layout."""

    def __init__(self, image: ExportEvidence):
        self.architecture, self.limit = _architecture(image.format)
        self._units = image.units
        self._ranges = image.runtime_spans
        self._starts = [span.linear for span in self._ranges]

    def linear(self, address: AddressInput) -> int:
        return _linear(address, self.architecture, self.limit)

    def location(self, linear: int, placements: Mapping[str, int] | None = None) -> tuple[ImageUnit, int] | None:
        ranges = self._ranges if placements is None else runtime_spans(self._units, dict(placements))
        starts = self._starts if placements is None else [span.linear for span in ranges]
        index = bisect_right(starts, linear) - 1
        if index >= 0:
            span = ranges[index]
            if linear < span.end:
                return span.unit, span.offset + linear - span.linear
        return None


def _register_inputs(regs: Mapping[str, int], widths: Mapping[str, int], *,
                     readonly: tuple[str, ...] = ()) -> dict[str, int]:
    values = {}
    for name, value in regs.items():
        if not isinstance(name, str):
            raise EmulatorError(f"invalid register name {name!r}")
        key = name.lower()
        if key not in widths or key in readonly:
            raise EmulatorError(f"cannot set register {name}")
        bits = widths[key]
        if type(value) is not int or not 0 <= value < 1 << bits:
            raise EmulatorError(f"{name} must be a {bits}-bit unsigned value")
        values[key] = value
    return values


class _Script:
    """Supply caller-defined OS and device responses in occurrence order."""

    def __init__(self, backend: "RoutineBackend", request: RoutineRequest):
        self.services = deque(request.services)
        self.hardware = deque(request.hardware)
        self.events: list[dict] = []
        self.service_sites: set[int] = set()
        kinds = {
            "x86": {"interrupt"}, "m68k": {"trap", "aline", "fline", "call"},
            "6502": {"brk", "call"}, "z80": {"call"},
        }[backend.architecture]
        self.memory_regions = [
            (region["linear"], region["linear"] + region["size"], region.get("read"), region.get("write"))
            for region in backend.program.get("memory_map", ())
            if region.get("read") == "io" or region.get("write") in ("io", "mapper")
        ]
        for service in self.services:
            if service.kind not in kinds or type(service.number) is not int or service.number < 0:
                raise EmulatorError(f"invalid {backend.architecture} service {service.kind} {service.number!r}")
            if service.kind == "call":
                self.service_sites.add(_linear(service.number, backend.architecture, backend.limit))
            else:
                bounds = {"interrupt": (0, 0x100), "trap": (0, 0x10), "brk": (0, 1),
                          "aline": (0xA000, 0xB000), "fline": (0xFE00, 0x10000)}
                first, end = bounds[service.kind]
                if not first <= service.number < end:
                    raise EmulatorError(f"invalid {service.kind} service number {service.number:#x}")
        for access in self.hardware:
            space = self._space(access.space)
            limit = backend.limit if space == "memory" else 0x10000
            if (
                space not in ("port", "memory") or access.operation not in ("read", "write")
                or type(access.size) is not int or access.size not in (1, 2, 4)
                or type(access.address) is not int or not 0 <= access.address < limit
                or type(access.value) is not int or not 0 <= access.value < 1 << (access.size * 8)
            ):
                raise EmulatorError(f"invalid hardware operation {access}")
            if space == "port" and backend.architecture not in ("x86", "z80"):
                raise EmulatorError(f"{backend.architecture} hardware uses memory-mapped I/O")
            if backend.architecture in ("6502", "z80") and access.size != 1:
                raise EmulatorError(f"{backend.architecture} hardware accesses are one byte")
            if space == "memory":
                if access.address + access.size > limit:
                    raise EmulatorError(f"hardware address exceeds {backend.architecture} address space")
                self.memory_regions.append((
                    access.address, access.address + access.size,
                    "io" if access.operation == "read" else None,
                    "io" if access.operation == "write" else None,
                ))

    @staticmethod
    def _space(space: str) -> str:
        return "memory" if space == "mmio" else space

    def touches_device(self, operation: str, address: int, size: int) -> bool:
        return any(
            (read if operation == "read" else write) in ("io", "mapper")
            and address + size > start and address < end
            for start, end, read, write in self.memory_regions
        )

    def io(self, space: str, operation: str, address: int, size: int, value: int | None = None) -> int:
        if not self.hardware:
            raise EmulatorError(f"unhandled {space} {operation} at {address:#x}")
        expected = self.hardware[0]
        if (operation, address, size, space) != (
            expected.operation, expected.address, expected.size, self._space(expected.space),
        ):
            raise EmulatorError(
                f"expected {expected.space} {expected.operation} at {expected.address:#x} ({expected.size} bytes), "
                f"got {space} {operation} at {address:#x} ({size} bytes)"
            )
        if value is not None and value != expected.value:
            raise EmulatorError(f"{space} write at {address:#x}: expected {expected.value:#x}, got {value:#x}")
        self.hardware.popleft()
        self.events.append({"kind": "io", "space": space, "operation": operation,
                            "address": address, "size": size, "value": expected.value})
        return expected.value

    def service(self, kind: str, number: int, registers: dict[str, int]) -> Service:
        if not self.services:
            raise EmulatorError(f"unhandled {kind} {number:#x}")
        expected = self.services[0]
        if (kind, number) != (expected.kind, expected.number):
            raise EmulatorError(f"expected {expected.kind} {expected.number:#x}, got {kind} {number:#x}")
        for register, value in expected.match.items():
            found = registers.get(register.lower())
            if found != value:
                raise EmulatorError(f"{kind} {number:#x}: expected {register}={value:#x}, got {found!r}")
        self.services.popleft()
        self.events.append({"kind": kind, "number": number, "registers": registers})
        return expected

    def finish(self) -> tuple[dict, ...]:
        if self.services:
            remaining = self.services[0]
            raise EmulatorError(f"missing {remaining.kind} {remaining.number:#x}")
        if self.hardware:
            remaining = self.hardware[0]
            raise EmulatorError(f"missing {remaining.space} {remaining.operation} at {remaining.address:#x}")
        return tuple(self.events)


def _install_unicorn_memory_io(cpu: Uc, script: _Script, endian: str) -> Callable[[], None]:
    if not script.memory_regions:
        return lambda: None
    saved = {}

    def restore(uc: Uc) -> None:
        if saved:
            # Restore in reverse access order, including overlapping accesses.
            for (address, _), original in reversed(saved.items()):
                uc.mem_write(address, original)
            saved.clear()

    def on_access(uc: Uc, access: int, address: int, size: int, value: int, _data: object) -> None:
        operation = "read" if access == UC_MEM_READ else "write"
        if not script.touches_device(operation, address, size):
            return
        if (address, size) not in saved:
            saved[address, size] = bytes(uc.mem_read(address, size))
        response = script.io("memory", operation, address, size, value if operation == "write" else None)
        if operation == "read":
            uc.mem_write(address, response.to_bytes(size, endian))

    cpu.hook_add(UC_HOOK_CODE, lambda uc, *_: restore(uc))
    cpu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, on_access)
    return lambda: restore(cpu)


class _MosMemory(bytearray):
    """Let the CPU use a flat view while explicitly scripted I/O stays off RAM."""

    def __init__(self, script: _Script, *, mirror_ram: bool):
        super().__init__(0x10000)
        self.script = script
        self.mirror_ram = mirror_ram

    def _ram_address(self, address: int) -> int:
        return address & 0x7FF if self.mirror_ram and 0 <= address < 0x2000 else address

    def _spans(self, start: int, size: int):
        end = start + size
        while self.mirror_ram and start < min(0x2000, end):
            length = min(end - start, 0x800 - (start & 0x7FF))
            where = self._ram_address(start)
            yield slice(where, where + length)
            start += length
        if start < end:
            yield slice(start, end)

    def peek(self, address: int) -> int:
        return super().__getitem__(self._ram_address(address))

    def read_span(self, start: int, size: int) -> bytes:
        return b"".join(bytes(self[span]) for span in self._spans(start, size))

    def write_span(self, start: int, data: bytes) -> None:
        offset = 0
        for span in self._spans(start, len(data)):
            length = span.stop - span.start
            self[span] = data[offset:offset + length]
            offset += length

    def __getitem__(self, index):
        if isinstance(index, int):
            if self.script.touches_device("read", index, 1):
                return self.script.io("memory", "read", index, 1)
            return self.peek(index)
        return super().__getitem__(index)

    def __setitem__(self, index, value):
        if isinstance(index, int) and self.script.touches_device("write", index, 1):
            self.script.io("memory", "write", index, 1, value)
        elif isinstance(index, int):
            super().__setitem__(self._ram_address(index), value)
        else:
            super().__setitem__(index, value)


class _Ricoh2A03(MPU):
    """The NES CPU has an NMOS 6502 instruction set but no decimal ALU."""

    def _binary(self, operation, operand) -> None:
        decimal = self.p & self.DECIMAL
        self.p &= ~self.DECIMAL
        operation(operand)
        self.p |= decimal

    def opADC(self, operand):
        self._binary(super().opADC, operand)

    def opSBC(self, operand):
        self._binary(super().opSBC, operand)


class RoutineBackend:
    """Execute a routine using the CPU and selected memory view of an export."""

    def __init__(self, image: bytes, program: dict):
        check_map_version(program)
        self.image = bytes(image)
        self.program = program
        self.format = program.get("format", "MZ")
        self.architecture, self.limit = _architecture(self.format)
        self._units = image_units(program, len(image))
        self._by_name = {unit.name.casefold(): unit for unit in self._units}
        self._x86 = Emulator(image, program) if self.architecture == "x86" else None

    @classmethod
    def from_export(cls, export: Path) -> "RoutineBackend":
        return cls((export / "image.bin").read_bytes(), read_map(export))

    def identity(self) -> dict:
        canonical = json.dumps(self.program, sort_keys=True, separators=(",", ":")).encode("ascii")
        return {"program": self.program.get("program"), "format": self.format,
                "image_sha256": sha256(self.image).hexdigest(), "map_sha256": sha256(canonical).hexdigest()}

    def resolve(self, address: AddressInput) -> ResolvedAddress:
        if isinstance(address, str):
            head, colon, tail = address.rpartition(":")
            if colon and (unit := self._by_name.get(head.casefold())) is not None:
                if not _HEX.fullmatch(tail) or (offset := int(tail, 16)) >= unit.size:
                    raise EmulatorError(f"offset outside unit {head}: {tail}")
                if self.architecture == "x86" and offset <= 0xFFFF:
                    return Address(unit.segment, offset)
                address = unit.linear + offset
            elif self._x86 is not None and colon:
                return self._x86.resolve(address)
        linear = _linear(address, self.architecture, self.limit)
        if self.architecture != "x86":
            return linear
        if isinstance(address, Address):
            return address
        segment = next((unit.segment for unit in self._units if unit.linear <= linear < unit.linear + unit.size
                        and linear - unit.linear <= 0xFFFF), min(linear >> 4, 0xFFFF))
        return self._x86.resolve(Address(segment, linear - segment * 16))

    def location(self, address: AddressInput) -> dict:
        value = self.resolve(address)
        if isinstance(value, Address):
            return {"segment": value.segment, "offset": value.offset, "linear": value.linear}
        width = 8 if self.architecture == "m68k" else 4
        return {"address": f"{value:0{width}x}", "linear": value}

    def _spans(self, entries, *, writes: bool = False) -> tuple:
        result = []
        for address, value in entries:
            where = self.resolve(address)
            linear = where.linear if isinstance(where, Address) else where
            if writes and not isinstance(value, bytes):
                raise EmulatorError(f"memory writes require bytes at {address}")
            size = len(value) if writes else value
            if type(size) is not int or not 0 < size <= self.limit - linear:
                raise EmulatorError(f"invalid memory size at {address}: {size}")
            result.append((where, value))
        return tuple(result)

    def run(self, request: RoutineRequest) -> RoutineResult:
        if type(request.limit) is not int or not 0 < request.limit < maxsize:
            raise EmulatorError("instruction limit must be a positive supported integer")
        if request.far and self._x86 is None:
            raise EmulatorError("far calls require an x86 image")
        address = self.resolve(request.address)
        writes = self._spans(request.writes, writes=True)
        reads = self._spans(request.reads)
        script = _Script(self, request)
        if self._x86 is not None:
            before, after = self._call_x86(address, request, writes, reads, script)
        else:
            if not self._initialized(address, writes):
                raise EmulatorError(f"routine address {address:#x} is outside initialized memory")
            runner = {"m68k": self._call_m68k, "6502": self._call_6502, "z80": self._call_z80}[self.architecture]
            before, after = runner(address, request, writes, reads, script)
        return RoutineResult(address, before, after, script.finish())

    def _initialized(self, address: int, writes: tuple) -> bool:
        return (
            any(unit.linear <= address < unit.linear + unit.size for unit in self._units)
            or any(where <= address < where + len(data) for where, data in writes)
        )

    def _populate(self, write, writes: tuple) -> None:
        for unit in self._units:
            if unit.size:
                start = unit.image_offset
                write(unit.linear, self.image[start:start + unit.size])
        for where, data in writes:
            write(where, data)

    def _call_x86(self, address: Address, request: RoutineRequest, writes: tuple, reads: tuple, script: _Script):
        widths = dict.fromkeys(_X86_REGISTERS, 16)
        before = None

        def regs(cpu: Uc) -> dict[str, int]:
            return {name: cpu.reg_read(register) for name, register in _X86_REGISTERS.items()}

        def capture(cpu: Uc) -> None:
            nonlocal before
            before = RoutineState(regs(cpu), tuple((where, bytes(cpu.mem_read(where.linear, size)))
                                                   for where, size in reads))

        def interrupt(cpu: Uc, number: int) -> None:
            reply = script.service("interrupt", number, regs(cpu))
            for name, value in _register_inputs(reply.registers, widths, readonly=("cs", "ip")).items():
                cpu.reg_write(_X86_REGISTERS[name], value)
            for where, data in self._spans(reply.writes, writes=True):
                cpu.mem_write(where.linear, data)

        result = self._x86.call(
            address, regs=request.registers, writes=writes, reads=reads, far=request.far, limit=request.limit,
            interrupts=dict.fromkeys((event.number for event in request.services), interrupt),
            on_in=(lambda _cpu, port, size: script.io("port", "read", port, size)) if request.hardware else None,
            on_out=(lambda _cpu, port, size, value: script.io("port", "write", port, size, value))
            if request.hardware else None, _capture=capture,
            _setup=lambda cpu: _install_unicorn_memory_io(cpu, script, "little"),
        )
        return before, RoutineState(result.registers, result.memory)

    def _call_m68k(self, address: int, request: RoutineRequest, writes: tuple, reads: tuple, script: _Script):
        cpu = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        model = m68k.UC_CPU_M68K_M68020 if self.format == X68K_FORMAT else m68k.UC_CPU_M68K_M68000
        cpu.ctl_set_cpu_model(model)
        cpu.mem_map(0, self.limit)
        self._populate(cpu.mem_write, writes)
        widths = dict.fromkeys(_M68K_REGISTERS, 32) | {"sr": 16}
        initial = _register_inputs(request.registers, widths, readonly=("pc",))
        if self.format == MAC68K_FORMAT and "a5" in self.program:
            initial.setdefault("a5", self.program["a5"]["linear"])
        if self.format == GENESIS_FORMAT:
            initial.setdefault("a7", self.program.get("initial_ssp", self.limit))
        stack = initial.pop("a7", 0x200000)
        if stack == 0 and self.format == GENESIS_FORMAT:
            stack = self.limit
        if not 4 <= stack <= self.limit or stack & 1:
            raise EmulatorError("a7 must point to an even stack address in the 24-bit memory view")
        if address & 1:
            raise EmulatorError("68000 routine address must be even")
        cpu.reg_write(_M68K_REGISTERS["sr"], initial.pop("sr", 0x2000))
        for name, value in (initial | {"a7": stack, "pc": address}).items():
            cpu.reg_write(_M68K_REGISTERS[name], value)

        def capture() -> RoutineState:
            return RoutineState(
                {name: cpu.reg_read(register) for name, register in _M68K_REGISTERS.items()},
                tuple((where, bytes(cpu.mem_read(where, size))) for where, size in reads),
            )

        before = capture()
        frame = stack - 4
        returning = returned = False
        instructions = 0
        saved_pc = address.to_bytes(4, "big")
        cpu.mem_write(frame, saved_pc)
        cpu.reg_write(_M68K_REGISTERS["a7"], frame)
        restore = _install_unicorn_memory_io(cpu, script, "big")

        def at_instruction(uc: Uc, pc: int, _size: int, _data: object) -> None:
            nonlocal instructions, returning, returned
            if returning and pc == address:
                returned = True
                uc.emu_stop()
                return
            if instructions == request.limit:
                uc.emu_stop()
                return
            instructions += 1
            returning = False
            opcode = int.from_bytes(uc.mem_read(pc, 2), "big")
            if opcode in (0x4E75, 0x4E74) and uc.reg_read(_M68K_REGISTERS["a7"]) == frame:
                returning = uc.mem_read(frame, 4) == saved_pc
            if pc in script.service_sites:
                kind, number = "call", pc
            elif 0x4E40 <= opcode <= 0x4E4F:
                kind, number = "trap", opcode & 15
            elif 0xA000 <= opcode <= 0xAFFF:
                kind, number = "aline", opcode
            elif self.format == X68K_FORMAT and opcode >= 0xFE00:
                kind, number = "fline", opcode
            else:
                return
            reply = script.service(kind, number, {name: uc.reg_read(register)
                                                  for name, register in _M68K_REGISTERS.items()})
            for name, value in _register_inputs(reply.registers, widths, readonly=("pc", "a7")).items():
                uc.reg_write(_M68K_REGISTERS[name], value)
            for where, data in self._spans(reply.writes, writes=True):
                uc.mem_write(where, data)
            if kind == "call":
                sp = uc.reg_read(_M68K_REGISTERS["a7"])
                target = int.from_bytes(uc.mem_read(sp, 4), "big")
                uc.reg_write(_M68K_REGISTERS["a7"], sp + 4)
                returning = sp == frame and target == address
            else:
                target = pc + 2
            uc.reg_write(_M68K_REGISTERS["pc"], target)

        cpu.hook_add(UC_HOOK_CODE, at_instruction)
        try:
            # Allow the code hook to observe the return target after the last
            # allowed instruction. It stops before that instruction executes.
            cpu.emu_start(address, self.limit, count=request.limit + 1)
        except UcError as error:
            pc = cpu.reg_read(_M68K_REGISTERS["pc"])
            raise EmulatorError(f"emulation failed at {pc:#x}: {error}") from error
        if not returned:
            pc = cpu.reg_read(_M68K_REGISTERS["pc"])
            raise EmulatorError(f"routine did not return within {request.limit} instructions (stopped at {pc:#x})")
        restore()
        return before, capture()

    def _call_6502(self, address: int, request: RoutineRequest, writes: tuple, reads: tuple, script: _Script):
        memory = _MosMemory(script, mirror_ram=self.format == NES_FORMAT)
        self._populate(memory.write_span, writes)
        model = _Ricoh2A03 if self.format == NES_FORMAT else MPU
        cpu = model(memory=memory, pc=address)
        for name, value in _register_inputs(request.registers, _6502_WIDTHS, readonly=("pc",)).items():
            setattr(cpu, name, value)

        def registers() -> dict[str, int]:
            return {name: getattr(cpu, name) for name in _6502_WIDTHS}

        def capture() -> RoutineState:
            return RoutineState(registers(), tuple((where, memory.read_span(where, size)) for where, size in reads))

        before = capture()
        # RTS consumes the caller's return address minus one. Observe the
        # original frame so nested calls and jumps to the entry can run.
        saved_pc = (address - 1) & 0xFFFF
        cpu.stPushWord(saved_pc)
        frame = cpu.sp
        for _ in range(request.limit):
            pc = cpu.pc
            opcode = memory.peek(pc)
            service = pc in script.service_sites
            returns = (
                (opcode == 0x60 or service) and cpu.sp == frame
                and int.from_bytes(bytes((memory[0x100 + ((frame + 1) & 255)],
                                          memory[0x100 + ((frame + 2) & 255)])), "little") == saved_pc
            )
            if service or opcode == 0:
                reply = script.service("call", pc, registers()) if service else script.service("brk", 0, registers())
                for name, value in _register_inputs(reply.registers, _6502_WIDTHS, readonly=("pc", "sp")).items():
                    setattr(cpu, name, value)
                for where, data in self._spans(reply.writes, writes=True):
                    memory.write_span(where, data)
                cpu.pc = ((cpu.stPopWord() + 1) if service else pc + 2) & 0xFFFF
            else:
                if cpu.disassemble[opcode][0] == "???":
                    raise EmulatorError(f"unsupported 6502 opcode {opcode:#04x} at {pc:#06x}")
                cpu.step()
            if returns and cpu.pc == address:
                return before, capture()
        raise EmulatorError(f"routine did not return within {request.limit} instructions (stopped at {cpu.pc:#06x})")

    def _call_z80(self, address: int, request: RoutineRequest, writes: tuple, reads: tuple, script: _Script):
        cpu = Z80Machine()
        memory = cpu.memory
        self._populate(cpu.set_memory_block, writes)
        initial = _register_inputs(request.registers, _Z80_WIDTHS, readonly=("pc",))
        initial.setdefault("sp", 0xFFF0)
        for name, value in initial.items():
            setattr(cpu, name, value)
        cpu.pc = address

        def registers() -> dict[str, int]:
            return {name: int(getattr(cpu, name)) for name in _Z80_WIDTHS}

        def capture() -> RoutineState:
            return RoutineState(registers(), tuple((where, bytes(cpu.memory[where:where + size])) for where, size in reads))

        before = capture()
        frame = (cpu.sp - 2) & 0xFFFF

        def word(where: int) -> int:
            return cpu.memory[where] | cpu.memory[(where + 1) & 0xFFFF] << 8

        cpu.memory[frame] = address & 255
        cpu.memory[(frame + 1) & 0xFFFF] = address >> 8
        cpu.sp = frame
        cpu.set_input_callback(lambda port: script.io("port", "read", port, 1))
        cpu.set_output_callback(lambda port, value: script.io("port", "write", port, 1, value))
        if script.memory_regions:
            def read(where: int) -> int:
                if script.touches_device("read", where, 1):
                    return script.io("memory", "read", where, 1)
                return memory[where]

            def write(where: int, value: int) -> None:
                if script.touches_device("write", where, 1):
                    script.io("memory", "write", where, 1, value)
                else:
                    memory[where] = value

            for first, end, *_ in script.memory_regions:
                cpu.mark_addrs(first, end - first, cpu.READ_MARK | cpu.WRITE_MARK)
            cpu.set_read_callback(read)
            cpu.set_write_callback(write)

        for _ in range(request.limit):
            pc, sp = cpu.pc, cpu.sp
            service = pc in script.service_sites
            original_frame = sp == frame and word(sp) == address
            if service:
                reply = script.service("call", pc, registers())
                for name, value in _register_inputs(reply.registers, _Z80_WIDTHS, readonly=("pc", "sp")).items():
                    setattr(cpu, name, value)
                for where, data in self._spans(reply.writes, writes=True):
                    cpu.set_memory_block(where, data)
                cpu.pc, cpu.sp = word(sp), (sp + 2) & 0xFFFF
                returns = True
            else:
                # The core's stepping API reports DD and FD prefixes as
                # individual steps. Treat a prefixed instruction as one.
                for _prefix in range(0x10000):
                    opcode = cpu.memory[cpu.pc]
                    if opcode not in (0xDD, 0xFD):
                        break
                    cpu.step_over_breakpoint()
                else:
                    raise EmulatorError(f"unterminated Z80 instruction prefixes at {pc:#06x}")
                returns = opcode == 0xC9 or opcode & 0xC7 == 0xC0 or (
                    opcode == 0xED and cpu.memory[(cpu.pc + 1) & 0xFFFF] & 0xC7 == 0x45
                )
                cpu.step_over_breakpoint()
            if original_frame and returns and cpu.pc == address and cpu.sp == (sp + 2) & 0xFFFF:
                return before, capture()
            if cpu.halted:
                break
        raise EmulatorError(f"routine did not return within {request.limit} instructions (stopped at {cpu.pc:#06x})")
