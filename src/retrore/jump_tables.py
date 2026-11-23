"""Recover bounded 16-bit near jumps and calls through CS-relative word tables.

A table is accepted only when the index register is provably bounded on the path that reaches the
indirect instruction: by an unsigned compare and branch (`cmp r,N` with `ja`/`jae`, or `jbe`/`jb` over
an unconditional jump to the default case), or by masking (`and r,MASK`), or by zero-extending a byte.
Scaling (`shl r,1`, `add r,r`, `rol r,1` on a masked value), register copies (`mov`, `xchg`), index
biases applied before the bound (`sub r,K`), and unrelated instructions between the bound and the use
are followed. Every table entry must then decode as code inside the segment.
"""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from struct import iter_unpack

from capstone import CS_ARCH_X86, CS_MODE_16, Cs, CsInsn
from capstone.x86 import (
    X86_INS_ADD, X86_INS_AND, X86_INS_CALL, X86_INS_CMP, X86_INS_INT, X86_INS_IRET, X86_INS_JA, X86_INS_JAE, X86_INS_JB,
    X86_INS_JBE, X86_INS_JMP, X86_INS_LJMP, X86_INS_MOV, X86_INS_MOVZX, X86_INS_RET, X86_INS_RETF, X86_INS_ROL,
    X86_INS_SHL, X86_INS_SUB, X86_INS_XCHG, X86_INS_XOR, X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_AH,
    X86_REG_AL, X86_REG_AX, X86_REG_BH, X86_REG_BL, X86_REG_BP, X86_REG_BX, X86_REG_CH, X86_REG_CL, X86_REG_CS,
    X86_REG_CX, X86_REG_DH, X86_REG_DI, X86_REG_DL, X86_REG_DX, X86_REG_INVALID, X86_REG_SI, X86_REG_SP,
)

_WINDOW_BYTES = 24
_MAX_CASES = 0x8000  # The scaled 16-bit index must fit without wrapping.
_WORD_MASK = 0xFFFF
# Switch cases stay near their dispatch; a wrong code segment scatters them across the segment.
_MAX_CASE_DISTANCE = 0x2000
_WORDS = (X86_REG_AX, X86_REG_BX, X86_REG_CX, X86_REG_DX, X86_REG_SI, X86_REG_DI, X86_REG_BP, X86_REG_SP)
_LOW = {X86_REG_AL: X86_REG_AX, X86_REG_BL: X86_REG_BX, X86_REG_CL: X86_REG_CX, X86_REG_DL: X86_REG_DX}
_HIGH = {X86_REG_AH: X86_REG_AX, X86_REG_BH: X86_REG_BX, X86_REG_CH: X86_REG_CX, X86_REG_DH: X86_REG_DX}
_PARENT = {**{register: register for register in _WORDS}, **_LOW, **_HIGH}
_STOPS = (X86_INS_JMP, X86_INS_LJMP, X86_INS_RET, X86_INS_RETF, X86_INS_IRET, X86_INS_INT)


@dataclass(frozen=True)
class JumpTable:
    guard: int
    jump: int
    table: int
    default: int | None
    targets: tuple[int, ...]
    kind: str = "jump"
    bound: str = "compare"


@dataclass(frozen=True)
class _Value:
    """A register value with a proved inclusive upper bound and known low zero bits."""

    maximum: int
    align: int
    origin: int  # Address of the instruction that bounded the value.
    bound: str
    default: int | None = None
    selector: int = X86_REG_INVALID  # Register the compare tested, for locating an index bias.


def _low_bit(value: int) -> int:
    return value & -value if value else 0x10000


def _reg(operand) -> int | None:
    return operand.reg if operand.type == X86_OP_REG else None


def _reg_imm(insn: CsInsn) -> tuple[int, int] | None:
    if len(insn.operands) != 2:
        return None
    left, right = insn.operands
    if left.type == X86_OP_REG and left.size == 2 and right.type == X86_OP_IMM:
        return left.reg, right.imm & _WORD_MASK
    return None


def _shift(value: _Value | None, count: int) -> _Value | None:
    if value is None or not 0 < count < 16 or value.maximum << count > _WORD_MASK:
        return None
    return _Value(
        value.maximum << count, min(value.align << count, 0x10000), value.origin, value.bound, value.default,
        value.selector,
    )


def _written(insn: CsInsn) -> set[int]:
    try:
        _, written = insn.regs_access()
    except Exception:  # noqa: BLE001 - capstone raises a bare CsError for some encodings.
        return set(_WORDS)
    return {_PARENT[register] for register in written if register in _PARENT}


def _interpret(insns: list[CsInsn]) -> dict[int, _Value]:
    """Return the bounded word registers after running the straight-line instructions."""
    state: dict[int, _Value] = {}
    index = 0
    while index < len(insns):
        insn = insns[index]
        index += 1
        if insn.id in _STOPS or insn.id == X86_INS_CALL:
            state.clear()
            continue
        operands = insn.operands
        target = _reg(operands[0]) if operands else None

        if insn.id == X86_INS_CMP and (compare := _reg_imm(insn)) and index < len(insns):
            selector, limit = compare
            branch = insns[index]
            if branch.id in (X86_INS_JA, X86_INS_JAE) and branch.operands[0].type == X86_OP_IMM:
                maximum = limit - (branch.id == X86_INS_JAE)
                default = branch.operands[0].imm & _WORD_MASK
                index += 1
            elif (
                branch.id in (X86_INS_JBE, X86_INS_JB) and index + 1 < len(insns)
                and insns[index + 1].id == X86_INS_JMP and insns[index + 1].operands[0].type == X86_OP_IMM
                and branch.operands[0].type == X86_OP_IMM
                and branch.operands[0].imm & _WORD_MASK
                == (insns[index + 1].address + insns[index + 1].size) & _WORD_MASK
            ):
                maximum = limit - (branch.id == X86_INS_JB)
                default = insns[index + 1].operands[0].imm & _WORD_MASK
                index += 2
            else:
                continue
            if maximum >= 0:
                state[selector] = _Value(maximum, 1, insn.address, "compare", default, selector)
            continue

        if insn.id in (X86_INS_MOV, X86_INS_XCHG) and len(operands) == 2 and all(
            operand.type == X86_OP_REG and operand.size == 2 for operand in operands
        ):
            left, right = operands[0].reg, operands[1].reg
            values = state.get(left), state.get(right)
            for register, value in zip((left, right), (values[1], values[0] if insn.id == X86_INS_XCHG else values[1])):
                if value is None:
                    state.pop(register, None)
                else:
                    state[register] = value
            continue

        if insn.id in (X86_INS_XOR, X86_INS_SUB) and len(operands) == 2 and target is not None and (
            operands[1].type == X86_OP_REG and operands[1].reg == target
        ):
            if target in _HIGH:
                word = _HIGH[target]
                previous = state.get(word)
                maximum = 0xFF if previous is None else min(previous.maximum, 0xFF)
                align = 1 if previous is None else previous.align
                state[word] = _Value(maximum, align, insn.address if previous is None else previous.origin, "byte")
            elif target in _WORDS:
                state[target] = _Value(0, 0x10000, insn.address, "byte")
            else:
                state.pop(_PARENT.get(target, -1), None)
            continue

        if insn.id == X86_INS_MOV and target in _HIGH and operands[1].type == X86_OP_IMM and operands[1].imm == 0:
            word = _HIGH[target]
            previous = state.get(word)
            state[word] = _Value(
                0xFF if previous is None else min(previous.maximum, 0xFF), 1 if previous is None else previous.align,
                insn.address if previous is None else previous.origin, "byte",
            )
            continue

        if insn.id == X86_INS_MOV and target in _LOW:
            word = _LOW[target]
            previous = state.get(word)
            if previous is not None and previous.maximum <= 0xFF:
                state[word] = _Value(0xFF, 1, previous.origin, "byte")
            else:
                state.pop(word, None)
            continue

        if insn.id == X86_INS_MOVZX and target in _WORDS and operands[1].size == 1:
            state[target] = _Value(0xFF, 1, insn.address, "byte")
            continue

        if insn.id == X86_INS_AND and (masked := _reg_imm(insn)):
            register, mask = masked
            previous = state.get(register)
            if previous is None:
                state[register] = _Value(mask, _low_bit(mask), insn.address, "mask")
            else:
                state[register] = _Value(
                    min(previous.maximum, mask), max(previous.align, _low_bit(mask)), previous.origin,
                    previous.bound, previous.default, previous.selector,
                )
            continue

        if insn.id in (X86_INS_SHL, X86_INS_ROL) and (shifted := _reg_imm(insn)):
            register, count = shifted
            # A rotate equals a shift only while the bound keeps the high bits clear.
            state_value = _shift(state.get(register), count)
            if state_value is None:
                state.pop(register, None)
            else:
                state[register] = state_value
            continue

        if insn.id == X86_INS_ADD and len(operands) == 2 and target in _WORDS and (
            operands[1].type == X86_OP_REG and operands[1].reg == target
        ):
            state_value = _shift(state.get(target), 1)
            if state_value is None:
                state.pop(target, None)
            else:
                state[target] = state_value
            continue

        for register in _written(insn):
            state.pop(register, None)
    return state


def _inline_starts(decoder: Cs, code: bytes, guard: int, selector: int, count: int) -> Iterator[int]:
    # Some compilers put an index bias between the table and the bounds check.
    yield guard - 2 * count
    for start in range(max(0, guard - 4), guard):
        normalize = next(decoder.disasm(code[start:guard], start, 1), None)
        if (
            normalize is not None and start + normalize.size == guard
            and normalize.id == X86_INS_SUB
        ):
            operands = _reg_imm(normalize)
            if operands is not None and operands[0] == selector:
                yield start - 2 * count


def _targets(
    decoder: Cs, code: bytes, table: int, count: int, bias: int,
    guard: int, jump_end: int, default: int | None, near: int | None = None,
) -> tuple[int, ...]:
    table_end = table + count * 2
    if not (0 <= table < table_end <= len(code) and (table_end <= guard or jump_end <= table)):
        return ()
    targets = tuple(
        (word - bias) & _WORD_MASK for word, in iter_unpack("<H", code[table:table_end])
    )
    extra = () if default is None else (default,)
    for target in {*targets, *extra}:
        if (
            target >= len(code) or table <= target < table_end or guard <= target < jump_end
            or (near is not None and abs(target - near) > _MAX_CASE_DISTANCE)
            or next(decoder.disasm_lite(code[target:target + 15], target, 1), None) is None
        ):
            return ()
    return targets


def _decoder() -> Cs:
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    return decoder


def recover_jump_tables(code: bytes, *, flat_overlay: bool = False) -> list[JumpTable]:
    """Scan one code segment, with offsets measured from the start of the supplied bytes."""
    code = code[:0x10000]
    decoder = _decoder()
    tables = []
    site = code.find(b"\x2e\xff")
    while site != -1:
        recovered = _recover_at(decoder, code, site, flat_overlay)
        if recovered is not None:
            tables.append(recovered)
        site = code.find(b"\x2e\xff", site + 1)
    return tables


def _bounds(decoder: Cs, code: bytes, jump: int, base: int) -> Iterable[_Value]:
    # Try the shortest straight-line window first: it holds the bound and nothing a misaligned decode
    # further back could have invented.
    for start in range(jump - 1, max(0, jump - _WINDOW_BYTES) - 1, -1):
        insns = list(decoder.disasm(code[start:jump], start))
        if not insns or insns[-1].address + insns[-1].size != jump:
            continue
        value = _interpret(insns).get(base)
        if value is not None:
            yield value


def _recover_at(decoder: Cs, code: bytes, jump: int, flat_overlay: bool) -> JumpTable | None:
    instruction = next(decoder.disasm(code[jump:jump + 15], jump, 1), None)
    if instruction is None or instruction.id not in (X86_INS_JMP, X86_INS_CALL):
        return None
    operand = instruction.operands[0]
    if operand.type != X86_OP_MEM or operand.size != 2:
        return None
    memory = operand.mem
    if (
        memory.segment != X86_REG_CS or memory.base == X86_REG_INVALID
        or memory.index != X86_REG_INVALID
    ):
        return None

    kind = "jump" if instruction.id == X86_INS_JMP else "call"
    displacement = memory.disp & _WORD_MASK
    jump_end = jump + instruction.size
    seen = set()
    for value in _bounds(decoder, code, jump, memory.base):
        if value in seen or value.align % 2:
            continue
        seen.add(value)
        count = value.maximum // 2 + 1
        if count > _MAX_CASES:
            continue
        guard = min(value.origin, jump)
        near = jump if kind == "jump" else None
        targets = _targets(decoder, code, displacement, count, 0, guard, jump_end, value.default, near)
        if targets:
            return JumpTable(guard, jump, displacement, value.default, targets, kind, value.bound)
        if not flat_overlay or value.bound != "compare":
            continue

        # Flat overlays may contain IPs relative to where they ran originally.
        # An inline table anchors that displacement to a known file offset.
        for table in _inline_starts(decoder, code, guard, value.selector, count):
            targets = _targets(
                decoder, code, table, count, displacement - table, guard, jump_end, value.default, near,
            )
            if targets and any(target < table for target in targets):
                return JumpTable(guard, jump, table, value.default, targets, kind, value.bound)
    return None


@dataclass(frozen=True)
class M68kJumpTable:
    """A 68k switch through a table of relocated 32-bit code addresses; offsets are relative to the unit."""

    guard: int
    jump: int
    table: int
    default: int
    targets: tuple[int, ...]


def _word(code: bytes, offset: int) -> int:
    return int.from_bytes(code[offset:offset + 2], "big") if 0 <= offset <= len(code) - 2 else -1


def _signed16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def recover_m68k_jump_tables(code: bytes, base: int, relocations: Iterable[int]) -> list[M68kJumpTable]:
    """Find compiler switches of the form used by Sharp XC and similar 68k C compilers.

        cmpi.l #N,dK; bhi default; asl.l #2,dK; lea table(pc),aM; movea.l (aM,dK.l),aN; jmp (aN)

    `code` is one code unit loaded at linear address `base`; `relocations` are unit offsets of relocated
    longs. Every table entry must be relocated and point at an even offset inside the unit.
    """
    relocated = set(relocations)
    tables = []
    for jump in range(8, len(code) - 1, 2):
        opcode = _word(code, jump)
        if opcode & 0xFFF8 != 0x4ED0:
            continue
        target_register = opcode & 7
        load, extension = _word(code, jump - 4), _word(code, jump - 2)
        if load & 0xFFF8 != 0x2070 | target_register << 9:
            continue
        table_register = load & 7
        if extension & 0x8FFF != 0x0800:  # Data register index, long size, no scale or displacement.
            continue
        index = extension >> 12 & 7
        if _word(code, jump - 8) != 0x41FA | table_register << 9:
            continue
        table = jump - 6 + _signed16(_word(code, jump - 6))
        if _word(code, jump - 10) not in (0xE580 | index, 0xE588 | index):  # asl.l / lsl.l #2
            continue
        short = _word(code, jump - 12)
        if short >> 8 in (0x62, 0x64) and short & 0xFF not in (0, 0xFF):  # bhi.b / bcc.b
            branch, displacement = jump - 12, (short & 0xFF) - (0x100 if short & 0x80 else 0)
        elif _word(code, jump - 14) in (0x6200, 0x6400):  # bhi.w / bcc.w
            branch, displacement = jump - 14, _signed16(short)
        else:
            continue
        condition = _word(code, branch) >> 8
        compare = branch - 6
        if _word(code, compare) != 0x0C80 | index:
            continue
        limit = int.from_bytes(code[compare + 2:compare + 6], "big")
        count = limit + (condition == 0x62)
        if not 1 <= count <= _MAX_CASES or table < 0 or table + 4 * count > len(code):
            continue
        entries = [table + 4 * case for case in range(count)]
        if not relocated.issuperset(entries):
            continue
        targets = tuple(int.from_bytes(code[entry:entry + 4], "big") - base for entry in entries)
        default = branch + 2 + displacement
        if all(0 <= target < len(code) and not target % 2 for target in (*targets, default)):
            tables.append(M68kJumpTable(compare, jump, table, default, targets))
    return tables


def m68k_jump_table_records(image: bytes, unit: dict) -> list[dict]:
    """Map records for the switches in one exported 68k code unit."""
    start, base = unit["image_offset"], unit["linear"]

    def record(offset: int) -> dict:
        return {"unit_address": f"{unit['name']}:{offset:04x}", "linear": base + offset}

    width4 = (relocation["offset"] for relocation in unit["relocations"] if relocation.get("width", 4) == 4)
    return [
        {
            "unit": unit["name"], "kind": "jump", "bound": "compare", "address": record(table.jump),
            "guard": record(table.guard), "table": record(table.table), "default": record(table.default),
            "targets": [record(target) for target in table.targets],
        }
        for table in recover_m68k_jump_tables(image[start:start + unit["size"]], base, width4)
    ]
