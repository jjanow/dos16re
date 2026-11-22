"""Recover bounded 16-bit near jumps through CS-relative word tables."""

from collections.abc import Iterator
from dataclasses import dataclass
from struct import iter_unpack

from capstone import CS_ARCH_X86, CS_MODE_16, Cs, CsInsn
from capstone.x86 import (
    X86_INS_ADD, X86_INS_CMP, X86_INS_JA, X86_INS_JAE, X86_INS_JMP, X86_INS_MOV,
    X86_INS_SHL, X86_INS_SUB, X86_INS_XCHG, X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
    X86_REG_CS, X86_REG_INVALID,
)

_MAX_GUARD_BYTES = 16
_MAX_CASES = 0x8000  # The scaled 16-bit index must fit without wrapping.
_WORD_MASK = 0xFFFF


@dataclass(frozen=True)
class JumpTable:
    guard: int
    jump: int
    table: int
    default: int
    targets: tuple[int, ...]


def _reg_imm(insn: CsInsn) -> tuple[int, int] | None:
    left, right = insn.operands
    if left.type == X86_OP_REG and left.size == 2 and right.type == X86_OP_IMM:
        return left.reg, right.imm & _WORD_MASK
    return None


def _guard(insns: list[CsInsn], index: int) -> tuple[int, int, int] | None:
    if len(insns) not in (3, 4):
        return None
    compare, branch, *setup = insns
    if compare.id != X86_INS_CMP or branch.id not in (X86_INS_JA, X86_INS_JAE):
        return None
    bound = _reg_imm(compare)
    if bound is None or branch.operands[0].type != X86_OP_IMM:
        return None
    selector, limit = bound
    count = limit + (branch.id == X86_INS_JA)
    if not 1 <= count <= _MAX_CASES:
        return None

    if len(setup) == 2:
        copy = setup[0]
        if copy.id not in (X86_INS_MOV, X86_INS_XCHG):
            return None
        if any(operand.type != X86_OP_REG or operand.size != 2 for operand in copy.operands):
            return None
        registers = tuple(operand.reg for operand in copy.operands)
        if registers != (index, selector) and (
            copy.id != X86_INS_XCHG or registers != (selector, index)
        ):
            return None
    elif selector != index:
        return None

    scale = setup[-1]
    if not (
        (scale.id == X86_INS_SHL and _reg_imm(scale) == (index, 1))
        or (scale.id == X86_INS_ADD and all(
            operand.type == X86_OP_REG and operand.reg == index for operand in scale.operands
        ))
    ):
        return None
    return selector, count, branch.operands[0].imm & _WORD_MASK


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
    guard: int, jump_end: int, default: int,
) -> tuple[int, ...]:
    table_end = table + count * 2
    if not (0 <= table < table_end <= len(code) and (table_end <= guard or jump_end <= table)):
        return ()
    targets = tuple(
        (word - bias) & _WORD_MASK for word, in iter_unpack("<H", code[table:table_end])
    )
    for target in {*targets, default}:
        if (
            target >= len(code) or table <= target < table_end or guard <= target < jump_end
            or next(decoder.disasm_lite(code[target:target + 15], target, 1), None) is None
        ):
            return ()
    return targets


def recover_jump_tables(code: bytes, *, flat_overlay: bool = False) -> list[JumpTable]:
    """Scan one code segment, with offsets measured from the start of the supplied bytes."""
    code = code[:0x10000]
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    tables = []
    jump = code.find(b"\x2e\xff")
    while jump != -1:
        recovered = _recover_at(decoder, code, jump, flat_overlay)
        if recovered is not None:
            tables.append(recovered)
        jump = code.find(b"\x2e\xff", jump + 1)
    return tables


def _recover_at(decoder: Cs, code: bytes, jump: int, flat_overlay: bool) -> JumpTable | None:
    instruction = next(decoder.disasm(code[jump:jump + 15], jump, 1), None)
    if instruction is None or instruction.id != X86_INS_JMP:
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

    displacement = memory.disp & _WORD_MASK
    jump_end = jump + instruction.size
    for start in range(max(0, jump - _MAX_GUARD_BYTES), jump):
        insns = list(decoder.disasm(code[start:jump], start))
        if not insns or insns[-1].address + insns[-1].size != jump:
            continue
        bound = _guard(insns, memory.base)
        if bound is None:
            continue
        selector, count, default = bound
        targets = _targets(decoder, code, displacement, count, 0, start, jump_end, default)
        if targets:
            return JumpTable(start, jump, displacement, default, targets)
        if not flat_overlay:
            return None

        # Flat overlays may contain IPs relative to where they ran originally.
        # An inline table anchors that displacement to a known file offset.
        for table in _inline_starts(decoder, code, start, selector, count):
            targets = _targets(
                decoder, code, table, count, displacement - table, start, jump_end, default,
            )
            if targets and any(target < table for target in targets):
                return JumpTable(start, jump, table, default, targets)
    return None
