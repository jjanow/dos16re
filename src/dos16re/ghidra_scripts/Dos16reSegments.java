// Track real-mode segment registers after Ghidra has recovered code and control flow.
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

public class Dos16reSegments extends HeadlessScript {
    private static final int WORD_MASK = 0xffff;
    private static final int STACK_LIMIT = 8;
    private SegmentedAddressSpace space;
    private Register cs, ds, es, ss, sp;
    private final Map<Long, Integer> words = new HashMap<>();
    private final Map<Address, List<Access>> accesses = new HashMap<>();
    private final Map<Address, State> states = new HashMap<>();
    private final ArrayDeque<Address> pending = new ArrayDeque<>();
    private final Map<String, Integer> overlaySegments = new HashMap<>();
    private Startup startup;

    private static class State {
        final Map<Register, Integer> registers = new HashMap<>();
        final List<Integer> stack = new ArrayList<>();

        State copy() {
            State result = new State();
            result.registers.putAll(registers);
            result.stack.addAll(stack);
            return result;
        }

        void set(Register register, Integer value) {
            if (value == null) {
                registers.remove(register);
            } else {
                registers.put(register, value);
            }
        }

        // Keep only values that agree on every incoming path.
        boolean merge(State incoming) {
            boolean changed = registers.entrySet().removeIf(
                entry -> !entry.getValue().equals(incoming.registers.get(entry.getKey())));
            if (stack.size() != incoming.stack.size()) {
                changed |= !stack.isEmpty();
                stack.clear();
            } else {
                for (int index = 0; index < stack.size(); index++) {
                    if (stack.get(index) != null && !stack.get(index).equals(incoming.stack.get(index))) {
                        stack.set(index, null);
                        changed = true;
                    }
                }
            }
            return changed;
        }
    }

    private record Startup(int dgroup, Address call) {}
    private record Access(int operand, Register segment, int offset, int size, RefType type) {}

    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        String[] args = getScriptArgs();
        Path result = Path.of(args[1]);
        try {
            JsonObject map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            applySegments(map);
            Files.writeString(result, new Gson().toJson(Map.of(
                "program", currentProgram.getName(), "units", map.getAsJsonArray("units").size()
            )));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(result, new Gson().toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private void applySegments(JsonObject map) throws Exception {
        space = (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
        cs = currentProgram.getRegister("CS");
        ds = currentProgram.getRegister("DS");
        es = currentProgram.getRegister("ES");
        ss = currentProgram.getRegister("SS");
        sp = currentProgram.getRegister("SP");
        var memory = currentProgram.getMemory();
        var units = map.getAsJsonArray("units");
        long origin = units.get(0).getAsJsonObject().get("linear").getAsLong();
        for (int index = 1; index < units.size(); index++) {
            var unit = units.get(index).getAsJsonObject();
            overlaySegments.put(unit.get("name").getAsString(), unit.get("segment").getAsInt());
        }
        if (map.has("relocations")) {
            for (JsonElement item : map.getAsJsonArray("relocations")) {
                Address address = space.getAddress(origin + item.getAsLong());
                var block = memory.getBlock(address);
                if (block != null && !address.equals(block.getEnd())) {
                    words.put(address.getOffset(), memory.getShort(address) & WORD_MASK);
                }
            }
        }

        var entryRecord = map.getAsJsonObject("entry");
        int codeSegment = entryRecord.get("segment").getAsInt();
        Address entry = space.getAddress(codeSegment, entryRecord.get("offset").getAsInt());
        State initial = new State();
        initial.set(cs, codeSegment);
        initial.set(ss, map.getAsJsonObject("stack").get("segment").getAsInt());
        startup = findStartup(entry, initial, 2);

        // A direct write may invalidate a segment word even when another path first reads it.
        // Re-run after removing such words so no context depends on their initial contents.
        do {
            states.clear();
            offer(entry, initial);
            follow();
            for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
                Address start = function.getEntryPoint();
                if (!states.containsKey(start)) {
                    State detached = new State();
                    detached.set(ds, startup == null ? null : startup.dgroup());
                    detached.set(cs, overlaySegments.get(memory.getBlock(start).getName()));
                    offer(start, detached);
                }
            }
            follow();
        } while (removeWrittenWords());
        writeContextAndReferences();
    }

    private Startup findStartup(Address address, State state, int callDepth) throws Exception {
        var relocatedValues = new HashSet<Integer>();
        for (int count = 0; address != null && count < 32; count++) {
            Instruction instruction = getInstructionAt(address);
            if (instruction == null) {
                break;
            }
            Integer immediate = words.get(instruction.getMaxAddress().getOffset() - 1);
            if (instruction.getMnemonicString().equals("MOV") && instruction.getRegister(0) != null &&
                    instruction.getScalar(1) != null && immediate != null &&
                    (instruction.getScalar(1).getUnsignedValue() & WORD_MASK) == immediate) {
                relocatedValues.add(immediate);
            }
            State output = transfer(instruction, state);
            Integer candidate = output.registers.get(ds);
            if (candidate != null && !Objects.equals(state.registers.get(ds), candidate) &&
                    relocatedValues.contains(candidate) &&
                    currentProgram.getMemory().contains(space.getAddress(candidate, 0))) {
                return new Startup(candidate, null);
            }
            var flow = instruction.getFlowType();
            if (flow.isCall() && !flow.isComputed() && callDepth > 0) {
                Address[] targets = instruction.getFlows();
                if (targets.length == 1) {
                    Startup callee = findStartup(targets[0], callState(instruction, state), callDepth - 1);
                    if (callee != null) {
                        return new Startup(callee.dgroup(), address);
                    }
                }
            }
            if (flow.isJump() || flow.isTerminal()) {
                break;
            }
            state = output;
            address = instruction.getFallThrough();
        }
        return null;
    }

    private void offer(Address address, State state) {
        if (address == null || getInstructionAt(address) == null) {
            return;
        }
        State previous = states.get(address);
        if (previous == null) {
            states.put(address, state.copy());
            pending.add(address);
        } else if (previous.merge(state)) {
            pending.add(address);
        }
    }

    private void follow() throws Exception {
        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            Address address = pending.remove();
            Instruction instruction = getInstructionAt(address);
            State input = states.get(address);
            var flow = instruction.getFlowType();
            State output = transfer(instruction, input);
            if (flow.isCall()) {
                State callee = callState(instruction, input);
                for (Address target : instruction.getFlows()) {
                    offer(target, callee);
                }
                if (startup != null && address.equals(startup.call())) {
                    output.set(ds, startup.dgroup());
                }
            } else if (flow.isJump()) {
                State jumped = output.copy();
                jumped.set(cs, targetCS(instruction, input));
                for (Address target : instruction.getFlows()) {
                    offer(target, jumped);
                }
            }
            offer(instruction.getFallThrough(), output);
        }
    }

    private State callState(Instruction instruction, State input) throws Exception {
        State callee = new State();
        callee.set(cs, targetCS(instruction, input));
        for (Register segment : List.of(ds, es, ss)) {
            callee.set(segment, input.registers.get(segment));
        }
        return callee;
    }

    private Integer targetCS(Instruction instruction, State input) throws Exception {
        byte[] bytes = instruction.getBytes();
        int opcode = bytes[0] & 0xff;
        if (bytes.length == 5 && (opcode == 0x9a || opcode == 0xea)) {
            return (bytes[3] & 0xff) | ((bytes[4] & 0xff) << 8);
        }
        if (instruction.getMnemonicString().endsWith("F")) {
            return null;
        }
        return input.registers.get(cs);
    }

    private State transfer(Instruction instruction, State input) {
        State output = input.copy();
        String op = instruction.getMnemonicString();
        Register dest = instruction.getNumOperands() == 0 ? null : instruction.getRegister(0);
        for (Object result : instruction.getResultObjects()) {
            if (result instanceof Register written) {
                output.registers.keySet().removeIf(
                    tracked -> tracked.getBaseRegister().equals(written.getBaseRegister()));
                if (written.getBaseRegister().equals(sp.getBaseRegister())) {
                    output.stack.clear();
                }
            }
        }

        if (op.equals("PUSH") || op.equals("POP") || op.equals("PUSHF") || op.equals("POPF")) {
            output.stack.clear();
            output.stack.addAll(input.stack);
            if (op.startsWith("PUSH")) {
                if (output.stack.size() == STACK_LIMIT) {
                    output.stack.removeFirst();
                }
                output.stack.add(op.equals("PUSH") ? value(instruction, 0, input) : null);
            } else {
                Integer word = output.stack.isEmpty() ? null : output.stack.removeLast();
                if (dest != null && dest.getBitLength() == 16) {
                    output.set(dest, word);
                }
            }
        } else if (instruction.getFlowType().isCall() || op.equals("INT") || op.equals("INTO")) {
            // Assume the usual DOS calling convention for DS and SS. ES and general registers
            // can be clobbered and a callee can remove arguments from the stack.
            output.registers.keySet().retainAll(List.of(cs, ds, ss));
            output.stack.clear();
        } else if (dest != null && dest.getBitLength() == 16) {
            if (op.equals("MOV")) {
                output.set(dest, value(instruction, 1, input));
            } else if (op.equals("XOR") && dest.equals(instruction.getRegister(1))) {
                output.set(dest, 0);
            } else if (op.equals("XCHG") && instruction.getRegister(1) != null) {
                Register source = instruction.getRegister(1);
                output.set(dest, input.registers.get(source));
                output.set(source, input.registers.get(dest));
            }
        }
        return output;
    }

    private Integer value(Instruction instruction, int operand, State input) {
        Register register = instruction.getRegister(operand);
        if (register != null) {
            return input.registers.get(register);
        }
        for (Access access : accesses(instruction)) {
            if (access.operand() == operand && access.size() == 2) {
                Address address = target(access, input);
                return address == null ? null : words.get(address.getOffset());
            }
        }
        Scalar scalar = instruction.getScalar(operand);
        if (scalar != null && !instruction.getDefaultOperandRepresentation(operand).contains("[")) {
            return (int) scalar.getUnsignedValue() & WORD_MASK;
        }
        return null;
    }

    private List<Access> accesses(Instruction instruction) {
        return accesses.computeIfAbsent(instruction.getAddress(), ignored -> {
            var result = new ArrayList<Access>();
            var pcode = instruction.getPcode();
            for (int index = 0; index < instruction.getNumOperands(); index++) {
                if (!instruction.getDefaultOperandRepresentation(index).contains("[")) {
                    continue;
                }
                // Direct memory operands have a displacement and at most a segment override.
                Register override = null;
                Integer offset = null;
                for (Object object : instruction.getOpObjects(index)) {
                    if (object instanceof Scalar scalar) {
                        offset = (int) scalar.getUnsignedValue() & WORD_MASK;
                    } else if (object instanceof Register register &&
                            List.of(cs, ds, es, ss).contains(register)) {
                        override = register;
                    } else {
                        offset = null;
                        break;
                    }
                }
                if (offset == null) {
                    continue;
                }
                for (PcodeOp op : pcode) {
                    if (op.getOpcode() != PcodeOp.CALLOTHER || op.getNumInputs() != 3 ||
                            !op.getInput(1).isRegister() || !op.getInput(2).isConstant() ||
                            op.getInput(2).getOffset() != offset ||
                            !currentProgram.getLanguage().getUserDefinedOpName(
                                (int) op.getInput(0).getOffset()).equals("segment")) {
                        continue;
                    }
                    var base = op.getInput(1);
                    Register segment = currentProgram.getRegister(base.getAddress(), base.getSize());
                    if (segment == null || !List.of(cs, ds, es, ss).contains(segment) ||
                            (override != null && !override.equals(segment))) {
                        continue;
                    }
                    boolean read = false;
                    boolean write = false;
                    int size = 0;
                    for (PcodeOp use : pcode) {
                        if (use.getNumInputs() >= 2 && use.getInput(1).equals(op.getOutput())) {
                            if (use.getOpcode() == PcodeOp.LOAD) {
                                read = true;
                                size = use.getOutput().getSize();
                            } else if (use.getOpcode() == PcodeOp.STORE) {
                                write = true;
                                size = use.getInput(2).getSize();
                            }
                        }
                    }
                    if (read || write) {
                        RefType type = write ? (read ? RefType.READ_WRITE : RefType.WRITE) : RefType.READ;
                        result.add(new Access(index, segment, offset, size, type));
                        break;
                    }
                }
            }
            return result;
        });
    }

    private Address target(Access access, State state) {
        Integer segment = state.registers.get(access.segment());
        return segment == null ? null : space.getAddress(segment, access.offset());
    }

    private boolean removeWrittenWords() throws Exception {
        if (words.isEmpty()) {
            return false;
        }
        boolean changed = false;
        for (var entry : states.entrySet()) {
            monitor.checkCancelled();
            for (Access access : accesses(getInstructionAt(entry.getKey()))) {
                Address address = target(access, entry.getValue());
                if (address != null && access.type().isWrite()) {
                    long start = address.getOffset();
                    for (long index = start - 1; index < start + access.size(); index++) {
                        changed |= words.remove(index) != null;
                    }
                }
            }
        }
        return changed;
    }

    private void writeContextAndReferences() throws Exception {
        var context = currentProgram.getProgramContext();
        var listing = currentProgram.getListing();
        var memory = currentProgram.getMemory();
        var refs = currentProgram.getReferenceManager();
        for (var entry : new TreeMap<>(states).entrySet()) {
            monitor.checkCancelled();
            Instruction instruction = getInstructionAt(entry.getKey());
            State state = entry.getValue();
            for (Register segment : List.of(ds, es, ss)) {
                Integer value = state.registers.get(segment);
                if (value != null) {
                    context.setValue(segment, instruction.getMinAddress(), instruction.getMaxAddress(),
                        BigInteger.valueOf(value));
                }
            }
            for (Access access : accesses(instruction)) {
                if (access.segment().equals(cs)) {
                    continue;
                }
                Address target = target(access, state);
                if (target == null || !memory.contains(target) || listing.getInstructionContaining(target) != null) {
                    continue;
                }
                for (var old : refs.getReferencesFrom(entry.getKey(), access.operand())) {
                    if (old.isMemoryReference() && old.getReferenceType().isData() &&
                            old.getSource() == SourceType.ANALYSIS && !old.getToAddress().equals(target)) {
                        refs.delete(old);
                    }
                }
                var ref = refs.addMemoryReference(entry.getKey(), target, access.type(),
                    SourceType.ANALYSIS, access.operand());
                refs.setPrimary(ref, true);
                nameGlobal((SegmentedAddress) target, access.size());
            }
        }
    }

    private void nameGlobal(SegmentedAddress address, int size) throws Exception {
        var listing = currentProgram.getListing();
        var block = currentProgram.getMemory().getBlock(address);
        var type = switch (size) {
            case 1 -> ByteDataType.dataType;
            case 2 -> WordDataType.dataType;
            case 4 -> DWordDataType.dataType;
            case 8 -> QWordDataType.dataType;
            default -> null;
        };
        if (type != null && block.getEnd().subtract(address) >= size - 1L) {
            boolean undefined = true;
            for (int index = 0; index < size; index++) {
                undefined &= listing.getUndefinedDataAt(address.addNoWrap(index)) != null;
            }
            if (undefined) {
                listing.createData(address, type);
            }
        }
        var symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        if (symbol == null || symbol.getSource() == SourceType.DEFAULT) {
            String name = startup != null && startup.dgroup() == address.getSegment()
                ? String.format("DGROUP_%04x", address.getSegmentOffset())
                : String.format("FAR%04x_%04x", address.getSegment(), address.getSegmentOffset());
            currentProgram.getSymbolTable().createLabel(address, name, SourceType.ANALYSIS).setPrimary();
        }
    }
}
