// Apply DOS conventions, runtime prototypes, and segment context after auto-analysis.
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.regex.Pattern;

public class RetroreSegments extends HeadlessScript {
    private static final int WORD_MASK = 0xffff;
    // While summarizing a function, values from SYMBOL up stand for a register's value at entry.
    private static final int SYMBOL = 0x10000;
    private static final int STACK_LIMIT = 16;
    private static final int UNKNOWN_HEIGHT = Integer.MIN_VALUE;
    private static final int SUMMARY_PASSES = 6;
    private static final int SUMMARY_STEPS = 50000;
    private static final int CONTEXT_ROUNDS = 4;
    private static final int PASCAL_FRAME_ROUNDS = 8;
    private static final int PASCAL_FRAME_HELPER_SIZE = 31;
    static final String PASCAL_FRAME_FIXUP = "retrore_microsoft_pascal_frame";
    // Read the size at CS:[return IP], save BP, check the stack, and jump past the size word.
    private static final Pattern PASCAL_FRAME_HELPER = Pattern.compile(
        "5e2e8b0c4646558bec2be972063b2e[0-9a-f]{4}7706569a[0-9a-f]{8}8be503e9ffe6");
    // Per instruction: "REG=origin;..." with the linear address where each unknown segment value was lost.
    private static final String LOSS_MAP = "RetroreSegmentLosses";
    // Per origin: one "REG\treason\tdetail" line for each segment register lost there.
    private static final String LOSS_ORIGIN_MAP = "RetroreSegmentLossOrigins";
    private static final String WRITE_CONTEXT_MAP = "RetroreWriteContextV2";
    private SegmentedAddressSpace space;
    private Register cs, ds, es, ss, sp, bp;
    private List<Register> segmentRegisters;
    private List<Register> summarized;
    private List<Register> baseRegisters;
    private final Map<Long, Integer> words = new HashMap<>();
    private final HashSet<Long> written = new HashSet<>();
    private final Map<Address, List<Access>> accesses = new HashMap<>();
    private final Map<Address, State> states = new HashMap<>();
    private final ArrayDeque<Address> pending = new ArrayDeque<>();
    private final Map<String, Integer> overlaySegments = new HashMap<>();
    private final Map<Long, Map<Long, Integer>> farSwitchSegments = new HashMap<>();
    private final Map<Address, Summary> symbolicSummaries = new HashMap<>();
    private Map<Address, Summary> contextSummaries = new HashMap<>();
    private Startup startup;
    private boolean auditingWrites;
    private int skippedJumps;
    private final Map<String, Object> segmentStats = new LinkedHashMap<>();

    // Why a register has no known value: the instruction where it was lost and a reason code.
    private record Loss(Address at, String reason, String detail) {}

    private static class State {
        final Map<Register, Integer> registers = new HashMap<>();
        final Map<Register, Loss> losses = new HashMap<>();
        final List<Integer> stack = new ArrayList<>(); // newest word last
        int height; // words pushed since function entry
        List<Integer> frame; // stack words when BP was set to SP, newest last
        int frameHeight = UNKNOWN_HEIGHT;

        State copy() {
            State result = new State();
            result.registers.putAll(registers);
            result.losses.putAll(losses);
            result.stack.addAll(stack);
            result.height = height;
            result.frame = frame == null ? null : new ArrayList<>(frame);
            result.frameHeight = frameHeight;
            return result;
        }

        void set(Register register, Integer value) {
            if (value == null) {
                registers.remove(register);
            } else {
                registers.put(register, value);
                losses.remove(register);
            }
        }

        void lose(Register register, Loss loss) {
            registers.remove(register);
            if (loss != null) {
                losses.put(register, loss);
            }
        }

        void push(Integer value) {
            if (stack.size() == STACK_LIMIT) {
                stack.removeFirst();
            }
            stack.add(value);
            if (height != UNKNOWN_HEIGHT) {
                height++;
            }
        }

        Integer pop() {
            if (height != UNKNOWN_HEIGHT) {
                height--;
            }
            return stack.isEmpty() ? null : stack.removeLast();
        }

        void drop(int count) {
            for (int index = 0; index < count; index++) {
                pop();
            }
        }

        void forgetStack() {
            stack.clear();
            height = UNKNOWN_HEIGHT;
        }

        void forgetStackValues() {
            Collections.fill(stack, null);
            if (frame != null) {
                Collections.fill(frame, null);
            }
        }

        // Keep only values that agree on every incoming path. Loss records never requeue a state.
        boolean merge(State incoming, Address at) {
            boolean changed = false;
            for (var entry : new ArrayList<>(registers.entrySet())) {
                Register register = entry.getKey();
                Integer other = incoming.registers.get(register);
                if (!entry.getValue().equals(other)) {
                    registers.remove(register);
                    Loss loss = other != null
                        ? new Loss(at, "join", String.format("paths disagree: %04x and %04x", entry.getValue(), other))
                        : incoming.losses.get(register);
                    losses.put(register, loss != null ? loss : new Loss(at, "join", "a path has no known value"));
                    changed = true;
                }
            }
            for (var entry : incoming.losses.entrySet()) {
                if (!registers.containsKey(entry.getKey())) {
                    losses.putIfAbsent(entry.getKey(), entry.getValue());
                }
            }
            if (height != incoming.height) {
                changed |= height != UNKNOWN_HEIGHT || !stack.isEmpty();
                forgetStack();
            } else {
                changed |= mergeWords(stack, incoming.stack);
            }
            if (frame != null) {
                if (incoming.frame == null || frameHeight != incoming.frameHeight) {
                    frame = null;
                    frameHeight = UNKNOWN_HEIGHT;
                    changed = true;
                } else {
                    changed |= mergeWords(frame, incoming.frame);
                }
            }
            return changed;
        }

        // Align two stacks at their newest word, drop words only one of them tracks, and forget disagreements.
        private static boolean mergeWords(List<Integer> mine, List<Integer> theirs) {
            boolean changed = false;
            int keep = Math.min(mine.size(), theirs.size());
            if (keep < mine.size()) {
                mine.subList(0, mine.size() - keep).clear();
                changed = true;
            }
            for (int index = 1; index <= keep; index++) {
                Integer word = mine.get(mine.size() - index);
                if (word != null && !word.equals(theirs.get(theirs.size() - index))) {
                    mine.set(mine.size() - index, null);
                    changed = true;
                }
            }
            return changed;
        }
    }

    private record Startup(int dgroup, Address call) {}
    private record Access(int operand, Register segment, int offset, List<Register> bases, int size, RefType type) {}
    // Register values when a function returns: concrete values or SYMBOL + index for an entry value.
    // A missing register is changed to an unknown value. Purge counts argument words the return removes.
    private record Summary(Map<Register, Integer> exits, Integer purge, boolean far,
            Map<Register, Integer> assumptions) {}


    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        space = (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
        if (args.length == 1) {
            applySegments(JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject(), true);
            return;
        }
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        Path result = Path.of(args[1]);
        try {
            JsonObject map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            var compiler = map.get("compiler");
            boolean microsoftPascal = compiler != null && compiler.isJsonObject() &&
                compiler.getAsJsonObject().get("family").getAsString().equals("Microsoft Pascal");
            int frameCalls = microsoftPascal ? recoverPascalFrames() : 0;
            int farProcedures = recoverFarProcedures();
            int runtimeSignatures = applyRuntimeSignatures(map.getAsJsonArray("runtime_signatures"));
            applySegments(map, false);
            var report = new HashMap<String, Object>(Map.of(
                "program", currentProgram.getName(), "units", map.getAsJsonArray("units").size(),
                "far_procedures", farProcedures, "runtime_signatures", runtimeSignatures
            ));
            if (!segmentStats.isEmpty()) {
                report.put("segment_analysis", segmentStats);
            }
            if (microsoftPascal) {
                report.put("microsoft_pascal_frame_calls", frameCalls);
            }
            if (map.has("format") && map.get("format").getAsString().equals("PC98")) {
                report.put("format", "PC98");
                report.put("memory_view", map.get("memory_view").getAsString());
            }
            Files.writeString(result, new Gson().toJson(report));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(result, new Gson().toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private int recoverPascalFrames() throws Exception {
        var listing = currentProgram.getListing();
        var memory = currentProgram.getMemory();
        var helperMatches = new HashMap<Address, Boolean>();
        var recoveredSites = new HashSet<Address>();
        var recoveredHelpers = new HashSet<Address>();
        for (int round = 0; round < PASCAL_FRAME_ROUNDS; round++) {
            var sites = new LinkedHashMap<Address, Address>();
            for (var instruction : listing.getInstructions(true)) {
                monitor.checkCancelled();
                if (instruction.getLength() != 3 || !instruction.getFlowType().isCall() ||
                        instruction.isFallThroughOverridden() || memory.getByte(instruction.getAddress()) != (byte) 0xe8) {
                    continue;
                }
                Address[] targets = instruction.getFlows();
                if (targets.length != 1) {
                    continue;
                }
                Address target = targets[0];
                var block = memory.getBlock(target);
                if (block == null || !block.isInitialized() || !block.isExecute() ||
                        block.getEnd().subtract(target) < PASCAL_FRAME_HELPER_SIZE - 1) {
                    continue;
                }
                if (!helperMatches.containsKey(target)) {
                    byte[] bytes = new byte[PASCAL_FRAME_HELPER_SIZE];
                    memory.getBytes(target, bytes);
                    helperMatches.put(target, PASCAL_FRAME_HELPER.matcher(HexFormat.of().formatHex(bytes)).matches());
                }
                if (helperMatches.get(target)) {
                    sites.put(instruction.getAddress(), target);
                }
            }
            int previous = recoveredSites.size();
            for (var candidate : sites.entrySet()) {
                Address site = candidate.getKey();
                var call = getInstructionAt(site);
                if (call == null) {
                    continue;
                }
                Address word = call.getMaxAddress().next();
                var block = memory.getBlock(site);
                if (word == null || block.getEnd().subtract(word) < 2 ||
                        hasOtherFrameWordEntry(site, word) || hasOtherFrameWordEntry(site, word.next())) {
                    continue;
                }
                Address resume = word.addNoWrap(2);
                var function = getFunctionContaining(site);
                call.setFallThrough(resume);
                listing.clearCodeUnits(word, word.next(), false);
                var size = listing.createData(word, WordDataType.dataType);
                MutabilitySettingsDefinition.DEF.setChoice(size, MutabilitySettingsDefinition.CONSTANT);
                listing.setComment(word, CommentType.EOL,
                    "Microsoft Pascal local frame size: " + (memory.getShort(word) & WORD_MASK) + " bytes");
                disassemble(resume);
                if (function != null) {
                    CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
                }
                recoveredHelpers.add(candidate.getValue());
                recoveredSites.add(site);
            }
            if (recoveredSites.size() == previous) {
                break;
            }
            analyzeChanges(currentProgram);
        }
        var helpers = new ArrayList<Function>();
        for (Address target : recoveredHelpers) {
            var helper = getFunctionAt(target);
            // The fixup is attached to the callee. Every known caller needs the recovered continuation.
            if (helper != null && hasOnlyRecoveredFrameCalls(target, recoveredSites)) {
                helpers.add(helper);
            }
        }
        if (!helpers.isEmpty()) {
            addPascalFrameFixup(helpers);
        }
        return recoveredSites.size();
    }

    private boolean hasOnlyRecoveredFrameCalls(Address helper, HashSet<Address> recoveredSites) {
        for (var reference : currentProgram.getReferenceManager().getReferencesTo(helper)) {
            if (reference.getReferenceType().isCall() && !recoveredSites.contains(reference.getFromAddress())) {
                return false;
            }
        }
        return true;
    }

    private void addPascalFrameFixup(List<Function> helpers) throws Exception {
        // Model the successful path. The near CALL already pushed its return IP, and the helper
        // replaces that word with the saved BP. inst_next points at the inline size before the
        // fall-through override. The helper's final ADD restores BP and sets the arithmetic flags.
        var extension = new SpecExtension(currentProgram);
        extension.addReplaceCompilerSpecExtension("<callfixup name=\"" + PASCAL_FRAME_FIXUP + "\">" + """
            <pcode><body><![CDATA[
                local slot:4 = segment(SS, SP);
                local sizeWord:4 = &:4 inst_next;
                SI = *:2 slot + 2;
                CX = *:2 sizeWord;
                *:2 slot = BP;
                BP = SP;
                SP = SP - CX;
                CF = carry(SP, CX);
                OF = scarry(SP, CX);
                AF = ((SP ^ CX ^ BP) & 0x10) != 0;
                SF = BP s< 0;
                ZF = BP == 0;
                PF = (popcount(BP & 0xff) & 1:1) == 0;
            ]]></body></pcode></callfixup>
            """, monitor);
        for (Function helper : helpers) {
            helper.setCallFixup(PASCAL_FRAME_FIXUP);
        }
    }

    private boolean hasOtherFrameWordEntry(Address call, Address wordByte) {
        if (currentProgram.getSymbolTable().isExternalEntryPoint(wordByte)) {
            return true;
        }
        for (var reference : currentProgram.getReferenceManager().getReferencesTo(wordByte)) {
            if (reference.getReferenceType().isFlow() &&
                    !reference.getFromAddress().equals(call) &&
                    !reference.getFromAddress().equals(call.add(3))) {
                return true;
            }
        }
        return false;
    }

    private int recoverFarProcedures() throws Exception {
        var listing = currentProgram.getListing();
        var functions = currentProgram.getFunctionManager();
        var references = currentProgram.getReferenceManager();
        var candidates = new HashSet<Address>();
        for (var call : listing.getInstructions(true)) {
            monitor.checkCancelled();
            if (!call.getFlowType().isCall() || call.getLength() != 3 || call.getByte(0) != (byte) 0xe8) {
                continue;
            }
            Address previous = call.getFallFrom();
            var push = previous == null ? null : listing.getInstructionAt(previous);
            if (push == null || push.getLength() != 1 || push.getByte(0) != 0x0e ||
                    !call.getAddress().equals(push.getFallThrough())) {
                continue;
            }
            boolean otherEntry = false;
            for (var reference : references.getReferencesTo(call.getAddress())) {
                if (reference.getReferenceType().isFlow() && !reference.getFromAddress().equals(push.getAddress())) {
                    otherEntry = true;
                    break;
                }
            }
            var targets = call.getFlows();
            if (!otherEntry && targets.length == 1) {
                candidates.add(targets[0]);
            }
        }

        int recovered = 0;
        for (Address target : candidates) {
            monitor.checkCancelled();
            var function = functions.getFunctionAt(target);
            if (function == null || function.isThunk() || function.getSignatureSource() == SourceType.USER_DEFINED) {
                continue;
            }
            Integer purge = null;
            for (var instruction : listing.getInstructions(function.getBody(), true)) {
                monitor.checkCancelled();
                String mnemonic = instruction.getMnemonicString();
                if (mnemonic.startsWith("RET") || mnemonic.startsWith("IRET")) {
                    int opcode = instruction.getByte(0) & 0xff;
                    if (opcode != 0xcb && opcode != 0xca) {
                        purge = null;
                        break;
                    }
                    int size = opcode == 0xcb ? 0 : (int) instruction.getScalar(0).getUnsignedValue();
                    if (purge != null && purge != size) {
                        purge = null;
                        break;
                    }
                    purge = size;
                }
            }
            if (purge != null) {
                function.setCallingConvention("__stdcall16far");
                function.setStackPurgeSize(purge);
                recovered++;
            }
        }
        return recovered;
    }

    private int applyRuntimeSignatures(JsonArray signatures) throws Exception {
        if (signatures == null) {
            return 0;
        }
        int applied = 0;
        for (var item : signatures) {
            monitor.checkCancelled();
            var signature = item.getAsJsonObject();
            Address address = space.getAddress(signature.getAsJsonObject("address").get("linear").getAsLong());
            var function = getFunctionAt(address);
            if (function == null || function.isThunk() || function.getSignatureSource() == SourceType.USER_DEFINED) {
                continue;
            }
            var registers = signature.getAsJsonArray("result_registers");
            boolean custom = !registers.isEmpty();
            var purge = signature.get("stack_purge");
            boolean far = !purge.isJsonNull() || signature.has("far") && signature.get("far").getAsBoolean();
            DataType result = runtimeType(signature.get("result").getAsString());
            var returnValue = custom ? new ReturnParameterImpl(result, registerStorage(registers), currentProgram)
                : new ReturnParameterImpl(result, currentProgram);
            var parameters = new ArrayList<Parameter>();
            int stackOffset = far ? 4 : 2;
            for (var argument : signature.getAsJsonArray("parameters")) {
                var parameter = argument.getAsJsonObject();
                String name = parameter.get("name").getAsString();
                DataType type = runtimeType(parameter.get("type").getAsString());
                var argumentRegisters = parameter.getAsJsonArray("registers");
                if (!custom) {
                    parameters.add(new ParameterImpl(name, type, currentProgram));
                } else if (!argumentRegisters.isEmpty()) {
                    parameters.add(new ParameterImpl(name, type, registerStorage(argumentRegisters), currentProgram));
                } else {
                    parameters.add(new ParameterImpl(name, type, stackOffset, currentProgram));
                    stackOffset += (type.getLength() + 1) & ~1;
                }
            }
            String convention = !purge.isJsonNull() ? "__stdcall16far" : far ? "__cdecl16far" : "__cdecl16near";
            function.updateFunction(convention, returnValue, parameters,
                custom ? FunctionUpdateType.CUSTOM_STORAGE : FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                true, SourceType.ANALYSIS);
            function.setStackPurgeSize(purge.isJsonNull() ? 0 : purge.getAsInt());
            function.setVarArgs(signature.get("variadic").getAsBoolean());
            function.setName(signature.get("name").getAsString(), SourceType.ANALYSIS);
            applied++;
        }
        return applied;
    }

    private VariableStorage registerStorage(JsonArray names) throws Exception {
        Register[] registers = new Register[names.size()];
        for (int i = 0; i < names.size(); i++) {
            registers[i] = currentProgram.getRegister(names.get(i).getAsString());
        }
        return new VariableStorage(currentProgram, registers);
    }

    private DataType runtimeType(String name) {
        var manager = currentProgram.getDataTypeManager();
        return switch (name) {
            case "void" -> VoidDataType.dataType;
            case "int" -> ShortDataType.dataType;
            case "uint" -> UnsignedShortDataType.dataType;
            case "long" -> LongDataType.dataType;
            case "char*" -> new PointerDataType(CharDataType.dataType, 2, manager);
            case "void*" -> new PointerDataType(VoidDataType.dataType, 2, manager);
            case "farptr" -> new PointerDataType(VoidDataType.dataType, 4, manager);
            case "Real48" -> {
                var type = new StructureDataType("Real48", 0, manager);
                type.add(ByteDataType.dataType, "exponent", null);
                type.add(new ArrayDataType(ByteDataType.dataType, 5, 1), "fraction_and_sign", null);
                yield type;
            }
            default -> throw new IllegalArgumentException("unknown runtime type " + name);
        };
    }


    private void applySegments(JsonObject map, boolean onlyWrites) throws Exception {
        cs = currentProgram.getRegister("CS");
        ds = currentProgram.getRegister("DS");
        es = currentProgram.getRegister("ES");
        ss = currentProgram.getRegister("SS");
        sp = currentProgram.getRegister("SP");
        bp = currentProgram.getRegister("BP");
        segmentRegisters = List.of(ds, es, ss);
        summarized = new ArrayList<>();
        for (String name : List.of("AX", "CX", "DX", "BX", "BP", "SI", "DI", "DS", "ES", "SS")) {
            summarized.add(currentProgram.getRegister(name));
        }
        baseRegisters = List.of(currentProgram.getRegister("BX"), currentProgram.getRegister("SI"),
            currentProgram.getRegister("DI"), bp);
        var memory = currentProgram.getMemory();
        var units = map.getAsJsonArray("units");
        boolean pc98 = map.has("format") && map.get("format").getAsString().equals("PC98");
        long origin = pc98 ? map.get("image_origin").getAsLong() : units.get(0).getAsJsonObject().get("linear").getAsLong();
        for (int index = pc98 ? 0 : 1; index < units.size(); index++) {
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
        if (map.has("jump_tables")) {
            for (JsonElement item : map.getAsJsonArray("jump_tables")) {
                var table = item.getAsJsonObject();
                if (!table.has("entry_size") || table.get("entry_size").getAsInt() != 4) {
                    continue;
                }
                var selectors = new HashMap<Long, Integer>();
                for (JsonElement destination : table.getAsJsonArray("targets")) {
                    var target = destination.getAsJsonObject();
                    selectors.merge(target.get("linear").getAsLong(), target.get("segment").getAsInt(),
                        (previous, next) -> previous.equals(next) ? previous : -1);
                }
                farSwitchSegments.put(table.getAsJsonObject("address").get("linear").getAsLong(), selectors);
            }
        }

        var entryRecord = map.getAsJsonObject("entry");
        int codeSegment = entryRecord.get("segment").getAsInt();
        Address entry = space.getAddress(codeSegment, entryRecord.get("offset").getAsInt());
        State initial = new State();
        initial.set(cs, codeSegment);
        Loss psp = new Loss(entry, "entry", "DS and ES hold the PSP at program entry");
        initial.lose(ds, psp);
        initial.lose(es, psp);
        if (map.has("initial_segments")) {
            var segments = map.getAsJsonObject("initial_segments");
            if (segments.has("ds")) {
                initial.set(ds, segments.get("ds").getAsInt());
            }
            if (segments.has("es")) {
                initial.set(es, segments.get("es").getAsInt());
            }
        }
        if (map.has("stack")) {
            initial.set(ss, map.getAsJsonObject("stack").get("segment").getAsInt());
        }
        var entryStates = new LinkedHashMap<Address, State>();
        entryStates.put(entry, initial);
        if (pc98) {
            for (int index = 1; index < map.getAsJsonArray("entries").size(); index++) {
                var extra = map.getAsJsonArray("entries").get(index).getAsJsonObject();
                int segment = extra.get("segment").getAsInt();
                Address start = space.getAddress(segment, extra.get("offset").getAsInt());
                State state = new State();
                state.set(cs, segment);
                entryStates.merge(start, state, (previous, incoming) -> {
                    previous.merge(incoming, start);
                    return previous;
                });
            }
        }

        if (!onlyWrites) {
            Integer detachedSS = pc98 ? null : unchangedStackSegment(initial.registers.get(ss));
            startup = findStartup(entry, initial, 2);
            recoverListingContext(entryStates, detachedSS);
        }
        // Listing references benefit from compiler conventions and DGROUP guesses. A write
        // audit must also admit addresses that those guesses would have ruled out.
        auditingWrites = true;
        symbolicSummaries.clear();
        contextSummaries.clear();
        summarize(symbolicSummaries, false);
        analyzeProgram(entryStates, null);
        writeStoreContext();
    }

    private void recoverListingContext(Map<Address, State> entryStates, Integer detachedSS) throws Exception {
        // Summaries say which registers each function preserves, sets, or changes. Summaries computed
        // under the entry values the whole-program pass found apply only where a call matches them.
        summarize(symbolicSummaries, false);
        int rounds = 1;
        for (;; rounds++) {
            analyzeProgram(entryStates, detachedSS);
            if (rounds == CONTEXT_ROUNDS) {
                break;
            }
            var previous = contextSummaries;
            contextSummaries = new HashMap<>();
            summarize(contextSummaries, true);
            if (contextSummaries.equals(previous)) {
                break;
            }
        }
        segmentStats.put("rounds", rounds);
        segmentStats.put("summaries", symbolicSummaries.size());
        segmentStats.put("context_summaries", contextSummaries.size());
        segmentStats.put("skipped_jumps", skippedJumps);
        writeContextAndReferences();
    }

    private Integer unchangedStackSegment(Integer initial) throws Exception {
        if (initial == null) {
            return null;
        }
        // The MZ stack segment is valid at detached entries when analyzed code never assigns SS.
        for (var instruction : currentProgram.getListing().getInstructions(true)) {
            monitor.checkCancelled();
            for (Object result : instruction.getResultObjects()) {
                if (result instanceof Register register && register.getBaseRegister().equals(ss.getBaseRegister())) {
                    return null;
                }
            }
        }
        return initial;
    }

    private void analyzeProgram(Map<Address, State> entryStates, Integer detachedSS) throws Exception {
        var memory = currentProgram.getMemory();
        // A direct write may invalidate a segment word even when another path first reads it.
        // Re-run after removing such words so no context depends on their initial contents.
        do {
            states.clear();
            skippedJumps = 0;
            for (var seed : entryStates.entrySet()) {
                offer(seed.getKey(), seed.getValue());
            }
            follow();
            // Seed functions that no analyzed path reaches, one at a time, callers before callees: a
            // callee seeded too early would merge its callers' arguments and values into its default
            // state instead of receiving them. Functions without call references go first.
            for (boolean roots : List.of(true, false)) {
                for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
                    monitor.checkCancelled();
                    Address start = function.getEntryPoint();
                    if (states.containsKey(start) || (roots && called(function))) {
                        continue;
                    }
                    State detached = new State();
                    Loss none = new Loss(start, "entry", "no analyzed caller reaches this function");
                    if (startup == null || auditingWrites) {
                        detached.lose(ds, none);
                    } else {
                        detached.set(ds, startup.dgroup());
                    }
                    detached.lose(es, none);
                    if (detachedSS == null) {
                        detached.lose(ss, none);
                    } else {
                        detached.set(ss, detachedSS);
                    }
                    if (!auditingWrites) {
                        detached.set(cs, overlaySegments.get(memory.getBlock(start).getName()));
                    }
                    offer(start, detached);
                    follow();
                }
            }
        } while (removeWrittenWords());
    }

    // Whether another function's code calls this function directly.
    private boolean called(ghidra.program.model.listing.Function function) {
        for (var reference : currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())) {
            if (reference.getReferenceType().isCall() && !function.getBody().contains(reference.getFromAddress()) &&
                    getInstructionAt(reference.getFromAddress()) != null) {
                return true;
            }
        }
        return false;
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
                    Startup callee = findStartup(targets[0], callState(instruction, state, targets[0]), callDepth - 1);
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
        } else if (previous.merge(state, address)) {
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
            boolean interrupt = auditingWrites && instruction.getMnemonicString().equals("INT");
            if (interrupt) {
                for (var ref : currentProgram.getReferenceManager().getReferencesFrom(address)) {
                    if (ref.getReferenceType() == RefType.COMPUTED_CALL && ref.getSource() == SourceType.IMPORTED) {
                        offer(ref.getToAddress(), callState(instruction, input, ref.getToAddress()));
                    }
                }
            } else if (flow.isCall()) {
                for (Address target : instruction.getFlows()) {
                    offer(target, callState(instruction, input, target));
                }
                if (!auditingWrites && startup != null && address.equals(startup.call())) {
                    output.set(ds, startup.dgroup());
                }
            } else if (flow.isJump()) {
                State jumped = output.copy();
                // A jump into the middle of another function is either a misread table or a shared
                // error or exit tail. Joining its state would erase the context that function's own
                // paths establish, so only jumps within a function or to a function entry carry state.
                var source = getFunctionContaining(address);
                for (Address target : instruction.getFlows()) {
                    var owner = getFunctionContaining(target);
                    if (!auditingWrites && source != null && owner != null && !owner.equals(source) &&
                            !owner.getEntryPoint().equals(target)) {
                        skippedJumps++;
                        continue;
                    }
                    jumped.set(cs, targetCS(instruction, input, target));
                    offer(target, jumped);
                }
            }
            offer(instruction.getFallThrough(), output);
        }
    }

    private State callState(Instruction instruction, State input, Address target) throws Exception {
        State callee = new State();
        callee.set(cs, targetCS(instruction, input, target));
        for (Register register : auditingWrites ? summarized : segmentRegisters) {
            Integer value = input.registers.get(register);
            if (value == null) {
                callee.lose(register, input.losses.get(register));
            } else {
                callee.set(register, value);
            }
        }
        // The callee sees the caller's pushed arguments below its return address.
        callee.stack.addAll(input.stack);
        int returnWords = instruction.getMnemonicString().equals("INT") ? 3 : farCall(instruction) ? 2 : 1;
        for (int word = 0; word < returnWords; word++) {
            callee.push(null);
        }
        callee.height = 0;
        return callee;
    }

    private static boolean farCall(Instruction instruction) throws Exception {
        return (instruction.getByte(0) & 0xff) == 0x9a || instruction.getMnemonicString().endsWith("F");
    }

    private Integer targetCS(Instruction instruction, State input, Address target) throws Exception {
        if (instruction.getMnemonicString().equals("INT")) {
            return null;  // A linear handler address alone does not establish the IVT selector.
        }
        byte[] bytes = instruction.getBytes();
        int opcode = bytes[0] & 0xff;
        if (bytes.length == 5 && (opcode == 0x9a || opcode == 0xea)) {
            return (bytes[3] & 0xff) | ((bytes[4] & 0xff) << 8);
        }
        if (instruction.getMnemonicString().endsWith("F")) {
            var switches = farSwitchSegments.get(instruction.getAddress().getOffset());
            Integer selector = switches == null ? null : switches.get(target.getOffset());
            return selector == null || selector < 0 ? null : selector;
        }
        return input.registers.get(cs);
    }

    // Compute a summary for every function, letting callers use their callees' summaries, until no
    // summary changes or the pass limit is reached.
    private void summarize(Map<Address, Summary> summaries, boolean contextual) throws Exception {
        var functions = currentProgram.getFunctionManager();
        for (int pass = 0; pass < SUMMARY_PASSES; pass++) {
            boolean changed = false;
            for (var function : functions.getFunctions(true)) {
                monitor.checkCancelled();
                Address entry = function.getEntryPoint();
                State start = new State();
                for (int index = 0; index < summarized.size(); index++) {
                    start.set(summarized.get(index), SYMBOL + index);
                }
                var assumptions = new HashMap<Register, Integer>();
                if (contextual) {
                    State known = states.get(entry);
                    for (Register segment : segmentRegisters) {
                        Integer value = known == null ? null : known.registers.get(segment);
                        if (value != null) {
                            assumptions.put(segment, value);
                            start.set(segment, value);
                        }
                    }
                    start.set(cs, known == null ? null : known.registers.get(cs));
                    if (assumptions.isEmpty()) {
                        continue;
                    }
                }
                Summary summary = summarize(function, start, assumptions);
                if (!Objects.equals(summaries.get(entry), summary)) {
                    changed = true;
                    if (summary == null) {
                        summaries.remove(entry);
                    } else {
                        summaries.put(entry, summary);
                    }
                }
            }
            if (!changed) {
                break;
            }
        }
    }

    private Summary summarize(ghidra.program.model.listing.Function function, State start,
            Map<Register, Integer> assumptions) throws Exception {
        var body = function.getBody();
        var local = new HashMap<Address, State>();
        var queue = new ArrayDeque<Address>();
        Address entry = function.getEntryPoint();
        local.put(entry, start);
        queue.add(entry);
        State exit = null;
        Integer purge = null;
        Boolean far = null;
        boolean balanced = true;
        for (int steps = 0; !queue.isEmpty(); steps++) {
            if (steps == SUMMARY_STEPS) {
                return null;
            }
            Address address = queue.remove();
            Instruction instruction = getInstructionAt(address);
            if (instruction == null) {
                return null;
            }
            State input = local.get(address);
            String mnemonic = instruction.getMnemonicString();
            if (mnemonic.startsWith("RET") || mnemonic.startsWith("IRET")) {
                if (exit == null) {
                    exit = input.copy();
                } else {
                    exit.merge(input, address);
                }
                int opcode = instruction.getByte(0) & 0xff;
                boolean farReturn = opcode == 0xca || opcode == 0xcb;
                int words = opcode == 0xc2 || opcode == 0xca ? (int) instruction.getScalar(0).getUnsignedValue() / 2 : 0;
                if (opcode == 0xcf || input.height != 0 || (purge != null && purge != words) ||
                        (far != null && far != farReturn)) {
                    balanced = false;
                }
                purge = words;
                far = farReturn;
                continue;
            }
            var flow = instruction.getFlowType();
            State output = transfer(instruction, input);
            if (flow.isJump()) {
                Address[] targets = instruction.getFlows();
                if (flow.isComputed() && targets.length == 0) {
                    return null;
                }
                State jumped = output.copy();
                for (Address target : targets) {
                    if (!body.contains(target)) {
                        return null;
                    }
                    jumped.set(cs, targetCS(instruction, input, target));
                    offerLocal(local, queue, target, jumped);
                }
            }
            Address next = instruction.getFallThrough();
            if (next != null) {
                if (!body.contains(next)) {
                    return null;
                }
                offerLocal(local, queue, next, output);
            }
        }
        if (exit == null) {
            return null;
        }
        var exits = new HashMap<Register, Integer>();
        for (Register register : summarized) {
            Integer value = exit.registers.get(register);
            if (value != null) {
                exits.put(register, value);
            }
        }
        return new Summary(exits, balanced ? purge : null, far, assumptions);
    }

    private static void offerLocal(Map<Address, State> local, ArrayDeque<Address> queue, Address address, State state) {
        State previous = local.get(address);
        if (previous == null) {
            local.put(address, state.copy());
            queue.add(address);
        } else if (previous.merge(state, address)) {
            queue.add(address);
        }
    }

    private Summary summaryAt(Instruction instruction, State input) {
        Address[] targets = instruction.getFlows();
        if (targets.length != 1 || instruction.getFlowType().isComputed()) {
            return null;
        }
        Summary contextual = contextSummaries.get(targets[0]);
        if (contextual != null && contextual.assumptions().entrySet().stream().allMatch(
                assumption -> assumption.getValue().equals(input.registers.get(assumption.getKey())))) {
            return contextual;
        }
        return symbolicSummaries.get(targets[0]);
    }

    // Apply the callee's summary: preserved and set registers carry over, and the caller's stack
    // loses the arguments the callee removes. Without a summary, keep DS and SS by convention.
    private void applyCall(Instruction instruction, State input, State output) throws Exception {
        Address at = instruction.getAddress();
        Summary summary = summaryAt(instruction, input);
        Address[] targets = instruction.getFlows();
        String callee = targets.length == 1 ? targets[0].toString() : "an indirect target";
        for (Register register : summarized) {
            boolean conventional = !auditingWrites && (register.equals(ds) || register.equals(ss));
            Integer exit = summary == null ? null : summary.exits().get(register);
            if (exit == null) {
                if (!conventional) {
                    output.lose(register, summary == null
                        ? new Loss(at, "unknown_call", "no summary for " + callee)
                        : new Loss(at, "call", callee + " changes " + register.getName()));
                }
            } else if (exit >= SYMBOL) {
                Register source = summarized.get(exit - SYMBOL);
                Integer value = input.registers.get(source);
                if (value != null) {
                    output.set(register, value);
                } else {
                    Loss loss = input.losses.get(source);
                    output.lose(register, loss != null ? loss
                        : new Loss(at, "call", callee + " copies " + source.getName() + " into " + register.getName()));
                }
            } else {
                output.set(register, exit);
            }
        }
        boolean keepFrame = summary == null ? !auditingWrites :
            Integer.valueOf(SYMBOL + summarized.indexOf(bp)).equals(summary.exits().get(bp));
        if (summary != null && summary.purge() != null) {
            // PUSH CS / CALL near / RETF also removes the pushed CS.
            output.drop(summary.purge() + (summary.far() && !farCall(instruction) ? 1 : 0));
        } else {
            output.forgetStack();
        }
        if (!keepFrame) {
            output.frame = null;
            output.frameHeight = UNKNOWN_HEIGHT;
        }
    }

    private State transfer(Instruction instruction, State input) throws Exception {
        State output = input.copy();
        Address at = instruction.getAddress();
        String op = instruction.getMnemonicString();
        Register dest = instruction.getNumOperands() == 0 ? null : instruction.getRegister(0);
        boolean stackWritten = false;
        boolean stackSegmentWritten = false;
        for (Object result : instruction.getResultObjects()) {
            if (result instanceof Register written) {
                Register base = written.getBaseRegister();
                stackSegmentWritten |= base.equals(ss.getBaseRegister());
                if (base.equals(sp.getBaseRegister())) {
                    stackWritten = true;
                    continue;
                }
                if (base.equals(bp.getBaseRegister())) {
                    output.frame = null;
                    output.frameHeight = UNKNOWN_HEIGHT;
                }
                var affected = new HashSet<>(output.registers.keySet());
                affected.addAll(summarized);
                for (Register tracked : affected) {
                    if (tracked.getBaseRegister().equals(base)) {
                        output.lose(tracked, new Loss(at, "write", instruction.toString()));
                    }
                }
            }
        }

        boolean stackHandled = false;
        if (op.equals("PUSH") || op.equals("PUSHF")) {
            output.push(op.equals("PUSH") ? value(instruction, 0, input) : null);
            stackHandled = true;
        } else if (op.equals("POP") || op.equals("POPF")) {
            Integer word = output.pop();
            if (dest != null && dest.getBitLength() == 16) {
                if (word != null) {
                    output.set(dest, word);
                } else {
                    output.lose(dest, new Loss(at, "pop", "the popped word is not tracked"));
                }
            }
            stackHandled = true;
        } else if (op.equals("INT") || op.equals("INTO")) {
            // Assume interrupt handlers keep DS, SS, and the stack; ES and general registers can change.
            for (Register register : summarized) {
                if (auditingWrites || !register.equals(ds) && !register.equals(ss)) {
                    output.lose(register, new Loss(at, "interrupt", instruction.toString()));
                }
            }
            if (auditingWrites) {
                output.forgetStackValues();
                output.frame = null;
                output.frameHeight = UNKNOWN_HEIGHT;
            }
            stackHandled = true;
        } else if (instruction.getFlowType().isCall()) {
            applyCall(instruction, input, output);
            stackHandled = true;
        } else if (op.equals("LEAVE")) {
            restoreFrame(input, output);
            Integer saved = output.pop();
            output.set(bp, saved);
            stackHandled = true;
        } else if (dest != null && dest.equals(sp)) {
            Scalar scalar = instruction.getScalar(1);
            int amount = scalar == null ? -1 : (int) scalar.getUnsignedValue() & WORD_MASK;
            if ((op.equals("ADD") || op.equals("SUB")) && amount >= 0 && amount % 2 == 0 &&
                    instruction.getRegister(1) == null) {
                for (int word = 0; word < amount / 2; word++) {
                    if (op.equals("ADD")) {
                        output.pop();
                    } else {
                        output.push(null);
                    }
                }
                stackHandled = true;
            } else if (op.equals("MOV") && bp.equals(instruction.getRegister(1))) {
                restoreFrame(input, output);
                stackHandled = true;
            }
        } else if (op.equals("MOV") && bp.equals(dest) && sp.equals(instruction.getRegister(1))) {
            output.frame = new ArrayList<>(input.stack);
            output.frameHeight = input.height;
        }
        if (stackWritten && !stackHandled) {
            output.forgetStack();
        }

        if (op.equals("LES") || op.equals("LDS")) {
            Register segment = op.equals("LES") ? es : ds;
            Integer offset = null;
            Integer selector = null;
            for (Access access : accesses(instruction)) {
                if (access.operand() == 1) {
                    offset = offsetWord(access, input);
                    selector = memoryWord(access, input, 2);
                }
            }
            if (dest != null) {
                setOrLose(output, dest, offset, new Loss(at, "load", "the far pointer offset is not a known constant"));
            }
            setOrLose(output, segment, selector, new Loss(at, "load", "the far pointer segment is not a relocated word"));
        } else if (dest != null && dest.getBitLength() == 16 && !dest.equals(sp)) {
            Integer result = null;
            boolean handled = true;
            Integer left = input.registers.get(dest);
            switch (op) {
                case "MOV" -> result = value(instruction, 1, input);
                case "XOR", "SUB" -> {
                    if (dest.equals(instruction.getRegister(1))) {
                        result = 0;
                    } else if (op.equals("SUB")) {
                        result = arithmetic(left, value(instruction, 1, input), -1);
                    }
                }
                case "ADD" -> result = arithmetic(left, value(instruction, 1, input), 1);
                case "INC" -> result = arithmetic(left, 1, 1);
                case "DEC" -> result = arithmetic(left, 1, -1);
                case "LEA" -> result = effectiveOffset(instruction, 1, input);
                case "XCHG" -> {
                    Register source = instruction.getRegister(1);
                    if (source != null) {
                        Integer right = input.registers.get(source);
                        setOrLose(output, source, left, input.losses.get(dest));
                        result = right;
                    }
                }
                default -> handled = false;
            }
            if (handled) {
                setOrLose(output, dest, result, lossFor(instruction, input));
            }
        }
        Integer oldSS = input.registers.get(ss);
        Integer newSS = output.registers.get(ss);
        if (!Objects.equals(oldSS, newSS) || stackSegmentWritten && newSS == null) {
            output.forgetStackValues();
        }
        for (Access access : accesses(instruction)) {
            if (!access.type().isWrite()) {
                continue;
            }
            Integer displacement = frameOffset(access, input);
            if (displacement != null && output.frame != null) {
                storeFrameWord(output, displacement, access.size(), op.equals("MOV") ? value(instruction, 1, input) : null);
            } else if (mayWriteStack(access.segment(), input)) {
                output.forgetStackValues();
            }
        }
        // The output of string stores is ES:DI. REP/DF can make the affected range larger than
        // one operand, so do not keep a tracked stack word when that range may reach SS.
        if ((op.startsWith("STOS") || op.startsWith("MOVS") && !op.startsWith("MOVSX") || op.startsWith("INS"))
                && mayWriteStack(es, input)) {
            output.forgetStackValues();
        }
        return output;
    }

    private boolean mayWriteStack(Register segment, State state) {
        if (segment.equals(ss)) {
            return true;
        }
        Integer destination = state.registers.get(segment);
        Integer stackSegment = state.registers.get(ss);
        if (auditingWrites) {
            if (destination == null || stackSegment == null || destination >= SYMBOL || stackSegment >= SYMBOL) {
                return true;
            }
            int distance = (destination - stackSegment) & WORD_MASK;
            return Math.min(distance, 0x10000 - distance) <= 0x1000;
        }
        return destination != null && destination.equals(stackSegment);
    }

    private static void setOrLose(State output, Register register, Integer value, Loss loss) {
        if (value == null) {
            output.lose(register, loss);
        } else {
            output.set(register, value);
        }
    }

    private void restoreFrame(State input, State output) {
        if (input.frame == null) {
            output.forgetStack();
            return;
        }
        output.stack.clear();
        output.stack.addAll(input.frame);
        output.height = input.frameHeight;
    }

    private static Integer arithmetic(Integer left, Integer right, int sign) {
        if (left == null || right == null || left >= SYMBOL || right >= SYMBOL) {
            return null;
        }
        return (left + sign * right) & WORD_MASK;
    }

    // Explain why the destination of a register write has no known value.
    private Loss lossFor(Instruction instruction, State input) {
        Address at = instruction.getAddress();
        Register source = instruction.getNumOperands() > 1 ? instruction.getRegister(1) : null;
        if (source != null && input.losses.containsKey(source) && !input.registers.containsKey(source)) {
            return input.losses.get(source);
        }
        for (Access access : accesses(instruction)) {
            if (access.operand() == 1) {
                Address address = target(access, input);
                return new Loss(at, "load", address == null ? "the operand address is not known"
                    : "the word at " + address + " is not a relocated segment value");
            }
        }
        return new Loss(at, "write", instruction.toString());
    }

    private Integer value(Instruction instruction, int operand, State input) {
        Register register = instruction.getRegister(operand);
        if (register != null) {
            return input.registers.get(register);
        }
        for (Access access : accesses(instruction)) {
            if (access.operand() == operand && access.size() == 2) {
                return memoryWord(access, input, 0);
            }
        }
        if (instruction.getDefaultOperandRepresentation(operand).contains("[")) {
            return null;
        }
        Scalar scalar = instruction.getScalar(operand);
        return scalar == null ? null : (int) scalar.getUnsignedValue() & WORD_MASK;
    }

    // A stack word addressed as [BP+n]. Arguments and the saved BP come from the words tracked when BP
    // was set; locals below BP come from the current stack while its height is known.
    private record Slot(List<Integer> words, int index) {
        Integer get() {
            return words.get(index);
        }
    }

    private Slot frameSlot(Access access, State state, int delta) {
        Integer offset = frameOffset(access, state);
        return offset == null ? null : frameSlot(state, (short) (offset + delta));
    }

    private Integer frameOffset(Access access, State state) {
        if (state.frame == null || !access.bases().contains(bp) || !access.segment().equals(ss)) {
            return null;
        }
        int displacement = access.offset();
        for (Register base : access.bases()) {
            if (!base.equals(bp)) {
                Integer value = state.registers.get(base);
                if (value == null || value >= SYMBOL) {
                    return null;
                }
                displacement += value;
            }
        }
        return (int) (short) displacement;
    }

    private static Slot frameSlot(State state, int displacement) {
        if (state.frame == null || displacement % 2 != 0) {
            return null;
        }
        if (displacement >= 0) {
            int index = state.frame.size() - 1 - displacement / 2;
            return index < 0 ? null : new Slot(state.frame, index);
        }
        return stackSlot(state, displacement);
    }

    private static Slot stackSlot(State state, int displacement) {
        if (state.height == UNKNOWN_HEIGHT || state.frameHeight == UNKNOWN_HEIGHT) {
            return null;
        }
        int index = state.stack.size() - 1 - (state.height - (state.frameHeight - displacement / 2));
        return index < 0 || index >= state.stack.size() ? null : new Slot(state.stack, index);
    }

    private Integer memoryWord(Access access, State state, int delta) {
        if (access.bases().contains(bp)) {
            Slot slot = frameSlot(access, state, delta);
            return slot == null ? null : slot.get();
        }
        Address address = target(access, state);
        return address == null ? null : words.get(address.getOffset() + delta);
    }

    // The offset half of a far pointer: a tracked frame word, or an initialized word nothing writes.
    private Integer offsetWord(Access access, State state) throws Exception {
        if (access.bases().contains(bp)) {
            Slot slot = frameSlot(access, state, 0);
            return slot == null ? null : slot.get();
        }
        Address address = target(access, state);
        if (address == null || !words.containsKey(address.getOffset() + 2) ||
                written.contains(address.getOffset()) || written.contains(address.getOffset() + 1)) {
            return null;
        }
        return currentProgram.getMemory().getShort(address) & WORD_MASK;
    }

    private void storeFrameWord(State output, int start, int size, Integer value) {
        for (int word = start & ~1; word < start + size; word += 2) {
            int displacement = (short) word;
            Integer known = word == start && size == 2 ? value : null;
            storeWord(frameSlot(output, displacement), known);
            if (displacement >= 0) {
                storeWord(stackSlot(output, displacement), known);
            }
        }
    }

    private static void storeWord(Slot slot, Integer value) {
        if (slot != null) {
            slot.words().set(slot.index(), value);
        }
    }

    private Integer effectiveOffset(Instruction instruction, int operand, State input) {
        int offset = 0;
        for (Object object : instruction.getOpObjects(operand)) {
            if (object instanceof Scalar scalar) {
                offset += (int) scalar.getValue();
            } else if (object instanceof Register register && baseRegisters.contains(register)) {
                Integer value = input.registers.get(register);
                if (value == null || value >= SYMBOL) {
                    return null;
                }
                offset += value;
            } else {
                return null;
            }
        }
        return offset & WORD_MASK;
    }

    private List<Access> accesses(Instruction instruction) {
        return accesses.computeIfAbsent(instruction.getAddress(), ignored -> {
            var result = new ArrayList<Access>();
            var pcode = instruction.getPcode();
            var segmentOps = new ArrayList<PcodeOp>();
            for (PcodeOp op : pcode) {
                if (op.getOpcode() == PcodeOp.CALLOTHER && op.getNumInputs() == 3 && op.getInput(1).isRegister() &&
                        currentProgram.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset())
                            .equals("segment")) {
                    segmentOps.add(op);
                }
            }
            var computed = segmentOps.stream().filter(op -> !op.getInput(2).isConstant()).toList();
            for (int index = 0; index < instruction.getNumOperands(); index++) {
                if (!instruction.getDefaultOperandRepresentation(index).contains("[")) {
                    continue;
                }
                // Memory operands have a displacement, base and index registers, and a segment override.
                Register override = null;
                int offset = 0;
                var bases = new ArrayList<Register>();
                boolean simple = true;
                for (Object object : instruction.getOpObjects(index)) {
                    if (object instanceof Scalar scalar) {
                        offset = (offset + (int) scalar.getValue()) & WORD_MASK;
                    } else if (object instanceof Register register && segmentRegisters.contains(register)) {
                        override = register;
                    } else if (object instanceof Register register && register.equals(cs)) {
                        override = register;
                    } else if (object instanceof Register register && baseRegisters.contains(register)) {
                        bases.add(register);
                    } else {
                        simple = false;
                        break;
                    }
                }
                if (!simple) {
                    continue;
                }
                final int displacement = offset;
                var candidates = bases.isEmpty()
                    ? segmentOps.stream().filter(op -> op.getInput(2).isConstant() &&
                        op.getInput(2).getOffset() == displacement).toList()
                    : computed.size() == 1 ? computed : List.<PcodeOp>of();
                Register expected = override != null ? override : bases.contains(bp) ? ss : ds;
                for (PcodeOp op : candidates) {
                    var base = op.getInput(1);
                    Register segment = currentProgram.getRegister(base.getAddress(), base.getSize());
                    if (segment == null || !(segmentRegisters.contains(segment) || segment.equals(cs)) ||
                            (override != null && !override.equals(segment)) ||
                            (!bases.isEmpty() && !expected.equals(segment))) {
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
                        result.add(new Access(index, segment, displacement, List.copyOf(bases), size, type));
                        break;
                    }
                }
            }
            return result;
        });
    }

    private Address target(Access access, State state) {
        Integer segment = state.registers.get(access.segment());
        if (segment == null || segment >= SYMBOL) {
            return null;
        }
        int offset = access.offset();
        for (Register base : access.bases()) {
            Integer value = state.registers.get(base);
            if (value == null || value >= SYMBOL) {
                return null;
            }
            offset += value;
        }
        return space.getAddress(segment, offset & WORD_MASK);
    }

    private boolean removeWrittenWords() throws Exception {
        boolean changed = false;
        for (var entry : states.entrySet()) {
            monitor.checkCancelled();
            for (Access access : accesses(getInstructionAt(entry.getKey()))) {
                Address address = target(access, entry.getValue());
                if (address != null && access.type().isWrite()) {
                    long start = address.getOffset();
                    for (long index = start - 1; index < start + access.size(); index++) {
                        changed |= words.remove(index) != null;
                        if (index >= start) {
                            changed |= written.add(index);
                        }
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
        var properties = currentProgram.getUsrPropertyManager();
        properties.removePropertyMap(LOSS_MAP);
        properties.removePropertyMap(LOSS_ORIGIN_MAP);
        var lossMap = properties.createStringPropertyMap(LOSS_MAP);
        var originMap = properties.createStringPropertyMap(LOSS_ORIGIN_MAP);
        var origins = new TreeMap<Address, Map<String, Loss>>();
        int direct = 0;
        int based = 0;
        int farPointers = 0;
        var targets = new HashSet<Address>();
        for (var entry : new TreeMap<>(states).entrySet()) {
            monitor.checkCancelled();
            Instruction instruction = getInstructionAt(entry.getKey());
            State state = entry.getValue();
            var lost = new StringBuilder();
            for (Register segment : segmentRegisters) {
                Integer value = state.registers.get(segment);
                if (value != null) {
                    context.setValue(segment, instruction.getMinAddress(), instruction.getMaxAddress(),
                        BigInteger.valueOf(value));
                } else if (state.losses.containsKey(segment)) {
                    Loss loss = state.losses.get(segment);
                    lost.append(lost.isEmpty() ? "" : ";").append(segment.getName()).append('=')
                        .append(Long.toHexString(loss.at().getOffset()));
                    origins.computeIfAbsent(loss.at(), ignored -> new LinkedHashMap<>())
                        .putIfAbsent(segment.getName(), loss);
                }
            }
            if (!lost.isEmpty()) {
                lossMap.add(entry.getKey(), lost.toString());
            }
            String op = instruction.getMnemonicString();
            if ((op.equals("LES") || op.equals("LDS")) &&
                    transfer(instruction, state).registers.containsKey(op.equals("LES") ? es : ds)) {
                farPointers++;
            }
            for (Access access : accesses(instruction)) {
                // Ghidra may have followed one incoming ES value before our analysis joined the paths.
                // Leave explicitly supplied references alone.
                if (access.segment().equals(es) && state.losses.containsKey(es)) {
                    for (var old : refs.getReferencesFrom(entry.getKey(), access.operand())) {
                        if (old.isMemoryReference() && old.getReferenceType().isData() &&
                                old.getSource() == SourceType.ANALYSIS) {
                            refs.delete(old);
                        }
                    }
                    continue;
                }
                if (access.segment().equals(cs) || access.bases().contains(bp)) {
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
                if (access.bases().isEmpty()) {
                    direct++;
                } else {
                    based++;
                }
                targets.add(target);
            }
        }
        for (var origin : origins.entrySet()) {
            var lines = new StringBuilder();
            for (var loss : origin.getValue().entrySet()) {
                lines.append(loss.getKey()).append('\t').append(loss.getValue().reason()).append('\t')
                    .append(loss.getValue().detail().replace('\t', ' ').replace('\n', ' ')).append('\n');
            }
            originMap.add(origin.getKey(), lines.toString());
        }

        int functionCount = 0;
        var known = new LinkedHashMap<String, Integer>();
        var entryLosses = new LinkedHashMap<String, Map<String, Integer>>();
        for (Register segment : segmentRegisters) {
            known.put(segment.getName(), 0);
            entryLosses.put(segment.getName(), new TreeMap<>());
        }
        for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
            functionCount++;
            State state = states.get(function.getEntryPoint());
            for (Register segment : segmentRegisters) {
                if (state != null && state.registers.get(segment) != null) {
                    known.merge(segment.getName(), 1, Integer::sum);
                } else {
                    Loss loss = state == null ? null : state.losses.get(segment);
                    entryLosses.get(segment.getName()).merge(loss == null ? "none" : loss.reason(), 1, Integer::sum);
                }
            }
        }
        segmentStats.put("data_references", direct + based);
        segmentStats.put("register_references", based);
        segmentStats.put("far_pointer_loads", farPointers);
        segmentStats.put("data_targets", targets.size());
        segmentStats.put("functions", functionCount);
        segmentStats.put("entry_known", known);
        segmentStats.put("entry_losses", entryLosses);
    }

    private void writeStoreContext() throws Exception {
        var properties = currentProgram.getUsrPropertyManager();
        properties.removePropertyMap("RetroreWriteContext");
        properties.removePropertyMap(WRITE_CONTEXT_MAP);
        var writeContext = properties.createStringPropertyMap(WRITE_CONTEXT_MAP);
        var gson = new Gson();
        for (var entry : states.entrySet()) {
            monitor.checkCancelled();
            var instruction = getInstructionAt(entry.getKey());
            if (java.util.Arrays.stream(instruction.getPcode()).noneMatch(op -> op.getOpcode() == PcodeOp.STORE)) {
                continue;
            }
            var registers = new TreeMap<String, Integer>();
            entry.getValue().registers.forEach((register, value) -> {
                if (value < SYMBOL) {
                    registers.put(register.getName(), value);
                }
            });
            writeContext.add(entry.getKey(), gson.toJson(registers));
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
            // Replace only undefined bytes or Ghidra's sized placeholders (undefined2 and the like)
            // that lie entirely within the access.
            Address end = address.addNoWrap(size - 1);
            boolean undefined = true;
            for (int index = 0; index < size && undefined; index++) {
                var unit = listing.getDataContaining(address.addNoWrap(index));
                undefined = unit != null && Undefined.isUndefined(unit.getDataType()) &&
                    unit.getMinAddress().compareTo(address) >= 0 && unit.getMaxAddress().compareTo(end) <= 0;
            }
            if (undefined) {
                listing.clearCodeUnits(address, end, false);
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
