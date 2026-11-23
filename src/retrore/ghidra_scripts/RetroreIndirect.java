// After analysis, record candidate targets for indirect calls and jumps that read their target from memory.
//
// Switch tables that the loader proved are already applied by RetroreImport.java. This pass handles the rest:
// procedure-variable and callback tables in data segments, and single far pointer variables. Tables in
// writable memory can change at run time, so their entries stay candidates: each one is kept with its table
// slot and the evidence for it (a relocated segment word, an existing function or instruction, a prologue, a
// clean decode). Candidates are stored per site as JSON in the "retrore.indirect" string property map, read
// back by the `indirect` query, and every candidate slot gets a DATA reference to its target. Relocated far
// pointers into undefined code also seed a function there.
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class RetroreIndirect extends HeadlessScript {
    static final String PROPERTY = "retrore.indirect";
    private static final int MAX_ENTRIES = 256;

    private SegmentedAddressSpace space;
    private final Set<Long> relocated = new HashSet<>();
    private final TreeSet<Integer> rootSegments = new TreeSet<>();
    private String rootName;
    private PseudoDisassembler pseudo;
    private StringPropertyMap segmentLosses;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path result = Path.of(args[1]);
        var gson = new Gson();
        try {
            JsonObject map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            // The segment pass before this one wrote the import report; add this pass's counts to it.
            JsonObject report = Files.exists(result)
                ? JsonParser.parseString(Files.readString(result)).getAsJsonObject() : new JsonObject();
            if (report.has("error")) {
                return;
            }
            report.add("indirect", gson.toJsonTree(analyze(map)));
            report.addProperty("seeded_gaps", seedGaps());
            Files.writeString(result, gson.toJson(report));
        } catch (Exception error) {
            Files.writeString(result, gson.toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private Map<String, Integer> analyze(JsonObject map) throws Exception {
        space = (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
        pseudo = new PseudoDisassembler(currentProgram);
        var units = map.getAsJsonArray("units");
        var root = units.get(0).getAsJsonObject();
        rootName = root.get("name").getAsString();
        long origin = map.has("image_origin") ? map.get("image_origin").getAsLong() : root.get("linear").getAsLong();
        int rootSegment = root.get("segment").getAsInt();
        long rootSize = root.get("size").getAsLong();
        rootSegments.add(rootSegment);
        rootSegments.add(map.getAsJsonObject("entry").get("segment").getAsInt());
        if (map.has("relocations")) {
            for (var item : map.getAsJsonArray("relocations")) {
                long linear = origin + item.getAsLong();
                relocated.add(linear);
                var at = space.getAddress(linear);
                if (item.getAsLong() < rootSize - 1 && currentProgram.getMemory().contains(at)) {
                    int segment = currentProgram.getMemory().getShort(at) & 0xFFFF;
                    if (segment >= rootSegment && (segment - rootSegment) * 16L < rootSize) {
                        rootSegments.add(segment);
                    }
                }
            }
        }

        var properties = currentProgram.getUsrPropertyManager();
        segmentLosses = properties.getStringPropertyMap("RetroreSegmentLosses");
        var store = properties.getStringPropertyMap(PROPERTY);
        if (store == null) {
            store = properties.createStringPropertyMap(PROPERTY);
        }
        int sites = 0, candidates = 0, seeded = 0, unresolved = 0;
        var listing = currentProgram.getListing();
        var instructions = new ArrayList<Instruction>();
        for (var instruction : listing.getInstructions(true)) {
            if (isIndirect(instruction) && instruction.getFlows().length == 0) {
                instructions.add(instruction);
            }
        }
        for (var instruction : instructions) {
            monitor.checkCancelled();
            var record = describe(instruction);
            sites++;
            @SuppressWarnings("unchecked")
            var entries = (List<Map<String, Object>>) record.getOrDefault("candidates", List.of());
            if (entries.isEmpty()) {
                unresolved++;
            } else {
                candidates++;
            }
            for (var entry : entries) {
                var slot = space.getAddress((Long) entry.get("slot"));
                var target = space.getAddress((Long) entry.get("target"));
                currentProgram.getReferenceManager().addMemoryReference(slot, target, RefType.DATA,
                    SourceType.ANALYSIS, 0);
                @SuppressWarnings("unchecked")
                var evidence = (List<String>) entry.get("evidence");
                if (evidence.contains("relocated") && listing.getInstructionAt(target) == null &&
                        listing.getUndefinedDataAt(target) != null && pseudo.isValidSubroutine(target, false)) {
                    disassemble(target);
                    if (getFunctionAt(target) == null && createFunction(target, null) != null) {
                        evidence.add("seeded");
                        seeded++;
                    }
                }
            }
            store.add(instruction.getAddress(), new Gson().toJson(record));
        }
        var counts = new LinkedHashMap<String, Integer>();
        counts.put("sites", sites);
        counts.put("candidate_sites", candidates);
        counts.put("unresolved_sites", unresolved);
        counts.put("seeded_functions", seeded);
        return counts;
    }

    /**
     * Create functions in undefined ranges that RetroreGaps.java scores as code and that a relocated far pointer
     * in data names exactly, with a frame prologue and a clean decode. Nothing else reaches such a routine, so
     * analysis leaves it undefined.
     */
    private int seedGaps() throws Exception {
        var file = Files.createTempFile("retrore-gaps", ".json");
        JsonObject report;
        try {
            runScript("RetroreGaps.java", new String[] {file.toString(), "classify"});
            report = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
        } finally {
            Files.deleteIfExists(file);
        }
        int seeded = 0;
        for (var item : report.getAsJsonArray("ranges")) {
            var range = item.getAsJsonObject();
            if (!range.has("class") || !range.get("class").getAsString().equals("code")) {
                continue;
            }
            String entry = range.get("entry").getAsString();
            var slots = new ArrayList<Address>();
            boolean frame = false, decodes = false;
            for (var row : range.getAsJsonArray("evidence")) {
                var evidence = row.getAsJsonObject();
                String kind = evidence.get("kind").getAsString();
                if (kind.equals("relocated_pointer") && evidence.get("at").getAsString().equals(entry)) {
                    slots.add(unitAddress(evidence.get("from").getAsString()));
                }
                frame |= kind.equals("prologue");
                decodes |= kind.equals("valid_subroutine");
            }
            if (slots.isEmpty() || !frame || !decodes) {
                continue;
            }
            var start = unitAddress(entry);
            if (disassemble(start) && getFunctionAt(start) == null && createFunction(start, null) != null) {
                seeded++;
                for (var slot : slots) {
                    currentProgram.getReferenceManager().addMemoryReference(slot, start, RefType.DATA,
                        SourceType.ANALYSIS, 0);
                }
            }
        }
        return seeded;
    }

    private Address unitAddress(String text) throws Exception {
        int colon = text.indexOf(':');
        var block = currentProgram.getMemory().getBlock(text.substring(0, colon));
        return block.getStart().addNoWrap(Long.parseLong(text.substring(colon + 1), 16));
    }

    static boolean isIndirect(Instruction instruction) {
        var flow = instruction.getFlowType();
        if (!flow.isComputed() || !(flow.isCall() || flow.isJump())) {
            return false;
        }
        // Software interrupts and traps are computed calls too, through vectors rather than program tables.
        String mnemonic = instruction.getMnemonicString().toUpperCase();
        return !mnemonic.startsWith("INT") && !mnemonic.startsWith("TRAP");
    }

    private Map<String, Object> describe(Instruction instruction) throws Exception {
        var record = new LinkedHashMap<String, Object>();
        boolean far = instruction.getMnemonicString().toUpperCase().endsWith("F");
        record.put("kind", instruction.getFlowType().isCall() ? "call" : "jump");
        record.put("width", far ? 4 : 2);
        if (!instruction.getDefaultOperandRepresentation(0).contains("[")) {
            record.put("reason", "register");
            return record;
        }
        var indexes = new ArrayList<Register>();
        int displacement = 0;
        for (Object object : instruction.getOpObjects(0)) {
            if (object instanceof Register register && !register.getName().matches("[CDEFGS]S")) {
                indexes.add(register);
            } else if (object instanceof Scalar scalar) {
                displacement = (int) scalar.getUnsignedValue() & 0xFFFF;
            }
        }
        for (var register : indexes) {
            if (register.getName().equals("BP") || register.getName().equals("SP")) {
                record.put("reason", "stack");  // A procedure variable in a local or parameter.
                return record;
            }
        }
        String segment = memorySegment(instruction);
        Integer segmentValue = segmentValue(instruction, segment);
        var segmentRecord = new LinkedHashMap<String, Object>();
        segmentRecord.put("register", segment);
        segmentRecord.put("value", segmentValue);
        record.put("segment", segmentRecord);
        if (segmentValue == null) {
            record.put("reason", "segment_unknown");
            return record;
        }
        var table = space.getAddress(segmentValue, displacement);
        record.put("table", table.getOffset());
        int limit = indexes.isEmpty() ? 1 : MAX_ENTRIES;
        var entries = new ArrayList<Map<String, Object>>();
        String stop = "limit";
        int codeSegment = codeSegment(instruction.getAddress());
        for (int index = 0; index < limit; index++) {
            var slot = table.addNoWrap((long) (far ? 4 : 2) * index);
            if (index > 0 && hasOtherReader(slot, instruction)) {
                stop = "next_variable";  // Another instruction reads this slot directly.
                break;
            }
            int before = entries.size();
            String initial = initialEntry(slot, far, codeSegment, entries);
            if (far) {
                storedEntries(slot, entries);
            }
            if (entries.size() == before) {
                stop = initial == null ? "no_target" : initial;
                // Arrays indexed from 1 leave the first slot unused.
                if (index == 0 && limit > 1) {
                    continue;
                }
                break;
            }
        }
        record.put("candidates", entries);
        record.put("stop", indexes.isEmpty() ? "variable" : stop);
        if (entries.isEmpty()) {
            record.put("reason", indexes.isEmpty() ? stop : "no_valid_entries");
        }
        return record;
    }

    /** Ghidra can omit an explicit segment override from the operand of a far memory transfer. */
    private static String memorySegment(Instruction instruction) throws Exception {
        String segment = "DS";
        for (byte value : instruction.getBytes()) {
            switch (value & 0xff) {
                case 0x26 -> segment = "ES";
                case 0x2e -> segment = "CS";
                case 0x36 -> segment = "SS";
                case 0x3e -> segment = "DS";
                case 0x64 -> segment = "FS";
                case 0x65 -> segment = "GS";
                case 0x66, 0x67, 0xf0, 0xf2, 0xf3 -> { }
                default -> { return segment; }
            }
        }
        return segment;
    }

    /** Add the slot's initial value as a candidate; return why it is not one otherwise. */
    private String initialEntry(Address slot, boolean far, int codeSegment, List<Map<String, Object>> entries)
            throws Exception {
        var memory = currentProgram.getMemory();
        var block = memory.getBlock(slot);
        int width = far ? 4 : 2;
        if (block == null || !memory.contains(slot.addNoWrap(width - 1))) {
            return "end_of_memory";
        }
        if (!block.isInitialized()) {
            return "uninitialized";  // Filled in at run time; only stores can name targets.
        }
        int offset = memory.getShort(slot) & 0xFFFF;
        int segment = far ? memory.getShort(slot.addNoWrap(2)) & 0xFFFF : codeSegment;
        if ((offset == 0 && (!far || segment == 0)) || offset == 0xFFFF) {
            return "sentinel";
        }
        var evidence = new ArrayList<String>();
        if (far && relocated.contains(slot.addNoWrap(2).getOffset())) {
            evidence.add("relocated");
        } else if (far) {
            return "unrelocated";
        }
        evidence.add("initial");
        return addCandidate(slot, space.getAddress(segment, offset), evidence, null, far, entries);
    }

    /** Add far pointers that instructions store into the slot: an offset and a segment written close together. */
    private void storedEntries(Address slot, List<Map<String, Object>> entries) throws Exception {
        var listing = currentProgram.getListing();
        for (var offsetWrite : getReferencesTo(slot)) {
            if (!offsetWrite.getReferenceType().isWrite()) {
                continue;
            }
            var writer = listing.getInstructionAt(offsetWrite.getFromAddress());
            Instruction offsetSource = writer == null ? null : storedSource(writer);
            if (offsetSource == null) {
                continue;
            }
            for (var segmentWrite : getReferencesTo(slot.addNoWrap(2))) {
                var other = listing.getInstructionAt(segmentWrite.getFromAddress());
                if (!segmentWrite.getReferenceType().isWrite() || other == null ||
                        Math.abs(other.getAddress().subtract(writer.getAddress())) > 16) {
                    continue;
                }
                Instruction segmentSource = storedSource(other);
                if (segmentSource == null) {
                    continue;
                }
                var evidence = new ArrayList<String>();
                long immediateAt = segmentSource.getAddress().getOffset() + segmentSource.getLength() - 2;
                if (relocated.contains(immediateAt)) {
                    evidence.add("relocated");
                }
                evidence.add("stored");
                var target = space.getAddress((int) immediate(segmentSource), (int) immediate(offsetSource));
                addCandidate(slot, target, evidence, writer.getAddress(), true, entries);
                break;
            }
        }
    }

    /** The instruction that supplies a stored immediate: the store itself, or a recent mov of the register. */
    private Instruction storedSource(Instruction store) {
        Object[] value = store.getOpObjects(1);
        if (value.length == 1 && value[0] instanceof Scalar) {
            return store;
        }
        if (value.length != 1 || !(value[0] instanceof Register register)) {
            return null;
        }
        var previous = store.getPrevious();
        for (int step = 0; step < 8 && previous != null; step++, previous = previous.getPrevious()) {
            var flow = previous.getFlowType();
            if (flow.isJump() || flow.isCall() || flow.isTerminal()) {
                return null;
            }
            boolean writes = false;
            for (Object result : previous.getResultObjects()) {
                writes |= result instanceof Register written && written.contains(register);
            }
            if (!writes) {
                continue;
            }
            Object[] source = previous.getOpObjects(1);
            return previous.getMnemonicString().equals("MOV") && source.length == 1 && source[0] instanceof Scalar
                ? previous : null;
        }
        return null;
    }

    private static long immediate(Instruction source) {
        return ((Scalar) source.getOpObjects(1)[0]).getUnsignedValue() & 0xFFFF;
    }

    /** Check that a candidate target looks like code and record it; return a stop reason when it does not. */
    private String addCandidate(Address slot, Address target, List<String> evidence, Address writer, boolean far,
            List<Map<String, Object>> entries) throws Exception {
        var block = currentProgram.getMemory().getBlock(target);
        if (block == null || !block.isExecute() || !block.isInitialized()) {
            return "not_code";
        }
        var listing = currentProgram.getListing();
        if (getFunctionAt(target) != null) {
            evidence.add("function_entry");
        } else if (listing.getInstructionAt(target) != null) {
            evidence.add("instruction");
        } else if (listing.getInstructionContaining(target) != null || listing.getDefinedDataContaining(target) != null) {
            return "conflict";
        }
        if (prologue(target)) {
            evidence.add("prologue");
        }
        if (pseudo.isValidSubroutine(target, true)) {
            evidence.add("decodes");
        } else if (!evidence.contains("function_entry")) {
            return "bad_code";
        }
        // Near tables have no relocations; require more than an initial value that decodes.
        if (!far && evidence.size() < 3) {
            return "weak";
        }
        for (var existing : entries) {
            // Several stores of the same pointer, or a store repeating the initial value: one candidate.
            if (existing.get("slot").equals(slot.getOffset()) && existing.get("target").equals(target.getOffset())) {
                @SuppressWarnings("unchecked")
                var known = (List<String>) existing.get("evidence");
                evidence.stream().filter(item -> !known.contains(item)).forEach(known::add);
                return null;
            }
        }
        var entry = new LinkedHashMap<String, Object>();
        entry.put("slot", slot.getOffset());
        entry.put("target", target.getOffset());
        entry.put("evidence", evidence);
        if (writer != null) {
            entry.put("writer", writer.getOffset());
        }
        entries.add(entry);
        return null;
    }

    private boolean hasOtherReader(Address slot, Instruction site) {
        for (var reference : getReferencesTo(slot)) {
            if (!reference.getFromAddress().equals(site.getAddress()) && reference.getReferenceType().isRead() &&
                    currentProgram.getListing().getInstructionAt(reference.getFromAddress()) != null) {
                return true;
            }
        }
        return false;
    }

    private Integer segmentValue(Instruction instruction, String segment) {
        if (segment.equals("CS")) {
            return codeSegment(instruction.getAddress());
        }
        String losses = segmentLosses == null ? null : segmentLosses.getString(instruction.getAddress());
        if (losses != null) {
            for (String loss : losses.split(";")) {
                if (loss.startsWith(segment + "=")) {
                    return null;
                }
            }
        }
        Register register = currentProgram.getRegister(segment);
        var value = register == null ? null :
            currentProgram.getProgramContext().getRegisterValue(register, instruction.getAddress());
        return value == null || !value.hasValue() ? null : value.getUnsignedValue().intValue();
    }

    /** The unit segment for overlays; in the root, the nearest known code segment at or below the address. */
    private int codeSegment(Address address) {
        var block = currentProgram.getMemory().getBlock(address);
        long linear = address.getOffset();
        if (block != null && !block.getName().equals(rootName)) {
            return (int) (block.getStart().getOffset() >> 4);
        }
        Integer segment = rootSegments.floor((int) (linear >> 4));
        return segment == null ? (int) (linear >> 4) : segment;
    }

    private boolean prologue(Address target) {
        try {
            byte[] bytes = new byte[3];
            currentProgram.getMemory().getBytes(target, bytes);
            int b0 = bytes[0] & 0xFF, b1 = bytes[1] & 0xFF, b2 = bytes[2] & 0xFF;
            // push bp; mov bp,sp (both encodings), or enter.
            return (b0 == 0x55 && ((b1 == 0x8B && b2 == 0xEC) || (b1 == 0x89 && b2 == 0xE5))) || b0 == 0xC8;
        } catch (Exception error) {
            return false;
        }
    }
}
