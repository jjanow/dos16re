// Report initialized bytes that Ghidra has classified as neither code nor data.
//
// Arguments: OUTPUT [classify [UNIT]]. With "classify", each range also gets a likely class (code, data,
// padding, or unknown), code and data scores, a conflict flag, the suggested code entry, and the evidence:
// references into the range, relocated pointers to it, relocated words inside it, a prologue, a clean
// linear decode, and text or zero-filled data.
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class RetroreGaps extends GhidraScript {
    private static final int ROWS_PER_KIND = 4;
    private static final int DECODE_LIMIT = 256;

    private PseudoDisassembler pseudo;
    private boolean x86;
    /** Pointer targets (linear) to the relocated slots that hold them. */
    private final TreeMap<Long, List<Address>> pointers = new TreeMap<>();
    private final TreeMap<Long, Address> relocatedWords = new TreeMap<>();
    /** Far pointers whose segment no far call or jump names: likely data. */
    private final TreeMap<Long, List<Address>> farDataPointers = new TreeMap<>();
    private final java.util.Set<Integer> codeSegments = new java.util.HashSet<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        boolean classify = args.length > 1 && args[1].equals("classify");
        String only = args.length > 2 && !args[2].isEmpty() ? args[2] : null;
        if (classify) {
            prepare();
        }
        var ranges = new ArrayList<Map<String, Object>>();
        long undefinedBytes = 0;
        var listing = currentProgram.getListing();
        for (var block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized() || !block.isExecute() || (only != null && !block.getName().equalsIgnoreCase(only))) {
                continue;
            }
            var start = block.getStart();
            var undefined = listing.getUndefinedRanges(new AddressSet(start, block.getEnd()), true, monitor);
            for (var range : undefined.getAddressRanges()) {
                monitor.checkCancelled();
                long size = range.getLength();
                undefinedBytes += size;
                String unit = block.getName();
                var record = new LinkedHashMap<String, Object>();
                record.put("unit", unit);
                record.put("size", size);
                record.put("linear", range.getMinAddress().getOffset());
                record.put("start", String.format("%s:%04x", unit, range.getMinAddress().subtract(start)));
                record.put("end", String.format("%s:%04x", unit, range.getMaxAddress().subtract(start)));
                if (classify) {
                    classify(block, range, record);
                }
                ranges.add(record);
            }
        }
        Files.writeString(Path.of(args[0]), new com.google.gson.GsonBuilder().serializeNulls().create().toJson(Map.of(
            "program", currentProgram.getName(), "undefined_bytes", undefinedBytes, "ranges", ranges
        )));
    }

    // ---- classification ----

    private void prepare() throws Exception {
        pseudo = new PseudoDisassembler(currentProgram);
        x86 = currentProgram.getLanguage().getProcessor().toString().startsWith("x86");
        var memory = currentProgram.getMemory();
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var marks = currentProgram.getUsrPropertyManager().getVoidPropertyMap("retrore.relocations");
        if (marks != null && space instanceof SegmentedAddressSpace segmented) {
            // DOS: each relocated word is a segment. Segments named by far calls and jumps hold code; a far
            // pointer in data keeps its offset just below its segment and points to code only in those.
            var listing = currentProgram.getListing();
            var dataPointers = new ArrayList<Address>();
            for (var iterator = marks.getPropertyIterator(); iterator.hasNext();) {
                Address site = iterator.next();
                relocatedWords.put(site.getOffset(), site);
                var instruction = listing.getInstructionContaining(site);
                if (instruction != null) {
                    var flow = instruction.getFlowType();
                    if ((flow.isCall() || flow.isJump()) && !flow.isComputed()) {
                        codeSegments.add(memory.getShort(site) & 0xFFFF);
                    }
                } else {
                    dataPointers.add(site);
                }
            }
            for (Address site : dataPointers) {
                try {
                    int segment = memory.getShort(site) & 0xFFFF;
                    int offset = memory.getShort(site.subtract(2)) & 0xFFFF;
                    var target = segmented.getAddress(segment, offset).getOffset();
                    (codeSegments.contains(segment) ? pointers : farDataPointers)
                        .computeIfAbsent(target, key -> new ArrayList<>()).add(site.subtract(2));
                } catch (Exception error) {
                    // The word below is outside memory: not a far pointer.
                }
            }
        }
        for (var iterator = currentProgram.getRelocationTable().getRelocations(); iterator.hasNext();) {
            // 68k and other flat targets: a relocated long is an absolute address.
            var relocation = iterator.next();
            var site = relocation.getAddress();
            relocatedWords.put(site.getOffset(), site);
            var values = relocation.getValues();
            if (values != null && values.length > 0) {
                pointers.computeIfAbsent(values[0], key -> new ArrayList<>()).add(site);
            }
        }
    }

    private void classify(MemoryBlock block, AddressRange range, Map<String, Object> record) throws Exception {
        var memory = currentProgram.getMemory();
        int size = (int) Math.min(range.getLength(), 1 << 16);
        byte[] bytes = new byte[size];
        memory.getBytes(range.getMinAddress(), bytes);
        var evidence = new ArrayList<Map<String, Object>>();
        int code = 0, data = 0;

        int padding = 0;
        while (padding < size && isPadding(bytes[padding]) && bytes[padding] == bytes[0]) {
            padding++;
        }
        if (padding == size) {
            record.put("class", "padding");
            record.put("code_score", 0);
            record.put("data_score", 0);
            record.put("conflict", false);
            record.put("entry", null);
            record.put("evidence", List.of(Map.of("kind", "uniform", "byte", bytes[0] & 0xFF)));
            record.put("counts", Map.of());
            return;
        }
        Address entry = range.getMinAddress().add(padding);

        // References into the range: flow from instructions argues for code, reads and writes for data.
        var counts = new LinkedHashMap<String, Integer>();
        int flowsToEntry = 0, flowsInside = 0, accesses = 0, pointerRefs = 0;
        var listing = currentProgram.getListing();
        var references = currentProgram.getReferenceManager();
        var destinations = references.getReferenceDestinationIterator(new AddressSet(range), true);
        while (destinations.hasNext()) {
            Address to = destinations.next();
            for (var reference : references.getReferencesTo(to)) {
                var type = reference.getReferenceType();
                boolean fromCode = listing.getInstructionAt(reference.getFromAddress()) != null;
                String kind;
                if (fromCode && type.isFlow()) {
                    kind = type.isCall() ? "call_target" : "jump_target";
                    if (to.equals(entry)) {
                        flowsToEntry++;
                    } else {
                        flowsInside++;
                    }
                } else if (fromCode && (type.isRead() || type.isWrite())) {
                    kind = type.isWrite() ? "data_write" : "data_read";
                    accesses++;
                } else if (!fromCode && type.isData()) {
                    kind = "pointer";  // A slot in data, such as a candidate table entry.
                    pointerRefs++;
                } else {
                    continue;
                }
                note(evidence, counts, kind, reference.getFromAddress(), to);
            }
        }

        // Relocated far pointers (or absolute longs) in data that point into the range. A relocated word inside
        // an instruction is an operand such as mov ax,SEG or a far call, which Ghidra already follows.
        int relocatedPointers = 0;
        for (var item : pointers.subMap(range.getMinAddress().getOffset(), true, range.getMaxAddress().getOffset(), true)
                .entrySet()) {
            for (Address slot : item.getValue()) {
                if (range.contains(slot) || listing.getInstructionContaining(slot) != null) {
                    continue;
                }
                var to = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(item.getKey());
                note(evidence, counts, "relocated_pointer", slot, to);
                relocatedPointers++;
            }
        }
        int dataPointers = 0;
        for (var item : farDataPointers.subMap(range.getMinAddress().getOffset(), true,
                range.getMaxAddress().getOffset(), true).entrySet()) {
            for (Address slot : item.getValue()) {
                var to = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(item.getKey());
                note(evidence, counts, "data_pointer", slot, to);
                dataPointers++;
            }
        }
        code += 4 * Math.min(flowsToEntry, 2) + 2 * Math.min(flowsInside, 3) + Math.min(pointerRefs, 2) +
            Math.min(relocatedPointers, 3);
        data += 3 * Math.min(accesses, 2) + Math.min(dataPointers, 2);
        int inside = relocatedWords.subMap(range.getMinAddress().getOffset(), true,
            range.getMaxAddress().getOffset(), true).size();
        if (inside > 0) {
            var row = new LinkedHashMap<String, Object>();
            row.put("kind", "relocations_inside");
            row.put("count", inside);
            evidence.add(row);
        }

        if (prologue(bytes, padding)) {
            note(evidence, counts, "prologue", null, entry);
            code += 2;
        }
        int decoded = decodedBytes(entry, range.getMaxAddress());
        int body = size - padding;
        var decode = new LinkedHashMap<String, Object>();
        decode.put("kind", "linear_decode");
        decode.put("bytes", decoded);
        decode.put("of", body);
        evidence.add(decode);
        boolean subroutine = pseudo.isValidSubroutine(entry, false);
        if (subroutine) {
            note(evidence, counts, "valid_subroutine", null, entry);
            code += 2;
        }
        if (decoded == body && body >= 4) {
            code += 1;
        } else if (decoded < Math.min(body, 8)) {
            data += 2;  // The first few bytes do not even decode.
        }

        int printable = 0, zeros = 0;
        for (int index = padding; index < size; index++) {
            int value = bytes[index] & 0xFF;
            printable += value >= 0x20 && value < 0x7F || value == 0x0A || value == 0x0D ? 1 : 0;
            zeros += value == 0 ? 1 : 0;
        }
        if (body >= 4 && printable * 4 >= body * 3) {
            var text = new LinkedHashMap<String, Object>();
            text.put("kind", "text");
            text.put("printable", printable);
            evidence.add(text);
            data += 3;
        }
        if (body >= 4 && zeros * 2 >= body) {
            var zero = new LinkedHashMap<String, Object>();
            zero.put("kind", "zeros");
            zero.put("count", zeros);
            evidence.add(zero);
            data += 2;
        }

        String kind = "unknown";
        if (code > data && (code >= 4 || (code >= 3 && data == 0))) {
            kind = "code";
        } else if (data >= 2 && data > code) {
            kind = "data";
        }
        record.put("class", kind);
        record.put("code_score", code);
        record.put("data_score", data);
        record.put("conflict", code >= 3 && data >= 3);
        record.put("entry", kind.equals("code") ? String.format("%s:%04x", block.getName(),
            entry.subtract(block.getStart())) : null);
        record.put("evidence", evidence);
        record.put("counts", counts);
    }

    /** Count one piece of evidence and keep the first few of each kind with their addresses. */
    private void note(List<Map<String, Object>> evidence, Map<String, Integer> counts, String kind, Address from,
            Address to) {
        if (counts.merge(kind, 1, Integer::sum) > ROWS_PER_KIND) {
            return;
        }
        var row = new LinkedHashMap<String, Object>();
        row.put("kind", kind);
        if (from != null) {
            row.put("from", unitAddress(from));
        }
        row.put("at", unitAddress(to));
        evidence.add(row);
    }

    private String unitAddress(Address address) {
        var block = currentProgram.getMemory().getBlock(address);
        return block == null ? address.toString()
            : String.format("%s:%04x", block.getName(), address.subtract(block.getStart()));
    }

    private static boolean isPadding(byte value) {
        int unsigned = value & 0xFF;
        return unsigned == 0x00 || unsigned == 0x90 || unsigned == 0xCC || unsigned == 0xFF;
    }

    private boolean prologue(byte[] bytes, int at) {
        if (at + 3 > bytes.length) {
            return false;
        }
        int b0 = bytes[at] & 0xFF, b1 = bytes[at + 1] & 0xFF, b2 = bytes[at + 2] & 0xFF;
        if (x86) {
            // push bp; mov bp,sp (both encodings), enter, or push si/di/ds before the frame.
            return (b0 == 0x55 && ((b1 == 0x8B && b2 == 0xEC) || (b1 == 0x89 && b2 == 0xE5))) || b0 == 0xC8;
        }
        // 68k link a6 or movem.l to -(sp).
        return (b0 == 0x4E && b1 == 0x56) || (b0 == 0x48 && b1 == 0xE7);
    }

    /** Bytes decoded in a straight line from the entry until an invalid instruction or the end of the range. */
    private int decodedBytes(Address entry, Address last) {
        Address at = entry;
        int count = 0;
        for (int step = 0; step < DECODE_LIMIT && at.compareTo(last) <= 0; step++) {
            try {
                var instruction = pseudo.disassemble(at);
                if (instruction == null) {
                    break;
                }
                count += instruction.getLength();
                at = at.add(instruction.getLength());
            } catch (Exception error) {
                break;
            }
        }
        return (int) Math.min(count, last.subtract(entry) + 1);
    }
}
