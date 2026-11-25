// Import a retrore program map before auto-analysis.
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.Map;

public class RetroreImport extends HeadlessScript {
    private SegmentedAddressSpace space;
    private static final String PASCAL_DGROUP_FILE = "pascal-dgroup.bin";

    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        String[] args = getScriptArgs();
        Path result = Path.of(args[1]);
        try {
            JsonObject map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            loadMap(map, Path.of(args[0]).resolveSibling(PASCAL_DGROUP_FILE));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(result, new Gson().toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private void loadMap(JsonObject map, Path capturePath) throws Exception {
        // Maps written before versioning have no "version" and read as version 1.
        if (map.has("version") && map.get("version").getAsInt() != 1) {
            throw new IllegalArgumentException("unsupported retrore map version");
        }
        space = (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
        Memory memory = currentProgram.getMemory();
        FileBytes bytes = memory.getAllFileBytes().getFirst();
        var units = map.getAsJsonArray("units");
        var root = units.get(0).getAsJsonObject();
        boolean pc98 = map.has("format") && map.get("format").getAsString().equals("PC98");
        long origin = pc98 ? map.get("image_origin").getAsLong() : root.get("linear").getAsLong();
        if (!root.get("name").getAsString().equals("root")) {
            throw new IllegalArgumentException("the first unit must be root");
        }
        for (MemoryBlock block : memory.getBlocks()) {
            memory.removeBlock(block, monitor);
        }
        currentProgram.setImageBase(space.getAddress(root.get("segment").getAsInt(), 0), true);

        for (JsonElement item : units) {
            JsonObject unit = item.getAsJsonObject();
            String name = unit.get("name").getAsString();
            Address start = space.getAddress(unit.get("segment").getAsInt(), 0);
            long size = unit.get("size").getAsLong();
            long fileOffset = unit.get("image_offset").getAsLong();
            if (start.getOffset() != unit.get("linear").getAsLong() ||
                    fileOffset != start.getOffset() - origin || fileOffset < 0 ||
                    size <= 0 || fileOffset > bytes.getSize() - size) {
                throw new IllegalArgumentException("invalid image range for unit " + name);
            }
            MemoryBlock block = memory.createInitializedBlock(name, start, bytes, fileOffset, size, false);
            block.setExecute(true);
            block.setWrite(true);
            if (unit.has("allocation_size")) {
                long allocation = unit.get("allocation_size").getAsLong();
                if (allocation < size || allocation > 0x100000L - start.getOffset()) {
                    throw new IllegalArgumentException("invalid allocation for unit " + name);
                }
                if (allocation > size) {
                    var extra = memory.createUninitializedBlock(name + "_bss",
                        space.getAddress(start.getOffset() + size), allocation - size, false);
                    extra.setRead(true);
                    extra.setWrite(true);
                    extra.setExecute(false);
                }
            }
        }
        long[] capturedRange = null;
        if (map.has("microsoft_pascal_capture")) {
            capturedRange = loadPascalCapture(map, memory, capturePath, memory.getBlock("root"));
        }
        if (map.has("memory_end")) {
            addRootAllocation(units, root, map.get("memory_end").getAsLong(), memory, capturedRange);
        }
        if (pc98) {
            addPc98Hardware(map.getAsJsonArray("memory_map"), memory);
        }
        var entry = address(map.getAsJsonObject("entry"));
        var entryBlock = memory.getBlock(entry);
        if (entryBlock == null || !entryBlock.isExecute()) {
            throw new IllegalArgumentException("entry point is outside the image");
        }
        if (map.has("relocations")) {
            markRelocations(map.getAsJsonArray("relocations"), origin, memory);
        }
        if (map.has("jump_tables")) {
            recoverSwitches(map.getAsJsonArray("jump_tables"));
        }
        seed(entry, "entry");
        if (pc98) {
            var entries = map.getAsJsonArray("entries");
            for (int index = 1; index < entries.size(); index++) {
                Address target = address(entries.get(index).getAsJsonObject());
                var block = memory.getBlock(target);
                if (block == null || !block.isExecute()) {
                    throw new IllegalArgumentException("entry point is outside the image: " + target);
                }
                seed(target, "entry_" + target.toString().replace(':', '_'));
            }
        }
        for (JsonElement item : units) {
            JsonObject unit = item.getAsJsonObject();
            if (!unit.has("entries")) {
                continue;
            }
            for (JsonElement entryOffset : unit.getAsJsonArray("entries")) {
                int offset = entryOffset.getAsInt();
                Address target = space.getAddress(unit.get("segment").getAsInt(), offset);
                seed(target, unit.get("name").getAsString() + String.format("_%04x", offset));
            }
        }

        if (!map.has("stubs")) {
            return;
        }
        for (JsonElement item : map.getAsJsonArray("stubs")) {
            JsonObject stub = item.getAsJsonObject();
            Address start = address(stub.getAsJsonObject("address"));
            Address target = address(stub.getAsJsonObject("target"));
            String name = String.format("stub_%s_%04x", stub.get("unit").getAsString(),
                stub.getAsJsonObject("address").get("offset").getAsInt());
            seed(start, name);
            comment(start, "Far jump to " + target + ". Original bytes " +
                stub.get("original").getAsString());
        }
        if (map.has("calls")) {
            for (JsonElement item : map.getAsJsonArray("calls")) {
                JsonObject call = item.getAsJsonObject();
                Address start = space.getAddress(call.get("linear").getAsLong());
                Address stub = address(call.getAsJsonObject("stub"));
                comment(start, "Originally called " + stub + ". Original bytes " +
                    call.get("original").getAsString());
            }
        }
    }

    private long[] loadPascalCapture(JsonObject map, Memory memory, Path path, MemoryBlock root) throws Exception {
        var capture = map.getAsJsonObject("microsoft_pascal_capture");
        var layout = map.getAsJsonObject("microsoft_pascal_dgroup");
        int segment = capture.get("segment").getAsInt();
        int shift = (segment - layout.get("biased_segment").getAsInt()) & 0xffff;
        long start = (layout.get("copy_start_segment").getAsLong() + shift) * 16;
        long end = (layout.get("copy_end_segment").getAsLong() + shift) * 16;
        if (segment < 0 || segment > 0xffff || shift > layout.get("max_shift_paragraphs").getAsInt() ||
                shift != capture.get("shift_paragraphs").getAsInt() || start != capture.get("linear").getAsLong() ||
                end - start != capture.get("size").getAsLong() || start < root.getStart().getOffset() ||
                start < layout.get("startup_linear").getAsLong() + 0xa2 || end <= start || end > 0x100000L) {
            throw new IllegalArgumentException("invalid captured Microsoft Pascal DGROUP range");
        }
        if (Files.size(path) != end - start) {
            throw new IllegalArgumentException("captured Microsoft Pascal DGROUP has the wrong length");
        }
        byte[] data = Files.readAllBytes(path);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        if (data.length != end - start || !hash.equals(capture.get("sha256").getAsString())) {
            throw new IllegalArgumentException("captured Microsoft Pascal DGROUP does not match map.json");
        }
        for (var block : memory.getBlocks()) {
            if (!block.getName().equals("root") && start <= block.getEnd().getOffset() && end > block.getStart().getOffset()) {
                throw new IllegalArgumentException("captured Microsoft Pascal DGROUP overlaps " + block.getName());
            }
        }
        // A small shift can leave part of the destination in the original root file range.
        int overlap = (int) Math.max(0, Math.min(end, root.getEnd().getOffset() + 1) - start);
        if (overlap > 0) {
            // Keep BinaryLoader's FileBytes available to manifest views of the static image.
            Address rootStart = root.getStart();
            byte[] view = new byte[(int) root.getSize()];
            memory.getBytes(rootStart, view);
            System.arraycopy(data, 0, view, (int) (start - rootStart.getOffset()), overlap);
            memory.removeBlock(root, monitor);
            var replacement = memory.createInitializedBlock("root", rootStart, new ByteArrayInputStream(view),
                view.length, monitor, false);
            replacement.setExecute(true);
            replacement.setWrite(true);
        }
        if (overlap < data.length) {
            var block = memory.createInitializedBlock("pascal_dgroup", space.getAddress(start + overlap),
                new ByteArrayInputStream(data, overlap, data.length - overlap), data.length - overlap, monitor, false);
            block.setWrite(true);
            block.setExecute(false);
            block.setComment("Captured Microsoft Pascal DGROUP (SHA-256 " + hash + ")");
        }
        return new long[] {start, end};
    }

    /** Back the root's uninitialized data and stack, skipping placed units and captured data. */
    private void addRootAllocation(JsonArray units, JsonObject root, long end, Memory memory, long[] capturedRange)
            throws Exception {
        long start = root.get("linear").getAsLong() + root.get("size").getAsLong();
        var used = new java.util.ArrayList<long[]>();
        for (JsonElement item : units) {
            JsonObject unit = item.getAsJsonObject();
            long linear = unit.get("linear").getAsLong();
            used.add(new long[] {linear, linear + unit.get("size").getAsLong()});
        }
        if (capturedRange != null) {
            used.add(capturedRange);
        }
        used.sort((left, right) -> Long.compare(left[0], right[0]));
        int part = 0;
        for (long[] range : used) {
            if (start >= end) {
                break;
            }
            if (range[1] <= start) {
                continue;
            }
            long stop = Math.min(range[0], end);
            if (stop > start) {
                createAllocation(memory, start, stop - start, part++);
            }
            start = Math.max(start, range[1]);
        }
        if (start < end) {
            createAllocation(memory, start, end - start, part);
        }
    }

    private void createAllocation(Memory memory, long linear, long size, int part) throws Exception {
        String name = part == 0 ? "root_bss" : "root_bss_" + part;
        var block = memory.createUninitializedBlock(name, space.getAddress(linear), size, false);
        block.setRead(true);
        block.setWrite(true);
        block.setExecute(false);
    }

    private void addPc98Hardware(JsonArray layout, Memory memory) throws Exception {
        for (JsonElement item : layout) {
            var region = item.getAsJsonObject();
            String kind = region.get("kind").getAsString();
            if (kind.equals("vram") || kind.equals("rom")) {
                long linear = region.get("linear").getAsLong();
                Address start = space.getAddress((int) (linear >> 4), 0);
                var block = memory.createUninitializedBlock(region.get("name").getAsString(), start,
                    region.get("size").getAsLong(), false);
                block.setWrite(kind.equals("vram"));
                block.setVolatile(kind.equals("vram"));
                block.setExecute(false);
            }
        }
    }

    /**
     * Record the relocated segment words as an address property for evidence queries such as `gaps
     * --classify`. Ghidra's own relocation table is left alone: its analyzers turn relocated 16-bit
     * immediates into references.
     */
    private void markRelocations(JsonArray relocations, long origin, Memory memory) throws Exception {
        var properties = currentProgram.getUsrPropertyManager();
        var marks = properties.getVoidPropertyMap(RELOCATIONS);
        if (marks == null) {
            marks = properties.createVoidPropertyMap(RELOCATIONS);
        }
        for (JsonElement item : relocations) {
            Address site = space.getAddress(origin + item.getAsLong());
            if (memory.contains(site)) {
                marks.add(site);
            }
        }
    }

    static final String RELOCATIONS = "retrore.relocations";

    private void recoverSwitches(JsonArray switches) throws Exception {
        var listing = currentProgram.getListing();
        var references = currentProgram.getReferenceManager();

        // Reserve table bytes before following any code through the switch.
        for (JsonElement item : switches) {
            monitor.checkCancelled();
            JsonObject record = item.getAsJsonObject();
            Address table = address(record.getAsJsonObject("table"));
            int count = record.getAsJsonArray("targets").size();
            int width = tableEntrySize(record);
            for (int index = 0; index < count; index++) {
                Address word = table.addNoWrap((long) width * index);
                boolean undefined = true;
                for (int offset = 0; offset < width; offset++) {
                    undefined &= listing.getUndefinedDataAt(word.addNoWrap(offset)) != null;
                }
                if (undefined) {
                    listing.createData(word, width == 4 ? DWordDataType.dataType : WordDataType.dataType);
                }
            }
        }
        for (JsonElement item : switches) {
            monitor.checkCancelled();
            JsonObject record = item.getAsJsonObject();
            Address jump = address(record.getAsJsonObject("address"));
            Address table = address(record.getAsJsonObject("table"));
            disassemble(address(record.getAsJsonObject("guard")));
            var instruction = listing.getInstructionAt(jump);
            // Call tables ("kind": "call") dispatch to subroutines; older maps hold only jump tables.
            boolean call = record.has("kind") && record.get("kind").getAsString().equals("call");
            if (instruction == null || !instruction.getFlowType().isComputed() ||
                    (call ? !instruction.getFlowType().isCall() : !instruction.getFlowType().isJump())) {
                continue;
            }
            instruction.addOperandReference(0, table, RefType.READ, SourceType.ANALYSIS);
            int width = tableEntrySize(record);
            int index = 0;
            var destinations = new LinkedHashSet<Address>();
            for (JsonElement target : record.getAsJsonArray("targets")) {
                Address destination = address(target.getAsJsonObject());
                destinations.add(destination);
                Address word = table.addNoWrap((long) width * index++);
                references.addMemoryReference(word, destination, RefType.DATA, SourceType.ANALYSIS, 0);
                instruction.addMnemonicReference(destination,
                    call ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
            }
            for (Address destination : instruction.getFlows()) {
                destinations.add(destination);
            }
            for (Address destination : destinations) {
                disassemble(destination);
                if (call && getFunctionAt(destination) == null) {
                    createFunction(destination, null);
                }
            }
        }
    }

    private static int tableEntrySize(JsonObject table) {
        int width = table.has("entry_size") ? table.get("entry_size").getAsInt() : 2;
        if (width != 2 && width != 4) {
            throw new IllegalArgumentException("unsupported DOS jump table entry size " + width);
        }
        return width;
    }

    private Address address(JsonObject record) {
        return space.getAddress(record.get("segment").getAsInt(), record.get("offset").getAsInt());
    }

    private void seed(Address address, String name) throws Exception {
        currentProgram.getSymbolTable().addExternalEntryPoint(address);
        disassemble(address);
        if (getFunctionAt(address) != null || createFunction(address, name) == null) {
            createLabel(address, name, true);
        }
    }

    private void comment(Address address, String text) {
        currentProgram.getListing().setComment(address, CommentType.EOL, text);
    }
}
