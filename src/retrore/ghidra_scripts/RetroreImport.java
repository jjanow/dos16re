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
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class RetroreImport extends HeadlessScript {
    private SegmentedAddressSpace space;

    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        String[] args = getScriptArgs();
        Path result = Path.of(args[1]);
        try {
            JsonObject map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            loadMap(map);
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(result, new Gson().toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private void loadMap(JsonObject map) throws Exception {
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
        }
        if (pc98) {
            addPc98Hardware(map.getAsJsonArray("memory_map"), memory);
        }
        var entry = address(map.getAsJsonObject("entry"));
        var entryBlock = memory.getBlock(entry);
        if (entryBlock == null || !entryBlock.isExecute()) {
            throw new IllegalArgumentException("entry point is outside the image");
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

    private void recoverSwitches(JsonArray switches) throws Exception {
        var listing = currentProgram.getListing();
        var references = currentProgram.getReferenceManager();

        // Reserve table bytes before following any code through the switch.
        for (JsonElement item : switches) {
            monitor.checkCancelled();
            JsonObject record = item.getAsJsonObject();
            Address table = address(record.getAsJsonObject("table"));
            int count = record.getAsJsonArray("targets").size();
            for (int index = 0; index < count; index++) {
                Address word = table.addNoWrap(2L * index);
                if (listing.getUndefinedDataAt(word) != null &&
                        listing.getUndefinedDataAt(word.addNoWrap(1)) != null) {
                    listing.createData(word, WordDataType.dataType);
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
            if (instruction == null || !instruction.getFlowType().isJump() ||
                    !instruction.getFlowType().isComputed()) {
                continue;
            }
            instruction.addOperandReference(0, table, RefType.READ, SourceType.ANALYSIS);
            int index = 0;
            for (JsonElement target : record.getAsJsonArray("targets")) {
                Address destination = address(target.getAsJsonObject());
                Address word = table.addNoWrap(2L * index++);
                references.addMemoryReference(word, destination, RefType.DATA, SourceType.ANALYSIS, 0);
                instruction.addMnemonicReference(destination, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
            }
            for (Address destination : instruction.getFlows()) {
                disassemble(destination);
            }
        }
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
