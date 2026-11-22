// Import a dos16re program map before auto-analysis.
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;

public class Dos16reImport extends HeadlessScript {
    private SegmentedAddressSpace space;

    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        String[] args = getScriptArgs();
        Path result = Path.of(args[1]);
        try {
            JsonObject map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            loadMap(map);
            Files.writeString(result, new Gson().toJson(Map.of(
                "program", currentProgram.getName(), "units", map.getAsJsonArray("units").size()
            )));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(result, new Gson().toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private void loadMap(JsonObject map) throws Exception {
        if (map.get("version").getAsInt() != 1) {
            throw new IllegalArgumentException("unsupported dos16re map version");
        }
        space = (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
        Memory memory = currentProgram.getMemory();
        FileBytes bytes = memory.getAllFileBytes().getFirst();
        var units = map.getAsJsonArray("units");
        var root = units.get(0).getAsJsonObject();
        long origin = root.get("linear").getAsLong();
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
        var entry = address(map.getAsJsonObject("entry"));
        if (!memory.contains(entry)) {
            throw new IllegalArgumentException("entry point is outside the image");
        }
        seed(entry, "entry");
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
