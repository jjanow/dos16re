// Show each declared runtime state in a separate Ghidra overlay address space.
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

public class RetroreLoadViews extends HeadlessScript {
    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        var args = getScriptArgs();
        var out = Path.of(args[1]);
        var gson = new Gson();
        try {
            var map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            var result = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
            result.add("load_views", gson.toJsonTree(addViews(map)));
            Files.writeString(out, gson.toJson(result));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(out, gson.toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private Map<String, Object> addViews(JsonObject map) throws Exception {
        var memory = currentProgram.getMemory();
        var base = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var bytes = memory.getAllFileBytes().getFirst();
        var units = new LinkedHashMap<String, JsonObject>();
        for (var element : map.getAsJsonArray("units")) {
            var unit = element.getAsJsonObject();
            units.put(unit.get("name").getAsString(), unit);
        }
        var views = new LinkedHashMap<String, Object>();
        for (var element : map.getAsJsonObject("load_manifest").getAsJsonArray("states")) {
            var state = element.getAsJsonObject();
            var name = state.get("name").getAsString();
            var space = currentProgram.createOverlaySpace("retrore_" + name, base);
            var blocks = new ArrayList<Map<String, Object>>();
            for (var item : state.getAsJsonArray("spans")) {
                monitor.checkCancelled();
                var load = item.getAsJsonObject();
                var unitName = load.get("unit").getAsString();
                var unit = units.get(unitName);
                var size = load.get("size").getAsLong();
                var offset = load.get("offset").getAsLong();
                var location = space.getAddressInThisSpaceOnly(load.get("linear").getAsLong());
                var original = memory.getBlock(unitName);
                var blockName = space.getName() + "_" + unitName + "_" + Long.toHexString(offset);
                MemoryBlock block;
                if (unit.has("file_size") && unit.get("file_size").getAsLong() == 0) {
                    block = memory.createUninitializedBlock(blockName, location, size, false);
                } else {
                    block = memory.createInitializedBlock(blockName, location, bytes,
                        unit.get("image_offset").getAsLong() + offset, size, false);
                }
                block.setRead(original.isRead());
                block.setWrite(original.isWrite());
                block.setExecute(original.isExecute());
                var sourceValue = unit.get("source");
                var memberValue = unit.get("disk_file");
                var source = sourceValue != null && !sourceValue.isJsonNull()
                    ? sourceValue.getAsString() : map.get("program").getAsString();
                var member = memberValue != null && !memberValue.isJsonNull() ? " / " + memberValue.getAsString() : "";
                block.setComment("retrore load state " + name + ", unit " + unitName + " from " + source + member);
                blocks.add(Map.of("unit", unitName, "block", blockName, "address", location.toString(true),
                    "offset", offset, "size", size));
            }
            views.put(name, Map.of("space", space.getName(), "blocks", blocks));
        }
        return views;
    }
}
