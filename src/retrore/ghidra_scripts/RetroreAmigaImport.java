// Rebuild the Amiga hunk layout and seed 68k analysis.
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class RetroreAmigaImport extends HeadlessScript {
    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        var args = getScriptArgs();
        var result = Path.of(args[1]);
        var gson = new Gson();
        try {
            var map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            var report = loadMap(map);
            Files.writeString(result, gson.toJson(report));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(result, gson.toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private Map<String, Object> loadMap(JsonObject map) throws Exception {
        var memory = currentProgram.getMemory();
        var bytes = memory.getAllFileBytes().getFirst();
        var units = map.getAsJsonArray("units");
        long origin = units.get(0).getAsJsonObject().get("linear").getAsLong();
        for (var block : memory.getBlocks()) {
            memory.removeBlock(block, monitor);
        }
        currentProgram.setImageBase(address(origin), true);

        for (var item : units) {
            monitor.checkCancelled();
            var unit = item.getAsJsonObject();
            long size = unit.get("size").getAsLong();
            if (size == 0) {
                continue;
            }
            var block = memory.createInitializedBlock(unit.get("name").getAsString(),
                address(unit.get("linear").getAsLong()), bytes, unit.get("image_offset").getAsLong(), size, false);
            boolean code = unit.get("kind").getAsString().equals("code");
            block.setExecute(code);
            block.setWrite(!code);
        }

        int relocations = 0;
        for (var item : units) {
            monitor.checkCancelled();
            var unit = item.getAsJsonObject();
            var block = memory.getBlock(unit.get("name").getAsString());
            if (block == null) {
                continue;
            }
            var start = block.getStart();
            var listing = currentProgram.getListing();
            for (var element : unit.getAsJsonArray("relocations")) {
                var fixup = element.getAsJsonObject();
                var site = start.addNoWrap(fixup.get("offset").getAsLong());
                long value = fixup.get("value").getAsLong();
                byte[] original = ByteBuffer.allocate(4).putInt(fixup.get("original").getAsInt()).array();
                currentProgram.getRelocationTable().add(site, Relocation.Status.APPLIED, 0x3ec,
                    new long[] {value}, original, null);
                relocations++;
                if (!block.isExecute() && memory.contains(address(value)) &&
                        listing.getUndefinedDataAt(site) != null &&
                        listing.getUndefinedDataAt(site.addNoWrap(3)) != null) {
                    listing.createData(site, PointerDataType.dataType);
                }
            }
            for (var element : unit.getAsJsonArray("symbols")) {
                var symbol = element.getAsJsonObject();
                long offset = symbol.get("offset").getAsLong();
                String name = SymbolUtilities.replaceInvalidChars(symbol.get("name").getAsString(), true);
                if (!name.isEmpty() && offset >= 0 && offset < block.getSize()) {
                    currentProgram.getSymbolTable().createLabel(start.addNoWrap(offset), name, SourceType.IMPORTED);
                }
            }
        }

        var entry = address(map.getAsJsonObject("entry").get("linear").getAsLong());
        if (!memory.contains(entry) || !memory.getBlock(entry).isExecute()) {
            throw new IllegalArgumentException("Amiga entry point is outside executable memory");
        }
        currentProgram.getSymbolTable().addExternalEntryPoint(entry);
        disassemble(entry);
        createFunction(entry, null);

        return Map.of("program", currentProgram.getName(), "format", "HUNK",
            "units", units.size(), "relocations", relocations);
    }

    private Address address(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }
}
