// Restore the selected C64 CPU memory view and seed 6502 analysis.
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class RetroreC64Import extends HeadlessScript {
    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        var args = getScriptArgs();
        var result = Path.of(args[1]);
        var gson = new Gson();
        try {
            var map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            Files.writeString(result, gson.toJson(loadMap(map)));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(result, gson.toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private Map<String, Object> loadMap(JsonObject map) throws Exception {
        var memory = currentProgram.getMemory();
        var bytes = memory.getAllFileBytes().getFirst();
        for (var block : memory.getBlocks()) {
            memory.removeBlock(block, monitor);
        }

        var initialized = new AddressSet();
        var units = map.getAsJsonArray("units");
        for (var element : units) {
            monitor.checkCancelled();
            var unit = element.getAsJsonObject();
            var block = memory.createInitializedBlock(unit.get("name").getAsString(),
                address(unit.get("linear").getAsLong()), bytes, unit.get("image_offset").getAsLong(),
                unit.get("size").getAsLong(), false);
            block.setWrite(true);
            block.setExecute(true);
            initialized.add(block.getStart(), block.getEnd());
        }

        for (var element : map.getAsJsonArray("memory_map")) {
            monitor.checkCancelled();
            var region = element.getAsJsonObject();
            var start = address(region.get("linear").getAsLong());
            var end = start.addNoWrap(region.get("size").getAsLong() - 1);
            var available = new AddressSet(start, end).subtract(initialized);
            for (var range : available.getAddressRanges()) {
                var base = range.getMinAddress();
                String name = "c64_" + region.get("name").getAsString();
                if (!base.equals(start)) {
                    name += "_" + base;
                }
                var block = memory.createUninitializedBlock(name, base, range.getLength(), false);
                String read = region.get("read").getAsString();
                block.setWrite(!read.equals("rom"));
                block.setVolatile(read.equals("io"));
            }
        }

        var symbols = currentProgram.getSymbolTable();
        symbols.createLabel(address(0), "CPU_PORT_DDR", SourceType.IMPORTED);
        symbols.createLabel(address(1), "CPU_PORT_DATA", SourceType.IMPORTED);
        var entries = map.getAsJsonArray("entries");
        for (var element : entries) {
            monitor.checkCancelled();
            var entry = address(element.getAsJsonObject().get("linear").getAsLong());
            if (!initialized.contains(entry)) {
                throw new IllegalArgumentException("Entry point is outside the loaded PRGs");
            }
            symbols.addExternalEntryPoint(entry);
            disassemble(entry);
            createFunction(entry, null);
        }
        return Map.of("program", currentProgram.getName(), "format", map.get("format").getAsString(),
            "units", units.size(), "entries", entries.size(), "bank", map.get("bank").getAsInt());
    }

    private Address address(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }
}
