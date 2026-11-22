// Restore the selected 8-bit CPU memory view and seed analysis.
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

public class Retrore8BitImport extends HeadlessScript {
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
        String format = map.get("format").getAsString();
        String prefix = switch (format) {
            case "C64_PRG" -> "c64_";
            case "APPLE2" -> "apple2_";
            case "ATARI8" -> "atari8_";
            case "MSX2" -> "msx2_";
            case "PC88" -> "pc88_";
            default -> throw new IllegalArgumentException("Unsupported 8-bit image format " + format);
        };
        for (var element : units) {
            monitor.checkCancelled();
            var unit = element.getAsJsonObject();
            var block = memory.createInitializedBlock(unit.get("name").getAsString(),
                address(unit.get("linear").getAsLong()), bytes, unit.get("image_offset").getAsLong(),
                unit.get("size").getAsLong(), false);
            block.setWrite(!unit.has("writable") || unit.get("writable").getAsBoolean());
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
                String name = prefix + region.get("name").getAsString();
                if (!base.equals(start)) {
                    name += "_" + base;
                }
                var block = memory.createUninitializedBlock(name, base, range.getLength(), false);
                String read = region.get("read").getAsString();
                block.setWrite(!read.equals("rom") && !region.get("write").getAsString().equals("none"));
                block.setVolatile(read.equals("io"));
            }
        }

        String viewKey = switch (format) {
            case "C64_PRG" -> "bank";
            case "APPLE2" -> "language_card";
            case "MSX2", "PC88" -> "memory_view";
            default -> "portb";
        };
        Object view;
        if (viewKey.equals("memory_view")) {
            addZ80Labels(format, prefix);
            view = map.get(viewKey).getAsString();
        } else {
            int bank = map.get(viewKey).getAsInt();
            addPlatformLabels(format, bank);
            view = bank;
        }
        var symbols = currentProgram.getSymbolTable();
        var entries = map.getAsJsonArray("entries");
        for (var element : entries) {
            monitor.checkCancelled();
            var entry = address(element.getAsJsonObject().get("linear").getAsLong());
            if (!initialized.contains(entry)) {
                throw new IllegalArgumentException("Entry point is outside the initialized memory");
            }
            symbols.addExternalEntryPoint(entry);
            disassemble(entry);
            createFunction(entry, null);
        }
        return Map.of("program", currentProgram.getName(), "format", format,
            "units", units.size(), "entries", entries.size(), viewKey, view);
    }

    private void addZ80Labels(String format, String prefix) throws Exception {
        var symbols = currentProgram.getSymbolTable();
        Map<Integer, String> ports;
        if (format.equals("MSX2")) {
            symbols.createLabel(address(0x0005), "BDOS", SourceType.IMPORTED);
            ports = Map.of(0x98, "VDP_DATA", 0x99, "VDP_CONTROL", 0xa8, "PRIMARY_SLOT",
                0xfc, "MAPPER_PAGE_0", 0xfd, "MAPPER_PAGE_1", 0xfe, "MAPPER_PAGE_2", 0xff, "MAPPER_PAGE_3");
        } else {
            ports = Map.ofEntries(
                Map.entry(0x31, "GRAPHICS_MEMORY_CONTROL"), Map.entry(0x32, "MISC_CONTROL"),
                Map.entry(0x50, "CRTC_DATA"), Map.entry(0x51, "CRTC_COMMAND"),
                Map.entry(0x53, "VIDEO_LAYER_MASK"), Map.entry(0x5c, "SELECT_BLUE_VRAM"),
                Map.entry(0x5d, "SELECT_RED_VRAM"), Map.entry(0x5e, "SELECT_GREEN_VRAM"),
                Map.entry(0x5f, "SELECT_MAIN_RAM"), Map.entry(0x70, "RAM_WINDOW_BANK"),
                Map.entry(0x71, "EXT_ROM_SELECT"), Map.entry(0xe2, "EXT_RAM_MODE"),
                Map.entry(0xe3, "EXT_RAM_BANK"), Map.entry(0xe4, "IRQ_LEVEL"), Map.entry(0xe6, "IRQ_MASK"),
                Map.entry(0xfc, "DISK_PPI_A"), Map.entry(0xfd, "DISK_PPI_B"),
                Map.entry(0xfe, "DISK_PPI_C"), Map.entry(0xff, "DISK_PPI_CONTROL"));
        }
        var io = currentProgram.getAddressFactory().getAddressSpace("io");
        var block = currentProgram.getMemory().createUninitializedBlock(prefix + "ports", io.getAddress(0), 0x100, false);
        block.setVolatile(true);
        for (var port : ports.entrySet()) {
            symbols.createLabel(io.getAddress(port.getKey()), port.getValue(), SourceType.IMPORTED);
        }
    }

    private void addPlatformLabels(String format, int bank) throws Exception {
        var labels = switch (format) {
            case "C64_PRG" -> Map.of(0, "CPU_PORT_DDR", 1, "CPU_PORT_DATA");
            case "APPLE2" -> Map.of(0xc000, "KBD", 0xc010, "KBDSTRB", 0xc030, "SPKR");
            default -> Map.of(0x02e0, "RUNAD", 0x02e2, "INITAD", 0xd01a, "COLBK",
                0xd301, "PORTB", 0xd400, "DMACTL", 0xd40a, "WSYNC", 0xd40e, "NMIEN");
        };
        var symbols = currentProgram.getSymbolTable();
        for (var label : labels.entrySet()) {
            symbols.createLabel(address(label.getKey()), label.getValue(), SourceType.IMPORTED);
        }
        if (format.equals("ATARI8") && (bank & 1) != 0) {
            symbols.createLabel(address(0xe456), "CIOV", SourceType.IMPORTED);
            symbols.createLabel(address(0xe459), "SIOV", SourceType.IMPORTED);
        }
    }

    private Address address(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }
}
