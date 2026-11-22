// Decompile an analyzed dos16re function.
import com.google.gson.Gson;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class Dos16reDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path output = Path.of(args[1]);
        try {
            Files.writeString(output, new Gson().toJson(decompile(args[0])));
        } catch (IllegalArgumentException error) {
            Files.writeString(output, new Gson().toJson(Map.of("error", error.getMessage())));
        }
    }

    private Map<String, Object> decompile(String input) throws Exception {
        Address address = resolve(input);
        var function = getFunctionContaining(address);
        if (function == null) {
            throw new IllegalArgumentException("no analyzed function contains " + input);
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalArgumentException(decompiler.getLastMessage());
            }
            var result = decompiler.decompileFunction(function, 60, monitor);
            if (!result.decompileCompleted()) {
                throw new IllegalArgumentException(result.getErrorMessage());
            }
            Address entry = function.getEntryPoint();
            MemoryBlock unit = currentProgram.getMemory().getBlock(entry);
            String unitAddress = String.format("%s:%04x", unit.getName(), entry.subtract(unit.getStart()));
            return Map.of("address", entry.toString(), "unit_address", unitAddress,
                "linear", entry.getOffset(), "name", function.getName(),
                "decompilation", result.getDecompiledFunction().getC());
        } finally {
            decompiler.dispose();
        }
    }

    private Address resolve(String input) throws Exception {
        String[] parts = input.split(":", 2);
        long offset = Long.parseLong(parts[1], 16);
        // Prefer unit names so that overlays named with hexadecimal characters still work.
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.getName().equalsIgnoreCase(parts[0])) {
                if (offset >= block.getSize()) {
                    throw new IllegalArgumentException("offset outside unit " + parts[0]);
                }
                return block.getStart().addNoWrap(offset);
            }
        }
        if (parts[0].matches("[0-9a-fA-F]{1,4}") && offset <= 0xffff) {
            var space = (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
            return space.getAddress(Integer.parseInt(parts[0], 16), (int) offset);
        }
        throw new IllegalArgumentException("unknown unit or invalid segment address " + input);
    }
}
