// Report initialized bytes that Ghidra has classified as neither code nor data.
import com.google.gson.Gson;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;

public class RetroreGaps extends GhidraScript {
    @Override
    public void run() throws Exception {
        var ranges = new ArrayList<Map<String, Object>>();
        long undefinedBytes = 0;
        var listing = currentProgram.getListing();
        for (var block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) {
                continue;
            }
            var start = block.getStart();
            var undefined = listing.getUndefinedRanges(new AddressSet(start, block.getEnd()), true, monitor);
            for (var range : undefined.getAddressRanges()) {
                monitor.checkCancelled();
                long size = range.getLength();
                undefinedBytes += size;
                String unit = block.getName();
                ranges.add(Map.of(
                    "unit", unit, "size", size, "linear", range.getMinAddress().getOffset(),
                    "start", String.format("%s:%04x", unit, range.getMinAddress().subtract(start)),
                    "end", String.format("%s:%04x", unit, range.getMaxAddress().subtract(start))
                ));
            }
        }
        Files.writeString(Path.of(getScriptArgs()[0]), new Gson().toJson(Map.of(
            "program", currentProgram.getName(), "undefined_bytes", undefinedBytes, "ranges", ranges
        )));
    }
}
