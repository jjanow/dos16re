// Attach external linker symbols, source lines, and unique byte matches.
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class RetroreToolchain extends HeadlessScript {
    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        var args = getScriptArgs();
        var out = Path.of(args[1]);
        var gson = new Gson();
        try {
            var map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            var result = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
            result.add("toolchain", gson.toJsonTree(Map.of(
                "symbols", addSymbols(map.getAsJsonArray("toolchain_symbols")),
                "source_lines", addSourceLines(map.getAsJsonArray("toolchain_source_lines")))));
            Files.writeString(out, gson.toJson(result));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(out, gson.toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private int addSymbols(JsonArray symbols) throws Exception {
        if (symbols == null) {
            return 0;
        }
        var table = currentProgram.getSymbolTable();
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int count = 0;
        for (var element : symbols) {
            monitor.checkCancelled();
            var row = element.getAsJsonObject();
            var at = space.getAddress(row.get("linear").getAsLong());
            var name = SymbolUtilities.replaceInvalidChars(row.get("name").getAsString(), true);
            if (name.isEmpty() || !currentProgram.getMemory().contains(at)) {
                continue;
            }
            var function = getFunctionAt(at);
            if (function == null && row.get("kind").getAsString().equals("toolchain_signature") &&
                    currentProgram.getMemory().getBlock(at).isExecute() && getFunctionContaining(at) == null) {
                if (disassemble(at)) {
                    function = createFunction(at, name);
                }
            }
            if (function != null && function.getSymbol().getSource() == SourceType.DEFAULT) {
                function.setName(name, SourceType.IMPORTED);
            } else if (function == null || !function.getName().equals(name)) {
                table.createLabel(at, name, SourceType.IMPORTED);
            }
            count++;
        }
        return count;
    }

    private int addSourceLines(JsonArray lines) throws Exception {
        if (lines == null) {
            return 0;
        }
        var listing = currentProgram.getListing();
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int count = 0;
        for (var element : lines) {
            monitor.checkCancelled();
            var row = element.getAsJsonObject();
            var at = space.getAddress(row.get("linear").getAsLong());
            if (!currentProgram.getMemory().contains(at)) {
                continue;
            }
            var line = row.get("file").getAsString() + ":" + row.get("line").getAsInt();
            var prior = listing.getComment(CommentType.PRE, at);
            listing.setComment(at, CommentType.PRE, prior == null ? line : prior + "\n" + line);
            count++;
        }
        return count;
    }
}
