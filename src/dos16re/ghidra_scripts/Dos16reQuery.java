// Query an analyzed dos16re project.
import com.google.gson.FieldNamingPolicy;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class Dos16reQuery extends GhidraScript {
    private record Location(String address, String unitAddress, Long linear) {}
    private record Routine(String name, Location entry) {}
    private record BodyRange(Location start, Location end) {}
    private record CrossReference(Location from, Location to, String type, int operand,
            Routine fromFunction, Routine toFunction) {}

    private static final Comparator<Reference> REFERENCE_ORDER = Comparator
        .comparing(Reference::getFromAddress).thenComparing(Reference::getToAddress)
        .thenComparingInt(Reference::getOperandIndex);

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Map<String, Object> report;
        try {
            report = args[0].equals("trace") ? trace(Path.of(args[1])) : query(args[0], args[1]);
        } catch (IllegalArgumentException error) {
            report = Map.of("error", error.getMessage());
        }
        var gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .serializeNulls().create();
        Files.writeString(Path.of(args[2]), gson.toJson(report));
    }

    private Map<String, Object> trace(Path input) throws Exception {
        var trace = JsonParser.parseString(Files.readString(input)).getAsJsonObject();
        if (!trace.get("sha256").getAsString().equals(currentProgram.getExecutableSHA256())) {
            throw new IllegalArgumentException("Ghidra project was imported from a different image.bin");
        }
        var memory = currentProgram.getMemory();
        for (var item : trace.getAsJsonArray("units")) {
            var unit = item.getAsJsonObject();
            var name = unit.get("name").getAsString();
            var block = memory.getBlock(name);
            if (block == null || !block.isInitialized() ||
                    block.getStart().getOffset() != 16L * unit.get("segment").getAsInt() ||
                    block.getSize() != unit.get("size").getAsLong()) {
                throw new IllegalArgumentException("Ghidra project has a different placement for unit " + name);
            }
        }

        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var listing = currentProgram.getListing();
        var misses = new ArrayList<JsonObject>();
        var executed = new LinkedHashMap<Function, Long>();
        for (var item : trace.getAsJsonArray("hits")) {
            monitor.checkCancelled();
            var hit = item.getAsJsonObject();
            var address = space.getAddress(hit.get("linear").getAsLong());
            if (listing.getInstructionAt(address) == null) {
                String reason = "undefined";
                if (listing.getInstructionContaining(address) != null) {
                    reason = "instruction_offcut";
                } else if (listing.getDefinedDataContaining(address) != null) {
                    reason = "defined_data";
                }
                hit.addProperty("reason", reason);
                misses.add(hit);
                continue;
            }
            var function = getFunctionContaining(address);
            if (function != null) {
                executed.merge(function, hit.get("count").getAsLong(), Long::sum);
            }
        }
        var functions = executed.entrySet().stream().map(entry ->
            Map.of("function", routine(entry.getKey()), "count", entry.getValue())).toList();
        return Map.of("functions", functions, "missed", misses);
    }

    private Map<String, Object> query(String command, String input) throws Exception {
        Address address = resolve(input);
        if (command.equals("xrefs")) {
            return crossReferences(address);
        }
        Function function = getFunctionContaining(address);
        if (function == null) {
            throw new IllegalArgumentException("no analyzed function contains " + input);
        }
        return switch (command) {
            case "decomp" -> decompile(function);
            case "callers" -> Map.of("function", routine(function), "callers", callers(function));
            case "callees" -> Map.of("function", routine(function), "callees", callees(function));
            case "func" -> describe(function, address);
            default -> throw new IllegalArgumentException("unknown query " + command);
        };
    }

    private Map<String, Object> crossReferences(Address address) throws Exception {
        if (!currentProgram.getMemory().contains(address)) {
            throw new IllegalArgumentException("address outside the loaded image: " + address);
        }
        var manager = currentProgram.getReferenceManager();
        var incoming = new ArrayList<Reference>();
        for (var reference : manager.getReferencesTo(address)) {
            monitor.checkCancelled();
            incoming.add(reference);
        }
        return Map.of("address", location(address), "incoming", referenceRecords(incoming),
            "outgoing", referenceRecords(List.of(manager.getReferencesFrom(address))));
    }

    private List<CrossReference> callers(Function function) throws Exception {
        var manager = currentProgram.getReferenceManager();
        var calls = new ArrayList<Reference>();
        for (var reference : manager.getReferencesTo(function.getEntryPoint())) {
            monitor.checkCancelled();
            if (reference.getReferenceType().isCall()) {
                calls.add(reference);
            }
        }
        return referenceRecords(calls);
    }

    private List<CrossReference> callees(Function function) throws Exception {
        var manager = currentProgram.getReferenceManager();
        var calls = new ArrayList<Reference>();
        for (Address source : manager.getReferenceSourceIterator(function.getBody(), true)) {
            monitor.checkCancelled();
            for (var reference : manager.getReferencesFrom(source)) {
                if (reference.getReferenceType().isCall()) {
                    calls.add(reference);
                }
            }
        }
        return referenceRecords(calls);
    }

    private Map<String, Object> describe(Function function, Address address) throws Exception {
        var body = function.getBody();
        var ranges = new ArrayList<BodyRange>();
        for (var range : body.getAddressRanges()) {
            ranges.add(new BodyRange(location(range.getMinAddress()), location(range.getMaxAddress())));
        }
        var segments = new LinkedHashMap<String, Integer>();
        var context = currentProgram.getProgramContext();
        for (String name : List.of("DS", "ES", "SS")) {
            var value = context.getValue(currentProgram.getRegister(name), address, false);
            segments.put(name, value == null ? null : value.intValue());
        }
        return Map.of("function", routine(function), "ranges", ranges, "size", body.getNumAddresses(),
            "address", location(address), "segments", segments, "callers", callers(function));
    }

    private List<CrossReference> referenceRecords(List<Reference> references) throws Exception {
        var result = new ArrayList<CrossReference>();
        for (var reference : references.stream().sorted(REFERENCE_ORDER).toList()) {
            monitor.checkCancelled();
            var from = reference.getFromAddress();
            var to = reference.getToAddress();
            result.add(new CrossReference(location(from), location(to), reference.getReferenceType().toString(),
                reference.getOperandIndex(), routine(getFunctionContaining(from)), routine(getFunctionContaining(to))));
        }
        return result;
    }

    private Routine routine(Function function) {
        return function == null ? null : new Routine(function.getName(), location(function.getEntryPoint()));
    }

    private Location location(Address address) {
        var block = currentProgram.getMemory().getBlock(address);
        String unitAddress = block == null ? null
            : String.format("%s:%04x", block.getName(), address.subtract(block.getStart()));
        return new Location(address.toString(), unitAddress, address.isMemoryAddress() ? address.getOffset() : null);
    }

    private Map<String, Object> decompile(Function function) throws Exception {
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalArgumentException(decompiler.getLastMessage());
            }
            var result = decompiler.decompileFunction(function, 60, monitor);
            if (!result.decompileCompleted()) {
                throw new IllegalArgumentException(result.getErrorMessage());
            }
            var entry = location(function.getEntryPoint());
            return Map.of("address", entry.address(), "unit_address", entry.unitAddress(),
                "linear", entry.linear(), "name", function.getName(),
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
