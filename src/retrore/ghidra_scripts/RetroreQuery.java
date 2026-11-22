// Query an analyzed retrore project.
import com.google.gson.FieldNamingPolicy;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
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
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class RetroreQuery extends GhidraScript {
    private record Location(String address, String unitAddress, Long linear) {}
    private record Routine(String name, Object entry) {}
    private record BodyRange(Object start, Object end) {}
    private record CrossReference(Object from, Object to, String type, int operand,
            Routine fromFunction, Routine toFunction) {}
    private record Page(int offset, int total, int returned, Integer nextOffset) {}

    private record Options(Set<String> fields, String direction, Set<String> types,
            Integer limit, int offset, boolean paged, boolean compact) {
        Options(JsonObject request) {
            this(values(request, "fields"), request.has("direction") ? request.get("direction").getAsString() : "both",
                values(request, "ref_types").stream().map(type -> type.toUpperCase(Locale.ROOT)).collect(Collectors.toSet()),
                request.has("limit") ? request.get("limit").getAsInt() : null,
                request.has("offset") ? request.get("offset").getAsInt() : 0,
                request.has("limit") || request.has("offset"),
                request.has("compact") && request.get("compact").getAsBoolean());
        }

        private static Set<String> values(JsonObject request, String key) {
            if (!request.has(key)) {
                return Set.of();
            }
            return StreamSupport.stream(request.getAsJsonArray(key).spliterator(), false)
                .map(element -> element.getAsString()).collect(Collectors.toSet());
        }

        boolean includes(String field) {
            return fields.isEmpty() || fields.contains(field);
        }

        boolean matches(Reference reference) {
            return types.isEmpty() || types.contains(reference.getReferenceType().toString().toUpperCase(Locale.ROOT));
        }
    }

    private static final Comparator<Reference> REFERENCE_ORDER = Comparator
        .comparing(Reference::getFromAddress).thenComparing(Reference::getToAddress)
        .thenComparingInt(Reference::getOperandIndex);

    private DecompInterface decompiler;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Map<String, Object> report;
        try {
            var input = JsonParser.parseString(Files.readString(Path.of(args[1])));
            report = switch (args[0]) {
                case "trace" -> trace(input.getAsJsonObject());
                case "batch" -> batch(input.getAsJsonArray());
                case "single" -> query(input.getAsJsonObject());
                default -> throw new IllegalArgumentException("unknown query mode " + args[0]);
            };
        } catch (IllegalArgumentException | AddressOutOfBoundsException | AddressOverflowException error) {
            report = Map.of("error", errorMessage(error));
        } finally {
            if (decompiler != null) {
                decompiler.dispose();
            }
        }
        var gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .serializeNulls().create();
        Files.writeString(Path.of(args[2]), gson.toJson(report));
    }

    private Map<String, Object> batch(JsonArray requests) throws Exception {
        var results = new ArrayList<Map<String, Object>>();
        for (var item : requests) {
            monitor.checkCancelled();
            var request = item.getAsJsonObject();
            String command = request.get("command").getAsString();
            String address = request.get("address").getAsString();
            var row = new LinkedHashMap<String, Object>();
            row.put("command", command);
            row.put("address", address);
            try {
                row.put("result", query(request));
            } catch (IllegalArgumentException | AddressOutOfBoundsException | AddressOverflowException error) {
                row.put("error", errorMessage(error));
            }
            results.add(row);
        }
        return Map.of("results", results);
    }

    private static String errorMessage(Exception error) {
        return Objects.toString(error.getMessage(), error.getClass().getSimpleName());
    }

    private Map<String, Object> trace(JsonObject trace) throws Exception {
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
            Map.of("function", routine(entry.getKey(), false), "count", entry.getValue())).toList();
        return Map.of("functions", functions, "missed", misses);
    }

    private Map<String, Object> query(JsonObject request) throws Exception {
        String command = request.get("command").getAsString();
        String input = request.get("address").getAsString();
        var options = new Options(request);
        Address address = resolve(input);
        var report = new LinkedHashMap<String, Object>();
        var pages = new LinkedHashMap<String, Page>();
        if (command.equals("xrefs")) {
            crossReferences(address, options, report, pages);
        } else {
            Function function = getFunctionContaining(address);
            if (function == null) {
                throw new IllegalArgumentException("no analyzed function contains " + input);
            }
            if (command.equals("decomp")) {
                return describeDecompilation(function, options);
            }
            if (options.includes("function")) {
                report.put("function", routine(function, options.compact()));
            }
            if (command.equals("func")) {
                describe(function, address, options, report);
            }
            if ((command.equals("func") || command.equals("callers")) && options.includes("callers")) {
                report.put("callers", referenceRecords("callers", callers(function, options), options, pages));
            }
            if (command.equals("callees") && options.includes("callees")) {
                report.put("callees", referenceRecords("callees", callees(function, options), options, pages));
            }
        }
        if (!pages.isEmpty()) {
            report.put("pagination", pages);
        }
        return report;
    }

    private void crossReferences(Address address, Options options, Map<String, Object> report, Map<String, Page> pages)
            throws Exception {
        if (!currentProgram.getMemory().contains(address)) {
            throw new IllegalArgumentException("address outside the loaded image: " + address);
        }
        if (options.includes("address")) {
            report.put("address", addressRecord(address, options.compact()));
        }
        var manager = currentProgram.getReferenceManager();
        if (!options.direction().equals("outgoing") && options.includes("incoming")) {
            var incoming = new ArrayList<Reference>();
            for (var reference : manager.getReferencesTo(address)) {
                monitor.checkCancelled();
                if (options.matches(reference)) {
                    incoming.add(reference);
                }
            }
            report.put("incoming", referenceRecords("incoming", incoming, options, pages));
        }
        if (!options.direction().equals("incoming") && options.includes("outgoing")) {
            var outgoing = new ArrayList<Reference>();
            for (var reference : manager.getReferencesFrom(address)) {
                if (options.matches(reference)) {
                    outgoing.add(reference);
                }
            }
            report.put("outgoing", referenceRecords("outgoing", outgoing, options, pages));
        }
    }

    private List<Reference> callers(Function function, Options options) throws Exception {
        var manager = currentProgram.getReferenceManager();
        var calls = new ArrayList<Reference>();
        for (var reference : manager.getReferencesTo(function.getEntryPoint())) {
            monitor.checkCancelled();
            if (reference.getReferenceType().isCall() && options.matches(reference)) {
                calls.add(reference);
            }
        }
        return calls;
    }

    private List<Reference> callees(Function function, Options options) throws Exception {
        var manager = currentProgram.getReferenceManager();
        var calls = new ArrayList<Reference>();
        for (Address source : manager.getReferenceSourceIterator(function.getBody(), true)) {
            monitor.checkCancelled();
            for (var reference : manager.getReferencesFrom(source)) {
                if (reference.getReferenceType().isCall() && options.matches(reference)) {
                    calls.add(reference);
                }
            }
        }
        return calls;
    }

    private void describe(Function function, Address address, Options options, Map<String, Object> report) {
        var body = function.getBody();
        if (options.includes("ranges")) {
            var ranges = new ArrayList<BodyRange>();
            for (var range : body.getAddressRanges()) {
                ranges.add(new BodyRange(addressRecord(range.getMinAddress(), options.compact()),
                    addressRecord(range.getMaxAddress(), options.compact())));
            }
            report.put("ranges", ranges);
        }
        if (options.includes("size")) {
            report.put("size", body.getNumAddresses());
        }
        if (options.includes("address")) {
            report.put("address", addressRecord(address, options.compact()));
        }
        if (options.includes("segments")) {
            var segments = new LinkedHashMap<String, Integer>();
            if (address.getAddressSpace() instanceof SegmentedAddressSpace) {
                var context = currentProgram.getProgramContext();
                for (String name : List.of("DS", "ES", "SS")) {
                    var value = context.getValue(currentProgram.getRegister(name), address, false);
                    segments.put(name, value == null ? null : value.intValue());
                }
            }
            report.put("segments", segments);
        }
    }

    private List<CrossReference> referenceRecords(String group, List<Reference> references, Options options,
            Map<String, Page> pages) throws Exception {
        references.sort(REFERENCE_ORDER);
        int total = references.size();
        int start = Math.min(options.offset(), total);
        int returned = options.limit() == null ? total - start : Math.min(options.limit(), total - start);
        int end = start + returned;
        if (options.paged()) {
            pages.put(group, new Page(options.offset(), total, returned, end < total ? end : null));
        }
        var result = new ArrayList<CrossReference>();
        for (var reference : references.subList(start, end)) {
            monitor.checkCancelled();
            var from = reference.getFromAddress();
            var to = reference.getToAddress();
            result.add(new CrossReference(addressRecord(from, options.compact()), addressRecord(to, options.compact()),
                reference.getReferenceType().toString(), reference.getOperandIndex(),
                routine(getFunctionContaining(from), options.compact()), routine(getFunctionContaining(to), options.compact())));
        }
        return result;
    }

    private Routine routine(Function function, boolean compact) {
        return function == null ? null : new Routine(function.getName(), addressRecord(function.getEntryPoint(), compact));
    }

    private Object addressRecord(Address address, boolean compact) {
        var location = location(address);
        return compact ? Objects.requireNonNullElse(location.unitAddress(), location.address()) : location;
    }

    private Location location(Address address) {
        var block = currentProgram.getMemory().getBlock(address);
        String unitAddress = block == null ? null
            : String.format("%s:%04x", block.getName(), address.subtract(block.getStart()));
        return new Location(address.toString(), unitAddress, address.isMemoryAddress() ? address.getOffset() : null);
    }

    private Map<String, Object> describeDecompilation(Function function, Options options) throws Exception {
        var report = new LinkedHashMap<String, Object>();
        var entry = location(function.getEntryPoint());
        if (options.includes("address")) {
            report.put("address", entry.address());
        }
        if (options.includes("unit_address")) {
            report.put("unit_address", entry.unitAddress());
        }
        if (options.includes("linear")) {
            report.put("linear", entry.linear());
        }
        if (options.includes("name")) {
            report.put("name", function.getName());
        }
        if (options.includes("decompilation")) {
            report.put("decompilation", decompile(function));
        }
        return report;
    }

    private String decompile(Function function) throws Exception {
        if (decompiler == null) {
            decompiler = new DecompInterface();
            if (!decompiler.openProgram(currentProgram)) {
                String message = decompiler.getLastMessage();
                decompiler.dispose();
                decompiler = null;
                throw new IllegalArgumentException(message);
            }
        }
        var result = decompiler.decompileFunction(function, 60, monitor);
        if (!result.decompileCompleted()) {
            throw new IllegalArgumentException(result.getErrorMessage());
        }
        return result.getDecompiledFunction().getC();
    }

    private Address resolve(String input) throws Exception {
        String[] parts = input.split(":", 2);
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        if (parts.length == 1) {
            if (space instanceof SegmentedAddressSpace) {
                throw new IllegalArgumentException("expected a seg:off or unit:offset address");
            }
            return space.getAddress(Long.parseLong(parts[0], 16));
        }
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
        if (space instanceof SegmentedAddressSpace segmented &&
                parts[0].matches("[0-9a-fA-F]{1,4}") && offset <= 0xffff) {
            return segmented.getAddress(Integer.parseInt(parts[0], 16), (int) offset);
        }
        throw new IllegalArgumentException("unknown unit or invalid segment address " + input);
    }
}
