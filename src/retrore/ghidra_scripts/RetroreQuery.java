// Query an analyzed retrore project.
import com.google.gson.FieldNamingPolicy;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class RetroreQuery extends GhidraScript {
    private record Location(String address, String unitAddress, Long linear) {}
    private record Routine(String name, Object entry) {}
    private record BodyRange(Object start, Object end) {}
    private record CrossReference(Object from, Object to, String type, int operand,
            Routine fromFunction, Routine toFunction) {}
    private record Page(int offset, int total, int returned, Integer nextOffset) {}
    private record Focus(Location address, String instruction, String bytes) {}
    private record ExcerptLine(int line, String text, boolean focused, List<Location> addresses) {}
    private record SliceValue(String storage, int size) {}
    private record SliceInput(String storage, int size, Integer definition) {}
    private record SliceOperation(int id, Location address, String opcode, boolean focused,
            List<SliceInput> inputs, SliceValue output) {}
    private record DataSlice(List<SliceOperation> operations, boolean truncated) {}
    private record GraphNode(Routine function, int depth) {}
    private record GraphEdge(Object from, Object to, int calls) {}
    private record FunctionParameter(String name, String type, String storage) {}
    private record CallTarget(Object target, Routine function, int calls) {}
    private record DataUse(Object address, String name, String type, Integer size, List<String> access,
            List<Integer> accessWidths, int references) {}

    private record Options(Set<String> fields, String direction, Set<String> types,
            Integer limit, int offset, boolean paged, boolean compact, Integer context, Integer slice) {
        Options(JsonObject request) {
            this(values(request, "fields"), request.has("direction") ? request.get("direction").getAsString() : "both",
                values(request, "ref_types").stream().map(type -> type.toUpperCase(Locale.ROOT)).collect(Collectors.toSet()),
                request.has("limit") ? request.get("limit").getAsInt() : null,
                request.has("offset") ? request.get("offset").getAsInt() : 0,
                request.has("limit") || request.has("offset"),
                request.has("compact") && request.get("compact").getAsBoolean(),
                request.has("context") ? request.get("context").getAsInt() : null,
                request.has("slice") ? request.get("slice").getAsInt() : null);
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

    private static final com.google.gson.Gson GSON = new GsonBuilder()
        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).serializeNulls().create();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args[0].equals("serve")) {
            try {
                serve(Integer.parseInt(args[1]));
            } finally {
                if (decompiler != null) {
                    decompiler.dispose();
                }
            }
            return;
        }
        Map<String, Object> report;
        try {
            report = answer(args[0], JsonParser.parseString(Files.readString(Path.of(args[1]))));
        } catch (IllegalArgumentException | AddressOutOfBoundsException | AddressOverflowException error) {
            report = Map.of("error", errorObject(error));
        } finally {
            if (decompiler != null) {
                decompiler.dispose();
            }
        }
        Files.writeString(Path.of(args[2]), GSON.toJson(report));
    }

    private Map<String, Object> answer(String mode, com.google.gson.JsonElement input) throws Exception {
        return switch (mode) {
            case "trace" -> trace(input.getAsJsonObject());
            case "batch" -> batch(input.getAsJsonArray());
            case "single" -> query(input.getAsJsonObject());
            default -> throw new IllegalArgumentException("unknown query mode " + mode);
        };
    }

    /**
     * Answer newline-delimited JSON requests from the retrore worker manager until it closes the connection.
     *
     * The manager listens on a loopback port and passes the port as an argument and a one-time token in the
     * RETRORE_WORKER_TOKEN environment variable. Each request is {"id", "mode", "input"}; each response is
     * {"id", "report"} with the same report the one-shot modes write, or {"id", "crash"} when the request
     * failed in a way the one-shot modes would report as a failed headless run.
     */
    private void serve(int port) throws Exception {
        try (var socket = new java.net.Socket(java.net.InetAddress.getLoopbackAddress(), port);
                var reader = new java.io.BufferedReader(new java.io.InputStreamReader(
                    socket.getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
                var writer = new java.io.BufferedWriter(new java.io.OutputStreamWriter(
                    socket.getOutputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
            var hello = new LinkedHashMap<String, Object>();
            hello.put("token", Objects.requireNonNullElse(System.getenv("RETRORE_WORKER_TOKEN"), ""));
            hello.put("program", currentProgram.getName());
            writer.write(GSON.toJson(hello));
            writer.newLine();
            writer.flush();
            String line;
            while ((line = reader.readLine()) != null) {
                var request = JsonParser.parseString(line).getAsJsonObject();
                String mode = request.get("mode").getAsString();
                if (mode.equals("shutdown")) {
                    break;
                }
                var response = new LinkedHashMap<String, Object>();
                response.put("id", request.get("id").getAsLong());
                try {
                    Object report;
                    try {
                        report = mode.equals("gaps") ? gapsScript() : answer(mode, request.get("input"));
                    } catch (IllegalArgumentException | AddressOutOfBoundsException | AddressOverflowException error) {
                        report = Map.of("error", errorObject(error));
                    }
                    response.put("report", report);
                } catch (Exception | LinkageError | AssertionError error) {
                    printerr("retrore worker request failed: " + error);
                    response.put("crash", Objects.toString(error.getMessage(), error.getClass().getName()));
                }
                writer.write(GSON.toJson(response));
                writer.newLine();
                writer.flush();
            }
        }
    }

    /** Run RetroreGaps.java in this session and return its report unchanged. */
    private com.google.gson.JsonElement gapsScript() throws Exception {
        var file = Files.createTempFile("retrore-gaps", ".json");
        try {
            runScript("RetroreGaps.java", new String[] {file.toString()});
            return JsonParser.parseString(Files.readString(file));
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private Map<String, Object> batch(JsonArray requests) throws Exception {
        var results = new ArrayList<Map<String, Object>>();
        for (var item : requests) {
            monitor.checkCancelled();
            // Python adds the command and identifying request keys to each row.
            var request = item.getAsJsonObject();
            var row = new LinkedHashMap<String, Object>();
            try {
                row.put("result", query(request));
            } catch (IllegalArgumentException | AddressOutOfBoundsException | AddressOverflowException error) {
                row.put("error", errorObject(error));
            }
            results.add(row);
        }
        return Map.of("results", results);
    }

    private static String errorMessage(Exception error) {
        return Objects.toString(error.getMessage(), error.getClass().getSimpleName());
    }

    /** An error with a stable code from retrore.errors. Throw it to report a code explicitly. */
    static final class QueryError extends IllegalArgumentException {
        final String code;

        QueryError(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    private static Map<String, Object> errorObject(Exception error) {
        String message = errorMessage(error);
        String code;
        if (error instanceof QueryError coded) {
            code = coded.code;
        } else if (error instanceof AddressOutOfBoundsException || error instanceof AddressOverflowException
                || error instanceof NumberFormatException || message.startsWith("address outside")
                || message.startsWith("offset outside") || message.startsWith("unknown unit")
                || message.startsWith("expected a seg:off")) {
            code = "address_not_found";
        } else if (message.startsWith("no analyzed")) {
            code = "no_function";
        } else if (message.startsWith("Ghidra project")) {
            code = "project_mismatch";
        } else {
            code = "query_failed";
        }
        var object = new LinkedHashMap<String, Object>();
        object.put("code", code);
        object.put("message", message);
        return object;
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
        var options = new Options(request);
        return switch (command) {
            case "functions" -> functions(request, options);
            case "symbols" -> symbols(request, options);
            case "inventory" -> inventory(request, options);
            case "callgraph" -> callGraph(request, options);
            case "context" -> context(request, options);
            case "gaps" -> gaps(request, options);
            case "coverage" -> coverage(request, options);
            default -> addressQuery(command, request, options);
        };
    }

    private Map<String, Object> addressQuery(String command, JsonObject request, Options options) throws Exception {
        String input = request.get("address").getAsString();
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
                return describeDecompilation(function, address, options);
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
        if (options.includes("segment_losses")) {
            report.put("segment_losses", segmentLosses(address, options.compact()));
        }
    }

    // Where and why each unknown segment register at an address lost its value, as recorded by
    // RetroreSegments. Projects imported before the record existed report no losses.
    private Map<String, Object> segmentLosses(Address address, boolean compact) {
        var losses = new LinkedHashMap<String, Object>();
        var properties = currentProgram.getUsrPropertyManager();
        var lossMap = properties.getStringPropertyMap("RetroreSegmentLosses");
        var originMap = properties.getStringPropertyMap("RetroreSegmentLossOrigins");
        var instruction = currentProgram.getListing().getInstructionContaining(address);
        if (lossMap == null || originMap == null || instruction == null) {
            return losses;
        }
        String record = lossMap.getString(instruction.getAddress());
        if (record == null) {
            return losses;
        }
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        for (String item : record.split(";")) {
            String[] parts = item.split("=", 2);
            Address origin = space.getAddress(Long.parseLong(parts[1], 16));
            String reason = null;
            String detail = null;
            String lines = originMap.getString(origin);
            for (String line : lines == null ? new String[0] : lines.split("\n")) {
                String[] fields = line.split("\t", 3);
                if (fields.length == 3 && fields[0].equals(parts[0])) {
                    reason = fields[1];
                    detail = fields[2];
                }
            }
            var loss = new LinkedHashMap<String, Object>();
            loss.put("address", addressRecord(origin, compact));
            loss.put("reason", reason);
            loss.put("detail", detail);
            losses.put(parts[0], loss);
        }
        return losses;
    }

    private List<CrossReference> referenceRecords(String group, List<Reference> references, Options options,
            Map<String, Page> pages) throws Exception {
        references.sort(REFERENCE_ORDER);
        var result = new ArrayList<CrossReference>();
        for (var reference : page(group, references, options, pages)) {
            monitor.checkCancelled();
            var from = reference.getFromAddress();
            var to = reference.getToAddress();
            result.add(new CrossReference(addressRecord(from, options.compact()), addressRecord(to, options.compact()),
                reference.getReferenceType().toString(), reference.getOperandIndex(),
                routine(getFunctionContaining(from), options.compact()), routine(getFunctionContaining(to), options.compact())));
        }
        return result;
    }

    private static <T> List<T> page(String group, List<T> items, Options options, Map<String, Page> pages) {
        int total = items.size();
        int start = Math.min(options.offset(), total);
        int returned = options.limit() == null ? total - start : Math.min(options.limit(), total - start);
        int end = start + returned;
        if (options.paged()) {
            pages.put(group, new Page(options.offset(), total, returned, end < total ? end : null));
        }
        return items.subList(start, end);
    }

    private static List<Map<String, Object>> select(List<Map<String, Object>> records, Options options) {
        for (var record : records) {
            record.keySet().removeIf(key -> !key.equals("query") && !key.equals("error") && !options.includes(key));
        }
        return records;
    }

    private static List<String> strings(JsonObject request, String key) {
        if (!request.has(key)) {
            return List.of();
        }
        return StreamSupport.stream(request.getAsJsonArray(key).spliterator(), false)
            .map(element -> element.getAsString()).toList();
    }

    private Function containing(String input) throws Exception {
        var function = getFunctionContaining(resolve(input));
        if (function == null) {
            throw new QueryError("no_function", "no analyzed function contains " + input);
        }
        return function;
    }

    private MemoryBlock unit(JsonObject request) {
        if (!request.has("unit")) {
            return null;
        }
        String name = request.get("unit").getAsString();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.getName().equalsIgnoreCase(name)) {
                return block;
            }
        }
        throw new QueryError("address_not_found", "unknown unit " + name);
    }

    private static AddressSet span(MemoryBlock block) {
        return new AddressSet(block.getStart(), block.getEnd());
    }

    private Map<String, Object> functionRecord(Function function, Options options) {
        boolean compact = options.compact();
        var record = new LinkedHashMap<String, Object>();
        record.put("name", function.getName());
        record.put("entry", addressRecord(function.getEntryPoint(), compact));
        var ranges = new ArrayList<BodyRange>();
        for (var range : function.getBody().getAddressRanges()) {
            ranges.add(new BodyRange(addressRecord(range.getMinAddress(), compact),
                addressRecord(range.getMaxAddress(), compact)));
        }
        record.put("ranges", ranges);
        record.put("size", function.getBody().getNumAddresses());
        record.put("prototype", function.getPrototypeString(false, true));
        record.put("calling_convention", function.getCallingConventionName());
        return record;
    }

    private Map<String, Object> functions(JsonObject request, Options options) throws Exception {
        var rows = new ArrayList<Map<String, Object>>();
        for (String input : strings(request, "addresses")) {
            monitor.checkCancelled();
            var row = new LinkedHashMap<String, Object>();
            row.put("query", input);
            try {
                row.putAll(functionRecord(containing(input), options));
            } catch (IllegalArgumentException | AddressOutOfBoundsException | AddressOverflowException error) {
                row.put("error", errorObject(error));
            }
            rows.add(row);
        }
        var symbols = currentProgram.getSymbolTable();
        for (String name : strings(request, "names")) {
            monitor.checkCancelled();
            var matches = new ArrayList<Function>();
            for (Symbol symbol : symbols.getSymbols(name)) {
                var function = symbol.getSymbolType() == SymbolType.FUNCTION ? getFunctionAt(symbol.getAddress()) : null;
                if (function != null) {
                    matches.add(function);
                }
            }
            matches.sort(Comparator.comparing(Function::getEntryPoint));
            if (matches.isEmpty()) {
                var row = new LinkedHashMap<String, Object>();
                row.put("query", name);
                row.put("error", errorObject(new QueryError("no_function", "no analyzed function named " + name)));
                rows.add(row);
            }
            for (var function : matches) {
                var row = new LinkedHashMap<String, Object>();
                row.put("query", name);
                row.putAll(functionRecord(function, options));
                rows.add(row);
            }
        }
        var pages = new LinkedHashMap<String, Page>();
        var report = new LinkedHashMap<String, Object>();
        report.put("functions", select(page("functions", rows, options, pages), options));
        report.put("pagination", pages);
        return report;
    }

    private Map<String, Object> symbols(JsonObject request, Options options) throws Exception {
        boolean ignoreCase = request.has("ignore_case") && request.get("ignore_case").getAsBoolean();
        Predicate<String> matches;
        if (request.has("name")) {
            String name = request.get("name").getAsString();
            matches = candidate -> ignoreCase ? candidate.equalsIgnoreCase(name) : candidate.equals(name);
        } else if (request.has("prefix")) {
            String prefix = request.get("prefix").getAsString();
            matches = candidate -> candidate.regionMatches(ignoreCase, 0, prefix, 0, prefix.length());
        } else {
            var regex = new StringBuilder();
            for (char character : request.get("glob").getAsString().toCharArray()) {
                regex.append(switch (character) {
                    case '*' -> ".*";
                    case '?' -> ".";
                    default -> Pattern.quote(String.valueOf(character));
                });
            }
            var pattern = Pattern.compile(regex.toString(),
                ignoreCase ? Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE : 0);
            matches = candidate -> pattern.matcher(candidate).matches();
        }
        var block = unit(request);
        var found = new ArrayList<Symbol>();
        boolean generated = request.has("generated") && request.get("generated").getAsBoolean();
        for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(generated)) {
            monitor.checkCancelled();
            var address = symbol.getAddress();
            if (address.isMemoryAddress() && (block == null || block.contains(address))
                    && matches.test(symbol.getName())) {
                found.add(symbol);
            }
        }
        found.sort(Comparator.comparing(Symbol::getAddress).thenComparing(symbol -> symbol.getName()));
        var pages = new LinkedHashMap<String, Page>();
        var rows = new ArrayList<Map<String, Object>>();
        for (var symbol : page("symbols", found, options, pages)) {
            var row = new LinkedHashMap<String, Object>();
            row.put("name", symbol.getName());
            row.put("address", addressRecord(symbol.getAddress(), options.compact()));
            row.put("kind", symbol.getSymbolType().toString());
            row.put("source", symbol.getSource().toString());
            row.put("namespace", symbol.isGlobal() ? null : symbol.getParentNamespace().getName(true));
            rows.add(row);
        }
        var report = new LinkedHashMap<String, Object>();
        report.put("symbols", select(rows, options));
        report.put("pagination", pages);
        return report;
    }

    private Map<String, Object> inventory(JsonObject request, Options options) throws Exception {
        var block = unit(request);
        var set = span(block);
        boolean compact = options.compact();
        var report = new LinkedHashMap<String, Object>();
        var pages = new LinkedHashMap<String, Page>();
        if (options.includes("unit")) {
            var unit = new LinkedHashMap<String, Object>();
            unit.put("name", block.getName());
            unit.put("start", addressRecord(block.getStart(), compact));
            unit.put("end", addressRecord(block.getEnd(), compact));
            unit.put("size", block.getSize());
            report.put("unit", unit);
        }
        if (options.includes("functions")) {
            var functions = new ArrayList<Function>();
            currentProgram.getFunctionManager().getFunctions(set, true).forEach(functions::add);
            var rows = new ArrayList<Map<String, Object>>();
            for (var function : page("functions", functions, options, pages)) {
                var row = new LinkedHashMap<String, Object>();
                row.put("name", function.getName());
                row.put("entry", addressRecord(function.getEntryPoint(), compact));
                row.put("size", function.getBody().getNumAddresses());
                rows.add(row);
            }
            report.put("functions", rows);
        }
        if (options.includes("labels")) {
            var labels = new ArrayList<Symbol>();
            currentProgram.getSymbolTable().getSymbols(set, SymbolType.LABEL, true).forEach(labels::add);
            var rows = new ArrayList<Map<String, Object>>();
            for (var label : page("labels", labels, options, pages)) {
                var row = new LinkedHashMap<String, Object>();
                row.put("name", label.getName());
                row.put("address", addressRecord(label.getAddress(), compact));
                row.put("source", label.getSource().toString());
                rows.add(row);
            }
            report.put("labels", rows);
        }
        if (options.includes("data")) {
            var data = new ArrayList<Data>();
            currentProgram.getListing().getDefinedData(set, true).forEach(data::add);
            var rows = new ArrayList<Map<String, Object>>();
            for (var item : page("data", data, options, pages)) {
                var symbol = item.getPrimarySymbol();
                var row = new LinkedHashMap<String, Object>();
                row.put("address", addressRecord(item.getAddress(), compact));
                row.put("name", symbol == null ? null : symbol.getName());
                row.put("type", item.getDataType().getDisplayName());
                row.put("size", item.getLength());
                rows.add(row);
            }
            report.put("data", rows);
        }
        if (!pages.isEmpty()) {
            report.put("pagination", pages);
        }
        return report;
    }

    private Map<String, Object> callGraph(JsonObject request, Options options) throws Exception {
        var root = containing(request.get("address").getAsString());
        boolean towardCallees = options.direction().equals("callees");
        int maxDepth = request.get("depth").getAsInt();
        int maxNodes = request.get("max_nodes").getAsInt();
        var nodes = new ArrayList<Function>(List.of(root));
        var depths = new HashMap<Address, Integer>(Map.of(root.getEntryPoint(), 0));
        var edges = new LinkedHashMap<List<Address>, Integer>();
        int unresolved = 0;
        boolean depthLimited = false;
        boolean nodeLimited = false;
        for (int index = 0; index < nodes.size(); index++) {
            monitor.checkCancelled();
            var node = nodes.get(index);
            int depth = depths.get(node.getEntryPoint());
            var calls = towardCallees ? callees(node, options) : callers(node, options);
            calls.sort(REFERENCE_ORDER);
            for (var call : calls) {
                var peer = getFunctionContaining(towardCallees ? call.getToAddress() : call.getFromAddress());
                if (peer == null) {
                    unresolved++;
                    continue;
                }
                var entry = peer.getEntryPoint();
                if (!depths.containsKey(entry)) {
                    if (depth >= maxDepth) {
                        depthLimited = true;
                        continue;
                    }
                    if (nodes.size() >= maxNodes) {
                        nodeLimited = true;
                        continue;
                    }
                    depths.put(entry, depth + 1);
                    nodes.add(peer);
                }
                var edge = towardCallees ? List.of(node.getEntryPoint(), entry) : List.of(entry, node.getEntryPoint());
                edges.merge(edge, 1, Integer::sum);
            }
        }
        boolean compact = options.compact();
        var report = new LinkedHashMap<String, Object>();
        var pages = new LinkedHashMap<String, Page>();
        if (options.includes("root")) {
            report.put("root", routine(root, compact));
        }
        if (options.includes("nodes")) {
            report.put("nodes", page("nodes", nodes, options, pages).stream().map(function ->
                new GraphNode(routine(function, compact), depths.get(function.getEntryPoint()))).toList());
        }
        if (options.includes("edges")) {
            report.put("edges", page("edges", new ArrayList<>(edges.entrySet()), options, pages).stream().map(edge ->
                new GraphEdge(addressRecord(edge.getKey().get(0), compact), addressRecord(edge.getKey().get(1), compact),
                    edge.getValue())).toList());
        }
        if (options.includes("unresolved")) {
            report.put("unresolved", unresolved);
        }
        if (options.includes("truncated")) {
            var truncated = new LinkedHashMap<String, Boolean>();
            truncated.put("depth", depthLimited);
            truncated.put("nodes", nodeLimited);
            report.put("truncated", truncated);
        }
        if (!pages.isEmpty()) {
            report.put("pagination", pages);
        }
        return report;
    }

    private Map<String, Object> context(JsonObject request, Options options) throws Exception {
        var function = containing(request.get("address").getAsString());
        boolean compact = options.compact();
        var report = new LinkedHashMap<String, Object>();
        var pages = new LinkedHashMap<String, Page>();
        if (options.includes("function")) {
            report.put("function", routine(function, compact));
        }
        if (options.includes("prototype")) {
            report.put("prototype", function.getPrototypeString(false, true));
        }
        if (options.includes("calling_convention")) {
            report.put("calling_convention", function.getCallingConventionName());
        }
        if (options.includes("return_type")) {
            report.put("return_type", function.getReturnType().getDisplayName());
        }
        if (options.includes("parameters")) {
            var parameters = new ArrayList<FunctionParameter>();
            for (var parameter : function.getParameters()) {
                parameters.add(new FunctionParameter(parameter.getName(), parameter.getDataType().getDisplayName(),
                    parameter.getVariableStorage().toString()));
            }
            report.put("parameters", page("parameters", parameters, options, pages));
        }
        if (options.includes("callees")) {
            var targets = new TreeMap<Address, Integer>();
            for (var call : callees(function, options)) {
                targets.merge(call.getToAddress(), 1, Integer::sum);
            }
            report.put("callees", page("callees", new ArrayList<>(targets.entrySet()), options, pages).stream()
                .map(target -> new CallTarget(addressRecord(target.getKey(), compact),
                    routine(getFunctionContaining(target.getKey()), compact), target.getValue())).toList());
        }
        if (options.includes("data")) {
            report.put("data", dataUses(function, options, pages));
        }
        if (!pages.isEmpty()) {
            report.put("pagination", pages);
        }
        return report;
    }

    private List<DataUse> dataUses(Function function, Options options, Map<String, Page> pages) throws Exception {
        var manager = currentProgram.getReferenceManager();
        var references = new TreeMap<Address, List<Reference>>();
        for (Address source : manager.getReferenceSourceIterator(function.getBody(), true)) {
            monitor.checkCancelled();
            for (var reference : manager.getReferencesFrom(source)) {
                if (reference.getReferenceType().isData() && reference.getToAddress().isMemoryAddress()) {
                    references.computeIfAbsent(reference.getToAddress(), key -> new ArrayList<>()).add(reference);
                }
            }
        }
        var listing = currentProgram.getListing();
        var symbols = currentProgram.getSymbolTable();
        var uses = new ArrayList<DataUse>();
        for (var target : page("data", new ArrayList<>(references.entrySet()), options, pages)) {
            var address = target.getKey();
            var access = new TreeSet<String>();
            var widths = new TreeSet<Integer>();
            for (var reference : target.getValue()) {
                access.add(reference.getReferenceType().toString());
                widths.addAll(accessWidths(reference));
            }
            String type = null;
            Integer size = null;
            Data data = listing.getDataContaining(address);
            if (data != null && data.isDefined()) {
                var primitive = data.getPrimitiveAt((int) address.subtract(data.getAddress()));
                if (primitive != null) {
                    type = primitive.getDataType().getDisplayName();
                    size = primitive.getLength();
                }
            }
            var symbol = symbols.getPrimarySymbol(address);
            uses.add(new DataUse(addressRecord(address, options.compact()), symbol == null ? null : symbol.getName(),
                type, size, List.copyOf(access), List.copyOf(widths), target.getValue().size()));
        }
        return uses;
    }

    // Widths come from the instruction's p-code: loads for reads, stores for writes, or direct memory operands.
    private Set<Integer> accessWidths(Reference reference) {
        var widths = new TreeSet<Integer>();
        var instruction = currentProgram.getListing().getInstructionAt(reference.getFromAddress());
        if (instruction == null) {
            return widths;
        }
        var type = reference.getReferenceType();
        long target = reference.getToAddress().getOffset();
        for (var op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.LOAD && type.isRead()) {
                widths.add(op.getOutput().getSize());
            } else if (op.getOpcode() == PcodeOp.STORE && type.isWrite()) {
                widths.add(op.getInput(2).getSize());
            }
            var output = op.getOutput();
            if (output != null && output.isAddress() && output.getOffset() == target && type.isWrite()) {
                widths.add(output.getSize());
            }
            for (var input : op.getInputs()) {
                if (input.isAddress() && input.getOffset() == target && type.isRead()) {
                    widths.add(input.getSize());
                }
            }
        }
        return widths;
    }

    private Map<String, Object> gaps(JsonObject request, Options options) throws Exception {
        var filter = unit(request);
        var listing = currentProgram.getListing();
        var ranges = new ArrayList<Map<String, Object>>();
        long undefinedBytes = 0;
        for (var block : currentProgram.getMemory().getBlocks()) {
            // Match RetroreGaps.java: only initialized executable blocks.
            if ((filter != null && !block.equals(filter)) || !block.isInitialized() || !block.isExecute()) {
                continue;
            }
            var start = block.getStart();
            for (var range : listing.getUndefinedRanges(span(block), true, monitor).getAddressRanges()) {
                monitor.checkCancelled();
                undefinedBytes += range.getLength();
                var record = new LinkedHashMap<String, Object>();
                record.put("unit", block.getName());
                record.put("size", range.getLength());
                record.put("linear", range.getMinAddress().getOffset());
                record.put("start", String.format("%s:%04x", block.getName(), range.getMinAddress().subtract(start)));
                record.put("end", String.format("%s:%04x", block.getName(), range.getMaxAddress().subtract(start)));
                ranges.add(record);
            }
        }
        var pages = new LinkedHashMap<String, Page>();
        var report = new LinkedHashMap<String, Object>();
        report.put("program", currentProgram.getName());
        report.put("undefined_bytes", undefinedBytes);
        report.put("ranges", select(page("ranges", ranges, options, pages), options));
        report.put("pagination", pages);
        return report;
    }

    private Map<String, Object> coverage(JsonObject request, Options options) throws Exception {
        var filter = unit(request);
        var blocks = new ArrayList<MemoryBlock>();
        for (var block : currentProgram.getMemory().getBlocks()) {
            if (filter == null || block.equals(filter)) {
                blocks.add(block);
            }
        }
        var listing = currentProgram.getListing();
        var pages = new LinkedHashMap<String, Page>();
        var rows = new ArrayList<Map<String, Object>>();
        for (var block : page("units", blocks, options, pages)) {
            var set = span(block);
            long instructionBytes = 0;
            for (var instruction : listing.getInstructions(set, true)) {
                monitor.checkCancelled();
                instructionBytes += instruction.getLength();
            }
            long dataBytes = 0;
            for (var data : listing.getDefinedData(set, true)) {
                dataBytes += data.getLength();
            }
            int functions = 0;
            for (var iterator = currentProgram.getFunctionManager().getFunctions(set, true); iterator.hasNext();
                    iterator.next()) {
                functions++;
            }
            var row = new LinkedHashMap<String, Object>();
            row.put("unit", block.getName());
            row.put("start", addressRecord(block.getStart(), options.compact()));
            row.put("size", block.getSize());
            row.put("initialized", block.isInitialized());
            row.put("execute", block.isExecute());
            row.put("functions", functions);
            row.put("instruction_bytes", instructionBytes);
            row.put("data_bytes", dataBytes);
            row.put("undefined_bytes", listing.getUndefinedRanges(set, true, monitor).getNumAddresses());
            rows.add(row);
        }
        var report = new LinkedHashMap<String, Object>();
        report.put("units", select(rows, options));
        report.put("pagination", pages);
        return report;
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

    private Map<String, Object> describeDecompilation(Function function, Address address, Options options)
            throws Exception {
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
        boolean targeted = options.context() != null || options.slice() != null;
        boolean full = targeted ? options.fields().contains("decompilation") : options.includes("decompilation");
        boolean excerpt = options.context() != null && options.includes("excerpt");
        boolean slice = options.slice() != null && options.includes("slice");
        Instruction instruction = null;
        if (targeted && (options.includes("focus") || excerpt || slice)) {
            instruction = currentProgram.getListing().getInstructionContaining(address);
            if (instruction == null) {
                throw new IllegalArgumentException("no analyzed instruction contains " + address);
            }
            if (options.includes("focus")) {
                report.put("focus", new Focus(location(instruction.getAddress()), instruction.toString(),
                    HexFormat.of().formatHex(instruction.getBytes())));
            }
        }
        if (full || excerpt || slice) {
            var result = decompile(function);
            if (full) {
                report.put("decompilation", result.getDecompiledFunction().getC());
            }
            if (excerpt) {
                report.put("excerpt", excerpt(result, instruction.getAddress(), options.context()));
            }
            if (slice) {
                report.put("slice", dataSlice(result, instruction, options.slice()));
            }
        }
        return report;
    }

    private List<ExcerptLine> excerpt(DecompileResults result, Address focus, int context) throws Exception {
        var lines = new PrettyPrinter(result.getFunction(), result.getCCodeMarkup(), null).getLines();
        var excerpt = new ArrayList<ExcerptLine>();
        for (int index = 0; index < lines.size(); index++) {
            monitor.checkCancelled();
            if (!lineAddresses(lines.get(index).getAllTokens()).contains(focus)) {
                continue;
            }
            int start = Math.max(0, index - context);
            int end = Math.min(lines.size(), index + context + 1);
            for (var line : lines.subList(start, end)) {
                var addresses = lineAddresses(line.getAllTokens());
                excerpt.add(new ExcerptLine(line.getLineNumber(), PrettyPrinter.getText(line),
                    addresses.contains(focus), addresses.stream().map(this::location).toList()));
            }
            break;
        }
        return excerpt;
    }

    private static Set<Address> lineAddresses(List<ClangToken> tokens) {
        var addresses = new TreeSet<Address>();
        for (var token : tokens) {
            var op = token.getPcodeOp();
            if (op != null) {
                addresses.add(op.getSeqnum().getTarget());
            }
            if (token.Parent() instanceof ClangStatement statement && statement.getPcodeOp() != null) {
                addresses.add(statement.getPcodeOp().getSeqnum().getTarget());
            }
        }
        return addresses;
    }

    private DataSlice dataSlice(DecompileResults result, Instruction instruction, int limit) throws Exception {
        var atFocus = new ArrayList<PcodeOp>();
        var candidates = result.getHighFunction().getPcodeOps(instruction.getAddress());
        while (candidates.hasNext()) {
            var op = candidates.next();
            if (op.getParent() != null) {
                atFocus.add(op);
            }
        }
        var flow = instruction.getFlowType();
        var focused = atFocus.stream().filter(op -> switch (op.getOpcode()) {
            case PcodeOp.CALL, PcodeOp.CALLIND -> flow.isCall();
            case PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND -> flow.isJump();
            case PcodeOp.LOAD, PcodeOp.STORE -> !flow.isCall() && !flow.isJump();
            default -> false;
        }).toList();
        if (focused.isEmpty()) {
            focused = atFocus;
        }
        var roots = new HashSet<>(focused);
        var seen = new HashSet<>(focused);
        var pending = new ArrayDeque<>(focused);
        var operations = new ArrayList<SliceOperation>();
        var language = currentProgram.getLanguage();
        while (!pending.isEmpty() && operations.size() < limit) {
            monitor.checkCancelled();
            var op = pending.removeFirst();
            var inputs = new ArrayList<SliceInput>();
            for (int index = 0; index < op.getNumInputs(); index++) {
                var input = op.getInput(index);
                var definition = input.getDef();
                if (definition != null && seen.add(definition)) {
                    pending.addLast(definition);
                }
                inputs.add(new SliceInput(inputStorage(op.getOpcode(), index, input), input.getSize(),
                    definition == null ? null : definition.getSeqnum().getTime()));
            }
            var output = op.getOutput();
            operations.add(new SliceOperation(op.getSeqnum().getTime(), location(op.getSeqnum().getTarget()),
                op.getMnemonic(), roots.contains(op), inputs,
                output == null ? null : new SliceValue(output.toString(language), output.getSize())));
        }
        return new DataSlice(operations, !pending.isEmpty());
    }

    private String inputStorage(int opcode, int index, Varnode input) {
        if (index == 0 && opcode == PcodeOp.SEGMENTOP) {
            // Ghidra emits a native pointer identifying the address space for this operator.
            return "segment address space";
        }
        if (index == 0 && (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE)) {
            var space = currentProgram.getAddressFactory().getAddressSpace((int) input.getOffset());
            if (space != null) {
                return space.getName();
            }
        }
        return input.toString(currentProgram.getLanguage());
    }

    private DecompileResults decompile(Function function) throws Exception {
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
        if (!result.decompileCompleted() || result.getCCodeMarkup() == null) {
            throw new IllegalArgumentException(Objects.requireNonNullElse(result.getErrorMessage(),
                "decompiler returned no C markup"));
        }
        return result;
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
