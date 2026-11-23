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
import java.util.Arrays;
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
    private record MappedLine(int line, String text, List<BodyRange> instructions) {}
    private record OperandReference(int operand, String type, String source, Location target) {}
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
            case "annotations" -> annotationQuery(input.getAsJsonObject());
            case "fingerprints" -> fingerprints();
            default -> throw new IllegalArgumentException("unknown query mode " + mode);
        };
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> fingerprints() throws Exception {
        Path output = Files.createTempFile("retrore-fingerprints", ".json");
        try {
            runScript("RetroreFingerprints.java", new String[] {output.toString()});
            return (Map<String, Object>) integral(GSON.fromJson(Files.readString(output), Map.class));
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> annotationQuery(JsonObject request) throws Exception {
        String mode = request.get("mode").getAsString();
        Path input = null;
        Path output = Files.createTempFile("retrore-annotations", ".json");
        try {
            String[] arguments = {mode, output.toString()};
            if (mode.equals("preview")) {
                input = Files.createTempFile("retrore-annotations-input", ".json");
                Files.writeString(input, GSON.toJson(request.get("document")));
                arguments = new String[] {mode, input.toString(), output.toString()};
            } else if (!mode.equals("export")) {
                throw new IllegalArgumentException("unknown read-only annotation mode " + mode);
            }
            runScript("RetroreAnnotations.java", arguments);
            return (Map<String, Object>) integral(GSON.fromJson(Files.readString(output), Map.class));
        } finally {
            Files.deleteIfExists(output);
            if (input != null) {
                Files.deleteIfExists(input);
            }
        }
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
        if (trace.has("classify_gaps") && trace.get("classify_gaps").getAsBoolean()) {
            return Map.of("functions", functions, "missed", misses, "observed_gaps", traceGaps(misses));
        }
        return Map.of("functions", functions, "missed", misses);
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> traceGaps(List<JsonObject> misses) throws Exception {
        var observed = new TreeMap<Long, JsonObject>();
        for (var hit : misses) {
            if (hit.get("reason").getAsString().equals("undefined")) {
                observed.put(hit.get("linear").getAsLong(), hit);
            }
        }
        var result = new ArrayList<Map<String, Object>>();
        if (observed.isEmpty()) {
            return result;
        }
        var report = classifiedGaps(null, new Options(new JsonObject()));
        for (var gap : (List<Map<String, Object>>) report.get("ranges")) {
            monitor.checkCancelled();
            long start = ((Number) gap.get("linear")).longValue();
            long size = ((Number) gap.get("size")).longValue();
            var hits = observed.subMap(start, true, start + size, false).values();
            if (hits.isEmpty()) {
                continue;
            }
            long count = 0;
            var examples = new ArrayList<JsonObject>();
            for (var hit : hits) {
                count += hit.get("count").getAsLong();
                if (examples.size() < 4) {
                    examples.add(hit);
                }
            }
            gap.put("trace_evidence", Map.of("kind", "executed", "hits", count,
                "addresses", hits.size(), "examples", examples));
            result.add(gap);
        }
        return result;
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
            case "layout" -> layout(request, options);
            case "indirect" -> indirect(request, options);
            case "disasm" -> disassembly(request, options);
            case "project-summary" -> projectSummary(options);
            default -> addressQuery(command, request, options);
        };
    }

    private Map<String, Object> disassembly(JsonObject request, Options options) throws Exception {
        Address start = resolve(request.get("address").getAsString());
        var memory = currentProgram.getMemory();
        var block = memory.getBlock(start);
        if (block == null) {
            throw new IllegalArgumentException("address outside the loaded image: " + start);
        }
        int length = options.limit();
        long remaining = block.getEnd().subtract(start) + 1;
        int size = (int) Math.min(remaining, length);
        var report = new LinkedHashMap<String, Object>();
        if (options.includes("start")) {
            report.put("start", location(start));
        }
        if (options.includes("size")) {
            report.put("size", size);
        }
        if (options.includes("next_address")) {
            report.put("next_address", size < remaining ? location(start.addNoWrap(size)) : null);
        }
        if (options.includes("rows")) {
            var listing = currentProgram.getListing();
            var rows = new ArrayList<Map<String, Object>>();
            for (int position = 0; position < size;) {
                monitor.checkCancelled();
                Address address = start.addNoWrap(position);
                var instruction = listing.getInstructionContaining(address);
                var data = instruction == null ? listing.getDefinedDataContaining(address) : null;
                var unit = instruction != null ? instruction : data;
                int count = unit == null ? (block.isInitialized() ? 1 : size - position) :
                    (int) Math.min(unit.getMaxAddress().subtract(address) + 1, size - position);
                var row = new LinkedHashMap<String, Object>();
                row.put("address", location(address));
                row.put("unit_offset", address.subtract(block.getStart()));
                row.put("size", count);
                row.put("kind", instruction != null ? "instruction" : data != null ? "data" :
                    block.isInitialized() ? "undefined" : "uninitialized");
                if (block.isInitialized()) {
                    byte[] bytes = new byte[count];
                    int read = memory.getBytes(address, bytes);
                    row.put("bytes", HexFormat.of().formatHex(bytes, 0, read));
                    addFileEvidence(block, address, read, row);
                }
                if (unit != null) {
                    boolean partial = !unit.getMinAddress().equals(address) || unit.getLength() != count;
                    row.put("partial", partial);
                    if (partial) {
                        row.put("start", location(unit.getMinAddress()));
                    }
                }
                if (instruction != null) {
                    row.put("instruction", instruction.toString());
                    var references = Arrays.stream(instruction.getReferencesFrom()).sorted(REFERENCE_ORDER)
                        .map(reference -> new OperandReference(reference.getOperandIndex(),
                            reference.getReferenceType().toString(), reference.getSource().toString(),
                            location(reference.getToAddress()))).toList();
                    row.put("references", references);
                row.put("unresolved_flow", indirectSite(instruction) && instruction.getFlows().length == 0);
                } else if (data != null) {
                    row.put("type", data.getDataType().getDisplayName());
                }
                rows.add(row);
                position += count;
            }
            report.put("rows", rows);
        }
        return report;
    }

    private void addFileEvidence(MemoryBlock block, Address address, int size, Map<String, Object> row)
            throws Exception {
        if (size == 0) {
            return;
        }
        Address last = address.addNoWrap(size - 1);
        for (var source : block.getSourceInfos()) {
            if (address.compareTo(source.getMinAddress()) < 0 || last.compareTo(source.getMaxAddress()) > 0) {
                continue;
            }
            long offset = source.getFileBytesOffset(address);
            if (offset < 0 || source.getFileBytesOffset(last) != offset + size - 1) {
                continue;
            }
            var file = source.getFileBytes().orElse(null);
            if (file == null) {
                continue;
            }
            byte[] original = new byte[size];
            int read = file.getOriginalBytes(offset, original);
            row.put("ghidra_file", Map.of("name", file.getFilename(), "offset", file.getFileOffset() + offset,
                "original", HexFormat.of().formatHex(original, 0, read)));
            return;
        }
    }

    private Map<String, Object> projectSummary(Options options) throws Exception {
        var report = new LinkedHashMap<String, Object>();
        if (options.includes("program")) {
            report.put("program", currentProgram.getName());
        }
        if (options.includes("language")) {
            report.put("language", currentProgram.getLanguageID().toString());
        }
        if (options.includes("compiler")) {
            report.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        }
        if (options.includes("function_count")) {
            report.put("function_count", currentProgram.getFunctionManager().getFunctionCount());
        }
        if (options.includes("units")) {
            var pages = new LinkedHashMap<String, Page>();
            var blocks = Arrays.asList(currentProgram.getMemory().getBlocks());
            var units = new ArrayList<Map<String, Object>>();
            for (var block : page("units", blocks, options, pages)) {
                monitor.checkCancelled();
                units.add(Map.of("name", block.getName(), "start", location(block.getStart()),
                    "size", block.getSize(), "initialized", block.isInitialized(), "execute", block.isExecute(),
                    "overlay", block.isOverlay()));
            }
            report.put("units", units);
            report.put("pagination", pages);
        }
        return report;
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
                return describeDecompilation(function, address, request, options);
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
        if (options.includes("segment_losses") && address.getAddressSpace() instanceof SegmentedAddressSpace) {
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
        if (request.has("classify") && request.get("classify").getAsBoolean()) {
            return classifiedGaps(filter, options);
        }
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

    /** Gaps with a likely class and evidence, scored by RetroreGaps.java in this session. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> classifiedGaps(MemoryBlock filter, Options options) throws Exception {
        var file = Files.createTempFile("retrore-gaps", ".json");
        Map<String, Object> scored;
        try {
            runScript("RetroreGaps.java", new String[] {file.toString(), "classify",
                filter == null ? "" : filter.getName()});
            scored = GSON.fromJson(Files.readString(file), Map.class);
        } finally {
            Files.deleteIfExists(file);
        }
        var ranges = new ArrayList<Map<String, Object>>();
        for (var range : (List<Map<String, Object>>) scored.get("ranges")) {
            ranges.add((Map<String, Object>) integral(range));
        }
        var pages = new LinkedHashMap<String, Page>();
        var report = new LinkedHashMap<String, Object>();
        report.put("program", currentProgram.getName());
        report.put("undefined_bytes", ((Number) scored.get("undefined_bytes")).longValue());
        report.put("ranges", select(page("ranges", ranges, options, pages), options));
        report.put("pagination", pages);
        return report;
    }

    /** Gson reads every JSON number as a double; the gap report only holds integers. */
    @SuppressWarnings("unchecked")
    private static Object integral(Object value) {
        if (value instanceof Double number) {
            return number.longValue();
        }
        if (value instanceof Map<?, ?> map) {
            ((Map<String, Object>) map).replaceAll((key, item) -> integral(item));
        } else if (value instanceof List<?> list) {
            ((List<Object>) list).replaceAll(RetroreQuery::integral);
        }
        return value;
    }

    // ---- indirect: computed calls and jumps, with candidates recorded by RetroreIndirect.java ----

    private Map<String, Object> indirect(JsonObject request, Options options) throws Exception {
        var filter = unit(request);
        String status = request.has("status") ? request.get("status").getAsString() : null;
        var listing = currentProgram.getListing();
        var store = currentProgram.getUsrPropertyManager().getStringPropertyMap("retrore.indirect");
        var sites = new ArrayList<Instruction>();
        if (request.has("at")) {
            var instruction = listing.getInstructionContaining(resolve(request.get("at").getAsString()));
            if (instruction == null || !indirectSite(instruction)) {
                throw new QueryError("address_not_found", "no indirect call or jump at " + request.get("at").getAsString());
            }
            sites.add(instruction);
        } else {
            for (var block : currentProgram.getMemory().getBlocks()) {
                if ((filter != null && !block.equals(filter)) || !block.isExecute()) {
                    continue;
                }
                for (var instruction : listing.getInstructions(span(block), true)) {
                    monitor.checkCancelled();
                    if (indirectSite(instruction)) {
                        sites.add(instruction);
                    }
                }
            }
        }
        var rows = new ArrayList<Map<String, Object>>();
        var counts = new LinkedHashMap<String, Integer>();
        for (String name : List.of("resolved", "candidate", "unresolved")) {
            counts.put(name, 0);
        }
        boolean compact = options.compact();
        for (var instruction : sites) {
            var record = new LinkedHashMap<String, Object>();
            record.put("address", addressRecord(instruction.getAddress(), compact));
            record.put("function", routine(getFunctionContaining(instruction.getAddress()), compact));
            record.put("instruction", instruction.toString());
            record.put("kind", instruction.getFlowType().isCall() ? "call" : "jump");
            var flows = instruction.getFlows();
            String json = store == null ? null : store.getString(instruction.getAddress());
            JsonObject stored = json == null ? null : JsonParser.parseString(json).getAsJsonObject();
            boolean candidates = stored != null && stored.has("candidates") && stored.getAsJsonArray("candidates").size() > 0;
            String state = flows.length > 0 ? "resolved" : candidates ? "candidate" : "unresolved";
            counts.merge(state, 1, Integer::sum);
            if (status != null && !status.equals(state)) {
                continue;
            }
            record.put("status", state);
            var targets = new ArrayList<Object>();
            for (var flow : flows) {
                targets.add(addressRecord(flow, compact));
            }
            record.put("targets", targets);
            record.put("table", stored != null && stored.has("table")
                ? addressRecord(linearAddress(stored.get("table").getAsLong()), compact) : null);
            Map<String, Object> segment = null;
            if (stored != null && stored.has("segment")) {
                var value = stored.getAsJsonObject("segment");
                segment = new LinkedHashMap<>();
                segment.put("register", value.get("register").getAsString());
                segment.put("value", value.has("value") && !value.get("value").isJsonNull()
                    ? value.get("value").getAsInt() : null);
            }
            record.put("segment", segment);
            var entries = new ArrayList<Map<String, Object>>();
            if (candidates) {
                for (var item : stored.getAsJsonArray("candidates")) {
                    var entry = item.getAsJsonObject();
                    var target = linearAddress(entry.get("target").getAsLong());
                    var row = new LinkedHashMap<String, Object>();
                    row.put("slot", addressRecord(linearAddress(entry.get("slot").getAsLong()), compact));
                    row.put("target", addressRecord(target, compact));
                    row.put("function", routine(getFunctionAt(target), compact));
                    var evidence = new ArrayList<String>();
                    entry.getAsJsonArray("evidence").forEach(element -> evidence.add(element.getAsString()));
                    row.put("evidence", evidence);
                    row.put("writer", entry.has("writer")
                        ? addressRecord(linearAddress(entry.get("writer").getAsLong()), compact) : null);
                    entries.add(row);
                }
            }
            record.put("candidates", entries);
            record.put("stop", stored != null && stored.has("stop") ? stored.get("stop").getAsString() : null);
            String reason = null;
            if (state.equals("unresolved")) {
                reason = stored == null ? "not_analyzed"
                    : stored.has("reason") ? stored.get("reason").getAsString() : "no_valid_entries";
            }
            record.put("reason", reason);
            if ("segment_unknown".equals(reason) && segment != null) {
                Object loss = segmentLosses(instruction.getAddress(), compact).get(segment.get("register"));
                if (loss != null) {
                    record.put("segment_loss", loss);
                }
            }
            rows.add(record);
        }
        var pages = new LinkedHashMap<String, Page>();
        var report = new LinkedHashMap<String, Object>();
        report.put("program", currentProgram.getName());
        report.put("counts", counts);
        report.put("sites", select(page("sites", rows, options, pages), options));
        report.put("pagination", pages);
        return report;
    }

    private static boolean indirectSite(Instruction instruction) {
        var flow = instruction.getFlowType();
        String mnemonic = instruction.getMnemonicString().toUpperCase(Locale.ROOT);
        // Software interrupts and traps are computed calls through vectors, not program tables.
        return flow.isComputed() && (flow.isCall() || flow.isJump()) &&
            !mnemonic.startsWith("INT") && !mnemonic.startsWith("TRAP");
    }

    private Address linearAddress(long linear) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(linear);
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

    private Map<String, Object> describeDecompilation(Function function, Address address, JsonObject request,
            Options options)
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
        boolean map = request.has("map_lines");
        boolean full = targeted || map ? options.fields().contains("decompilation") : options.includes("decompilation");
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
        if (full || excerpt || slice || map && (options.includes("line_map") || options.includes("line_pagination"))) {
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
            if (map) {
                int offset = request.has("line_offset") ? request.get("line_offset").getAsInt() : 0;
                mapDecompiledLines(result, offset, request.get("map_lines").getAsInt(), options, report);
            }
        }
        return report;
    }

    private void mapDecompiledLines(DecompileResults result, int offset, int limit, Options options,
            Map<String, Object> report) throws Exception {
        var lines = new PrettyPrinter(result.getFunction(), result.getCCodeMarkup(), null).getLines();
        int start = Math.min(offset, lines.size());
        int end = start + Math.min(limit, lines.size() - start);
        if (options.includes("line_pagination")) {
            report.put("line_pagination", new Page(offset, lines.size(), end - start, end < lines.size() ? end : null));
        }
        if (!options.includes("line_map")) {
            return;
        }
        var mapped = new ArrayList<MappedLine>();
        var listing = currentProgram.getListing();
        for (var line : lines.subList(start, end)) {
            monitor.checkCancelled();
            var ranges = new ArrayList<BodyRange>();
            Address first = null;
            Address last = null;
            for (Address address : lineAddresses(line.getAllTokens())) {
                var instruction = listing.getInstructionAt(address);
                if (instruction == null || !result.getFunction().getBody().contains(address)) {
                    continue;
                }
                if (last != null && (!address.getAddressSpace().equals(last.getAddressSpace()) ||
                        address.subtract(last) != 1)) {
                    ranges.add(new BodyRange(location(first), location(last)));
                    first = null;
                }
                if (first == null) {
                    first = address;
                }
                last = instruction.getMaxAddress();
            }
            if (last != null) {
                ranges.add(new BodyRange(location(first), location(last)));
            }
            mapped.add(new MappedLine(line.getLineNumber(), PrettyPrinter.getText(line), ranges));
        }
        report.put("line_map", mapped);
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

    // ---- layout: data layout recovery from access patterns ----------------------------------------------------
    //
    // For a global range, decompile every function that references it and evaluate the address of each LOAD
    // and STORE in high p-code as constant + sum(scale * variable). Scales come from INT_MULT, INT_LEFT, PTRADD,
    // and loop induction variables (a MULTIEQUAL of an initial value and itself plus a constant step). Accesses
    // whose constant falls in the range give field offsets and widths; scales give element strides; compares of
    // induction variables against constants give count bounds. Direct ram varnodes in the range are accesses with
    // constant offsets.

    private static final int LAYOUT_DEPTH = 48;
    private static final long LAYOUT_MAX_SIZE = 0x100000;

    private record LayoutIndex(String variable, long scale, List<String> evidence) {}
    private record LayoutAccess(Object address, String function, String instruction, String access, int width,
            long offset, List<LayoutIndex> index, String matchedBy) {}
    private record LayoutBound(String variable, String address, String compare, long constant, boolean incremented,
            Long initial, long step, Long count) {}
    private record LayoutStride(long stride, int accesses, List<String> evidence, int evidenceTotal) {}
    private record LayoutConflict(long offset, String kind, List<Integer> widths, Long overlaps,
            List<Object> instructions) {}

    /** An affine expression over named variables, with notes on where each scale came from. */
    private static final class Affine {
        long constant;
        boolean anchored;
        boolean segmentOffset;
        final Set<Address> anchors = new HashSet<>();
        final Map<String, Long> terms = new LinkedHashMap<>();
        final Map<String, List<String>> evidence = new LinkedHashMap<>();
        final Map<String, LoopInfo> loops = new LinkedHashMap<>();

        static Affine constant(long value) {
            var result = new Affine();
            result.constant = value;
            result.anchored = value != 0;
            return result;
        }

        static Affine variable(String name) {
            var result = new Affine();
            result.terms.put(name, 1L);
            return result;
        }

        Affine plus(Affine other, long sign) {
            var result = copy();
            result.constant += sign * other.constant;
            result.anchored |= other.anchored;
            result.segmentOffset |= other.segmentOffset;
            result.anchors.addAll(other.anchors);
            other.terms.forEach((name, scale) -> result.terms.merge(name, sign * scale, Long::sum));
            result.terms.values().removeIf(scale -> scale == 0);
            other.evidence.forEach((name, notes) -> result.evidence.computeIfAbsent(name, key -> new ArrayList<>())
                .addAll(notes));
            result.loops.putAll(other.loops);
            return result;
        }

        Affine times(long factor, String note) {
            var result = copy();
            result.constant *= factor;
            result.terms.replaceAll((name, scale) -> scale * factor);
            for (var name : result.terms.keySet()) {
                result.evidence.computeIfAbsent(name, key -> new ArrayList<>()).add(note);
            }
            return result;
        }

        Affine copy() {
            var result = new Affine();
            result.constant = constant;
            result.anchored = anchored;
            result.segmentOffset = segmentOffset;
            result.anchors.addAll(anchors);
            result.terms.putAll(terms);
            evidence.forEach((name, notes) -> result.evidence.put(name, new ArrayList<>(notes)));
            result.loops.putAll(loops);
            return result;
        }
    }

    private record LoopInfo(Long initial, long step, List<PcodeOp> values) {}

    private final class LayoutEvaluator {
        private final Map<Varnode, Affine> cache = new HashMap<>();

        Affine eval(Varnode varnode, int depth) {
            if (varnode == null) {
                return Affine.variable("unknown");
            }
            if (varnode.isConstant()) {
                return Affine.constant(signed(varnode.getOffset(), varnode.getSize()));
            }
            var cached = cache.get(varnode);
            if (cached != null) {
                return cached;
            }
            cache.put(varnode, leaf(varnode));  // Breaks cycles through MULTIEQUAL.
            var result = depth > LAYOUT_DEPTH ? leaf(varnode) : define(varnode, depth);
            cache.put(varnode, result);
            return result;
        }

        private Affine define(Varnode varnode, int depth) {
            var op = varnode.getDef();
            if (op == null) {
                return leaf(varnode);
            }
            String at = layoutWhere(op);
            var result = defineOp(varnode, op, at, depth);
            for (var input : op.getInputs()) {
                if (input.isConstant() && input.getOffset() != 0 && op.getOpcode() != PcodeOp.PTRADD) {
                    result = result.copy();
                    result.anchors.add(op.getSeqnum().getTarget());
                    break;
                }
            }
            return result;
        }

        private Affine defineOp(Varnode varnode, PcodeOp op, String at, int depth) {
            switch (op.getOpcode()) {
                case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT:
                    return eval(op.getInput(0), depth + 1);
                case PcodeOp.SUBPIECE:
                    return op.getInput(1).getOffset() == 0 ? eval(op.getInput(0), depth + 1) : leaf(varnode);
                case PcodeOp.INT_ADD, PcodeOp.PTRSUB:
                    return eval(op.getInput(0), depth + 1).plus(eval(op.getInput(1), depth + 1), 1);
                case PcodeOp.INT_SUB:
                    return eval(op.getInput(0), depth + 1).plus(eval(op.getInput(1), depth + 1), -1);
                case PcodeOp.PTRADD: {
                    long size = op.getInput(2).getOffset();
                    var index = eval(op.getInput(1), depth + 1)
                        .times(size, at + " PTRADD element size 0x" + Long.toHexString(size));
                    return eval(op.getInput(0), depth + 1).plus(index, 1);
                }
                case PcodeOp.INT_MULT: {
                    var left = op.getInput(0);
                    var right = op.getInput(1);
                    var constant = right.isConstant() ? right : left.isConstant() ? left : null;
                    if (constant == null) {
                        var a = eval(left, depth + 1);
                        var b = eval(right, depth + 1);
                        if (b.terms.isEmpty()) {
                            return a.times(b.constant, at + " INT_MULT by 0x" + Long.toHexString(b.constant));
                        }
                        if (a.terms.isEmpty()) {
                            return b.times(a.constant, at + " INT_MULT by 0x" + Long.toHexString(a.constant));
                        }
                        return leaf(varnode);
                    }
                    long factor = signed(constant.getOffset(), constant.getSize());
                    var other = constant == right ? left : right;
                    return eval(other, depth + 1).times(factor, at + " INT_MULT by 0x" + Long.toHexString(factor));
                }
                case PcodeOp.INT_LEFT: {
                    var amount = op.getInput(1);
                    if (!amount.isConstant() || amount.getOffset() > 31) {
                        return leaf(varnode);
                    }
                    long factor = 1L << amount.getOffset();
                    return eval(op.getInput(0), depth + 1)
                        .times(factor, at + " INT_LEFT by " + amount.getOffset() + " (x" + factor + ")");
                }
                case PcodeOp.SEGMENTOP: {
                    var offset = eval(op.getInput(2), depth + 1).copy();
                    offset.segmentOffset = true;
                    return offset;
                }
                case PcodeOp.MULTIEQUAL:
                    return induction(varnode, op, depth);
                default:
                    return leaf(varnode);
            }
        }

        // A loop variable: one initial value and every other input equal to the variable plus the same step.
        private Affine induction(Varnode varnode, PcodeOp phi, int depth) {
            Varnode initial = null;
            Long step = null;
            var values = new ArrayList<PcodeOp>();
            for (var input : phi.getInputs()) {
                var increment = increment(input, varnode);
                if (increment != null) {
                    if (step != null && !step.equals(increment)) {
                        return leaf(varnode);
                    }
                    step = increment;
                    values.add(input.getDef());
                } else if (initial == null) {
                    initial = input;
                } else if (!sameValue(initial, input)) {
                    return leaf(varnode);
                }
            }
            if (initial == null || step == null) {
                return leaf(varnode);
            }
            var start = eval(initial, depth + 1);
            // Decompilers reuse register names across functions and loops. The phi distinguishes them.
            String name = "loop " + variableName(varnode) + " [" + layoutWhere(phi) + ", "
                + phi.getSeqnum().getTime() + "]";
            var counter = Affine.variable(name);
            counter.evidence.computeIfAbsent(name, key -> new ArrayList<>()).add(String.format(
                "%s MULTIEQUAL steps by %s%s", layoutWhere(phi), step < 0 ? "-0x" : "0x", Long.toHexString(Math.abs(step))));
            counter = counter.times(step, layoutWhere(values.get(0)) + " increment by " + step);
            var result = start.plus(counter, 1);
            values.add(0, phi);
            result.loops.put(name, new LoopInfo(start.terms.isEmpty() ? start.constant : null, step, values));
            return result;
        }

        // The constant step if input is phi output plus or minus a constant.
        private Long increment(Varnode input, Varnode phiOutput) {
            var op = input.getDef();
            if (op == null) {
                return null;
            }
            int opcode = op.getOpcode();
            if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB) {
                for (int side = 0; side < 2; side++) {
                    var self = op.getInput(side);
                    var other = op.getInput(1 - side);
                    if (other.isConstant() && reaches(self, phiOutput) && (opcode == PcodeOp.INT_ADD || side == 0)) {
                        long value = signed(other.getOffset(), other.getSize());
                        return opcode == PcodeOp.INT_SUB ? -value : value;
                    }
                }
            } else if (opcode == PcodeOp.PTRADD && op.getInput(1).isConstant() && reaches(op.getInput(0), phiOutput)) {
                return signed(op.getInput(1).getOffset(), op.getInput(1).getSize()) * op.getInput(2).getOffset();
            } else if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
                return increment(op.getInput(0), phiOutput);
            }
            return null;
        }

        private boolean reaches(Varnode value, Varnode target) {
            for (int hops = 0; value != null && hops < 8; hops++) {
                if (value.equals(target)) {
                    return true;
                }
                var op = value.getDef();
                if (op == null || (op.getOpcode() != PcodeOp.COPY && op.getOpcode() != PcodeOp.CAST)) {
                    return false;
                }
                value = op.getInput(0);
            }
            return false;
        }

        private boolean sameValue(Varnode left, Varnode right) {
            if (left.isConstant() && right.isConstant()) {
                return left.getOffset() == right.getOffset();
            }
            return left.equals(right);
        }

        private Affine leaf(Varnode varnode) {
            var op = varnode.getDef();
            String name = variableName(varnode);
            if (op != null && op.getOpcode() == PcodeOp.LOAD) {
                name = "load@" + layoutWhere(op);
            }
            return Affine.variable(name);
        }
    }

    private String variableName(Varnode varnode) {
        var high = varnode.getHigh();
        var language = currentProgram.getLanguage();
        if (high != null) {
            var representative = high.getRepresentative();
            String storage = representative == null ? varnode.toString(language) : representative.toString(language);
            String name = high.getName();
            return name == null || name.equals("UNNAMED") ? storage : name + "@" + storage;
        }
        return varnode.toString(language);
    }

    private String layoutWhere(PcodeOp op) {
        var location = location(op.getSeqnum().getTarget());
        return Objects.requireNonNullElse(location.unitAddress(), location.address());
    }

    private static long signed(long value, int size) {
        if (size >= 8) {
            return value;
        }
        long sign = 1L << (size * 8 - 1);
        long mask = (1L << (size * 8)) - 1;
        value &= mask;
        return (value & sign) != 0 ? value - (mask + 1) : value;
    }

    private Map<String, Object> layout(JsonObject request, Options options) throws Exception {
        boolean compact = options.compact();
        var start = resolve(request.get("address").getAsString());
        var symbols = currentProgram.getSymbolTable();
        String sizeSource;
        long size;
        boolean knownExtent = false;
        if (request.has("size")) {
            size = request.get("size").getAsLong();
            sizeSource = "given";
            knownExtent = true;
        } else {
            size = 0x100;
            sizeSource = "default";
            var data = currentProgram.getListing().getDataAt(start);
            if (data != null && data.isDefined() && data.getLength() > 1) {
                size = data.getLength();
                sizeSource = "defined data " + data.getDataType().getDisplayName();
                knownExtent = true;
            } else {
                for (var symbol : symbols.getSymbolIterator(start.addNoWrap(1), true)) {
                    monitor.checkCancelled();
                    if (symbol.getSource() == ghidra.program.model.symbol.SourceType.DEFAULT || symbol.isDynamic()) {
                        continue;
                    }
                    long distance = symbol.getAddress().subtract(start);
                    if (distance > 0 && distance <= LAYOUT_MAX_SIZE && symbol.getAddress().getAddressSpace()
                            .equals(start.getAddressSpace())) {
                        size = distance;
                        sizeSource = "next symbol " + symbol.getName();
                    }
                    break;
                }
            }
        }
        var block = currentProgram.getMemory().getBlock(start);
        if (block == null) {
            throw new IllegalArgumentException("address is not in a memory block");
        }
        size = Math.min(size, block.getEnd().subtract(start) + 1);
        var end = start.addNoWrap(size - 1);
        var range = new AddressSet(start, end);
        int maxFunctions = request.has("max_functions") ? request.get("max_functions").getAsInt() : 64;

        // Functions that reference the range, and which instructions do.
        var manager = currentProgram.getReferenceManager();
        var referencing = new TreeSet<Address>();
        var functions = new TreeMap<Address, Function>();
        for (Address target : manager.getReferenceDestinationIterator(range, true)) {
            monitor.checkCancelled();
            for (var reference : manager.getReferencesTo(target)) {
                referencing.add(reference.getFromAddress());
                var function = getFunctionContaining(reference.getFromAddress());
                if (function != null) {
                    functions.put(function.getEntryPoint(), function);
                }
            }
        }
        // Indexed operands such as [BX+0x200] get no reference; find their displacements and immediates instead.
        int referencingFunctions = functions.size();
        long low = start instanceof ghidra.program.model.address.SegmentedAddress segmentedStart
            ? segmentedStart.getSegmentOffset() : start.getOffset();
        for (var instruction : currentProgram.getListing().getInstructions(
                currentProgram.getMemory().getExecuteSet(), true)) {
            monitor.checkCancelled();
            var function = getFunctionContaining(instruction.getAddress());
            if (function == null || functions.containsKey(function.getEntryPoint())) {
                continue;
            }
            scan:
            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                for (var object : instruction.getOpObjects(operand)) {
                    if (object instanceof ghidra.program.model.scalar.Scalar scalar
                            && scalar.getUnsignedValue() >= low && scalar.getUnsignedValue() - low < size) {
                        functions.put(function.getEntryPoint(), function);
                        break scan;
                    }
                }
            }
        }
        var ordered = new ArrayList<>(functions.values());
        var prioritized = new ArrayList<Function>();
        for (var function : ordered) {
            if (referencing.stream().anyMatch(site -> function.getBody().contains(site))) {
                prioritized.add(function);
            }
        }
        ordered.removeAll(prioritized);
        prioritized.addAll(ordered);
        var scanned = prioritized.subList(0, Math.min(maxFunctions, prioritized.size()));
        var failed = new ArrayList<Map<String, Object>>();
        var accesses = new ArrayList<LayoutAccess>();
        var seen = new HashSet<String>();
        var loops = new LinkedHashMap<String, LoopInfo>();
        var listing = currentProgram.getListing();
        long segmentBase = start instanceof ghidra.program.model.address.SegmentedAddress segmented
            ? start.getOffset() - segmented.getSegmentOffset() : 0;
        for (var function : scanned) {
            monitor.checkCancelled();
            DecompileResults result;
            try {
                result = decompile(function);
            } catch (IllegalArgumentException error) {
                var failure = new LinkedHashMap<String, Object>();
                failure.put("function", function.getName());
                failure.put("message", error.getMessage());
                failed.add(failure);
                continue;
            }
            var evaluator = new LayoutEvaluator();
            var ops = result.getHighFunction().getPcodeOps();
            while (ops.hasNext()) {
                var op = ops.next();
                int opcode = op.getOpcode();
                var site = op.getSeqnum().getTarget();
                if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
                    var address = evaluator.eval(op.getInput(1), 0);
                    if (!address.anchored) {
                        continue;
                    }
                    long linear = address.segmentOffset ? segmentBase + (address.constant & 0xffff) : address.constant;
                    long offset = linear - start.getOffset();
                    if (offset < 0 || offset >= size) {
                        continue;
                    }
                    boolean referenced = referencing.contains(site)
                        || address.anchors.stream().anyMatch(referencing::contains);
                    boolean explained = address.terms.keySet().stream().allMatch(name -> name.startsWith("loop ")
                        || !address.evidence.getOrDefault(name, List.of()).isEmpty());
                    if (!referenced && !explained) {
                        continue;
                    }
                    int width = opcode == PcodeOp.LOAD ? op.getOutput().getSize() : op.getInput(2).getSize();
                    var index = new ArrayList<LayoutIndex>();
                    address.terms.forEach((name, scale) -> index.add(new LayoutIndex(name, scale,
                        List.copyOf(address.evidence.getOrDefault(name, List.of())))));
                    loops.putAll(address.loops);
                    addLayoutAccess(accesses, seen, site, function, opcode == PcodeOp.LOAD ? "read" : "write", width,
                        offset, index, referenced ? "reference" : "constant", compact);
                } else if (opcode != PcodeOp.MULTIEQUAL && opcode != PcodeOp.INDIRECT) {
                    var output = op.getOutput();
                    if (output != null && output.isAddress() && range.contains(output.getAddress())) {
                        addLayoutAccess(accesses, seen, site, function, "write", output.getSize(),
                            output.getAddress().subtract(start), List.of(), "direct", compact);
                    }
                    for (var input : op.getInputs()) {
                        if (input.isAddress() && range.contains(input.getAddress())) {
                            addLayoutAccess(accesses, seen, site, function, "read", input.getSize(),
                                input.getAddress().subtract(start), List.of(), "direct", compact);
                        }
                    }
                }
            }
        }
        accesses.sort(Comparator.comparingLong(LayoutAccess::offset).thenComparing(access -> access.address().toString()));

        // Stride candidates: scales of loop variables and of multiplied or shifted indexes.
        var votes = new TreeMap<Long, Set<String>>();
        var strideNotes = new TreeMap<Long, Set<String>>();
        for (var access : accesses) {
            for (var index : access.index()) {
                long scale = Math.abs(index.scale());
                if (scale == 0 || (scale == 1 && !index.variable().startsWith("loop "))) {
                    continue;
                }
                votes.computeIfAbsent(scale, key -> new TreeSet<>()).add(access.address().toString());
                for (var note : index.evidence()) {
                    if (!note.endsWith(" PTRADD element size 0x1")) {
                        strideNotes.computeIfAbsent(scale, key -> new TreeSet<>()).add(note);
                    }
                }
            }
        }
        var strides = new ArrayList<LayoutStride>();
        votes.forEach((stride, sites) -> {
            var notes = List.copyOf(strideNotes.getOrDefault(stride, Set.of()));
            strides.add(new LayoutStride(stride, sites.size(), notes.subList(0, Math.min(8, notes.size())),
                notes.size()));
        });
        strides.sort(Comparator.comparingInt(LayoutStride::accesses).reversed()
            .thenComparing(Comparator.comparingLong(LayoutStride::stride).reversed()));
        Long stride = request.has("stride") ? Long.valueOf(request.get("stride").getAsLong()) : null;
        String strideSource = stride == null ? null : "given";
        if (stride == null) {
            final long limit = size;
            var choice = strides.stream().filter(candidate -> candidate.stride() > 1 && candidate.stride() <= limit)
                .findFirst().or(() -> strides.stream().filter(candidate -> candidate.stride() <= limit).findFirst());
            if (choice.isPresent()) {
                stride = choice.get().stride();
                strideSource = "most accesses";
            }
        }

        // Fields per offset inside one element.
        var fields = new TreeMap<Long, Map<String, Object>>();
        var fieldWidths = new TreeMap<Long, TreeSet<Integer>>();
        var bulkWidths = new TreeMap<Long, TreeSet<Integer>>();
        var fieldSites = new TreeMap<Long, List<Object>>();
        for (var access : accesses) {
            long fieldOffset = stride == null ? access.offset() : Math.floorMod(access.offset(), stride);
            var field = fields.computeIfAbsent(fieldOffset, key -> {
                var record = new LinkedHashMap<String, Object>();
                record.put("offset", key);
                record.put("reads", 0);
                record.put("writes", 0);
                record.put("elements", new TreeSet<Long>());
                record.put("inner_strides", new TreeSet<Long>());
                record.put("bulk", 0);
                return record;
            });
            field.merge(access.access().equals("read") ? "reads" : "writes", 1, (a, b) -> (Integer) a + (Integer) b);
            if (stride != null) {
                ((TreeSet<Long>) field.get("elements")).add(Math.floorDiv(access.offset(), stride));
            }
            // Loops that step through an element in smaller units (block copies and clears) keep their widths
            // apart so they do not read as conflicting field widths.
            boolean bulk = false;
            for (var index : access.index()) {
                long scale = Math.abs(index.scale());
                if (scale > 0 && (stride == null || scale < stride) && (scale > 1 || index.variable().startsWith("loop "))) {
                    ((TreeSet<Long>) field.get("inner_strides")).add(scale);
                    bulk |= index.variable().startsWith("loop ");
                }
            }
            if (bulk) {
                field.merge("bulk", 1, (a, b) -> (Integer) a + (Integer) b);
            }
            (bulk ? bulkWidths : fieldWidths).computeIfAbsent(fieldOffset, key -> new TreeSet<>()).add(access.width());
            var sites = fieldSites.computeIfAbsent(fieldOffset, key -> new ArrayList<>());
            if (!sites.contains(access.address()) && sites.size() < 8) {
                sites.add(access.address());
            }
        }
        // Conflicts come from single accesses only; block loops report widths when nothing else does.
        var exactWidths = new TreeMap<>(fieldWidths);
        bulkWidths.forEach((offset, widths) -> fieldWidths.putIfAbsent(offset, widths));
        var conflicts = new ArrayList<LayoutConflict>();
        Long previous = null;
        for (var entry : fields.entrySet()) {
            long fieldOffset = entry.getKey();
            entry.getValue().put("widths", List.copyOf(fieldWidths.get(fieldOffset)));
            entry.getValue().put("instructions", fieldSites.get(fieldOffset));
            var widths = exactWidths.get(fieldOffset);
            if (widths == null) {
                continue;
            }
            if (widths.size() > 1) {
                conflicts.add(new LayoutConflict(fieldOffset, "widths", List.copyOf(widths), null,
                    fieldSites.get(fieldOffset)));
            }
            if (previous != null && previous + exactWidths.get(previous).last() > fieldOffset) {
                conflicts.add(new LayoutConflict(previous, "overlap", List.copyOf(exactWidths.get(previous)),
                    fieldOffset, fieldSites.get(previous)));
            }
            previous = fieldOffset;
        }

        // Count bounds from compares of the loop variables that step through elements.
        var bounds = new ArrayList<LayoutBound>();
        for (var loop : loops.entrySet()) {
            bounds.addAll(loopBounds(loop.getKey(), loop.getValue(), compact));
        }
        Long count = null;
        String countSource = null;
        if (stride != null) {
            for (var bound : bounds) {
                if (bound.count() != null && usesStride(bound, stride, accesses)
                        && (count == null || bound.count() > count)) {
                    count = bound.count();
                    countSource = String.format("%s %s %d%s at %s", bound.variable().substring(5), bound.compare(),
                        bound.constant(), bound.incremented() ? " after the increment" : "", bound.address());
                }
            }
            // A loop can touch only a prefix of a global. A known aligned extent gives a lower bound on
            // the count. A scan window or gap to a following symbol is weaker evidence.
            if (size % stride == 0 && (count == null || (knownExtent && count < size / stride))) {
                count = size / stride;
                countSource = "range size / stride";
            }
        }

        boolean writes = accesses.stream().anyMatch(access -> access.access().equals("write"));
        String text = initialText(start, size);
        String kind;
        if (accesses.isEmpty()) {
            kind = "unknown";
        } else if (stride != null && fields.size() == 1 && fields.containsKey(0L)
                && fieldWidths.get(0L).size() == 1 && fieldWidths.get(0L).first() == stride.intValue()) {
            kind = stride == 1 && text != null ? "string" : "array";
        } else if (stride != null) {
            kind = "record_array";
        } else {
            kind = fields.size() == 1 && text != null ? "string" : "record";
        }
        var layout = new LinkedHashMap<String, Object>();
        layout.put("kind", kind);
        layout.put("size_source", sizeSource);
        layout.put("element_size", stride);
        layout.put("element_size_source", strideSource);
        layout.put("count", count);
        layout.put("count_source", countSource);
        layout.put("read_only", !writes && block.isInitialized());
        layout.put("initial_text", text);
        layout.put("fields", new ArrayList<>(fields.values()));

        var report = new LinkedHashMap<String, Object>();
        var pages = new LinkedHashMap<String, Page>();
        if (options.includes("address")) {
            report.put("address", addressRecord(start, compact));
        }
        if (options.includes("size")) {
            report.put("size", size);
        }
        if (options.includes("functions")) {
            var scannedRecords = new ArrayList<Routine>();
            for (var function : scanned) {
                scannedRecords.add(routine(function, compact));
            }
            var summary = new LinkedHashMap<String, Object>();
            summary.put("referencing", referencingFunctions);
            summary.put("matching_operands", functions.size() - referencingFunctions);
            summary.put("scanned", scannedRecords);
            summary.put("failed", failed);
            summary.put("truncated", scanned.size() < prioritized.size());
            summary.put("omitted", prioritized.size() - scanned.size());
            report.put("functions", summary);
        }
        if (options.includes("accesses")) {
            report.put("accesses", page("accesses", accesses, options, pages));
        }
        if (options.includes("strides")) {
            report.put("strides", strides);
        }
        if (options.includes("bounds")) {
            report.put("bounds", bounds);
        }
        if (options.includes("layout")) {
            report.put("layout", layout);
        }
        if (options.includes("conflicts")) {
            report.put("conflicts", conflicts);
        }
        var extent = layoutExtent(start, block, size, stride, count);
        var existing = extent == null ? null : existingLayoutData(start, extent);
        if (options.includes("proposal")) {
            var proposal = layoutProposal(start, size, stride, count, fields, fieldWidths, request);
            proposal.put("existing_data", existing == null ? null : Map.of("count", existing.count(),
                "partial_overlap", existing.partialOverlap()));
            report.put("proposal", proposal);
        }
        if (request.has("apply") && request.get("apply").getAsBoolean()) {
            report.put("applied", applyLayout(start, extent, existing, size, stride, count, fields, fieldWidths,
                request));
        }
        if (!pages.isEmpty()) {
            report.put("pagination", pages);
        }
        return report;
    }

    private void addLayoutAccess(List<LayoutAccess> accesses, Set<String> seen, Address site, Function function,
            String access, int width, long offset, List<LayoutIndex> index, String matchedBy, boolean compact) {
        String key = site + "/" + access + "/" + width + "/" + offset + "/" + index;
        if (!seen.add(key)) {
            return;
        }
        var instruction = currentProgram.getListing().getInstructionAt(site);
        accesses.add(new LayoutAccess(addressRecord(site, compact), function.getName(),
            instruction == null ? null : instruction.toString(), access, width, offset, index, matchedBy));
    }

    // The element step a bound's loop variable takes in the accesses it indexes.
    private static boolean usesStride(LayoutBound bound, long stride, List<LayoutAccess> accesses) {
        return accesses.stream().flatMap(access -> access.index().stream()).anyMatch(index ->
            index.variable().equals(bound.variable()) && Math.abs(index.scale()) == stride);
    }

    private List<LayoutBound> loopBounds(String name, LoopInfo loop, boolean compact) {
        var bounds = new ArrayList<LayoutBound>();
        for (var value : loop.values()) {
            if (value == null || value.getOutput() == null) {
                continue;
            }
            var pending = new ArrayDeque<Varnode>(List.of(value.getOutput()));
            var visited = new HashSet<Varnode>();
            while (!pending.isEmpty()) {
                var varnode = pending.removeFirst();
                if (!visited.add(varnode) || visited.size() > 32) {
                    continue;
                }
                for (var it = varnode.getDescendants(); it.hasNext(); ) {
                    var use = it.next();
                    int opcode = use.getOpcode();
                    if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST || opcode == PcodeOp.INT_ZEXT
                            || opcode == PcodeOp.INT_SEXT) {
                        pending.add(use.getOutput());
                        continue;
                    }
                    if (opcode != PcodeOp.INT_LESS && opcode != PcodeOp.INT_SLESS && opcode != PcodeOp.INT_LESSEQUAL
                            && opcode != PcodeOp.INT_SLESSEQUAL && opcode != PcodeOp.INT_EQUAL
                            && opcode != PcodeOp.INT_NOTEQUAL) {
                        continue;
                    }
                    var left = use.getInput(0);
                    var right = use.getInput(1);
                    boolean variableLeft = left == varnode;
                    var other = variableLeft ? right : left;
                    if (!other.isConstant()) {
                        continue;
                    }
                    long constant = signed(other.getOffset(), other.getSize());
                    boolean next = value != loop.values().get(0);
                    String compare = (variableLeft ? "" : "constant ") + use.getMnemonic();
                    Long count = null;
                    if (loop.initial() != null && loop.step() != 0) {
                        long span = constant - loop.initial();
                        long step = loop.step();
                        if (variableLeft && (opcode == PcodeOp.INT_LESS || opcode == PcodeOp.INT_SLESS
                                || opcode == PcodeOp.INT_NOTEQUAL)) {
                            count = Math.floorDiv(span + step - 1, step);
                        } else if (variableLeft && (opcode == PcodeOp.INT_LESSEQUAL || opcode == PcodeOp.INT_SLESSEQUAL)) {
                            count = Math.floorDiv(span, step) + 1;
                        } else if (!variableLeft && (opcode == PcodeOp.INT_LESS || opcode == PcodeOp.INT_SLESS)) {
                            // constant < variable: the loop continues while the variable stays at or below it.
                            count = null;
                        }
                        if (count != null && count <= 0) {
                            count = null;
                        }
                    }
                    bounds.add(new LayoutBound(name, layoutWhere(use), compare,
                        constant, next, loop.initial(), loop.step(), count));
                }
            }
        }
        return bounds;
    }

    private String initialText(Address start, long size) {
        var memory = currentProgram.getMemory();
        var block = memory.getBlock(start);
        if (block == null || !block.isInitialized()) {
            return null;
        }
        var text = new StringBuilder();
        try {
            for (long index = 0; index < Math.min(size, 256); index++) {
                int value = memory.getByte(start.addNoWrap(index)) & 0xff;
                if (value == 0) {
                    break;
                }
                if (value < 0x20 || value > 0x7e) {
                    return null;
                }
                text.append((char) value);
            }
        } catch (Exception error) {
            return null;
        }
        return text.length() >= 4 ? text.toString() : null;
    }

    private static String layoutTypeName(int width) {
        return switch (width) {
            case 1 -> "byte";
            case 2 -> "word";
            case 4 -> "dword";
            case 8 -> "qword";
            default -> "undefined" + width;
        };
    }

    private static String layoutName(Address start, JsonObject request) {
        return request.has("name") ? request.get("name").getAsString()
            : "layout_" + start.toString().replace(':', '_');
    }

    // Fields that a structure can hold: the narrowest observed width at each offset, skipping overlaps.
    private static List<long[]> layoutMembers(long length, Map<Long, Map<String, Object>> fields,
            Map<Long, TreeSet<Integer>> widths) {
        var members = new ArrayList<long[]>();
        long next = 0;
        for (var offset : fields.keySet()) {
            int width = widths.get(offset).first();
            if (offset < next || offset + width > length) {
                continue;
            }
            members.add(new long[] {offset, width});
            next = offset + width;
        }
        return members;
    }

    private Map<String, Object> layoutProposal(Address start, long size, Long stride, Long count,
            Map<Long, Map<String, Object>> fields, Map<Long, TreeSet<Integer>> widths, JsonObject request) {
        String name = layoutName(start, request);
        long length = stride == null ? size : stride;
        var text = new StringBuilder("struct ").append(name).append(" {  /* 0x")
            .append(Long.toHexString(length)).append(" bytes */\n");
        long next = 0;
        for (var member : layoutMembers(length, fields, widths)) {
            if (member[0] > next) {
                text.append(String.format("    undefined1 pad_%04x[0x%x];%n", next, member[0] - next));
            }
            var field = fields.get(member[0]);
            text.append(String.format("    %s field_%04x;  /* %s reads, %s writes%s */%n",
                layoutTypeName((int) member[1]), member[0], field.get("reads"), field.get("writes"),
                widths.get(member[0]).size() > 1 ? ", widths " + widths.get(member[0]) : ""));
            next = member[0] + member[1];
        }
        if (next < length) {
            text.append(String.format("    undefined1 pad_%04x[0x%x];%n", next, length - next));
        }
        text.append("};\n");
        if (stride != null) {
            text.append(String.format("struct %s %s_array[%s];%n", name, name, count == null ? "" : count));
        }
        var proposal = new LinkedHashMap<String, Object>();
        proposal.put("name", name);
        proposal.put("length", length);
        proposal.put("count", stride == null ? null : count);
        proposal.put("c", text.toString());
        return proposal;
    }

    private static Address layoutExtent(Address start, MemoryBlock block, long size, Long stride, Long count)
            throws AddressOverflowException {
        long available = block.getEnd().subtract(start) + 1;
        if (stride == null) {
            return start.addNoWrap(size - 1);
        }
        if (count == null || count < 1 || count > Math.min(available, Integer.MAX_VALUE) / stride) {
            return null;
        }
        return start.addNoWrap(stride * count - 1);
    }

    private record ExistingLayoutData(int count, boolean partialOverlap) {}

    private ExistingLayoutData existingLayoutData(Address start, Address end) throws Exception {
        var listing = currentProgram.getListing();
        var atStart = listing.getDefinedDataContaining(start);
        boolean partial = atStart != null && atStart.getMinAddress().compareTo(start) < 0;
        int count = partial ? 1 : 0;
        for (var data : listing.getDefinedData(new AddressSet(start, end), true)) {
            monitor.checkCancelled();
            count++;
            partial |= data.getMaxAddress().compareTo(end) > 0;
        }
        return new ExistingLayoutData(count, partial);
    }

    private Map<String, Object> applyLayout(Address start, Address end, ExistingLayoutData existing,
            long size, Long stride, Long count,
            Map<Long, Map<String, Object>> fields, Map<Long, TreeSet<Integer>> widths, JsonObject request)
            throws Exception {
        if (fields.isEmpty()) {
            throw new IllegalArgumentException("no accesses to build a layout from");
        }
        if (stride != null && count == null) {
            throw new IllegalArgumentException("element count unknown; give size or stride so the count follows");
        }
        if (end == null) {
            throw new IllegalArgumentException("the proposed type does not fit in the memory block");
        }
        var listing = currentProgram.getListing();
        if (listing.getInstructionContaining(start) != null
                || listing.getInstructions(new AddressSet(start, end), true).hasNext()) {
            throw new IllegalArgumentException("the proposed type would cover instructions");
        }
        if (existing.partialOverlap()) {
            throw new IllegalArgumentException("the proposed type would partially cover existing defined data");
        }
        if (existing.count() > 0 && !(request.has("replace") && request.get("replace").getAsBoolean())) {
            throw new IllegalArgumentException("the proposed type would replace existing defined data; use --replace");
        }
        String name = layoutName(start, request);
        long length = stride == null ? size : stride;
        var types = currentProgram.getDataTypeManager();
        var structure = new ghidra.program.model.data.StructureDataType(
            new ghidra.program.model.data.CategoryPath("/retrore"), name, (int) length, types);
        for (var member : layoutMembers(length, fields, widths)) {
            var type = switch ((int) member[1]) {
                case 1 -> ghidra.program.model.data.ByteDataType.dataType;
                case 2 -> ghidra.program.model.data.WordDataType.dataType;
                case 4 -> ghidra.program.model.data.DWordDataType.dataType;
                case 8 -> ghidra.program.model.data.QWordDataType.dataType;
                default -> ghidra.program.model.data.Undefined.getUndefinedDataType((int) member[1]);
            };
            structure.replaceAtOffset((int) member[0], type, (int) member[1], String.format("field_%04x", member[0]),
                null);
        }
        int transaction = currentProgram.startTransaction("Apply retrore layout");
        boolean saved = false;
        try {
            var resolved = types.addDataType(structure, ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
            ghidra.program.model.data.DataType applied = resolved;
            if (stride != null) {
                applied = new ghidra.program.model.data.ArrayDataType(resolved, count.intValue(), (int) length, types);
            }
            if (existing.count() > 0) {
                listing.clearCodeUnits(start, end, false, monitor);
            }
            listing.createData(start, applied);
            saved = true;
            var result = new LinkedHashMap<String, Object>();
            result.put("data_type", applied.getDisplayName());
            result.put("path", resolved.getPathName());
            result.put("length", applied.getLength());
            return result;
        } finally {
            currentProgram.endTransaction(transaction, saved);
        }
    }
}
