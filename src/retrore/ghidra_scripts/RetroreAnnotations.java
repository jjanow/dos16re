// Export and replay address-based Ghidra annotations.
import com.google.gson.FieldNamingPolicy;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class RetroreAnnotations extends GhidraScript {
    private record Item(String unit, long offset, String kind, String value, String commentType,
            String callingConvention) {}
    private static final Set<String> KINDS = Set.of("label", "function_name", "comment", "entry_point", "signature");

    private String language() {
        return currentProgram.getLanguageID().toString();
    }

    @Override
    public void run() throws Exception {
        var args = getScriptArgs();
        Map<String, Object> report;
        try {
            report = args[0].equals("export") ? exportAnnotations() :
                replay(JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonObject(),
                    args[0].equals("apply"));
        } catch (Exception error) {
            report = Map.of("error", Map.of("code", "invalid_request",
                "message", Objects.requireNonNullElse(error.getMessage(), error.getClass().getSimpleName())));
        }
        var gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create();
        Files.writeString(Path.of(args[args.length - 1]), gson.toJson(report));
    }

    private Item item(Address address, String kind, String value, String detail) {
        var block = currentProgram.getMemory().getBlock(address);
        return block == null ? null : new Item(block.getName(), address.subtract(block.getStart()), kind, value,
            kind.equals("comment") ? detail : null, kind.equals("signature") ? detail : null);
    }

    private Map<String, Object> exportAnnotations() throws Exception {
        var symbols = currentProgram.getSymbolTable();
        var listing = currentProgram.getListing();
        var items = new ArrayList<Item>();
        for (var symbol : symbols.getAllSymbols(false)) {
            monitor.checkCancelled();
            if (symbol.getSource() != SourceType.USER_DEFINED) {
                continue;
            }
            String kind;
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                kind = "function_name";
            } else if (symbol.getSymbolType() == SymbolType.LABEL && symbol.getParentNamespace().isGlobal()) {
                kind = "label";
            } else {
                continue;
            }
            var item = item(symbol.getAddress(), kind, symbol.getName(), null);
            if (item != null) {
                items.add(item);
            }
        }
        for (var function : listing.getFunctions(true)) {
            monitor.checkCancelled();
            if (function.getSignatureSource() != SourceType.USER_DEFINED || function.hasCustomVariableStorage()) {
                continue;
            }
            var item = item(function.getEntryPoint(), "signature", function.getSignature().getPrototypeString(false),
                function.getCallingConventionName());
            if (item != null) {
                items.add(item);
            }
        }
        var memory = currentProgram.getMemory();
        var addresses = listing.getCommentAddressIterator(memory, true);
        while (addresses.hasNext()) {
            monitor.checkCancelled();
            var address = addresses.next();
            for (var type : CommentType.values()) {
                String value = listing.getComment(type, address);
                if (value != null) {
                    items.add(item(address, "comment", value, type.name()));
                }
            }
        }
        for (var address : symbols.getExternalEntryPointIterator()) {
            monitor.checkCancelled();
            var item = item(address, "entry_point", null, null);
            if (item != null) {
                items.add(item);
            }
        }
        items.sort(Comparator.comparing(Item::unit).thenComparingLong(Item::offset).thenComparing(Item::kind)
            .thenComparing(Item::commentType, Comparator.nullsFirst(Comparator.naturalOrder()))
            .thenComparing(Item::value, Comparator.nullsFirst(Comparator.naturalOrder())));
        var report = new LinkedHashMap<String, Object>();
        report.put("version", 1);
        report.put("language", language());
        report.put("sha256", currentProgram.getExecutableSHA256());
        report.put("annotations", items);
        return report;
    }

    private record Change(Item item, Address address, String status, String reason) {}

    private Map<String, Object> replay(JsonObject document, boolean apply) throws Exception {
        if (!language().equals(string(document, "language"))) {
            throw new IllegalArgumentException("annotation language differs from the Ghidra program");
        }
        String hash = document.has("sha256") && !document.get("sha256").isJsonNull() ? string(document, "sha256") : null;
        if (hash != null && !hash.isEmpty() && !hash.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalArgumentException("annotation executable SHA-256 differs from the Ghidra program");
        }
        var changes = new ArrayList<Change>();
        var keys = new HashSet<Item>();
        int conflicts = 0;
        int additions = 0;
        for (var element : document.getAsJsonArray("annotations")) {
            monitor.checkCancelled();
            var row = element.getAsJsonObject();
            var kind = string(row, "kind");
            if (!KINDS.contains(kind)) {
                throw new IllegalArgumentException("unsupported annotation kind " + kind);
            }
            var offsetValue = row.get("offset");
            if (offsetValue == null || !offsetValue.isJsonPrimitive() || !offsetValue.getAsJsonPrimitive().isNumber()) {
                throw new IllegalArgumentException("annotation offset must be an integer");
            }
            var offset = offsetValue.getAsBigDecimal().longValueExact();
            var item = new Item(string(row, "unit"), offset, kind,
                kind.equals("entry_point") ? null : string(row, "value"),
                kind.equals("comment") ? string(row, "comment_type") : null,
                kind.equals("signature") ? string(row, "calling_convention") : null);
            var key = new Item(item.unit(), item.offset(), item.kind(),
                kind.equals("label") ? item.value() : null, item.commentType(), null);
            if (!keys.add(key)) {
                throw new IllegalArgumentException("duplicate annotation at " + item.unit() + "+" + item.offset());
            }
            var change = check(item);
            if (change.status().equals("conflict")) {
                conflicts++;
            } else if (change.status().equals("add")) {
                additions++;
            }
            changes.add(change);
        }
        boolean applied = apply && conflicts == 0;
        if (applied && additions != 0) {
            int transaction = currentProgram.startTransaction("Apply retrore annotations");
            boolean commit = false;
            try {
                for (var change : changes) {
                    monitor.checkCancelled();
                    if (change.status().equals("add")) {
                        add(change.item(), change.address());
                    }
                }
                commit = true;
            } finally {
                currentProgram.endTransaction(transaction, commit);
            }
        }
        var report = new LinkedHashMap<String, Object>();
        report.put("version", 1);
        report.put("applied", applied);
        report.put("additions", additions);
        report.put("conflicts", conflicts);
        report.put("unchanged", changes.size() - conflicts - additions);
        report.put("changes", changes.stream().map(change -> Map.of(
            "annotation", change.item(), "status", change.status(), "reason", change.reason())).toList());
        return report;
    }

    private Change check(Item item) throws Exception {
        var block = currentProgram.getMemory().getBlock(item.unit());
        if (block == null || item.offset() < 0 || item.offset() >= block.getSize()) {
            return new Change(item, null, "conflict", "unit or offset is missing");
        }
        Address address = block.getStart().addNoWrap(item.offset());
        var listing = currentProgram.getListing();
        var symbols = currentProgram.getSymbolTable();
        if (item.kind().equals("label") || item.kind().equals("function_name")) {
            SymbolUtilities.validateName(item.value());
        }
        if (item.kind().equals("function_name")) {
            var function = listing.getFunctionAt(address);
            if (function == null) {
                return new Change(item, address, "conflict", "no function starts at this address");
            }
            if (item.value().equals(function.getName()) && function.getSymbol().getSource() == SourceType.USER_DEFINED) {
                return new Change(item, address, "unchanged", "");
            }
            if (function.getSymbol().getSource() == SourceType.USER_DEFINED) {
                return new Change(item, address, "conflict", "a manual function name already exists");
            }
        } else if (item.kind().equals("label")) {
            for (var symbol : symbols.getSymbols(address)) {
                if (symbol.getSymbolType() == SymbolType.LABEL && symbol.getParentNamespace().isGlobal() &&
                        symbol.getName().equals(item.value())) {
                    return new Change(item, address, "unchanged", "");
                }
            }
        } else if (item.kind().equals("comment")) {
            String previous = listing.getComment(CommentType.valueOf(item.commentType()), address);
            if (item.value().equals(previous)) {
                return new Change(item, address, "unchanged", "");
            }
            if (previous != null) {
                return new Change(item, address, "conflict", "a different comment already exists");
            }
        } else if (item.kind().equals("entry_point")) {
            if (symbols.isExternalEntryPoint(address)) {
                return new Change(item, address, "unchanged", "");
            }
        } else if (item.kind().equals("signature")) {
            var function = listing.getFunctionAt(address);
            if (function == null) {
                return new Change(item, address, "conflict", "no function starts at this address");
            }
            if (function.hasCustomVariableStorage()) {
                return new Change(item, address, "conflict", "the function has custom variable storage");
            }
            var signature = parseSignature(item, address);
            if (signature.isEquivalentSignature(function.getSignature())
                    && item.callingConvention().equals(function.getCallingConventionName())
                    && function.getSignatureSource() == SourceType.USER_DEFINED) {
                return new Change(item, address, "unchanged", "");
            }
            if (function.getSignatureSource() == SourceType.USER_DEFINED) {
                return new Change(item, address, "conflict", "a manual function signature already exists");
            }
        }
        return new Change(item, address, "add", "");
    }

    private ghidra.program.model.data.FunctionDefinitionDataType parseSignature(Item item, Address address)
            throws Exception {
        var function = currentProgram.getListing().getFunctionAt(address);
        var signature = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null)
            .parse(function.getSignature(), item.value());
        signature.setCallingConvention(item.callingConvention());
        // Function names are replayed by a separate annotation.
        signature.setName(function.getName());
        return signature;
    }

    private void add(Item item, Address address) throws Exception {
        var listing = currentProgram.getListing();
        var symbols = currentProgram.getSymbolTable();
        switch (item.kind()) {
            case "function_name" -> listing.getFunctionAt(address).setName(item.value(), SourceType.USER_DEFINED);
            case "label" -> symbols.createLabel(address, item.value(), SourceType.USER_DEFINED);
            case "comment" -> listing.setComment(address, CommentType.valueOf(item.commentType()), item.value());
            case "entry_point" -> symbols.addExternalEntryPoint(address);
            case "signature" -> {
                var command = new ApplyFunctionSignatureCmd(address, parseSignature(item, address),
                    SourceType.USER_DEFINED, false, FunctionRenameOption.NO_CHANGE);
                if (!command.applyTo(currentProgram, monitor)) {
                    throw new IllegalArgumentException(command.getStatusMsg());
                }
            }
            default -> throw new IllegalArgumentException("unsupported annotation kind " + item.kind());
        }
    }

    private static String string(JsonObject object, String field) {
        var value = object.get(field);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("expected a string for annotation " + field);
        }
        return value.getAsString();
    }
}
