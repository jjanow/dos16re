// Export and replay Ghidra annotations and their data types.
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class RetroreAnnotations extends GhidraScript {
    private record Item(String unit, long offset, String kind, String value, String commentType,
            String callingConvention, Prototype prototype) {}
    private record TypePath(String category, String name) {
        static TypePath of(DataType type) {
            return new TypePath(type.getCategoryPath().getPath(), type.getName());
        }

        DataType find(DataTypeManager manager) {
            return manager.getDataType(new DataTypePath(new CategoryPath(category), name));
        }
    }
    private record Argument(String name, TypePath type) {}
    private record Prototype(TypePath returnType, List<Argument> parameters, boolean varargs, boolean noreturn) {
        static Prototype of(FunctionSignature signature) {
            return new Prototype(TypePath.of(signature.getReturnType()),
                Arrays.stream(signature.getArguments()).map(param ->
                    new Argument(param.getName(), TypePath.of(param.getDataType()))).toList(),
                signature.hasVarArgs(), signature.hasNoReturn());
        }
    }
    private record TypeArchive(String format, List<TypePath> types, String archive) {}
    private record TypeChange(TypePath type, String status, String reason) {}

    private static final Set<String> KINDS = Set.of("label", "function_name", "comment", "entry_point", "signature");
    private static final String ARCHIVE_FORMAT = "ghidra-gdt";
    private static final DataTypeConflictHandler TYPE_HANDLER = DataTypeConflictHandler.DEFAULT_HANDLER;
    private static final Comparator<DataType> TYPE_ORDER = Comparator
        .comparing((DataType type) -> type.getCategoryPath().getPath()).thenComparing(DataType::getName);
    private static final Gson GSON = new GsonBuilder()
        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create();

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
        Files.writeString(Path.of(args[args.length - 1]), GSON.toJson(report));
    }

    private Item item(Address address, String kind, String value, String detail) {
        var block = currentProgram.getMemory().getBlock(address);
        return block == null ? null : new Item(block.getName(), address.subtract(block.getStart()), kind, value,
            kind.equals("comment") ? detail : null, kind.equals("signature") ? detail : null, null);
    }

    private Map<String, Object> exportAnnotations() throws Exception {
        var symbols = currentProgram.getSymbolTable();
        var listing = currentProgram.getListing();
        var items = new ArrayList<Item>();
        var types = new ArrayList<DataType>();
        var manager = currentProgram.getDataTypeManager();
        for (var type : namedDefinitions(manager)) {
            if (manager.getLocalSourceArchive().equals(type.getSourceArchive())) {
                types.add(type);
            }
        }
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
            var signature = function.getSignature();
            var item = item(function.getEntryPoint(), "signature", signature.getPrototypeString(false),
                function.getCallingConventionName());
            if (item != null) {
                var signatureTypes = new ArrayList<DataType>();
                signatureTypes.add(signature.getReturnType());
                for (var parameter : signature.getArguments()) {
                    signatureTypes.add(parameter.getDataType());
                }
                if (signatureTypes.stream().anyMatch(RetroreAnnotations::usesNamedDefinition)) {
                    types.addAll(signatureTypes);
                    item = new Item(item.unit(), item.offset(), item.kind(), item.value(), null,
                        item.callingConvention(), Prototype.of(signature));
                }
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
        report.put("version", types.isEmpty() ? 1 : 2);
        report.put("language", language());
        report.put("sha256", currentProgram.getExecutableSHA256());
        report.put("annotations", items);
        if (!types.isEmpty()) {
            report.put("data_types", exportTypes(types));
        }
        return report;
    }

    private static boolean isNamedDefinition(DataType type) {
        return type instanceof Composite || type instanceof Enum || type instanceof TypeDef ||
            type instanceof FunctionDefinition;
    }

    private static boolean usesNamedDefinition(DataType type) {
        if (type instanceof Pointer pointer) {
            return usesNamedDefinition(pointer.getDataType());
        }
        if (type instanceof Array array) {
            return usesNamedDefinition(array.getDataType());
        }
        return isNamedDefinition(type);
    }

    private List<DataType> namedDefinitions(DataTypeManager manager) throws Exception {
        var types = new ArrayList<DataType>();
        var all = manager.getAllDataTypes();
        while (all.hasNext()) {
            monitor.checkCancelled();
            var type = all.next();
            if (isNamedDefinition(type)) {
                types.add(type);
            }
        }
        types.sort(TYPE_ORDER);
        return types;
    }

    private TypeArchive exportTypes(List<DataType> types) throws Exception {
        var directory = Files.createTempDirectory("retrore-types");
        var path = directory.resolve("annotations.gdt");
        var compiler = currentProgram.getCompilerSpec().getCompilerSpecID();
        try (var archive = FileDataTypeManager.createFileArchive(path.toFile(),
                currentProgram.getLanguageID(), compiler)) {
            int transaction = archive.startTransaction("Export retrore data types");
            try {
                archive.addDataTypes(types, TYPE_HANDLER, monitor);
                verifyTypes(archive, types);
            } finally {
                archive.endTransaction(transaction, true);
            }
            archive.save();
            var paths = namedDefinitions(archive).stream().map(TypePath::of).toList();
            return new TypeArchive(ARCHIVE_FORMAT, paths, Base64.getEncoder().encodeToString(Files.readAllBytes(path)));
        } finally {
            Files.deleteIfExists(path);
            Files.delete(directory);
        }
    }

    private StandAloneDataTypeManager readTypes(JsonObject document) throws Exception {
        var bundle = document.getAsJsonObject("data_types");
        if (!ARCHIVE_FORMAT.equals(string(bundle, "format"))) {
            throw new IllegalArgumentException("unsupported annotation data type archive format");
        }
        var bytes = Base64.getDecoder().decode(string(bundle, "archive"));
        var directory = Files.createTempDirectory("retrore-types");
        var path = directory.resolve("annotations.gdt");
        try {
            Files.write(path, bytes);
            try (var archive = FileDataTypeManager.openFileArchive(path.toFile(), false)) {
                var architecture = archive.getProgramArchitecture();
                var compiler = currentProgram.getCompilerSpec().getCompilerSpecID();
                if (architecture == null || !currentProgram.getLanguageID().equals(architecture.getLanguage().getLanguageID())
                        || !compiler.equals(architecture.getCompilerSpec().getCompilerSpecID())) {
                    throw new IllegalArgumentException("annotation data type archive architecture differs from the Ghidra program");
                }
                var paths = namedDefinitions(archive).stream().map(TypePath::of).toList();
                if (paths.isEmpty() || !GSON.toJsonTree(paths).equals(bundle.get("types"))) {
                    throw new IllegalArgumentException("annotation data type paths differ from the archive");
                }
                return stageTypes(archive);
            }
        } finally {
            Files.deleteIfExists(path);
            Files.delete(directory);
        }
    }

    private StandAloneDataTypeManager stageTypes(FileDataTypeManager archive) throws Exception {
        var staged = new StandAloneDataTypeManager("retrore annotations");
        boolean done = false;
        try {
            staged.setProgramArchitecture(currentProgram.getLanguage(), currentProgram.getCompilerSpec().getCompilerSpecID(),
                StandAloneDataTypeManager.LanguageUpdateOption.CLEAR, monitor);
            var types = new ArrayList<DataType>();
            archive.getAllDataTypes(types);
            int transaction = staged.startTransaction("Stage retrore data types");
            try {
                staged.addDataTypes(types, TYPE_HANDLER, monitor);
                // Replay local copies so Ghidra cannot synchronize or reassociate destination definitions.
                for (var source : staged.getSourceArchives()) {
                    staged.removeSourceArchive(source);
                }
                verifyTypes(staged, types);
            } finally {
                staged.endTransaction(transaction, true);
            }
            done = true;
            return staged;
        } finally {
            if (!done) {
                staged.close();
            }
        }
    }

    private void verifyTypes(DataTypeManager manager, List<DataType> types) throws Exception {
        for (var type : types) {
            monitor.checkCancelled();
            if (type == DataType.DEFAULT) {
                continue;
            }
            var copied = manager.getDataType(type.getDataTypePath());
            if (copied == null || !equivalentType(copied, type)) {
                throw new IllegalArgumentException("could not copy annotation data type " + type.getPathName());
            }
        }
    }

    private static boolean equivalentType(DataType existing, DataType incoming) {
        return existing.getLength() == incoming.getLength() && existing.getAlignment() == incoming.getAlignment() &&
            Objects.equals(existing.getDescription(), incoming.getDescription()) && existing.isEquivalent(incoming);
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
        int version = document.get("version").getAsBigDecimal().intValueExact();
        if ((version != 1 && version != 2) || document.has("data_types") != (version == 2)) {
            throw new IllegalArgumentException("expected a version 1 or 2 annotation document");
        }
        try (var staged = version == 2 ? readTypes(document) : null) {
            return replay(document, apply, version, staged);
        }
    }

    private Map<String, Object> replay(JsonObject document, boolean apply, int version,
            DataTypeManager staged) throws Exception {
        var changes = new ArrayList<Change>();
        var typeChanges = new ArrayList<TypeChange>();
        var typesToAdd = new ArrayList<DataType>();
        var manager = currentProgram.getDataTypeManager();
        var keys = new HashSet<Item>();
        int conflicts = 0;
        int additions = 0;
        if (staged != null) {
            for (var type : namedDefinitions(staged)) {
                monitor.checkCancelled();
                var path = TypePath.of(type);
                var existing = path.find(manager);
                if (existing == null) {
                    typeChanges.add(new TypeChange(path, "add", ""));
                    typesToAdd.add(type);
                    additions++;
                } else if (equivalentType(existing, type)) {
                    typeChanges.add(new TypeChange(path, "unchanged", ""));
                } else {
                    typeChanges.add(new TypeChange(path, "conflict", "a different data type already exists at this path"));
                    conflicts++;
                }
            }
        }
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
            Prototype prototype = null;
            if (row.has("prototype")) {
                if (!kind.equals("signature") || staged == null || !row.get("prototype").isJsonObject()) {
                    throw new IllegalArgumentException("a typed signature requires an annotation data type archive");
                }
                prototype = GSON.fromJson(row.get("prototype"), Prototype.class);
            }
            var item = new Item(string(row, "unit"), offset, kind,
                kind.equals("entry_point") ? null : string(row, "value"),
                kind.equals("comment") ? string(row, "comment_type") : null,
                kind.equals("signature") ? string(row, "calling_convention") : null, prototype);
            var key = new Item(item.unit(), item.offset(), item.kind(),
                kind.equals("label") ? item.value() : null, item.commentType(), null, null);
            if (!keys.add(key)) {
                throw new IllegalArgumentException("duplicate annotation at " + item.unit() + "+" + item.offset());
            }
            var change = check(item, staged);
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
                if (!typesToAdd.isEmpty()) {
                    manager.addDataTypes(typesToAdd, TYPE_HANDLER, monitor);
                    verifyTypes(manager, typesToAdd);
                }
                for (var change : changes) {
                    monitor.checkCancelled();
                    if (change.status().equals("add")) {
                        add(change.item(), change.address(), staged);
                    }
                }
                commit = true;
            } finally {
                currentProgram.endTransaction(transaction, commit);
            }
        }
        var report = new LinkedHashMap<String, Object>();
        report.put("version", version);
        report.put("applied", applied);
        report.put("additions", additions);
        report.put("conflicts", conflicts);
        report.put("unchanged", changes.size() + typeChanges.size() - conflicts - additions);
        report.put("changes", changes.stream().map(change -> Map.of(
            "annotation", change.item(), "status", change.status(), "reason", change.reason())).toList());
        if (staged != null) {
            report.put("data_type_changes", typeChanges);
        }
        return report;
    }

    private Change check(Item item, DataTypeManager staged) throws Exception {
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
            var signature = parseSignature(item, address, staged);
            if (signature.isEquivalentSignature(function.getSignature())
                    && (item.prototype() == null || item.prototype().equals(Prototype.of(function.getSignature())))
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

    private FunctionDefinitionDataType parseSignature(Item item, Address address, DataTypeManager staged)
            throws Exception {
        var function = currentProgram.getListing().getFunctionAt(address);
        var manager = currentProgram.getDataTypeManager();
        FunctionDefinitionDataType signature;
        var prototype = item.prototype();
        if (prototype == null) {
            signature = new FunctionSignatureParser(manager, null).parse(function.getSignature(), item.value());
        } else {
            if (prototype.parameters() == null) {
                throw new IllegalArgumentException("expected annotation signature parameters");
            }
            signature = new FunctionDefinitionDataType(function.getName(), manager);
            signature.setReturnType(signatureType(prototype.returnType(), staged, manager));
            var parameters = new ArrayList<ParameterDefinition>();
            for (var param : prototype.parameters()) {
                parameters.add(new ParameterDefinitionImpl(param.name(), signatureType(param.type(), staged, manager), null));
            }
            signature.setArguments(parameters.toArray(ParameterDefinition[]::new));
            signature.setVarArgs(prototype.varargs());
            signature.setNoReturn(prototype.noreturn());
        }
        signature.setCallingConvention(item.callingConvention());
        // Function names are replayed by a separate annotation.
        signature.setName(function.getName());
        return signature;
    }

    private static DataType signatureType(TypePath path, DataTypeManager staged, DataTypeManager destination) {
        if (TypePath.of(DataType.DEFAULT).equals(path)) {
            return DataType.DEFAULT;
        }
        var type = path == null ? null : path.find(staged);
        if (type == null) {
            throw new IllegalArgumentException("signature references a data type missing from the annotation archive: " + path);
        }
        var existing = path.find(destination);
        return existing != null && equivalentType(existing, type) ? existing : type;
    }

    private void add(Item item, Address address, DataTypeManager staged) throws Exception {
        var listing = currentProgram.getListing();
        var symbols = currentProgram.getSymbolTable();
        switch (item.kind()) {
            case "function_name" -> listing.getFunctionAt(address).setName(item.value(), SourceType.USER_DEFINED);
            case "label" -> symbols.createLabel(address, item.value(), SourceType.USER_DEFINED);
            case "comment" -> listing.setComment(address, CommentType.valueOf(item.commentType()), item.value());
            case "entry_point" -> symbols.addExternalEntryPoint(address);
            case "signature" -> {
                var command = new ApplyFunctionSignatureCmd(address, parseSignature(item, address, staged),
                    SourceType.USER_DEFINED, false, FunctionRenameOption.NO_CHANGE);
                if (!command.applyTo(currentProgram, monitor)) {
                    throw new IllegalArgumentException(command.getStatusMsg());
                }
                if (item.prototype() != null) {
                    var function = listing.getFunctionAt(address);
                    function.setNoReturn(item.prototype().noreturn());
                    if (!item.prototype().equals(Prototype.of(function.getSignature())) ||
                            !item.callingConvention().equals(function.getCallingConventionName())) {
                        throw new IllegalArgumentException("could not apply typed signature at " + address);
                    }
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
