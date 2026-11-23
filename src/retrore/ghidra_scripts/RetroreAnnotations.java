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
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
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
import ghidra.program.model.lang.UnknownRegister;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;

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
            String callingConvention, Prototype prototype, CustomStorage customStorage, DataLayout dataLayout,
            Location function) {}
    private record Location(String unit, long offset) {}
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
    private record StoredVariable(String name, TypePath type, String storage, int firstUse, String comment,
            SourceType source) {
        static StoredVariable of(Variable variable) {
            return new StoredVariable(variable.getName(), TypePath.of(variable.getDataType()),
                variable.getVariableStorage().getSerializationString(), variable.getFirstUseOffset(),
                variable.getComment(), variable.getSource());
        }
    }
    private record CustomStorage(TypePath returnType, String returnStorage, List<StoredVariable> parameters,
            List<StoredVariable> locals, boolean varargs, boolean noreturn, int stackPurge) {
        static CustomStorage of(Function function) {
            return new CustomStorage(TypePath.of(function.getReturnType()),
                function.getReturn().getVariableStorage().getSerializationString(),
                Arrays.stream(function.getParameters()).map(StoredVariable::of).toList(),
                Arrays.stream(function.getLocalVariables()).map(StoredVariable::of).toList(),
                function.hasVarArgs(), function.hasNoReturn(), function.getStackPurgeSize());
        }

        boolean matchesSignature(CustomStorage actual) {
            return returnType.equals(actual.returnType) && returnStorage.equals(actual.returnStorage)
                && parameters.equals(actual.parameters) && varargs == actual.varargs
                && noreturn == actual.noreturn && stackPurge == actual.stackPurge;
        }
    }
    private record StorageBlock(String unit, String space, String beforeStart, String afterStart, long size) {
        long sourceOffset(Address address) {
            return address.getOffset() - Long.parseUnsignedLong(beforeStart, 16);
        }
    }
    private record TypeArchive(String format, List<TypePath> types, String archive) {}
    private record TypeChange(TypePath type, String status, String reason) {}
    private record DataLayout(TypePath type, int length) {
        static boolean supports(DataType type, int length) {
            var base = type instanceof TypeDef alias ? alias.getBaseDataType() : type;
            return length > 0 && length == type.getLength() && (base instanceof Composite || base instanceof Array);
        }
    }

    private static final Set<String> KINDS =
        Set.of("label", "local_label", "function_name", "comment", "entry_point", "signature", "data_layout");
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
        return item(address, kind, value, detail, null);
    }

    private Location location(Address address) {
        var block = currentProgram.getMemory().getBlock(address);
        return block == null ? null : new Location(block.getName(), address.subtract(block.getStart()));
    }

    private Item item(Address address, String kind, String value, String detail, Location function) {
        var site = location(address);
        return site == null ? null : new Item(site.unit(), site.offset(), kind, value, kind.equals("comment") ? detail :
            null, kind.equals("signature") ? detail : null, null, null, null, function);
    }

    private Map<String, Object> exportAnnotations() throws Exception {
        var symbols = currentProgram.getSymbolTable();
        var listing = currentProgram.getListing();
        var items = new ArrayList<Item>();
        var types = new ArrayList<DataType>();
        var manager = currentProgram.getDataTypeManager();
        boolean customStorage = false;
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
            Location owner = null;
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                kind = "function_name";
            } else if (symbol.getSymbolType() == SymbolType.LABEL) {
                var namespace = symbol.getParentNamespace();
                if (namespace.isGlobal()) {
                    kind = "label";
                } else if (namespace instanceof Function function && function.getBody().contains(symbol.getAddress())
                        && listing.getInstructionAt(symbol.getAddress()) != null
                        && (owner = location(function.getEntryPoint())) != null) {
                    kind = "local_label";
                } else {
                    continue;
                }
            } else {
                continue;
            }
            var item = item(symbol.getAddress(), kind, symbol.getName(), null, owner);
            if (item != null) {
                items.add(item);
            }
        }
        for (var function : listing.getFunctions(true)) {
            monitor.checkCancelled();
            if (function.getSignatureSource() != SourceType.USER_DEFINED ||
                    (function.hasCustomVariableStorage() && function.isThunk())) {
                continue;
            }
            var signature = function.getSignature();
            var item = item(function.getEntryPoint(), "signature", signature.getPrototypeString(false),
                function.getCallingConventionName());
            if (item == null) {
                continue;
            }
            if (function.hasCustomVariableStorage()) {
                types.add(function.getReturnType());
                for (var variable : function.getAllVariables()) {
                    types.add(variable.getDataType());
                }
                item = new Item(item.unit(), item.offset(), item.kind(), item.value(), null,
                    item.callingConvention(), null, CustomStorage.of(function), null, null);
                customStorage = true;
            } else {
                var signatureTypes = new ArrayList<DataType>();
                signatureTypes.add(signature.getReturnType());
                for (var parameter : signature.getArguments()) {
                    signatureTypes.add(parameter.getDataType());
                }
                if (signatureTypes.stream().anyMatch(RetroreAnnotations::usesNamedDefinition)) {
                    types.addAll(signatureTypes);
                    item = new Item(item.unit(), item.offset(), item.kind(), item.value(), null,
                        item.callingConvention(), Prototype.of(signature), null, null, null);
                }
            }
            items.add(item);
        }
        var memory = currentProgram.getMemory();
        boolean dataLayouts = false;
        for (var data : listing.getDefinedData(true)) {
            monitor.checkCancelled();
            var type = data.getDataType();
            var address = data.getMinAddress();
            var block = memory.getBlock(address);
            if (block != null && block.contains(data.getMaxAddress()) && DataLayout.supports(type, data.getLength())) {
                types.add(type);
                items.add(new Item(block.getName(), address.subtract(block.getStart()), "data_layout",
                    null, null, null, null, null, new DataLayout(TypePath.of(type), data.getLength()), null));
                dataLayouts = true;
            }
        }
        var addresses = listing.getCommentAddressIterator(memory, true);
        while (addresses.hasNext()) {
            monitor.checkCancelled();
            var address = addresses.next();
            for (var type : CommentType.values()) {
                String value = listing.getComment(type, address);
                if (value != null) {
                    var item = item(address, "comment", value, type.name());
                    if (item != null) {
                        items.add(item);
                    }
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
        report.put("version", dataLayouts ? 4 : customStorage ? 3 : types.isEmpty() ? 1 : 2);
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

    private StandAloneDataTypeManager readTypes(JsonObject document, int version) throws Exception {
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
                if ((version == 2 && paths.isEmpty()) || !GSON.toJsonTree(paths).equals(bundle.get("types"))) {
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
        if (version < 1 || version > 5 || document.has("data_types") != (version >= 2) ||
                document.has("storage_blocks") != (version == 5)) {
            throw new IllegalArgumentException("expected a version 1 through 5 annotation document");
        }
        try (var staged = version >= 2 ? readTypes(document, version) : null) {
            var blocks = version == 5 ? readStorageBlocks(document) : null;
            return replay(document, apply, version, staged, blocks);
        }
    }

    private static List<StorageBlock> readStorageBlocks(JsonObject document) {
        var records = document.getAsJsonArray("storage_blocks");
        var blocks = new ArrayList<StorageBlock>();
        var units = new HashSet<String>();
        for (var record : records) {
            var block = GSON.fromJson(record, StorageBlock.class);
            if (block == null || !GSON.toJsonTree(block).equals(record) || block.unit() == null ||
                    block.space() == null || block.beforeStart() == null || block.afterStart() == null ||
                    block.size() <= 0 || !units.add(block.unit())) {
                throw new IllegalArgumentException("invalid annotation storage block");
            }
            Long.parseUnsignedLong(block.beforeStart(), 16);
            Long.parseUnsignedLong(block.afterStart(), 16);
            blocks.add(block);
        }
        return blocks;
    }

    private Map<String, Object> replay(JsonObject document, boolean apply, int version,
            DataTypeManager staged, List<StorageBlock> storageBlocks) throws Exception {
        var changes = new ArrayList<Change>();
        var typeChanges = new ArrayList<TypeChange>();
        var typesToAdd = new ArrayList<DataType>();
        var manager = currentProgram.getDataTypeManager();
        var keys = new HashSet<Item>();
        var layoutRanges = new AddressSet();
        var unitNames = new HashSet<String>();
        var ambiguousUnits = new HashSet<String>();
        for (var block : currentProgram.getMemory().getBlocks()) {
            if (!unitNames.add(block.getName())) {
                ambiguousUnits.add(block.getName());
            }
        }
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
            CustomStorage customStorage = null;
            if (row.has("custom_storage")) {
                if (version < 3 || !kind.equals("signature") || prototype != null ||
                        !row.get("custom_storage").isJsonObject()) {
                    throw new IllegalArgumentException("custom storage requires a version 3 through 5 signature annotation");
                }
                customStorage = GSON.fromJson(row.get("custom_storage"), CustomStorage.class);
                if (!GSON.toJsonTree(customStorage).equals(row.get("custom_storage")) ||
                        customStorage.parameters() == null || customStorage.locals() == null) {
                    throw new IllegalArgumentException("invalid custom storage record");
                }
            }
            var dataLayout = readLayout(row, kind, version);
            var function = readInstructionFunction(row, kind);
            var item = new Item(string(row, "unit"), offset, kind,
                kind.equals("entry_point") || dataLayout != null ? null : string(row, "value"),
                kind.equals("comment") ? string(row, "comment_type") : null,
                kind.equals("signature") ? string(row, "calling_convention") : null,
                prototype, customStorage, dataLayout, function);
            var key = new Item(item.unit(), item.offset(), item.kind(),
                isLabel(kind) ? item.value() : null, item.commentType(), null, null, null, null, null);
            if (!keys.add(key)) {
                throw new IllegalArgumentException("duplicate annotation at " + item.unit() + "+" + item.offset());
            }
            var change = check(item, staged, layoutRanges, storageBlocks, ambiguousUnits);
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

    private static DataLayout readLayout(JsonObject row, String kind, int version) {
        if (!kind.equals("data_layout") && !row.has("data_layout")) {
            return null;
        }
        if (version != 4 || !kind.equals("data_layout") || !row.has("data_layout") ||
                !row.get("data_layout").isJsonObject()) {
            throw new IllegalArgumentException("data layouts require a version 4 data_layout annotation");
        }
        var layout = GSON.fromJson(row.get("data_layout"), DataLayout.class);
        if (!GSON.toJsonTree(layout).equals(row.get("data_layout")) || layout.type() == null || layout.length() < 1) {
            throw new IllegalArgumentException("invalid data layout record");
        }
        return layout;
    }

    private static boolean isLabel(String kind) {
        return kind.equals("label") || kind.equals("local_label");
    }

    private static Location readInstructionFunction(JsonObject row, String kind) {
        if (!row.has("function") && !kind.equals("local_label")) {
            return null;
        }
        if (!(isLabel(kind) || kind.equals("comment")) || !row.has("function")
                || !row.get("function").isJsonObject()) {
            throw new IllegalArgumentException("expected an instruction's function for the label or comment");
        }
        var location = GSON.fromJson(row.get("function"), Location.class);
        if (location.unit() == null || location.unit().isEmpty() || location.offset() < 0
                || !GSON.toJsonTree(location).equals(row.get("function"))) {
            throw new IllegalArgumentException("invalid instruction function location");
        }
        return location;
    }

    private Change check(Item item, DataTypeManager staged, AddressSet layoutRanges,
            List<StorageBlock> storageBlocks, Set<String> ambiguousUnits) throws Exception {
        var block = currentProgram.getMemory().getBlock(item.unit());
        if (block == null || item.offset() < 0 || item.offset() >= block.getSize()) {
            return new Change(item, null, "conflict", "unit or offset is missing");
        }
        Address address = block.getStart().addNoWrap(item.offset());
        if (item.dataLayout() != null) {
            return checkLayout(item, address, block.getSize() - item.offset(), staged, layoutRanges);
        }
        var listing = currentProgram.getListing();
        var symbols = currentProgram.getSymbolTable();
        Function owner = null;
        if (item.function() != null) {
            if (ambiguousUnits.contains(item.unit()) || ambiguousUnits.contains(item.function().unit())) {
                return new Change(item, address, "conflict", "the instruction or its expected function has an ambiguous unit");
            }
            owner = listing.getFunctionContaining(address);
            if (owner == null || !item.function().equals(location(owner.getEntryPoint()))
                    || listing.getInstructionAt(address) == null) {
                return new Change(item, address, "conflict", "no instruction at this address in the expected function");
            }
        }
        if (isLabel(item.kind()) || item.kind().equals("function_name")) {
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
        } else if (isLabel(item.kind())) {
            var namespace = item.kind().equals("local_label") ? owner : currentProgram.getGlobalNamespace();
            for (var symbol : symbols.getSymbols(address)) {
                if (symbol.getSymbolType() == SymbolType.LABEL && symbol.getParentNamespace().equals(namespace) &&
                        symbol.getName().equals(item.value())) {
                    return new Change(item, address, "unchanged", "");
                }
            }
            if (owner != null && owner.getEntryPoint().equals(address)
                    && owner.getSymbol().getSource() == SourceType.DEFAULT) {
                return new Change(item, address, "conflict", "the label would rename the destination function");
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
            if (item.customStorage() != null) {
                try {
                    if (storageBlocks != null) {
                        var storage = remapCustomStorage(item.customStorage(), function, storageBlocks);
                        item = new Item(item.unit(), item.offset(), item.kind(), item.value(), null,
                            item.callingConvention(), null, storage, null, null);
                    }
                    var update = customUpdate(item, function, staged);
                    return new Change(item, address, update.unchanged() ? "unchanged" : "add", "");
                } catch (InvalidInputException error) {
                    return new Change(item, address, "conflict", error.getMessage());
                }
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

    private Change checkLayout(Item item, Address start, long available, DataTypeManager staged,
            AddressSet layoutRanges) throws Exception {
        var layout = item.dataLayout();
        var type = annotationType(layout.type(), staged, currentProgram.getDataTypeManager());
        if (!DataLayout.supports(type, layout.length())) {
            return new Change(item, start, "conflict", "the archived type does not match the data layout length or kind");
        }
        if (layout.length() > available) {
            return new Change(item, start, "conflict", "the data layout extends beyond its memory block");
        }
        var end = start.addNoWrap(layout.length() - 1);
        var range = new AddressSet(start, end);
        var listing = currentProgram.getListing();
        if (listing.getInstructionContaining(start) != null || listing.getInstructions(range, true).hasNext()) {
            return new Change(item, start, "conflict", "the data layout would cover instructions");
        }
        var existing = listing.getDefinedDataContaining(start);
        if (existing != null && existing.getMinAddress().equals(start) && existing.getLength() == layout.length()
                && layout.type().equals(TypePath.of(existing.getDataType())) && equivalentType(existing.getDataType(), type)) {
            return new Change(item, start, "unchanged", "");
        }
        if (existing != null || listing.getDefinedData(range, true).hasNext()) {
            return new Change(item, start, "conflict", "the data layout would overlap existing defined data");
        }
        if (layoutRanges.intersects(range)) {
            return new Change(item, start, "conflict", "the data layout overlaps another annotation in the document");
        }
        layoutRanges.add(range);
        return new Change(item, start, "add", "");
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
            signature.setReturnType(annotationType(prototype.returnType(), staged, manager));
            var parameters = new ArrayList<ParameterDefinition>();
            for (var param : prototype.parameters()) {
                parameters.add(new ParameterDefinitionImpl(param.name(), annotationType(param.type(), staged, manager), null));
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

    private static DataType annotationType(TypePath path, DataTypeManager staged, DataTypeManager destination) {
        if (TypePath.of(DataType.DEFAULT).equals(path)) {
            return DataType.DEFAULT;
        }
        var type = path == null || path.category() == null || path.name() == null ? null : path.find(staged);
        if (type == null) {
            throw new IllegalArgumentException("annotation references a data type missing from the archive: " + path);
        }
        var existing = path.find(destination);
        return existing != null && equivalentType(existing, type) ? existing : type;
    }

    private record CustomUpdate(boolean updateSignature, Variable returnValue, List<Variable> parameters,
            Map<StoredVariable, Variable> newLocals, Set<StoredVariable> originalLocals) {
        boolean unchanged() {
            return !updateSignature && newLocals.isEmpty();
        }
    }

    private CustomUpdate customUpdate(Item item, Function function, DataTypeManager staged)
            throws InvalidInputException {
        if (function.isThunk()) {
            throw new InvalidInputException("custom storage belongs to the thunk target");
        }
        var storage = item.customStorage();
        boolean updateSignature = !matchesCustomSignature(item, function);
        if (updateSignature && function.getSignatureSource() == SourceType.USER_DEFINED) {
            throw new InvalidInputException("a different manual function signature or storage already exists");
        }

        var manager = currentProgram.getDataTypeManager();
        var returnValue = new ReturnParameterImpl(annotationType(storage.returnType(), staged, manager),
            variableStorage(storage.returnStorage()), true, currentProgram);
        var originalLocals = new HashSet<StoredVariable>();
        var names = new HashSet<String>();
        var variables = new ArrayList<Variable>();
        for (var local : function.getLocalVariables()) {
            originalLocals.add(StoredVariable.of(local));
            names.add(local.getName());
            variables.add(local);
        }
        for (var symbol : currentProgram.getSymbolTable().getSymbols(function)) {
            if (symbol.getSymbolType() != SymbolType.PARAMETER && symbol.getSymbolType() != SymbolType.LOCAL_VAR &&
                    symbol.getSource() != SourceType.DEFAULT) {
                names.add(symbol.getName());
            }
        }
        var parameters = new ArrayList<Variable>();
        for (var saved : storage.parameters()) {
            var parameter = readVariable(saved, staged, parameters.size());
            checkVariable(parameter, names, variables);
            parameters.add(parameter);
        }
        var newLocals = new LinkedHashMap<StoredVariable, Variable>();
        var savedLocals = new HashSet<StoredVariable>();
        for (var saved : storage.locals()) {
            if (!savedLocals.add(saved)) {
                throw new InvalidInputException("duplicate custom local variable");
            }
            var local = readVariable(saved, staged, -1);
            if (!originalLocals.contains(saved)) {
                checkVariable(local, names, variables);
                newLocals.put(saved, local);
            }
        }
        return new CustomUpdate(updateSignature, returnValue, parameters, newLocals, originalLocals);
    }

    private static boolean matchesCustomSignature(Item item, Function function) {
        return function.hasCustomVariableStorage() && function.getSignatureSource() == SourceType.USER_DEFINED &&
            item.callingConvention().equals(function.getCallingConventionName()) &&
            item.customStorage().matchesSignature(CustomStorage.of(function));
    }

    private VariableStorage variableStorage(String encoded) throws InvalidInputException {
        var storage = VariableStorage.deserialize(currentProgram, encoded);
        if (storage.isBadStorage() || !storage.getSerializationString().equals(encoded)) {
            throw new InvalidInputException("invalid custom variable storage: " + encoded);
        }
        return storage;
    }

    private CustomStorage remapCustomStorage(CustomStorage storage, Function function, List<StorageBlock> blocks)
            throws InvalidInputException {
        var returnStorage = remapStorage(storage.returnStorage(), blocks);
        var parameters = new ArrayList<StoredVariable>();
        var locals = new ArrayList<StoredVariable>();
        for (var parameter : storage.parameters()) {
            parameters.add(remapVariable(parameter, blocks));
        }
        for (var local : storage.locals()) {
            if (local == null) {
                throw new InvalidInputException("invalid custom local variable");
            }
            if (local.firstUse() != 0) {
                try {
                    var use = function.getEntryPoint().addNoWrap(local.firstUse());
                    if (!function.getBody().contains(use) || currentProgram.getListing().getInstructionAt(use) == null) {
                        throw new InvalidInputException("custom local first use is not a destination instruction: " + local.name());
                    }
                } catch (AddressOverflowException error) {
                    throw new InvalidInputException("custom local first use is out of range: " + local.name());
                }
            }
            locals.add(remapVariable(local, blocks));
        }
        return new CustomStorage(storage.returnType(), returnStorage, parameters, locals, storage.varargs(),
            storage.noreturn(), storage.stackPurge());
    }

    private StoredVariable remapVariable(StoredVariable variable, List<StorageBlock> blocks)
            throws InvalidInputException {
        if (variable == null) {
            throw new InvalidInputException("invalid custom variable record");
        }
        return new StoredVariable(variable.name(), variable.type(), remapStorage(variable.storage(), blocks),
            variable.firstUse(), variable.comment(), variable.source());
    }

    private String remapStorage(String encoded, List<StorageBlock> blocks) throws InvalidInputException {
        var pieces = variableStorage(encoded).getVarnodes();
        for (int i = 0; i < pieces.length; i++) {
            var piece = pieces[i];
            var address = piece.getAddress();
            if (address.isStackAddress() || address.isRegisterAddress() || address.isConstantAddress()) {
                continue;
            }
            if (!address.isMemoryAddress()) {
                throw new InvalidInputException("unsupported custom storage address across layouts: " + address);
            }
            var register = currentProgram.getLanguage().getRegister(address, piece.getSize());
            if (register == null || register instanceof UnknownRegister) {
                pieces[i] = remapMemoryPiece(piece, blocks);
            }
        }
        return pieces.length == 0 ? encoded : new VariableStorage(currentProgram, pieces).getSerializationString();
    }

    private Varnode remapMemoryPiece(Varnode piece, List<StorageBlock> blocks) throws InvalidInputException {
        var address = piece.getAddress();
        var space = address.getAddressSpace().getName();
        for (var pair : blocks) {
            long offset = pair.sourceOffset(address);
            if (!space.equals(pair.space()) || offset < 0 || offset >= pair.size()) {
                continue;
            }
            var block = currentProgram.getMemory().getBlock(pair.unit());
            if (block == null || !space.equals(block.getStart().getAddressSpace().getName()) ||
                    block.getStart().getOffset() != Long.parseUnsignedLong(pair.afterStart(), 16) ||
                    block.getSize() != pair.size()) {
                throw new InvalidInputException("destination storage block differs from the comparison: " + pair.unit());
            }
            if (piece.getSize() > pair.size() - offset) {
                throw new InvalidInputException("custom storage crosses the block boundary: " + address.toString(true));
            }
            return new Varnode(block.getStart().add(offset), piece.getSize());
        }
        throw new InvalidInputException("custom storage has no matching memory block: " + address.toString(true));
    }

    private Variable readVariable(StoredVariable saved, DataTypeManager staged, int ordinal)
            throws InvalidInputException {
        if (saved == null || saved.name() == null || saved.source() == null ||
                (ordinal >= 0 && saved.firstUse() != 0)) {
            throw new InvalidInputException("invalid custom variable record");
        }
        var type = annotationType(saved.type(), staged, currentProgram.getDataTypeManager());
        var storage = variableStorage(saved.storage());
        if (ordinal < 0 && storage.hasStackStorage() && saved.firstUse() != 0) {
            throw new InvalidInputException("a stack local must start at the function entry");
        }
        return ordinal >= 0
            ? new ParameterImpl(saved.name(), ordinal, type, storage, true, currentProgram, saved.source())
            : new LocalVariableImpl(saved.name(), saved.firstUse(), type, storage, true, currentProgram, saved.source());
    }

    private static void checkVariable(Variable variable, Set<String> names, List<Variable> variables)
            throws InvalidInputException {
        SymbolUtilities.validateName(variable.getName());
        if (!names.add(variable.getName())) {
            throw new InvalidInputException("a different variable or symbol is already named " + variable.getName());
        }
        VariableUtilities.checkVariableConflict(variables, variable, variable.getVariableStorage(), null);
        variables.add(variable);
    }

    private void addCustomSignature(Item item, Function function, DataTypeManager staged) throws Exception {
        var storage = item.customStorage();
        var update = customUpdate(item, function, staged);
        if (update.updateSignature()) {
            function.updateFunction(item.callingConvention(), update.returnValue(), update.parameters(),
                FunctionUpdateType.CUSTOM_STORAGE, false, SourceType.USER_DEFINED);
            for (int i = 0; i < storage.parameters().size(); i++) {
                function.getParameter(i).setComment(storage.parameters().get(i).comment());
            }
            function.setVarArgs(storage.varargs());
            function.setNoReturn(storage.noreturn());
            function.setStackPurgeSize(storage.stackPurge());
        }
        for (var entry : update.newLocals().entrySet()) {
            monitor.checkCancelled();
            var local = entry.getValue();
            function.addLocalVariable(local, local.getSource()).setComment(entry.getKey().comment());
        }
        var installedLocals = CustomStorage.of(function).locals();
        if (!matchesCustomSignature(item, function) || !installedLocals.containsAll(storage.locals()) ||
                !installedLocals.containsAll(update.originalLocals())) {
            throw new InvalidInputException("could not reproduce custom storage at " + function.getEntryPoint());
        }
    }

    private void add(Item item, Address address, DataTypeManager staged) throws Exception {
        var listing = currentProgram.getListing();
        var symbols = currentProgram.getSymbolTable();
        switch (item.kind()) {
            case "function_name" -> listing.getFunctionAt(address).setName(item.value(), SourceType.USER_DEFINED);
            case "label" -> symbols.createLabel(address, item.value(), SourceType.USER_DEFINED);
            case "local_label" -> symbols.createLabel(address, item.value(), listing.getFunctionContaining(address),
                SourceType.USER_DEFINED);
            case "comment" -> listing.setComment(address, CommentType.valueOf(item.commentType()), item.value());
            case "entry_point" -> symbols.addExternalEntryPoint(address);
            case "data_layout" -> {
                var layout = item.dataLayout();
                var type = annotationType(layout.type(), staged, currentProgram.getDataTypeManager());
                var data = listing.createData(address, type);
                if (data.getLength() != layout.length() || !layout.type().equals(TypePath.of(data.getDataType()))
                        || !equivalentType(data.getDataType(), type)) {
                    throw new IllegalArgumentException("could not apply data layout at " + address);
                }
            }
            case "signature" -> {
                if (item.customStorage() != null) {
                    addCustomSignature(item, listing.getFunctionAt(address), staged);
                    break;
                }
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
