// Read a Ghidra listing as address-independent function bodies and call/data evidence.
import com.google.gson.FieldNamingPolicy;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;

public class RetroreFingerprints extends GhidraScript {
    private record Shape(String id, String name, String stableName, String address, String unit, Long offset,
            int instructions, String fingerprint, String rawSha256, TreeSet<String> calls,
            TreeSet<String> externalCalls, TreeSet<String> data, List<Long> instructionOffsets,
            List<Location> instructionSites, SemanticProfile semantics) {}
    private record SemanticProfile(Map<String, Integer> operations, List<Integer> branchDegrees,
            TreeSet<Long> constants) {}
    private record Location(String unit, long offset) {}
    private record StorageBlock(String unit, String space, String start, long size, String type,
            boolean initialized, boolean read, boolean write, boolean execute, String contentSha256,
            boolean nonUniform, String content) {}
    private record BlockContent(String sha256, boolean nonUniform, String bytes) {}

    private final Map<Address, List<String>> dataCache = new HashMap<>();
    private final HashSet<String> ambiguousUnits = new HashSet<>();

    @Override
    public void run() throws Exception {
        var args = Arrays.asList(getScriptArgs());
        boolean storage = args.subList(1, args.size()).contains("storage");
        boolean instructions = args.subList(1, args.size()).contains("instructions");
        boolean semantics = args.subList(1, args.size()).contains("semantics");
        if (instructions) {
            var names = new HashSet<String>();
            for (var block : currentProgram.getMemory().getBlocks()) {
                if (!names.add(block.getName())) {
                    ambiguousUnits.add(block.getName());
                }
            }
        }
        var functions = new ArrayList<Shape>();
        var decompiler = semantics ? new DecompInterface() : null;
        try {
            if (decompiler != null) {
                decompiler.toggleCCode(false);
                if (!decompiler.openProgram(currentProgram)) {
                    throw new IllegalArgumentException(decompiler.getLastMessage());
                }
            }
            for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                functions.add(fingerprint(function, storage, instructions, decompiler));
            }
        } finally {
            if (decompiler != null) {
                decompiler.dispose();
            }
        }
        var report = new HashMap<String, Object>(Map.of("program", currentProgram.getName(),
            "language", currentProgram.getLanguageID().toString(),
            "sha256", Objects.toString(currentProgram.getExecutableSHA256(), ""), "functions", functions));
        if (semantics) {
            report.put("semantics", true);
        }
        if (storage) {
            var blocks = new ArrayList<StorageBlock>();
            var digest = MessageDigest.getInstance("SHA-256");
            var buffer = new byte[64 * 1024];
            long bytesRemaining = 4 * 1024 * 1024;
            for (var block : currentProgram.getMemory().getBlocks()) {
                var start = block.getStart();
                var content = blockContent(block, digest, buffer, bytesRemaining);
                if (content.bytes() != null) {
                    bytesRemaining -= block.getSize();
                }
                blocks.add(new StorageBlock(block.getName(), start.getAddressSpace().getName(),
                    Long.toUnsignedString(start.getOffset(), 16), block.getSize(), block.getType().name(),
                    block.isInitialized(), block.isRead(), block.isWrite(), block.isExecute(),
                    content.sha256(), content.nonUniform(), content.bytes()));
            }
            report.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
            report.put("storage_blocks", blocks);
        }
        var gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .serializeNulls().create();
        Files.writeString(Path.of(args.getFirst()), gson.toJson(report));
    }

    private BlockContent blockContent(MemoryBlock block, MessageDigest digest, byte[] buffer, long budget)
            throws Exception {
        if (!block.isInitialized()) {
            return new BlockContent(null, false, null);
        }
        byte[] content = block.getSize() <= budget ? new byte[(int) block.getSize()] : null;
        digest.reset();
        byte first = 0;
        boolean distinct = false;
        try {
            for (long offset = 0; offset < block.getSize();) {
                monitor.checkCancelled();
                int count = (int) Math.min(buffer.length, block.getSize() - offset);
                if (block.getBytes(block.getStart().addNoWrap(offset), buffer, 0, count) != count) {
                    return new BlockContent(null, false, null);
                }
                if (content != null) {
                    System.arraycopy(buffer, 0, content, (int) offset, count);
                }
                digest.update(buffer, 0, count);
                if (offset == 0) {
                    first = buffer[0];
                }
                if (!distinct) {
                    for (int i = 0; i < count && !distinct; i++) {
                        distinct = buffer[i] != first;
                    }
                }
                offset += count;
            }
        } catch (MemoryAccessException e) {
            return new BlockContent(null, false, null);
        }
        return new BlockContent(HexFormat.of().formatHex(digest.digest()), distinct,
            content == null ? null : Base64.getEncoder().encodeToString(content));
    }

    private Shape fingerprint(Function function, boolean storage, boolean includeSites, DecompInterface decompiler)
            throws Exception {
        var entry = function.getEntryPoint();
        var block = currentProgram.getMemory().getBlock(entry);
        var instructions = new ArrayList<Instruction>();
        var ordinals = new HashMap<Address, Integer>();
        for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
            monitor.checkCancelled();
            ordinals.put(instruction.getAddress(), instructions.size());
            instructions.add(instruction);
        }
        var normalized = MessageDigest.getInstance("SHA-256");
        var raw = MessageDigest.getInstance("SHA-256");
        var calls = new TreeSet<String>();
        var externals = new TreeSet<String>();
        var data = new TreeSet<String>();
        for (var instruction : instructions) {
            monitor.checkCancelled();
            token(normalized, instruction.getMnemonicString());
            for (int index = 0; index < instruction.getNumOperands(); index++) {
                token(normalized, "operand");
                operand(normalized, instruction, index, ordinals);
            }
            if (instruction.getFlowType().isComputed()) {
                var edges = new TreeSet<Integer>();
                for (var destination : instruction.getFlows()) {
                    var local = ordinals.get(destination);
                    if (local != null) {
                        edges.add(local);
                    }
                }
                edges.forEach(edge -> token(normalized, "edge:" + edge));
            }
            token(normalized, "instruction_end");
            raw.update(instruction.getBytes());
            for (var reference : instruction.getReferencesFrom()) {
                var type = reference.getReferenceType();
                var destination = reference.getToAddress();
                if (type.isCall()) {
                    if (reference.isExternalReference()) {
                        var symbol = currentProgram.getSymbolTable().getPrimarySymbol(destination);
                        if (symbol != null && symbol.getSource() != SourceType.DEFAULT) {
                            externals.add(symbol.getName());
                        }
                    } else if (destination.isMemoryAddress()) {
                        calls.add(destination.toString(true));
                    }
                } else if (!type.isFlow() && reference.isMemoryReference()) {
                    data.addAll(dataCache.computeIfAbsent(destination, this::dataEvidence));
                }
            }
        }
        String stableName = function.getSymbol().getSource() == SourceType.DEFAULT ? null : function.getName();
        var offsets = storage ? instructions.stream().map(instruction -> instruction.getAddress().subtract(entry))
            .toList() : null;
        var sites = includeSites ? instructions.stream().map(instruction -> location(instruction.getAddress()))
            .toList() : null;
        var profile = decompiler != null && instructions.size() >= 4 && !function.isThunk() ?
            semantics(function, decompiler) : null;
        return new Shape(entry.toString(true), function.getName(), stableName, entry.toString(),
            block == null ? null : block.getName(), block == null ? null : entry.subtract(block.getStart()),
            instructions.size(), HexFormat.of().formatHex(normalized.digest()), HexFormat.of().formatHex(raw.digest()),
            calls, externals, data, offsets, sites, profile);
    }

    private SemanticProfile semantics(Function function, DecompInterface decompiler) throws Exception {
        var result = decompiler.decompileFunction(function, 5, monitor);
        var high = result.getHighFunction();
        if (!result.decompileCompleted() || high == null) {
            return null;
        }
        var operations = new TreeMap<String, Integer>();
        var constants = new TreeSet<Long>();
        var iterator = high.getPcodeOps();
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            var op = iterator.next();
            String operation = switch (op.getOpcode()) {
                case PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL -> "equal";
                case PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL -> "order";
                case PcodeOp.INT_ADD, PcodeOp.INT_SUB -> "add_sub";
                case PcodeOp.INT_MULT -> "multiply";
                case PcodeOp.INT_DIV, PcodeOp.INT_SDIV, PcodeOp.INT_REM, PcodeOp.INT_SREM -> "divide_remainder";
                case PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR -> op.getMnemonic().toLowerCase(Locale.ROOT);
                case PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT -> "shift";
                default -> null;
            };
            if (operation == null) {
                continue;
            }
            operations.merge(operation, 1, Integer::sum);
            for (var input : op.getInputs()) {
                long value = input.getOffset();
                if (input.isConstant() && value >= 3 && value <= 0xffff) {
                    constants.add(value);
                }
            }
        }
        var branches = high.getBasicBlocks().stream().map(block -> block.getOutSize()).filter(n -> n > 1)
            .sorted().toList();
        return new SemanticProfile(operations, branches, constants);
    }

    private Location location(Address address) {
        var block = currentProgram.getMemory().getBlock(address);
        return block == null || ambiguousUnits.contains(block.getName()) ? null :
            new Location(block.getName(), address.subtract(block.getStart()));
    }

    private void operand(MessageDigest hash, Instruction instruction, int index, Map<Address, Integer> ordinals) {
        var reference = instruction.getPrimaryReference(index);
        if (reference != null && reference.getReferenceType().isFlow() && !instruction.getFlowType().isComputed()) {
            token(hash, addressToken(reference.getToAddress(), ordinals));
            return;
        }
        var parts = instruction.getDefaultOperandRepresentationList(index);
        if (parts == null) {
            token(hash, Objects.toString(instruction.getDefaultOperandRepresentation(index)));
            return;
        }
        for (var part : parts) {
            if (part instanceof Address address && address.isMemoryAddress()) {
                token(hash, addressToken(address, ordinals));
            } else if (part instanceof Scalar scalar) {
                var target = reference == null || !reference.isMemoryReference() ? null : reference.getToAddress();
                if (target != null && scalarAddress(scalar, target)) {
                    token(hash, addressToken(target, ordinals));
                } else {
                    token(hash, "scalar:" + scalar.bitLength() + ":" + Long.toUnsignedString(scalar.getUnsignedValue()));
                }
            } else if (part instanceof Register register) {
                token(hash, "register:" + register.getName());
            } else {
                token(hash, Objects.toString(part));
            }
        }
    }

    private static boolean scalarAddress(Scalar scalar, Address address) {
        long value = scalar.getUnsignedValue();
        return value == address.getOffset() ||
            (address instanceof SegmentedAddress segmented && value == segmented.getSegmentOffset());
    }

    private String addressToken(Address address, Map<Address, Integer> ordinals) {
        var local = ordinals.get(address);
        if (local != null) {
            return "local:" + local;
        }
        var block = currentProgram.getMemory().getBlock(address);
        return block == null ? "unmapped:" + address : block.isExecute() ? "code_address" : "data_address";
    }

    private List<String> dataEvidence(Address address) {
        var result = new ArrayList<String>();
        var symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        if (symbol != null && (symbol.getSource() == SourceType.IMPORTED || symbol.getSource() == SourceType.USER_DEFINED)) {
            result.add("name:" + symbol.getName());
        }
        var data = currentProgram.getListing().getDefinedDataAt(address);
        if (data != null && data.getLength() <= 4096 && data.hasStringValue()
                && data.getValue() instanceof String value && value.length() >= 4) {
            try {
                var hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
                result.add("string_sha256:" + HexFormat.of().formatHex(hash));
            } catch (java.security.NoSuchAlgorithmException impossible) {
                throw new IllegalStateException(impossible);
            }
        }
        return result;
    }

    private static void token(MessageDigest digest, String text) {
        digest.update(text.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
    }
}
