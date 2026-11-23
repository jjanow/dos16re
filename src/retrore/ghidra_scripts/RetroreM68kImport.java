// Rebuild the exported 68k memory layout and seed analysis.
// For X68000 programs this script also runs after auto-analysis to patch line-F calls that analysis reached.
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class RetroreM68kImport extends HeadlessScript {
    // Human68k line-F calls get stub functions outside the 24-bit X68000 bus, so they cannot collide with memory.
    private static final String CALL_BLOCK = "human68k_calls";
    private static final long CALL_BASE = 0x01000000L;
    private static final short JSR_SP = 0x4e97;
    private static final short RTS = 0x4e75;
    private static final short NOP = 0x4e71;
    // movem.l Da/Db,-(sp) and movem.l (sp)+,Da/Db around an XC integer helper, keyed by the push word.
    private static final Map<Integer, int[]> STACKED_PAIRS = Map.of(
        0x48e7c000, new int[] {0, 1, 0x4cdf0003},
        0x48e76000, new int[] {1, 2, 0x4cdf0006},
        0x48e73000, new int[] {2, 3, 0x4cdf000c});

    private final Map<Integer, String> callNames = new HashMap<>();
    private final Map<Integer, JsonObject> dosPrototypes = new HashMap<>();
    private final Map<Integer, String> iocsNames = new HashMap<>();
    private final Set<Integer> noReturn = new HashSet<>();
    private final Map<String, Integer> callCounts = new TreeMap<>();
    private int callSites;
    private int arithmeticRewrites;

    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        var args = getScriptArgs();
        var result = Path.of(args[1]);
        var gson = new Gson();
        try {
            var map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            Object report;
            if (currentProgram.getMemory().getBlock(CALL_BLOCK) != null) {
                report = finishLineF(map, result, gson);
            } else {
                report = loadMap(map);
            }
            Files.writeString(result, gson.toJson(report));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(result, gson.toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private Map<String, Object> loadMap(JsonObject map) throws Exception {
        String format = map.get("format").getAsString();
        int relocationType = format.equals("HUNK") ? 0x3ec : 1;
        var memory = currentProgram.getMemory();
        var bytes = memory.getAllFileBytes().getFirst();
        var units = map.getAsJsonArray("units");
        long origin = units.get(0).getAsJsonObject().get("linear").getAsLong();
        for (var block : memory.getBlocks()) {
            memory.removeBlock(block, monitor);
        }
        currentProgram.setImageBase(address(origin), true);

        var loaded = new AddressSet();
        for (var item : units) {
            monitor.checkCancelled();
            var unit = item.getAsJsonObject();
            long size = unit.get("size").getAsLong();
            if (size == 0) {
                continue;
            }
            var block = memory.createInitializedBlock(unit.get("name").getAsString(),
                address(unit.get("linear").getAsLong()), bytes, unit.get("image_offset").getAsLong(), size, false);
            boolean code = unit.get("kind").getAsString().equals("code");
            block.setExecute(code);
            block.setWrite(!code);
            loaded.add(block.getStart(), block.getEnd());
        }

        int relocations = 0;
        for (var item : units) {
            monitor.checkCancelled();
            var unit = item.getAsJsonObject();
            var block = memory.getBlock(unit.get("name").getAsString());
            if (block == null) {
                continue;
            }
            var start = block.getStart();
            var listing = currentProgram.getListing();
            for (var element : unit.getAsJsonArray("relocations")) {
                var fixup = element.getAsJsonObject();
                var site = start.addNoWrap(fixup.get("offset").getAsLong());
                long value = fixup.get("value").getAsLong();
                int width = fixup.has("width") ? fixup.get("width").getAsInt() : 4;
                byte[] original = ByteBuffer.allocate(4).putInt(fixup.get("original").getAsInt()).array();
                if (width == 2) {
                    original = new byte[] {original[2], original[3]};
                }
                currentProgram.getRelocationTable().add(site, Relocation.Status.APPLIED, relocationType,
                    new long[] {value}, original, null);
                relocations++;
                if (width == 4 && !block.isExecute() && memory.contains(address(value)) &&
                        listing.getUndefinedDataAt(site) != null &&
                        listing.getUndefinedDataAt(site.addNoWrap(3)) != null) {
                    listing.createData(site, PointerDataType.dataType);
                }
            }
            for (var element : unit.getAsJsonArray("symbols")) {
                var symbol = element.getAsJsonObject();
                long offset = symbol.get("offset").getAsLong();
                String name = SymbolUtilities.replaceInvalidChars(symbol.get("name").getAsString(), true);
                if (!name.isEmpty() && offset >= 0 && offset < block.getSize()) {
                    currentProgram.getSymbolTable().createLabel(start.addNoWrap(offset), name, SourceType.IMPORTED);
                }
            }
        }

        boolean x68k = format.equals("X68K");
        if (x68k) {
            addMemoryMap(map.getAsJsonArray("memory_map"), loaded);
            for (var element : map.getAsJsonArray("hardware_labels")) {
                var label = element.getAsJsonObject();
                var at = address(label.get("linear").getAsLong());
                if (memory.contains(at)) {
                    currentProgram.getSymbolTable().createLabel(at, label.get("name").getAsString(),
                        SourceType.IMPORTED);
                }
            }
            readCallNames(map);
            // XC enters each routine with a bra to a trailing link and a bra back. Discovered non-returning
            // analysis misreads that split as a call that never returns and drops the code after its callers.
            // Line-F exit calls get explicit flow overrides instead.
            setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false");
            // DOS stubs, then FPACK stubs, then IOCS stubs, 256 two-byte slots each.
            var block = memory.createInitializedBlock(CALL_BLOCK, address(CALL_BASE), 0x600, (byte) 0, monitor, false);
            for (int index = 0; index < 0x300; index++) {
                memory.setShort(block.getStart().addNoWrap(index * 2L), RTS);
            }
            block.setExecute(true);
            block.setWrite(false);
            // Every slot is an rts, so unused stubs do not show up as undefined gaps.
            new DisassembleCommand(new AddressSet(block.getStart(), block.getEnd()), null, false)
                .applyTo(currentProgram, monitor);
            block.setComment("retrore stubs for Human68k DOS ($FFxx) and FPACK ($FExx) line-F calls and IOCS calls");
            addFpackFixups();
        }

        var entry = address(map.getAsJsonObject("entry").get("linear").getAsLong());
        if (!memory.contains(entry) || !memory.getBlock(entry).isExecute()) {
            throw new IllegalArgumentException("Entry point is outside executable memory");
        }
        currentProgram.getSymbolTable().addExternalEntryPoint(entry);
        disassemble(entry);
        createFunction(entry, null);

        var report = new LinkedHashMap<String, Object>();
        report.put("program", currentProgram.getName());
        report.put("format", format);
        report.put("units", units.size());
        report.put("relocations", relocations);
        if (x68k) {
            patchLineF();
            report.put("line_f", lineFReport());
        }
        return report;
    }

    private void addMemoryMap(JsonArray regions, AddressSet loaded) throws Exception {
        var memory = currentProgram.getMemory();
        for (var element : regions) {
            monitor.checkCancelled();
            var region = element.getAsJsonObject();
            var start = address(region.get("linear").getAsLong());
            var end = start.addNoWrap(region.get("size").getAsLong() - 1);
            var available = new AddressSet(start, end).subtract(loaded);
            for (var range : available.getAddressRanges()) {
                var base = range.getMinAddress();
                String name = region.get("name").getAsString();
                if (!base.equals(start)) {
                    name += "_" + base;
                }
                var block = memory.createUninitializedBlock(name, base, range.getLength(), false);
                String read = region.get("read").getAsString();
                block.setWrite(!read.equals("rom"));
                block.setVolatile(read.equals("io"));
            }
        }
    }

    private void readCallNames(JsonObject map) {
        var calls = map.getAsJsonObject("line_f_calls");
        for (String group : List.of("dos", "fpack")) {
            for (var entry : calls.getAsJsonObject(group).entrySet()) {
                callNames.put(Integer.parseInt(entry.getKey(), 16), entry.getValue().getAsString());
            }
        }
        for (var word : calls.getAsJsonArray("no_return")) {
            noReturn.add(Integer.parseInt(word.getAsString(), 16));
        }
        if (calls.has("iocs")) {
            for (var entry : calls.getAsJsonObject("iocs").entrySet()) {
                iocsNames.put(Integer.parseInt(entry.getKey(), 16), entry.getValue().getAsString());
            }
        }
        if (calls.has("dos_prototypes")) {
            for (var entry : calls.getAsJsonObject("dos_prototypes").entrySet()) {
                dosPrototypes.put(Integer.parseInt(entry.getKey(), 16), entry.getValue().getAsJsonObject());
            }
        }
    }

    // After auto-analysis: seed text symbols that look like code, patch line-F words that disassembly reached,
    // then repair function bodies and reanalyze.
    private JsonObject finishLineF(JsonObject map, Path result, Gson gson) throws Exception {
        readCallNames(map);
        countExistingSites();
        int merged = mergeTrailingLinks();
        int seeded = seedTextSymbols(map);
        var listing = currentProgram.getListing();
        for (int round = 0; round < 8; round++) {
            var patched = patchLineF();
            if (patched.isEmpty() && round > 0) {
                break;
            }
            for (var site : patched) {
                var previous = listing.getInstructionBefore(site);
                var function = previous == null ? null : getFunctionContaining(previous.getAddress());
                if (function != null) {
                    CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
                }
            }
            analyzeChanges(currentProgram);
        }
        // Reanalysis can split XC entries again, so join them once more after the last round.
        merged += mergeTrailingLinks();
        restoreCallOverrides();
        int iocs = nameIocsCalls();
        JsonObject report = new JsonObject();
        if (Files.isRegularFile(result)) {
            var previous = JsonParser.parseString(Files.readString(result));
            if (previous.isJsonObject() && !previous.getAsJsonObject().has("error")) {
                report = previous.getAsJsonObject();
            }
        }
        var lineF = gson.toJsonTree(lineFReport()).getAsJsonObject();
        lineF.addProperty("seeded_symbols", seeded);
        lineF.addProperty("merged_entries", merged);
        lineF.addProperty("iocs_calls", iocs);
        report.add("line_f", lineF);
        return report;
    }

    // Rejoin routines that enter through "bra L; ...; L: link An,#n; bra body", which analysis splits at the link.
    private int mergeTrailingLinks() throws Exception {
        var functions = currentProgram.getFunctionManager();
        var listing = currentProgram.getListing();
        int merged = 0;
        var entries = new ArrayList<Address>();
        functions.getFunctions(true).forEach(function -> entries.add(function.getEntryPoint()));
        for (var entry : entries) {
            var function = functions.getFunctionAt(entry);
            if (function == null) {
                continue;
            }
            monitor.checkCancelled();
            var instruction = listing.getInstructionAt(function.getEntryPoint());
            if (!isBranch(instruction)) {
                continue;
            }
            var target = instruction.getFlows()[0];
            var split = functions.getFunctionAt(target);
            var link = listing.getInstructionAt(target);
            if (split == null || split.equals(function) || link == null ||
                    !link.getMnemonicString().toLowerCase().startsWith("link")) {
                continue;
            }
            if (!onlyFrom(target, instruction.getAddress())) {
                continue;
            }
            // Analysis records the entry bra as a tail call or thunk. Remove all three pieces and recreate the
            // routine with an explicit body, because CreateFunctionCmd would split the entry bra off as a thunk.
            String name = function.getSymbol().getSource() == SourceType.DEFAULT ? null : function.getName();
            var namespace = function.getParentNamespace();
            instruction.setFlowOverride(FlowOverride.NONE);
            functions.removeFunction(entry);
            functions.removeFunction(target);
            var back = link.getNext();
            if (isBranch(back)) {
                back.setFlowOverride(FlowOverride.NONE);
                var body = functions.getFunctionAt(back.getFlows()[0]);
                if (body != null && onlyFrom(body.getEntryPoint(), back.getAddress())) {
                    functions.removeFunction(body.getEntryPoint());
                }
            }
            // Keep code that other routines already own (shared tails) out of the rebuilt body.
            AddressSetView flow = CreateFunctionCmd.getFunctionBody(currentProgram, entry, monitor);
            for (var overlap : iterable(functions.getFunctionsOverlapping(flow))) {
                flow = flow.subtract(overlap.getBody());
            }
            if (!flow.contains(entry)) {
                continue;
            }
            if (name == null) {
                var primary = currentProgram.getSymbolTable().getPrimarySymbol(entry);
                name = primary == null ? null : primary.getName();
            }
            if (name == null || name.startsWith("FUN_") || name.startsWith("LAB_")) {
                functions.createFunction(null, namespace, entry, flow, SourceType.DEFAULT);
            } else {
                functions.createFunction(name, namespace, entry, flow, SourceType.IMPORTED);
            }
            merged++;
        }
        return merged;
    }

    private static <T> Iterable<T> iterable(java.util.Iterator<T> iterator) {
        var items = new ArrayList<T>();
        iterator.forEachRemaining(items::add);
        return items;
    }

    // An unconditional bra, including one that analysis turned into a tail call with a flow override.
    private boolean isBranch(ghidra.program.model.listing.Instruction instruction) {
        return instruction != null && instruction.getMnemonicString().toLowerCase().startsWith("bra") &&
            instruction.getFlows().length == 1;
    }

    private boolean onlyFrom(Address target, Address source) {
        for (var reference : currentProgram.getReferenceManager().getReferencesTo(target)) {
            if (!reference.getFromAddress().equals(source)) {
                return false;
            }
        }
        return true;
    }

    // Disassemble text symbols that analysis did not reach, unless they start with a line-F word or code reads or
    // writes them as data. Human68k linkers export only global symbols, so most text symbols are routines.
    private int seedTextSymbols(JsonObject map) throws Exception {
        var listing = currentProgram.getListing();
        var references = currentProgram.getReferenceManager();
        var memory = currentProgram.getMemory();
        int seeded = 0;
        for (var item : map.getAsJsonArray("units")) {
            var unit = item.getAsJsonObject();
            if (!unit.get("kind").getAsString().equals("code")) {
                continue;
            }
            var block = memory.getBlock(unit.get("name").getAsString());
            if (block == null) {
                continue;
            }
            for (var element : unit.getAsJsonArray("symbols")) {
                monitor.checkCancelled();
                long offset = element.getAsJsonObject().get("offset").getAsLong();
                if (offset % 2 != 0 || offset + 2 > block.getSize()) {
                    continue;
                }
                var site = block.getStart().addNoWrap(offset);
                if (listing.getInstructionContaining(site) != null || listing.getDefinedDataContaining(site) != null ||
                        callNames.containsKey(memory.getShort(site) & 0xffff)) {
                    continue;
                }
                boolean data = false;
                for (var reference : references.getReferencesTo(site)) {
                    var type = reference.getReferenceType();
                    if (!type.isFlow() && listing.getInstructionAt(reference.getFromAddress()) != null &&
                            (type.isRead() || type.isWrite())) {
                        data = true;
                        break;
                    }
                }
                if (data) {
                    continue;
                }
                disassemble(site);
                if (listing.getInstructionAt(site) != null) {
                    if (getFunctionAt(site) == null) {
                        createFunction(site, null);
                    }
                    seeded++;
                }
            }
        }
        return seeded;
    }

    // Non-returning analysis gives calls to exit stubs a CALL_RETURN flow override, which turns the stub
    // reference into a computed call. Put the override reference back; the stub itself does not return.
    private void restoreCallOverrides() throws Exception {
        var references = currentProgram.getReferenceManager();
        var listing = currentProgram.getListing();
        var block = currentProgram.getMemory().getBlock(CALL_BLOCK);
        var sites = new ArrayList<Reference>();
        for (var address : references.getReferenceDestinationIterator(new AddressSet(block.getStart(),
                block.getEnd()), true)) {
            for (var reference : references.getReferencesTo(address)) {
                sites.add(reference);
            }
        }
        for (var reference : sites) {
            var instruction = listing.getInstructionAt(reference.getFromAddress());
            if (instruction == null || (memoryWord(instruction.getAddress()) != (JSR_SP & 0xffff))) {
                continue;
            }
            if (instruction.getFlowOverride() != FlowOverride.NONE) {
                instruction.setFlowOverride(FlowOverride.NONE);
            }
            if (reference.getReferenceType() != RefType.CALL_OVERRIDE_UNCONDITIONAL) {
                references.delete(reference);
                var restored = references.addMemoryReference(reference.getFromAddress(), reference.getToAddress(),
                    RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.IMPORTED, Reference.MNEMONIC);
                references.setPrimary(restored, true);
            }
        }
    }

    // IOCS calls are trap #15 with the call number in D0. Name the sites where the instruction just before the trap
    // loads D0 with a constant, and turn each trap into a call to a named stub that the decompiler shows.
    private int nameIocsCalls() throws Exception {
        var memory = currentProgram.getMemory();
        var block = memory.getBlock(CALL_BLOCK);
        if (iocsNames.isEmpty() || block.getSize() < 0x600) {
            return 0;
        }
        var listing = currentProgram.getListing();
        var references = currentProgram.getReferenceManager();
        var code = memory.getExecuteSet().subtract(new AddressSet(block.getStart(), block.getEnd()));
        var sites = new ArrayList<ghidra.program.model.listing.Instruction>();
        for (var instruction : listing.getInstructions(code, true)) {
            if (instruction.getLength() == 2 && memoryWord(instruction.getAddress()) == 0x4e4f) {
                sites.add(instruction);
            }
        }
        int named = 0;
        for (var trap : sites) {
            monitor.checkCancelled();
            var from = trap.getFallFrom();
            var load = from == null ? null : listing.getInstructionAt(from);
            if (load == null) {
                continue;
            }
            int opcode = memoryWord(load.getAddress());
            int number;
            if ((opcode & 0xff00) == 0x7000 && load.getLength() == 2) {
                number = opcode & 0xff;                                                 // moveq #n,d0
            } else if (opcode == 0x203c && load.getLength() == 6) {
                number = memory.getByte(load.getAddress().addNoWrap(5)) & 0xff;         // move.l #n,d0
            } else if (opcode == 0x303c && load.getLength() == 4) {
                number = memory.getByte(load.getAddress().addNoWrap(3)) & 0xff;         // move.w #n,d0
            } else {
                continue;
            }
            String name = iocsNames.get(number);
            if (name == null) {
                continue;
            }
            var entry = block.getStart().addNoWrap(0x400 + number * 2L);
            var function = getFunctionAt(entry);
            if (function == null) {
                disassemble(entry);
                Namespace namespace = currentProgram.getSymbolTable().getOrCreateNameSpace(
                    currentProgram.getGlobalNamespace(), "IOCS", SourceType.IMPORTED);
                function = createFunction(entry, name);
                function.setParentNamespace(namespace);
                function.setComment(String.format("X68000 IOCS call $%02X (trap #15)", number));
            }
            boolean present = false;
            for (var reference : references.getReferencesFrom(trap.getAddress())) {
                present |= reference.getToAddress().equals(entry);
            }
            if (!present) {
                var reference = references.addMemoryReference(trap.getAddress(), entry,
                    RefType.CALLOTHER_OVERRIDE_CALL, SourceType.IMPORTED, Reference.MNEMONIC);
                references.setPrimary(reference, true);
            }
            trap.setComment(CodeUnit.EOL_COMMENT, String.format("retrore: IOCS %s ($%02X)", name, number));
            named++;
        }
        return named;
    }

    private int memoryWord(Address address) throws Exception {
        return currentProgram.getMemory().getShort(address) & 0xffff;
    }

    private Map<String, Object> lineFReport() {
        var report = new LinkedHashMap<String, Object>();
        report.put("call_sites", callSites);
        report.put("arithmetic_rewrites", arithmeticRewrites);
        report.put("calls", callCounts);
        return report;
    }

    // Count sites patched before this session (the pre-script ran in a different script instance).
    private void countExistingSites() {
        var references = currentProgram.getReferenceManager();
        var block = currentProgram.getMemory().getBlock(CALL_BLOCK);
        for (var address : references.getReferenceDestinationIterator(new AddressSet(block.getStart(),
                block.getEnd()), true)) {
            String name = getSymbolAt(address) == null ? address.toString() : getSymbolAt(address).getName();
            for (var reference : references.getReferencesTo(address)) {
                if (reference.getReferenceType().isCall()) {
                    callSites++;
                    callCounts.merge(name, 1, Integer::sum);
                }
            }
        }
        var comments = currentProgram.getListing();
        var text = currentProgram.getMemory().getExecuteSet().subtract(new AddressSet(block.getStart(), block.getEnd()));
        for (var address : comments.getCommentAddressIterator(CodeUnit.EOL_COMMENT, text, true)) {
            String comment = comments.getComment(CodeUnit.EOL_COMMENT, address);
            if (comment != null && comment.startsWith("retrore: FPACK ") && comment.contains(" on stacked ")) {
                arithmeticRewrites++;
                callCounts.merge(comment.substring("retrore: FPACK ".length()).split(" ", 2)[0], 1, Integer::sum);
            }
        }
    }

    // Replace line-F words that disassembly stopped at until none are left. Returns the patched addresses.
    private List<Address> patchLineF() throws Exception {
        var patched = new ArrayList<Address>();
        var memory = currentProgram.getMemory();
        var bookmarks = currentProgram.getBookmarkManager();
        var listing = currentProgram.getListing();
        while (true) {
            monitor.checkCancelled();
            var sites = new ArrayList<Address>();
            var iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
            while (iterator.hasNext()) {
                var bookmark = iterator.next();
                var site = bookmark.getAddress();
                var block = memory.getBlock(site);
                if (block == null || !block.isExecute() || block.getName().equals(CALL_BLOCK) ||
                        listing.getInstructionAt(site) != null || site.getOffset() % 2 != 0) {
                    continue;
                }
                int word = memory.getShort(site) & 0xffff;
                if (callNames.containsKey(word)) {
                    sites.add(site);
                }
            }
            // The MC68020 language decodes a few line-F words as coprocessor instructions. X68000 software uses
            // coprocessor ID 1 for the FPU, so an instruction word of $FExx or $FFxx is always a Human68k call.
            for (var instruction : listing.getInstructions(memory.getExecuteSet(), true)) {
                var site = instruction.getAddress();
                if (!memory.getBlock(site).getName().equals(CALL_BLOCK) &&
                        callNames.containsKey(memory.getShort(site) & 0xffff)) {
                    listing.clearCodeUnits(site, site, false);
                    sites.add(site);
                }
            }
            if (sites.isEmpty()) {
                return patched;
            }
            for (var site : sites) {
                for (var bookmark : bookmarks.getBookmarks(site, BookmarkType.ERROR)) {
                    bookmarks.removeBookmark(bookmark);
                }
                if (listing.getInstructionAt(site) == null) {
                    patchSite(site);
                    patched.add(site);
                }
            }
        }
    }

    private void patchSite(Address site) throws Exception {
        var memory = currentProgram.getMemory();
        var listing = currentProgram.getListing();
        int word = memory.getShort(site) & 0xffff;
        String name = callNames.get(word);
        if (rewriteArithmetic(site, word, name)) {
            return;
        }
        listing.clearCodeUnits(site, site.addNoWrap(1), false);
        memory.setShort(site, JSR_SP);
        new DisassembleCommand(site, new AddressSet(site, site.addNoWrap(1)), false).applyTo(currentProgram, monitor);
        var instruction = listing.getInstructionAt(site);
        if (instruction == null) {
            return;
        }
        var stub = stub(word, name);
        var references = currentProgram.getReferenceManager();
        var reference = references.addMemoryReference(site, stub.getEntryPoint(), RefType.CALL_OVERRIDE_UNCONDITIONAL,
            SourceType.IMPORTED, Reference.MNEMONIC);
        references.setPrimary(reference, true);
        String group = word >= 0xff00 ? "DOS" : "FPACK";
        instruction.setComment(CodeUnit.EOL_COMMENT,
            String.format("retrore: %s %s (line-F $%04X patched to jsr (sp) for analysis)", group, name, word));
        // The stub of an exit call is non-returning, so the bytes after it are left alone. A flow override
        // would replace the stub reference and turn the call back into an indirect jsr (sp).
        if (!noReturn.contains(word) && instruction.getFallThrough() != null) {
            disassemble(instruction.getFallThrough());
        }
        callSites++;
        callCounts.merge(name, 1, Integer::sum);
    }

    // XC compiles 32-bit integer multiply and divide as a stacked FPACK call. Rewrite the exact sequence as the
    // equivalent 68020 instruction so the decompiler shows the arithmetic. Remainders keep their stub call because
    // the 68020 form would clobber the divisor register.
    private boolean rewriteArithmetic(Address site, int word, String name) throws Exception {
        int operation = word - 0xfee0;
        if (operation < 0 || operation > 5 || operation % 3 == 2) {
            return false;
        }
        var memory = currentProgram.getMemory();
        if (site.getOffset() < 4) {
            return false;
        }
        var start = site.subtractNoWrap(4);
        int push = memory.getInt(start);
        int[] pair = STACKED_PAIRS.get(push);
        if (pair == null || memory.getInt(site.addNoWrap(2)) != pair[2]) {
            return false;
        }
        int a = pair[0];
        int b = pair[1];
        int signed = operation < 3 ? 0x0800 : 0;
        short[] code;
        String text;
        if (operation % 3 == 0) {
            code = new short[] {(short) (0x4c00 | b), (short) ((a << 12) | signed)};
            text = String.format("%s.l d%d,d%d", signed != 0 ? "muls" : "mulu", b, a);
        } else {
            code = new short[] {(short) (0x4c40 | b), (short) ((a << 12) | signed | a)};
            text = String.format("%s.l d%d,d%d", signed != 0 ? "divs" : "divu", b, a);
        }
        var end = site.addNoWrap(5);
        byte[] original = new byte[10];
        memory.getBytes(start, original);
        currentProgram.getListing().clearCodeUnits(start, end, false);
        var buffer = ByteBuffer.allocate(10);
        for (short value : code) {
            buffer.putShort(value);
        }
        while (buffer.hasRemaining()) {
            buffer.putShort(NOP);
        }
        memory.setBytes(start, buffer.array());
        disassemble(start);
        StringBuilder hex = new StringBuilder();
        for (byte value : original) {
            hex.append(String.format("%02X", value & 0xff));
        }
        currentProgram.getListing().setComment(start, CodeUnit.EOL_COMMENT,
            String.format("retrore: FPACK %s on stacked d%d,d%d rewritten as %s (original %s)", name, a, b, text, hex));
        arithmeticRewrites++;
        callCounts.merge(name, 1, Integer::sum);
        return true;
    }

    private Function stub(int word, String name) throws Exception {
        var block = currentProgram.getMemory().getBlock(CALL_BLOCK);
        var entry = block.getStart().addNoWrap((word >= 0xff00 ? 0 : 0x200) + (word & 0xff) * 2L);
        var function = getFunctionAt(entry);
        if (function != null) {
            return function;
        }
        disassemble(entry);
        var symbols = currentProgram.getSymbolTable();
        Namespace namespace = symbols.getOrCreateNameSpace(currentProgram.getGlobalNamespace(),
            word >= 0xff00 ? "DOS" : "FPACK", SourceType.IMPORTED);
        function = createFunction(entry, name);
        function.setParentNamespace(namespace);
        function.setComment(String.format("Human68k %s call $%04X", word >= 0xff00 ? "DOS" : "FPACK", word));
        if (noReturn.contains(word)) {
            function.setNoReturn(true);
        }
        // DOS calls take stacked arguments and return in D0. FPACK helpers other than the register integer ones
        // take stacked arguments and write their result over the first one. Variadic prototypes let the
        // decompiler show the arguments of each call; IMPORTED keeps analysis from replacing them.
        if (word >= 0xff00) {
            function.setReturnType(IntegerDataType.dataType, SourceType.IMPORTED);
        } else {
            function.setReturnType(ghidra.program.model.data.VoidDataType.dataType, SourceType.IMPORTED);
        }
        function.setVarArgs(true);
        function.setSignatureSource(SourceType.IMPORTED);
        if (FPACK_STACKED.containsKey(word)) {
            // XC's stacked FPACK calls work on the caller's stack, which a prototype cannot express. The call
            // fixup replaces each call with p-code for the operation, so the decompiler shows the result.
            function.setVarArgs(false);
            function.setCallFixup(fixupName(word));
        }
        if (dosPrototypes.containsKey(word)) {
            applyDosPrototype(function, dosPrototypes.get(word));
        }
        if (word >= 0xfe00 && word <= 0xfe09 && word != 0xfe03 && word != 0xfe07) {
            function.setVarArgs(false);
            // Register helpers: D0 op D1, result in D0.
            var d0 = currentProgram.getRegister("D0");
            var d1 = currentProgram.getRegister("D1");
            var integer = IntegerDataType.dataType;
            function.updateFunction(null,
                new ReturnParameterImpl(integer, new VariableStorage(currentProgram, d0), currentProgram),
                FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.IMPORTED,
                new ParameterImpl("left", integer, d0, currentProgram),
                new ParameterImpl("right", integer, d1, currentProgram));
        }
        return function;
    }

    // XC's FPACK calls with operands on the stack (FLOAT2 numbering, XEiJ fefunc.mac). The last value pushed is
    // the left operand and receives the result; integer operands are longs, F is a 4-byte float, D an 8-byte
    // double. Each body runs after jsr (sp) pushed its return address, so the operands start at SP + 4.
    private static final Map<Integer, String> FPACK_STACKED = new LinkedHashMap<>();
    static {
        String[][] integer = {{"fee0", "*"}, {"fee1", "s/"}, {"fee2", "s%"}, {"fee3", "*"}, {"fee4", "/"},
            {"fee5", "%"}};
        for (var operation : integer) {
            FPACK_STACKED.put(Integer.parseInt(operation[0], 16),
                "l:4 = *:4 (SP + 4); r:4 = *:4 (SP + 8); *:4 (SP + 4) = l " + operation[1] + " r;");
        }
        FPACK_STACKED.put(0xfee6, "v:4 = *:4 (SP + 4); *:8 (SP + 4) = int2float(v);");
        FPACK_STACKED.put(0xfee7, "v:8 = *:8 (SP + 4); *:4 (SP + 4) = trunc(v);");
        FPACK_STACKED.put(0xfee8, "v:4 = *:4 (SP + 4); *:4 (SP + 4) = int2float(v);");
        FPACK_STACKED.put(0xfee9, "v:4 = *:4 (SP + 4); *:4 (SP + 4) = trunc(v);");
        FPACK_STACKED.put(0xfeea, "v:4 = *:4 (SP + 4); *:8 (SP + 4) = float2float(v);");
        FPACK_STACKED.put(0xfeeb, "v:8 = *:8 (SP + 4); *:4 (SP + 4) = float2float(v);");
        String[] operators = {"f+", "f-", "f*", "f/"};
        for (int index = 0; index < operators.length; index++) {
            FPACK_STACKED.put(0xfeed + index,
                "l:8 = *:8 (SP + 4); r:8 = *:8 (SP + 12); *:8 (SP + 4) = l " + operators[index] + " r;");
            FPACK_STACKED.put(0xfef3 + index,
                "l:4 = *:4 (SP + 4); r:4 = *:4 (SP + 8); *:4 (SP + 4) = l " + operators[index] + " r;");
        }
        // Comparisons set the condition codes as cmp left - right would, for the signed branches XC emits.
        String flags = "NF = l f< r; ZF = l f== r; VF = 0; CF = l f< r;";
        FPACK_STACKED.put(0xfeec, "l:8 = *:8 (SP + 4); r:8 = *:8 (SP + 12); " + flags);
        FPACK_STACKED.put(0xfef2, "l:4 = *:4 (SP + 4); r:4 = *:4 (SP + 8); " + flags);
        FPACK_STACKED.put(0xfef8, "l:8 = *:8 (SP + 4); r:8 = int2float(0:4); " + flags);
        FPACK_STACKED.put(0xfef9, "l:4 = *:4 (SP + 4); r:4 = int2float(0:4); " + flags);
        FPACK_STACKED.put(0xfefa, "v:8 = *:8 (SP + 4); *:8 (SP + 4) = v f+ int2float(1:4);");
        FPACK_STACKED.put(0xfefb, "v:4 = *:4 (SP + 4); *:4 (SP + 4) = v f+ int2float(1:4);");
        FPACK_STACKED.put(0xfefc, "v:8 = *:8 (SP + 4); *:8 (SP + 4) = v f- int2float(1:4);");
        FPACK_STACKED.put(0xfefd, "v:4 = *:4 (SP + 4); *:4 (SP + 4) = v f- int2float(1:4);");
    }

    private static String fixupName(int word) {
        return String.format("retrore_fpack_%04x", word);
    }

    // Program-specific compiler spec extensions hold the call fixups, so the stock 68000 language stays untouched.
    private void addFpackFixups() throws Exception {
        var extension = new ghidra.program.database.SpecExtension(currentProgram);
        for (var entry : FPACK_STACKED.entrySet()) {
            String xml = "<callfixup name=\"" + fixupName(entry.getKey()) + "\"><pcode><body><![CDATA[" +
                entry.getValue() + " SP = SP + 4;]]></body></pcode></callfixup>";
            extension.addReplaceCompilerSpecExtension(xml, monitor);
        }
    }

    // The line-F word sits where the patched jsr (sp) pushes its return address, so the last value pushed
    // before the call is at +4. Words and longs are packed as pushed, which the 68000 calling convention's
    // 4-byte stack slots cannot express, so every parameter gets explicit stack storage.
    private void applyDosPrototype(Function function, JsonObject prototype) throws Exception {
        var parameters = new ArrayList<ghidra.program.model.listing.Parameter>();
        int offset = 4;
        for (var element : prototype.getAsJsonArray("parameters")) {
            var parameter = element.getAsJsonObject();
            int size = parameter.get("size").getAsInt();
            var type = lineFType(parameter.get("type").getAsString());
            parameters.add(new ParameterImpl(parameter.get("name").getAsString(), type,
                new VariableStorage(currentProgram, offset, size), currentProgram));
            offset += size;
        }
        var d0 = currentProgram.getRegister("D0");
        function.updateFunction(null,
            new ReturnParameterImpl(lineFType(prototype.get("result").getAsString()),
                new VariableStorage(currentProgram, d0), currentProgram),
            parameters, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.IMPORTED);
        function.setVarArgs(prototype.get("variadic").getAsBoolean());
        function.setStackPurgeSize(0);
    }

    private ghidra.program.model.data.DataType lineFType(String name) {
        var manager = currentProgram.getDataTypeManager();
        return switch (name) {
            case "short" -> ghidra.program.model.data.ShortDataType.dataType;
            case "int" -> IntegerDataType.dataType;
            case "char*" -> new PointerDataType(ghidra.program.model.data.CharDataType.dataType, 4, manager);
            case "void*" -> new PointerDataType(ghidra.program.model.data.VoidDataType.dataType, 4, manager);
            default -> throw new IllegalArgumentException("unknown line-F type " + name);
        };
    }

    private Address address(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }
}
