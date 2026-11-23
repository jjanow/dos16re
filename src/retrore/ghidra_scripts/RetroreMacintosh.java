// Resolve Macintosh A5 jump calls and model reached A-line traps for static analysis.
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.TreeMap;

public class RetroreMacintosh extends HeadlessScript {
    private static final String TRAP_BLOCK = "mac68k_traps";
    private static final long TRAP_BASE = 0x01000000L;
    private static final short JSR_SP = 0x4e97;
    private static final short RTS = 0x4e75;
    private static final int EXIT_TO_SHELL = 0xa9f4;
    // Pascal and assembler names from Apple's Inside Macintosh system trap index.
    private static final Map<Integer, String> TRAP_NAMES = Map.ofEntries(
        Map.entry(0xa000, "_Open"), Map.entry(0xa001, "_Close"),
        Map.entry(0xa002, "_Read"), Map.entry(0xa003, "_Write"),
        Map.entry(0xa00c, "_GetFileInfo"), Map.entry(0xa011, "_GetEOF"),
        Map.entry(0xa018, "_GetFPos"), Map.entry(0xa01c, "_FreeMem"),
        Map.entry(0xa025, "_GetHandleSize"), Map.entry(0xa029, "_HLock"),
        Map.entry(0xa02a, "_HUnlock"), Map.entry(0xa02e, "_BlockMove"),
        Map.entry(0xa032, "_FlushEvents"), Map.entry(0xa146, "_GetTrapAddress"),
        Map.entry(0xa047, "_SetTrapAddress"), Map.entry(0xa055, "_StripAddress"),
        Map.entry(0xa11e, "_NewPtr"), Map.entry(0xa01f, "_DisposePtr"),
        Map.entry(0xa122, "_NewHandle"), Map.entry(0xa023, "_DisposeHandle"),
        Map.entry(0xa31e, "_NewPtrClear"), Map.entry(0xa322, "_NewHandleClear"),
        Map.entry(0xa346, "_GetOSTrapAddress"), Map.entry(0xa746, "_GetToolboxTrapAddress"),
        Map.entry(0xa247, "_SetOSTrapAddress"), Map.entry(0xa647, "_SetToolboxTrapAddress"),
        Map.entry(0xa860, "_WaitNextEvent"), Map.entry(0xa86e, "_InitGraf"),
        Map.entry(0xa850, "_InitCursor"), Map.entry(0xa873, "_SetPort"),
        Map.entry(0xa874, "_GetPort"), Map.entry(0xa884, "_DrawString"),
        Map.entry(0xa8a1, "_FrameRect"),
        Map.entry(0xa8a2, "_PaintRect"), Map.entry(0xa8a3, "_EraseRect"),
        Map.entry(0xa8a7, "_SetRect"), Map.entry(0xa8a8, "_OffsetRect"),
        Map.entry(0xa8fe, "_InitFonts"), Map.entry(0xa912, "_InitWindows"),
        Map.entry(0xa913, "_NewWindow"), Map.entry(0xa914, "_DisposeWindow"),
        Map.entry(0xa915, "_ShowWindow"), Map.entry(0xa917, "_GetWRefCon"),
        Map.entry(0xa91f, "_SelectWindow"), Map.entry(0xa924, "_FrontWindow"),
        Map.entry(0xa92c, "_FindWindow"), Map.entry(0xa930, "_InitMenus"),
        Map.entry(0xa937, "_DrawMenuBar"), Map.entry(0xa93d, "_MenuSelect"),
        Map.entry(0xa963, "_SetCtlValue"), Map.entry(0xa970, "_GetNextEvent"),
        Map.entry(0xa975, "_TickCount"), Map.entry(0xa97b, "_InitDialogs"),
        Map.entry(0xa97c, "_GetNewDialog"), Map.entry(0xa983, "_DisposeDialog"),
        Map.entry(0xa985, "_Alert"), Map.entry(0xa987, "_NoteAlert"),
        Map.entry(0xa98d, "_GetDItem"), Map.entry(0xa98e, "_SetDItem"),
        Map.entry(0xa98f, "_SetIText"), Map.entry(0xa991, "_ModalDialog"),
        Map.entry(0xa995, "_InitResources"), Map.entry(0xa997, "_OpenResFile"),
        Map.entry(0xa99a, "_CloseResFile"), Map.entry(0xa99d, "_GetIndResource"),
        Map.entry(0xa9a0, "_GetResource"), Map.entry(0xa9a2, "_LoadResource"),
        Map.entry(0xa9a3, "_ReleaseResource"), Map.entry(0xa9a5, "_SizeRsrc"),
        Map.entry(0xa9a6, "_GetResAttrs"), Map.entry(0xa9af, "_ResError"),
        Map.entry(0xa9b9, "_GetCursor"), Map.entry(0xa9ba, "_GetString"),
        Map.entry(0xa9bc, "_GetPicture"), Map.entry(0xa9c8, "_SysBeep"),
        Map.entry(0xa9eb, "_FP68K"), Map.entry(0xa9f0, "_LoadSeg"),
        Map.entry(0xa9f1, "_UnloadSeg"), Map.entry(EXIT_TO_SHELL, "_ExitToShell"),
        Map.entry(0xa9f5, "_GetAppParms"), Map.entry(0xa9ff, "_Debugger")
    );
    private final Map<String, Integer> traps = new TreeMap<>();

    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        var args = getScriptArgs();
        var result = Path.of(args[1]);
        var gson = new Gson();
        try {
            var map = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            var report = JsonParser.parseString(Files.readString(result)).getAsJsonObject();
            var macintosh = new JsonObject();
            macintosh.addProperty("jump_entries", map.getAsJsonArray("a5_jumps").size());
            macintosh.addProperty("trap_sites", recoverTraps());
            seedNewEntries(map);
            macintosh.addProperty("a5_calls", resolveJumpCalls(map));
            macintosh.add("traps", gson.toJsonTree(traps));
            report.add("macintosh", macintosh);
            Files.writeString(result, gson.toJson(report));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(result, gson.toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    private void seedNewEntries(JsonObject map) throws Exception {
        for (var element : map.getAsJsonArray("a5_jumps")) {
            monitor.checkCancelled();
            var target = address(element.getAsJsonObject().getAsJsonObject("target").get("linear").getAsLong());
            if (getFunctionAt(target) == null && getInstructionAt(target) != null) {
                createFunction(target, null);
            }
        }
    }

    private int resolveJumpCalls(JsonObject map) throws Exception {
        var targetByOffset = new HashMap<Integer, Address>();
        var targetByStub = new HashMap<Address, Address>();
        for (var element : map.getAsJsonArray("a5_jumps")) {
            var jump = element.getAsJsonObject();
            int displacement = jump.get("a5_offset").getAsInt();
            var target = address(jump.getAsJsonObject("target").get("linear").getAsLong());
            targetByOffset.put(displacement, target);
            targetByStub.put(address(jump.getAsJsonObject("stub").get("linear").getAsLong()), target);
        }
        var memory = currentProgram.getMemory();
        var listing = currentProgram.getListing();
        var references = currentProgram.getReferenceManager();
        int count = 0;
        for (var instruction : listing.getInstructions(memory.getExecuteSet(), true)) {
            monitor.checkCancelled();
            var site = instruction.getAddress();
            var flow = instruction.getFlowType();
            if (!flow.isCall() && !flow.isJump()) {
                continue;
            }
            Address target = null;
            int opcode = memory.getShort(site) & 0xffff;
            if ((opcode == 0x4ead || opcode == 0x4eed) && instruction.getLength() == 4) {
                int displacement = memory.getShort(site.addNoWrap(2));
                target = targetByOffset.get(displacement);
            }
            var flows = instruction.getFlows();
            if (target == null && flows.length == 1) {
                // For an indexed call, Ghidra may already have propagated the A5 slot address.
                target = targetByStub.get(flows[0]);
            }
            if (target == null) {
                continue;
            }
            for (var reference : references.getReferencesFrom(site)) {
                if (target.equals(targetByStub.get(reference.getToAddress())) &&
                        reference.getReferenceType().isFlow() && reference.getSource() != SourceType.USER_DEFINED) {
                    references.delete(reference);
                }
            }
            var type = flow.isCall() ? RefType.CALL_OVERRIDE_UNCONDITIONAL : RefType.JUMP_OVERRIDE_UNCONDITIONAL;
            var reference = references.addMemoryReference(site, target, type, SourceType.IMPORTED, Reference.MNEMONIC);
            references.setPrimary(reference, true);
            count++;
        }
        return count;
    }

    private int recoverTraps() throws Exception {
        int total = 0;
        // Analysis after patching can discover more function entries and follow new edges.
        for (int round = 0; round < 8; round++) {
            var affected = new HashSet<Function>();
            int count = patchTraps(affected);
            if (count == 0) {
                break;
            }
            total += count;
            for (var function : affected) {
                CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
            }
            analyzeChanges(currentProgram);
        }
        return total;
    }

    private int patchTraps(HashSet<Function> affected) throws Exception {
        var listing = currentProgram.getListing();
        var memory = currentProgram.getMemory();
        var bookmarks = currentProgram.getBookmarkManager();
        int count = 0;
        while (true) {
            monitor.checkCancelled();
            var sites = new ArrayList<Address>();
            var iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
            while (iterator.hasNext()) {
                var site = iterator.next().getAddress();
                var block = memory.getBlock(site);
                if (block == null || !block.isExecute() || block.getName().equals(TRAP_BLOCK) ||
                        block.getName().equals("a5_jump") || !block.contains(site.addNoWrap(1)) ||
                        site.getOffset() % 2 != 0 || listing.getUndefinedDataAt(site) == null) {
                    continue;
                }
                if ((memory.getShort(site) & 0xf000) == 0xa000) {
                    sites.add(site);
                }
            }
            if (sites.isEmpty()) {
                return count;
            }
            for (var site : sites) {
                for (var bookmark : bookmarks.getBookmarks(site, BookmarkType.ERROR)) {
                    bookmarks.removeBookmark(bookmark);
                }
                if ((memory.getShort(site) & 0xf000) != 0xa000 || listing.getUndefinedDataAt(site) == null) {
                    continue;
                }
                var before = listing.getInstructionBefore(site);
                var owner = before == null ? null : getFunctionContaining(before.getAddress());
                if (owner != null) {
                    affected.add(owner);
                }
                patchTrap(site);
                count++;
            }
        }
    }

    private void patchTrap(Address site) throws Exception {
        var memory = currentProgram.getMemory();
        var listing = currentProgram.getListing();
        int word = memory.getShort(site) & 0xffff;
        String name = trapName(word);
        var block = memory.getBlock(TRAP_BLOCK);
        if (block == null) {
            block = memory.createInitializedBlock(TRAP_BLOCK, address(TRAP_BASE), 0x2000, (byte) 0, monitor, false);
            block.setExecute(true);
            block.setWrite(false);
            block.setComment("retrore analysis stubs for Macintosh A-line traps");
        }
        var target = block.getStart().addNoWrap((word & 0x0fff) * 2L);
        var function = getFunctionAt(target);
        if (function == null) {
            memory.setShort(target, RTS);
            disassemble(target);
            function = createFunction(target, name);
            function.setNoReturn(word == EXIT_TO_SHELL);
        }
        memory.setShort(site, JSR_SP);
        currentProgram.getRelocationTable().add(site, Relocation.Status.APPLIED, 0xa000,
            new long[] {JSR_SP}, new byte[] {(byte) (word >> 8), (byte) word}, null);
        new DisassembleCommand(site, new AddressSet(site, site.addNoWrap(1)), false).applyTo(currentProgram, monitor);
        var instruction = listing.getInstructionAt(site);
        var references = currentProgram.getReferenceManager();
        var ref = references.addMemoryReference(site, target, RefType.CALL_OVERRIDE_UNCONDITIONAL,
            SourceType.IMPORTED, Reference.MNEMONIC);
        references.setPrimary(ref, true);
        instruction.setComment(CodeUnit.EOL_COMMENT, String.format("retrore: Macintosh %s (A-line $%04X)", name, word));
        if (word != EXIT_TO_SHELL && instruction.getFallThrough() != null) {
            disassemble(instruction.getFallThrough());
        }
        traps.merge(name, 1, Integer::sum);
    }

    private static String trapName(int word) {
        String name = TRAP_NAMES.get(word);
        if (name != null) {
            return name;
        }
        if ((word & 0x0c00) == 0x0c00) {
            name = TRAP_NAMES.get(word & ~0x0400);
        } else if ((word & 0x0800) == 0) {
            name = TRAP_NAMES.get(word & ~0x0600);
        }
        return String.format("%s_%04X", name == null ? "MacTrap" : name, word);
    }

    private Address address(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
}
