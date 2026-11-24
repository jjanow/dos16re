// Recover DOS calling conventions from instruction evidence and name INT 21h services at their call sites.
// Runs after RetroreSegments.java and adds its counts to the import report.
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

public class RetroreConventions extends HeadlessScript {
    private static final String SERVICE_BLOCK = "dos_services";
    // INT 21h services by AH (names after Ralf Brown's Interrupt List).
    private static final Map<Integer, String> SERVICES = new HashMap<>();
    private static final Set<Integer> EXITS = Set.of(0x00, 0x31, 0x4c);
    // Services that return values in BX, CX, DX, or ES as well as AX.
    private static final Set<Integer> REGISTER_RESULTS = Set.of(
        0x1b, 0x1c, 0x2a, 0x2c, 0x30, 0x33, 0x34, 0x35, 0x36, 0x42, 0x44, 0x48, 0x51, 0x52, 0x57, 0x59, 0x62);
    static {
        String[] names = {
            "00:Terminate", "01:ReadCharEcho", "02:WriteChar", "03:AuxRead", "04:AuxWrite", "05:PrinterWrite",
            "06:DirectConsoleIO", "07:DirectInput", "08:ReadChar", "09:WriteString", "0a:BufferedInput",
            "0b:InputStatus", "0c:FlushAndRead", "0d:DiskReset", "0e:SelectDrive", "0f:FcbOpen", "10:FcbClose",
            "11:FcbFindFirst", "12:FcbFindNext", "13:FcbDelete", "14:FcbSequentialRead", "15:FcbSequentialWrite",
            "16:FcbCreate", "17:FcbRename", "19:GetDrive", "1a:SetDta", "1b:GetDefaultDriveInfo", "1c:GetDriveInfo",
            "21:FcbRandomRead", "22:FcbRandomWrite", "23:FcbFileSize", "24:FcbSetRecord", "25:SetVector",
            "26:CreatePsp", "27:FcbBlockRead", "28:FcbBlockWrite", "29:ParseFilename", "2a:GetDate", "2b:SetDate",
            "2c:GetTime", "2d:SetTime", "2e:SetVerify", "2f:GetDta", "30:GetVersion", "31:KeepProcess",
            "33:CtrlBreak", "34:GetInDosFlag", "35:GetVector", "36:GetFreeSpace", "38:CountryInfo", "39:MakeDir",
            "3a:RemoveDir", "3b:ChangeDir", "3c:CreateFile", "3d:OpenFile", "3e:CloseFile", "3f:ReadFile",
            "40:WriteFile", "41:DeleteFile", "42:SeekFile", "43:FileAttributes", "44:Ioctl", "45:DuplicateHandle",
            "46:ForceDuplicateHandle", "47:GetCurrentDir", "48:Allocate", "49:Free", "4a:Resize", "4b:Exec",
            "4c:Exit", "4d:GetReturnCode", "4e:FindFirst", "4f:FindNext", "50:SetPsp", "51:GetPsp", "52:GetListOfLists",
            "54:GetVerify", "56:RenameFile", "57:FileDateTime", "58:AllocationStrategy", "59:ExtendedError",
            "5a:CreateTempFile", "5b:CreateNewFile", "5c:LockRegion", "62:GetPspAddress", "67:SetHandleCount",
            "68:CommitFile", "6c:ExtendedOpen",
        };
        for (String entry : names) {
            String[] parts = entry.split(":");
            SERVICES.put(Integer.parseInt(parts[0], 16), parts[1]);
        }
    }
    // Register arguments of the common services (register:name). The rest get no arguments.
    private static final Map<Integer, String> SERVICE_ARGUMENTS = Map.ofEntries(
        Map.entry(0x02, "DL:character"), Map.entry(0x06, "DL:character"), Map.entry(0x09, "DX:string"),
        Map.entry(0x0a, "DX:buffer"), Map.entry(0x0e, "DL:drive"), Map.entry(0x1a, "DX:buffer"),
        Map.entry(0x25, "AL:vector DX:handler"), Map.entry(0x35, "AL:vector"), Map.entry(0x36, "DL:drive"),
        Map.entry(0x39, "DX:name"), Map.entry(0x3a, "DX:name"), Map.entry(0x3b, "DX:name"),
        Map.entry(0x3c, "CX:attributes DX:name"), Map.entry(0x3d, "AL:mode DX:name"), Map.entry(0x3e, "BX:handle"),
        Map.entry(0x3f, "BX:handle CX:count DX:buffer"), Map.entry(0x40, "BX:handle CX:count DX:buffer"),
        Map.entry(0x41, "DX:name"), Map.entry(0x42, "AL:origin BX:handle CX:offset_high DX:offset_low"),
        Map.entry(0x43, "AL:function CX:attributes DX:name"), Map.entry(0x44, "AL:function BX:handle"),
        Map.entry(0x45, "BX:handle"), Map.entry(0x46, "BX:handle CX:new_handle"),
        Map.entry(0x47, "DL:drive SI:buffer"), Map.entry(0x48, "BX:paragraphs"), Map.entry(0x49, "ES:segment"),
        Map.entry(0x4a, "BX:paragraphs ES:segment"), Map.entry(0x4b, "AL:mode BX:parameters DX:name"),
        Map.entry(0x4c, "AL:code"), Map.entry(0x4e, "CX:attributes DX:name"),
        Map.entry(0x56, "DX:old_name DI:new_name"), Map.entry(0x57, "AL:function BX:handle"),
        Map.entry(0x5b, "CX:attributes DX:name"));
    private static final Pattern FRAME_ACCESS = Pattern.compile("\\[(BP|BX) \\+ 0x([0-9a-fA-F]+)\\]");
    private static final Set<String> ARGUMENT_REGISTERS = Set.of("EAX", "EBX", "ECX", "EDX", "ESI", "EDI");
    // A stray frame access or RET immediate can imply thousands of unobserved word slots.
    private static final int MAX_INFERRED_STACK_BYTES = 256;

    private SegmentedAddressSpace space;
    private int farPointers;

    private record Frame(int start, Map<Integer, Integer> sizes, Set<Integer> pointers, Set<Integer> bytes) {}

    @Override
    public void run() throws Exception {
        setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
        Path result = Path.of(getScriptArgs()[1]);
        var gson = new Gson();
        try {
            JsonObject report = new JsonObject();
            if (Files.isRegularFile(result)) {
                var previous = JsonParser.parseString(Files.readString(result));
                if (previous.isJsonObject()) {
                    report = previous.getAsJsonObject();
                }
            }
            if (report.has("error")) {
                return;
            }
            space = (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
            report.addProperty("dos_services", nameDosServices());
            report.add("calling_conventions", gson.toJsonTree(recoverConventions()));
            Files.writeString(result, gson.toJson(report));
            setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
        } catch (Exception error) {
            Files.writeString(result, gson.toJson(Map.of("error", error.toString())));
            throw error;
        }
    }

    // ---- INT 21h services ----

    // Each named INT 21h becomes a call to a stub in a block outside the program, so the decompiler shows the
    // service by name with its register arguments, and callers queries list every site of a service.
    private int nameDosServices() throws Exception {
        var listing = currentProgram.getListing();
        var memory = currentProgram.getMemory();
        var sites = new ArrayList<Instruction>();
        for (var instruction : listing.getInstructions(true)) {
            if (instruction.getLength() == 2 && (instruction.getByte(0) & 0xff) == 0xcd &&
                    (instruction.getByte(1) & 0xff) == 0x21) {
                sites.add(instruction);
            }
        }
        if (sites.isEmpty()) {
            return 0;
        }
        var block = serviceBlock();
        if (block == null) {
            return 0;
        }
        addServiceConventions();
        var references = currentProgram.getReferenceManager();
        int named = 0;
        for (var site : sites) {
            monitor.checkCancelled();
            Integer service = serviceNumber(site);
            String name = service == null ? null : SERVICES.get(service);
            if (name == null) {
                continue;
            }
            var stub = serviceStub(block, service, name);
            references.removeAllReferencesFrom(site.getAddress());
            var reference = references.addMemoryReference(site.getAddress(), stub.getEntryPoint(),
                RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.IMPORTED, Reference.MNEMONIC);
            references.setPrimary(reference, true);
            if (EXITS.contains(service)) {
                // Drop the fall-through here, so non-returning analysis has nothing left to override.
                site.setFallThrough(null);
            }
            listing.setComment(site.getAddress(), CommentType.EOL, String.format("retrore: INT 21h AH=%02Xh %s", service, name));
            named++;
        }
        return named;
    }

    // AH from the nearest preceding instruction in the same straight-line run that writes AH or AX. A jump into
    // the run after that load could bring another AH, so such sites stay unnamed.
    private Integer serviceNumber(Instruction site) throws Exception {
        var listing = currentProgram.getListing();
        var current = site;
        for (int step = 0; step < 8; step++) {
            if (jumpedTo(current)) {
                return null;
            }
            var from = current.getFallFrom();
            if (from == null) {
                return null;
            }
            var previous = listing.getInstructionAt(from);
            if (previous == null || previous.getFlowType().isJump() || previous.getFlowType().isCall()) {
                return null;
            }
            int opcode = previous.getByte(0) & 0xff;
            if (opcode == 0xb4 && previous.getLength() == 2) {
                return previous.getByte(1) & 0xff;                       // mov ah,imm8
            }
            if (opcode == 0xb8 && previous.getLength() == 3) {
                return previous.getByte(2) & 0xff;                       // mov ax,imm16
            }
            for (Object written : previous.getResultObjects()) {
                if (written instanceof Register register &&
                        register.getBaseRegister().getName().equals("EAX") && !register.getName().equals("AL")) {
                    return null;
                }
            }
            current = previous;
        }
        return null;
    }

    private boolean jumpedTo(Instruction instruction) {
        for (var reference : currentProgram.getReferenceManager().getReferencesTo(instruction.getAddress())) {
            if (reference.getReferenceType().isFlow()) {
                return true;
            }
        }
        return false;
    }

    private ghidra.program.model.mem.MemoryBlock serviceBlock() throws Exception {
        var memory = currentProgram.getMemory();
        var existing = memory.getBlock(SERVICE_BLOCK);
        if (existing != null) {
            return existing;
        }
        // The top of the BIOS area, which DOS programs never load into.
        for (int segment = 0xffe0; segment >= 0xf000; segment -= 0x20) {
            Address start = space.getAddress(segment, 0);
            Address end = start.addNoWrap(0xff);
            if (memory.getBlock(start) != null || memory.getBlock(end) != null ||
                    memory.intersects(start, end)) {
                continue;
            }
            var block = memory.createInitializedBlock(SERVICE_BLOCK, start, 0x100, (byte) 0xcf, monitor, false);
            block.setExecute(true);
            block.setWrite(false);
            // Each stub is an iret: the segmented calling convention analyzer resets functions that end in ret.
            block.setComment("retrore stubs for INT 21h services, one per AH value");
            new DisassembleCommand(new AddressSet(start, end), null, false).applyTo(currentProgram, monitor);
            return block;
        }
        return null;
    }

    // INT 21h pushes nothing the caller sees, so the stubs need a convention with no stack effect.
    private void addServiceConventions() throws Exception {
        var extension = new SpecExtension(currentProgram);
        String inputs = "<input>" + entry("AX") + entry("BX") + entry("CX") + entry("DX") + "</input>";
        String outputs = "<output>" + entry("AX") +
            "<pentry minsize=\"3\" maxsize=\"4\"><addr space=\"join\" piece1=\"DX\" piece2=\"AX\"/></pentry></output>";
        String fixed = "<register name=\"SP\"/><register name=\"BP\"/><register name=\"SI\"/>" +
            "<register name=\"DI\"/><register name=\"DS\"/><register name=\"SS\"/><register name=\"CS\"/>" +
            "<register name=\"DF\"/>";
        extension.addReplaceCompilerSpecExtension("<prototype name=\"__dosint\" extrapop=\"0\" stackshift=\"0\">" +
            inputs + outputs + "<unaffected>" + fixed + "<register name=\"BX\"/><register name=\"CX\"/>" +
            "<register name=\"DX\"/><register name=\"ES\"/></unaffected><killedbycall><register name=\"AX\"/>" +
            "<register name=\"CF\"/></killedbycall></prototype>", monitor);
        extension.addReplaceCompilerSpecExtension("<prototype name=\"__dosint_registers\" extrapop=\"0\" " +
            "stackshift=\"0\">" + inputs + outputs + "<unaffected>" + fixed + "</unaffected><killedbycall>" +
            "<register name=\"AX\"/><register name=\"BX\"/><register name=\"CX\"/><register name=\"DX\"/>" +
            "<register name=\"ES\"/><register name=\"CF\"/></killedbycall></prototype>", monitor);
        // Functions resolve convention names against the installed compiler spec, which picks up new extensions
        // only when the program reinstalls them.
        var install = ghidra.program.database.ProgramDB.class.getDeclaredMethod("installExtensions");
        install.setAccessible(true);
        install.invoke(currentProgram);
    }

    private static String entry(String register) {
        return "<pentry minsize=\"1\" maxsize=\"2\"><register name=\"" + register + "\"/></pentry>";
    }

    private Function serviceStub(ghidra.program.model.mem.MemoryBlock block, int service, String name)
            throws Exception {
        Address entry = block.getStart().addNoWrap(service);
        var function = getFunctionAt(entry);
        if (function != null) {
            return function;
        }
        function = createFunction(entry, name);
        Namespace namespace = currentProgram.getSymbolTable().getOrCreateNameSpace(
            currentProgram.getGlobalNamespace(), "DOS", SourceType.IMPORTED);
        function.setParentNamespace(namespace);
        var parameters = new ArrayList<Parameter>();
        var manager = currentProgram.getDataTypeManager();
        for (String argument : SERVICE_ARGUMENTS.getOrDefault(service, "").split(" ")) {
            if (argument.isEmpty()) {
                continue;
            }
            String[] parts = argument.split(":");
            var register = currentProgram.getRegister(parts[0]);
            DataType type = register.getMinimumByteSize() == 1 ? ByteDataType.dataType
                : parts[1].endsWith("name") || parts[1].equals("string")
                    ? new PointerDataType(CharDataType.dataType, 2, manager)
                    : parts[1].equals("buffer") ? new PointerDataType(VoidDataType.dataType, 2, manager)
                    : Undefined2DataType.dataType;
            parameters.add(new ParameterImpl(parts[1], type, register, currentProgram));
        }
        var ax = currentProgram.getRegister("AX");
        function.updateFunction(REGISTER_RESULTS.contains(service) ? "__dosint_registers" : "__dosint",
            new ReturnParameterImpl(Undefined2DataType.dataType, new VariableStorage(currentProgram, ax),
                currentProgram),
            parameters, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.IMPORTED);
        // A known purge keeps the x86 callee purge analyzer from replacing the convention after this script.
        function.setStackPurgeSize(0);
        function.setComment(String.format("INT 21h AH=%02Xh", service));
        if (EXITS.contains(service)) {
            function.setNoReturn(true);
        }
        return function;
    }

    // ---- Calling conventions ----

    private Map<String, Integer> recoverConventions() throws Exception {
        var counts = new TreeMap<String, Integer>();
        var functions = new ArrayList<Function>();
        currentProgram.getFunctionManager().getFunctions(true).forEach(functions::add);
        var serviceBlock = currentProgram.getMemory().getBlock(SERVICE_BLOCK);
        for (var function : functions) {
            monitor.checkCancelled();
            if (function.isThunk() || function.isExternal() || function.getSignatureSource() != SourceType.DEFAULT ||
                    (serviceBlock != null && serviceBlock.contains(function.getEntryPoint()))) {
                continue;
            }
            String kind = recover(function);
            if (kind != null) {
                counts.merge(kind, 1, Integer::sum);
            }
        }
        counts.put("far_pointer_arguments", farPointers);
        return counts;
    }

    // Returns the recovered kind, or null when the evidence is missing or conflicting.
    private String recover(Function function) throws Exception {
        var listing = currentProgram.getListing();
        Boolean far = null;
        Integer purge = null;
        for (var instruction : listing.getInstructions(function.getBody(), true)) {
            if (!instruction.getFlowType().isTerminal() || !instruction.getMnemonicString().startsWith("RET")) {
                continue;
            }
            int opcode = instruction.getByte(0) & 0xff;
            boolean isFar = opcode == 0xcb || opcode == 0xca;
            if (!isFar && opcode != 0xc3 && opcode != 0xc2) {
                return null;
            }
            int size = (opcode == 0xc2 || opcode == 0xca) ? (int) instruction.getScalar(0).getUnsignedValue() : 0;
            if ((far != null && far != isFar) || (purge != null && purge != size)) {
                return null;
            }
            far = isFar;
            purge = size;
        }
        if (far == null) {
            return null;
        }
        var frame = frame(function, far ? 4 : 2);
        if (frame == null) {
            return null;
        }
        int extent = 0;
        for (var access : frame.sizes().entrySet()) {
            extent = Math.max(extent, access.getKey() + access.getValue());
        }
        extent += extent & 1;
        int size;
        boolean variadic = false;
        String kind;
        if (purge > 0) {
            if (extent > purge || purge % 2 != 0) {
                return null;
            }
            size = purge;
            kind = "callee_cleanup";
        } else {
            var cleanups = callerCleanups(function);
            if (cleanups.isEmpty()) {
                size = extent;
            } else {
                int low = cleanups.stream().min(Integer::compare).get();
                int high = cleanups.stream().max(Integer::compare).get();
                variadic = low != high;
                size = low;
                if (extent > high) {
                    return null;
                }
            }
            // Without a direct caller only the frame accesses give the size, as for Turbo Pascal's text Read
            // helpers, which leave the file pointer on the stack for the next call.
            kind = size == 0 ? "no_stack_arguments" : cleanups.isEmpty() ? "accessed_arguments"
                : variadic ? "caller_cleanup_variadic" : "caller_cleanup";
        }
        if (size > MAX_INFERRED_STACK_BYTES) {
            return null;  // Ghidra checks custom parameter storage for conflicts pairwise.
        }
        if (size == 0 && frame.start() < 0) {
            return null;  // No frame and no stack arguments: leave register routines to the decompiler.
        }
        var parameters = new ArrayList<Parameter>();
        var manager = currentProgram.getDataTypeManager();
        for (int offset = 0; offset < size;) {
            int slot = frame.sizes().getOrDefault(offset, 2) >= 4 && offset + 4 <= size ? 4 : 2;
            DataType type;
            if (slot == 4) {
                type = frame.pointers().contains(offset) ? new PointerDataType(VoidDataType.dataType, 4, manager)
                    : Undefined4DataType.dataType;
                if (frame.pointers().contains(offset)) {
                    farPointers++;
                }
            } else {
                type = frame.bytes().contains(offset) ? ByteDataType.dataType : Undefined2DataType.dataType;
            }
            // Explicit stack offsets: dynamic storage would align far pointers to four bytes.
            int stack = offset + (far ? 4 : 2);
            parameters.add(new ParameterImpl(null, type, stack, currentProgram));
            offset += slot;
        }
        function.setCallingConvention(far ? "__stdcall16far" : "__stdcall16near");
        function.replaceParameters(parameters, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
        function.setStackPurgeSize(purge);
        function.setVarArgs(variadic);
        return kind;
    }

    // Stack argument accesses relative to the first argument, from [BP + n] after push bp; mov bp,sp or from
    // SS:[BX + n] after mov bx,sp. Returns null when the entry reads an argument register before writing it,
    // which marks a register-argument routine that this pass leaves alone.
    private Frame frame(Function function, int arguments) throws Exception {
        var listing = currentProgram.getListing();
        Integer bpDelta = null;
        Integer bxDelta = null;
        int delta = 0;
        var written = new HashSet<String>();
        var instruction = listing.getInstructionAt(function.getEntryPoint());
        while (instruction != null) {
            String mnemonic = instruction.getMnemonicString();
            String text = instruction.toString();
            if (text.equals("MOV BP,SP")) {
                bpDelta = delta;
            } else if (text.equals("MOV BX,SP")) {
                bxDelta = delta;
            }
            boolean clears = (mnemonic.equals("XOR") || mnemonic.equals("SUB")) && instruction.getNumOperands() == 2 &&
                instruction.getDefaultOperandRepresentation(0).equals(instruction.getDefaultOperandRepresentation(1));
            if (!mnemonic.equals("PUSH") && !clears) {
                for (Object read : instruction.getInputObjects()) {
                    if (read instanceof Register register && !written.contains(base(register)) &&
                            ARGUMENT_REGISTERS.contains(base(register)) && !text.equals("MOV BX,SP")) {
                        return null;
                    }
                }
            }
            for (Object result : instruction.getResultObjects()) {
                if (result instanceof Register register) {
                    written.add(base(register));
                }
            }
            if (mnemonic.equals("PUSH")) {
                delta -= 2;
            } else if (mnemonic.equals("POP")) {
                delta += 2;
            } else if (mnemonic.equals("SUB") && text.startsWith("SUB SP,")) {
                break;
            }
            if (instruction.getFlowType().isJump() || instruction.getFlowType().isCall() ||
                    instruction.getFlowType().isTerminal()) {
                break;
            }
            var next = instruction.getFallThrough();
            instruction = next == null ? null : listing.getInstructionAt(next);
        }
        var sizes = new HashMap<Integer, Integer>();
        var pointers = new HashSet<Integer>();
        var bytes = new HashSet<Integer>();
        var wide = new HashSet<Integer>();
        if (bpDelta == null && bxDelta == null) {
            return new Frame(-1, sizes, pointers, bytes);
        }
        boolean bxValid = false;
        for (var item : listing.getInstructions(function.getBody(), true)) {
            String text = item.toString();
            if (bxDelta != null && text.equals("MOV BX,SP")) {
                bxValid = true;
                continue;
            }
            var matcher = FRAME_ACCESS.matcher(text);
            while (matcher.find()) {
                boolean bp = matcher.group(1).equals("BP");
                Integer frameDelta = bp ? bpDelta : (bxValid ? bxDelta : null);
                if (frameDelta == null) {
                    continue;
                }
                // Ghidra can print negative 16-bit displacements as unsigned hex.
                int displacement = (short) Integer.parseInt(matcher.group(2), 16);
                int offset = displacement + frameDelta - arguments;
                if (offset < 0) {
                    continue;
                }
                String mnemonic = item.getMnemonicString();
                int size = text.contains("dword ptr") || mnemonic.equals("LES") || mnemonic.equals("LDS") ? 4
                    : text.contains("byte ptr") ? 1 : 2;
                if (mnemonic.equals("LES") || mnemonic.equals("LDS")) {
                    pointers.add(offset);
                }
                if (size == 1) {
                    bytes.add(offset);
                    size = 2;
                } else {
                    wide.add(offset);
                }
                sizes.merge(offset, size, Math::max);
            }
            if (bxDelta != null && bxValid) {
                for (Object result : item.getResultObjects()) {
                    if (result instanceof Register register && base(register).equals("EBX")) {
                        bxValid = false;
                    }
                }
            }
        }
        bytes.removeIf(wide::contains);
        return new Frame(0, sizes, pointers, bytes);
    }

    private static String base(Register register) {
        return register.getBaseRegister().getName();
    }

    // Stack bytes each caller removes after a call: add sp,n or pops into scratch registers.
    private List<Integer> callerCleanups(Function function) throws Exception {
        var listing = currentProgram.getListing();
        var cleanups = new ArrayList<Integer>();
        for (var reference : currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())) {
            if (!reference.getReferenceType().isCall()) {
                continue;
            }
            var call = listing.getInstructionAt(reference.getFromAddress());
            if (call == null || call.getFallThrough() == null) {
                continue;
            }
            var next = listing.getInstructionAt(call.getFallThrough());
            int removed = 0;
            while (next != null) {
                String text = next.toString();
                if (text.startsWith("ADD SP,") && next.getScalar(1) != null) {
                    removed += (int) next.getScalar(1).getUnsignedValue();
                    break;
                }
                if (text.equals("POP CX") || text.equals("POP BX") || text.equals("POP DX")) {
                    removed += 2;
                    next = next.getFallThrough() == null ? null : listing.getInstructionAt(next.getFallThrough());
                    continue;
                }
                break;
            }
            cleanups.add(removed);
        }
        return cleanups;
    }
}
