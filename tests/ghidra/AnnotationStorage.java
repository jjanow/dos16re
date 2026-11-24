// Seed and inspect a synthetic function with custom variable storage.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

import java.util.List;

public class AnnotationStorage extends GhidraScript {
    @Override
    public void run() throws Exception {
        var args = getScriptArgs();
        var entry = args.length > 1 ? toAddr(Long.parseLong(args[1], 16)) : toAddr(0xc000);
        var scratch = args.length > 2 ? entry.add(Long.parseLong(args[2], 16)) : toAddr(0x200);
        var function = getFunctionAt(entry);
        var accumulator = currentProgram.getRegister("A");
        var x = currentProgram.getRegister("X");
        var y = currentProgram.getRegister("Y");
        var pair = new VariableStorage(currentProgram, x, y);
        var word = UnsignedShortDataType.dataType;
        var byteType = ByteDataType.dataType;
        var variant = args.length > 3 ? args[3] : "";
        var manual = SourceType.USER_DEFINED;
        switch (args[0]) {
            case "seed" -> {
                var registerArg = new ParameterImpl("index", word, pair, currentProgram, manual);
                registerArg.setComment("XY index");
                var stackArg = new ParameterImpl("mode", byteType, 4, currentProgram, manual);
                function.updateFunction("default", new ReturnParameterImpl(byteType, accumulator, currentProgram),
                    List.of(registerArg, stackArg), FunctionUpdateType.CUSTOM_STORAGE, false, manual);
                function.getParameter(1).setComment("Mode byte\n");
                var local = new LocalVariableImpl("cached_index", word, -4, currentProgram, manual);
                local.setComment("Previous index");
                function.addLocalVariable(local, manual);
                function.addLocalVariable(new LocalVariableImpl("reused_x", 2, byteType, x, currentProgram), manual);
                function.addLocalVariable(
                    new LocalVariableImpl("scratch", 0, variant.equals("resized") ? word : byteType,
                        scratch, currentProgram), manual);
                if (variant.equals("renamed") || variant.startsWith("moved")) {
                    createData(entry.add(0x10), new ArrayDataType(byteType, 4, 1));
                }
                function.setVarArgs(true);
                function.setNoReturn(true);
                function.setStackPurgeSize(2);
            }
            case "conflict" -> function.addLocalVariable(
                new LocalVariableImpl("manual_cache", word, -4, currentProgram), manual);
            case "rename" -> currentProgram.getMemory().getBlock(entry).setName("renamed_root");
            case "patch" -> currentProgram.getMemory().setByte(scratch, (byte) 0);
            case "check" -> {
                check(function.hasCustomVariableStorage(), "custom storage mode");
                check(function.getReturn().getRegister().equals(accumulator), "return register");
                check(function.getParameter(0).getVariableStorage().equals(pair), "ordered register pair");
                check("XY index".equals(function.getParameter(0).getComment()), "parameter comment");
                check(function.getParameter(1).getStackOffset() == 4, "stack parameter");
                check("Mode byte\n".equals(function.getParameter(1).getComment()), "exact parameter comment");
                var locals = List.of(function.getLocalVariables());
                check(locals.stream().anyMatch(local -> local.getName().equals("cached_index") &&
                      local.getStackOffset() == -4 && "Previous index".equals(local.getComment())), "stack local");
                check(locals.stream().anyMatch(local -> local.getName().equals("reused_x") &&
                      local.getFirstUseOffset() == 2 && x.equals(local.getRegister())), "scoped register local");
                check(locals.stream().anyMatch(local -> local.getName().equals("scratch") &&
                      local.getFirstStorageVarnode().getAddress().equals(scratch)), "absolute local");
                check(function.hasVarArgs() && function.hasNoReturn() && function.getStackPurgeSize() == 2,
                    "signature flags and stack purge");
            }
            default -> throw new AssertionError("Unknown test mode");
        }
        println("Annotation storage checked");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
