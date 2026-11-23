// Seed and inspect synthetic data types for annotation replay tests.
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.symbol.SourceType;

import java.util.List;

public class AnnotationDataTypes extends GhidraScript {
    private static final CategoryPath RECORDS = new CategoryPath("/records");
    private static final CategoryPath OTHER = new CategoryPath("/other");

    @Override
    public void run() throws Exception {
        var types = currentProgram.getDataTypeManager();
        var function = getFunctionAt(toAddr(0xc000));
        if (getScriptArgs()[0].equals("seed")) {
            var mode = new EnumDataType(RECORDS, "Mode", 1, types);
            mode.add("READY", 7);
            mode.add("STOPPED", 9);
            var otherMode = new EnumDataType(OTHER, "Mode", 1, types);
            otherMode.add("UNKNOWN", 0);
            types.addDataType(otherMode, null);
            var node = new StructureDataType(RECORDS, "Node", 0, types);
            node.setExplicitPackingValue(1);
            node.add(new PointerDataType(node, 2, types), "next", null);
            node.addBitField(ByteDataType.dataType, 3, "flags", "Low bits");
            node.add(mode, "mode", null);
            var reference = new TypedefDataType(RECORDS, "NodeRef", new PointerDataType(node, 2, types), types);
            var choice = new UnionDataType(RECORDS, "Selection", types);
            choice.add(reference, "selected", null);
            choice.add(new ArrayDataType(mode, 3, 1, types), "modes", null);
            types.addDataType(choice, null);
            var callback = new FunctionDefinitionDataType(RECORDS, "OnSelected", types);
            callback.setReturnType(mode);
            callback.setArguments(new ParameterDefinition[] {new ParameterDefinitionImpl("node", reference, null)});
            types.addDataType(callback, null);

            var signature = new FunctionDefinitionDataType(function.getName(), types);
            signature.setReturnType(mode);
            signature.setArguments(new ParameterDefinition[] {new ParameterDefinitionImpl("node", reference, null)});
            var command = new ApplyFunctionSignatureCmd(function.getEntryPoint(), signature,
                SourceType.USER_DEFINED, false, FunctionRenameOption.NO_CHANGE);
            check(command.applyTo(currentProgram, monitor), command.getStatusMsg());
        } else {
            var mode = (Enum) types.getDataType(RECORDS, "Mode");
            var node = (Structure) types.getDataType(RECORDS, "Node");
            var choice = (Union) types.getDataType(RECORDS, "Selection");
            var callback = (FunctionDefinition) types.getDataType(RECORDS, "OnSelected");
            var pointer = (Pointer) node.getDefinedComponents()[0].getDataType();
            check(pointer.getDataType() == node && pointer.getLength() == 2, "recursive pointer");
            var flags = node.getDefinedComponents()[1];
            check(node.getExplicitPackingValue() == 1 && node.getLength() == 4, "packed layout");
            check(flags.getDataType() instanceof BitFieldDataType field && field.getBitSize() == 3 &&
                "Low bits".equals(flags.getComment()), "bitfield");
            check(choice.getComponent(1).getDataType() instanceof Array array && array.getNumElements() == 3 &&
                array.getDataType() == mode, "union array");
            check(callback.getArguments()[0].getDataType() instanceof TypeDef typeDef &&
                typeDef.getCategoryPath().equals(RECORDS), "function definition");
            check(function.getReturnType() == mode && mode.getValue("READY") == 7, "category-qualified return type");
            check(function.getParameter(0).getDataType() == types.getDataType(RECORDS, "NodeRef"), "typed parameter");
            check(types.getSourceArchives().isEmpty(), "temporary archive association");
            if (getScriptArgs()[0].equals("conflict")) {
                mode.add("EXTRA", 10);
                types.remove(List.of(types.getDataType(OTHER, "Mode")), monitor);
            }
        }
        println("Annotation data types checked");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
