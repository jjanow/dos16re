import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.symbol.SourceType;

import java.math.BigInteger;

public class CheckSegmentReferences extends GhidraScript {
    @Override
    public void run() throws Exception {
        var context = currentProgram.getProgramContext();
        var refs = currentProgram.getReferenceManager();
        var symbols = currentProgram.getSymbolTable();
        for (String check : getScriptArgs()) {
            String[] parts = check.split("/");
            Address instruction = address(parts[0]);
            require(getInstructionAt(instruction) != null, check, "instruction");
            String register = parts[1];
            var value = context.getValue(currentProgram.getRegister(register), instruction, false);
            if (parts[2].equals("?")) {
                require(value == null, check, "unknown " + register);
                continue;
            }
            require(new BigInteger(parts[2], 16).equals(value), check, register);
            Address target = address(parts[4]);
            var ref = refs.getPrimaryReferenceFrom(instruction, Integer.parseInt(parts[3]));
            require(ref != null && target.equals(ref.getToAddress()) &&
                ref.getSource() == SourceType.ANALYSIS, check, "data reference");
            var data = getDataAt(target);
            require(data != null && data.getDataType().getName().equals(parts[5]), check, "data type");
            var symbol = symbols.getPrimarySymbol(target);
            require(symbol != null && symbol.getName().equals(parts[6]), check, "global name");
        }
        println("All segment references checked");
    }

    private Address address(String value) {
        var space = (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
        String[] parts = value.split(":");
        return space.getAddress(Integer.parseInt(parts[0], 16), Integer.parseInt(parts[1], 16));
    }

    private void require(boolean condition, String check, String field) {
        if (!condition) {
            throw new AssertionError("Expected " + field + " for " + check);
        }
    }
}
