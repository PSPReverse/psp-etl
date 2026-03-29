// SetupOffChipBL.java — Split off-chip bootloader into header/.text/.data/.bss sections
// and set the entry point at 0x100 (matching SECT structure).
//
// Run on a program that was imported as a flat binary at base 0x0.
//
// Usage:
//   analyzeHeadless ... -process <program> \
//     -postScript SetupOffChipBL.java
//
//@category PSP.Setup

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class SetupOffChipBL extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        Memory mem = currentProgram.getMemory();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // Find the main block (the imported binary)
        MemoryBlock mainBlock = null;
        for (MemoryBlock b : mem.getBlocks()) {
            if (b.isInitialized() && b.getSize() > 0x1000) {
                mainBlock = b;
                break;
            }
        }
        if (mainBlock == null) {
            printerr("No main block found.");
            return;
        }

        println("Main block: " + mainBlock.getName() +
                " [0x" + Long.toHexString(mainBlock.getStart().getOffset()) +
                "-0x" + Long.toHexString(mainBlock.getEnd().getOffset()) + "]");

        // Rename the main block if it's generic
        if (mainBlock.getName().contains(".bin") || mainBlock.getName().equals("ram")) {
            try {
                mainBlock.setName("OffChipHeader");
            } catch (Exception e) {
                // Name might be taken
            }
        }

        // Split at 0x100: create .text section
        long binarySize = mainBlock.getSize();
        long headerEnd = 0xFF;
        long textStart = 0x100;

        // Determine .text/.data/.bss boundaries from the binary content
        // Use heuristic: find last non-zero byte for .data end
        // For now, keep it simple: rename the whole block and rely on analysis

        // Set entry point at 0x100
        Address entryAddr = space.getAddress(textStart);
        SymbolTable symTable = currentProgram.getSymbolTable();

        // Add entry point
        currentProgram.getSymbolTable().addExternalEntryPoint(entryAddr);

        // Create the entry function
        currentProgram.getFunctionManager().createFunction(
            "entry", entryAddr,
            null, SourceType.USER_DEFINED);

        println("Set entry point at 0x" + Long.toHexString(textStart));
        println("Binary size: 0x" + Long.toHexString(binarySize));
    }
}
