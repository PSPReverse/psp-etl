// SeedRawPrologues.java — Seed code and functions in a raw ARM/Thumb blob that
// has no entry points (for example a SecOS userland driver blob imported with
// the Binary loader).
//
// Pass 1 (ARM): word-aligned `push {..., lr}` (0xE92Dxxxx with bit 14 set) is
//   disassembled in ARM mode and made a function.
// Pass 2 (Thumb): halfword `push {..., lr}` (0xB5xx) and `push.w {..., lr}`
//   (0xE92D + 0x4xxx) outside existing code are disassembled in Thumb mode and
//   made functions.
//
// Run before auto-analysis; analysis then follows calls from the seeds.
//
// Usage:
//   analyzeHeadless ... -import blob.bin -loader BinaryLoader \
//     -loader-baseAddr 0xe00100 -processor ARM:LE:32:v8 -noanalysis \
//     -scriptPath ghidra_scripts/setup -postScript SeedRawPrologues.java
//
//@category PSP.Setup

import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class SeedRawPrologues extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        Register tmode = currentProgram.getLanguage().getRegister("TMode");
        int armFunctions = 0;
        int thumbFunctions = 0;

        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute() && !block.isRead()) {
                continue;
            }
            Address start = block.getStart();
            long size = block.getSize();

            for (long off = 0; off + 4 <= size; off += 4) {
                Address addr = start.add(off);
                int word = mem.getInt(addr);
                if ((word & 0xFFFF0000) == 0xE92D0000 && (word & 0x4000) != 0) {
                    setMode(tmode, addr, 0);
                    if (listing.getInstructionContaining(addr) == null && disassemble(addr)) {
                        createFunction(addr, null);
                        armFunctions++;
                    }
                }
            }
            for (long off = 0; off + 2 <= size; off += 2) {
                Address addr = start.add(off);
                if (listing.getInstructionContaining(addr) != null
                        || listing.getDefinedDataContaining(addr) != null) {
                    continue;
                }
                int half = mem.getShort(addr) & 0xFFFF;
                boolean pushLr = (half & 0xFF00) == 0xB500;
                if (!pushLr && half == 0xE92D && off + 4 <= size) {
                    pushLr = (mem.getShort(addr.add(2)) & 0x4000) != 0;
                }
                if (pushLr) {
                    setMode(tmode, addr, 1);
                    if (disassemble(addr)) {
                        createFunction(addr, null);
                        thumbFunctions++;
                    }
                }
            }
        }
        println("SeedRawPrologues: " + armFunctions + " ARM and " + thumbFunctions
                + " Thumb function seeds");
    }

    private void setMode(Register tmode, Address addr, int value) throws Exception {
        if (tmode != null) {
            currentProgram.getProgramContext().setValue(tmode, addr, addr, BigInteger.valueOf(value));
        }
    }
}
