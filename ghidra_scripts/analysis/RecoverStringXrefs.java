// RecoverStringXrefs.java — Recover missing string cross-references in ARM binaries.
//
// Scans for: literal pool LDR, MOVW/MOVT pairs, pointer tables.
// Creates data references from instructions to strings.
//
//@category PSP.Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.data.*;

public class RecoverStringXrefs extends GhidraScript {

    private int xrefsCreated = 0;
    private int stringsFound = 0;

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // Count strings with and without xrefs before
        int totalStrings = 0;
        int referencedBefore = 0;
        DataIterator dataIt = listing.getDefinedData(true);
        while (dataIt.hasNext()) {
            Data d = dataIt.next();
            if (d.hasStringValue()) {
                totalStrings++;
                if (refMgr.getReferenceCountTo(d.getMinAddress()) > 0) referencedBefore++;
            }
        }

        println("Before: " + totalStrings + " strings, " + referencedBefore + " with xrefs, " +
                (totalStrings - referencedBefore) + " orphaned");

        // === Pass 1: Scan raw bytes for string addresses in code sections ===
        // ARM literal pools: 32-bit values after branches that point to strings
        println("--- Pass 1: Literal pool / data reference scan ---");
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || block.isVolatile()) continue;
            if (block.getSize() > 0x100000) continue;
            if (!block.isExecute() && !block.isRead()) continue;

            long blockStart = block.getStart().getOffset();
            long blockEnd = block.getEnd().getOffset();
            long size = block.getSize();

            // Scan for 32-bit values that point to defined strings
            byte[] data = new byte[(int) Math.min(size, 0x100000)];
            mem.getBytes(block.getStart(), data);

            for (int i = 0; i <= data.length - 4; i += 4) {
                long val = ((data[i] & 0xFFL)) |
                          ((data[i+1] & 0xFFL) << 8) |
                          ((data[i+2] & 0xFFL) << 16) |
                          ((data[i+3] & 0xFFL) << 24);

                if (val < 0x100 || val > 0xFFFFFF) continue;

                Address target;
                try {
                    target = space.getAddress(val);
                } catch (Exception e) { continue; }

                Data strData = listing.getDataAt(target);
                if (strData != null && strData.hasStringValue()) {
                    Address from = space.getAddress(blockStart + i);
                    // Don't add if reference already exists
                    if (refMgr.getReferenceCountTo(target) > 0) {
                        Reference[] existing = refMgr.getReferencesFrom(from);
                        boolean found = false;
                        for (Reference r : existing) {
                            if (r.getToAddress().equals(target)) { found = true; break; }
                        }
                        if (found) continue;
                    }
                    // Only add if 'from' is in a code area or after a branch
                    Instruction instr = listing.getInstructionContaining(from);
                    if (instr == null) {
                        // This is in a literal pool (data between functions)
                        refMgr.addMemoryReference(from, target,
                            RefType.DATA, SourceType.ANALYSIS, 0);
                        xrefsCreated++;
                    }
                }
            }
        }
        println("  Literal pool xrefs: " + xrefsCreated);

        // === Pass 2: MOVW/MOVT pair recovery ===
        println("--- Pass 2: MOVW/MOVT pairs ---");
        int movPairs = 0;
        InstructionIterator instrIt = listing.getInstructions(true);
        while (instrIt.hasNext()) {
            Instruction instr = instrIt.next();
            String mn = instr.getMnemonicString().toLowerCase();

            if (!mn.equals("movw")) continue;
            if (instr.getNumOperands() < 2) continue;

            // Get the low 16 bits
            Object[] ops = instr.getOpObjects(1);
            long lo16 = -1;
            for (Object o : ops) {
                if (o instanceof Scalar) {
                    lo16 = ((Scalar) o).getUnsignedValue();
                    break;
                }
            }
            if (lo16 < 0) continue;

            // Get destination register
            String destReg = instr.getDefaultOperandRepresentation(0);

            // Search forward for MOVT to same register (within 5 instructions)
            Instruction scan = instr;
            for (int i = 0; i < 5; i++) {
                scan = listing.getInstructionAfter(scan.getMaxAddress());
                if (scan == null) break;
                String smn = scan.getMnemonicString().toLowerCase();
                if (smn.equals("movt") && scan.getNumOperands() >= 2) {
                    String tReg = scan.getDefaultOperandRepresentation(0);
                    if (tReg.equals(destReg)) {
                        Object[] tops = scan.getOpObjects(1);
                        for (Object o : tops) {
                            if (o instanceof Scalar) {
                                long hi16 = ((Scalar) o).getUnsignedValue();
                                long fullAddr = (hi16 << 16) | lo16;

                                Address target;
                                try {
                                    target = space.getAddress(fullAddr);
                                } catch (Exception e) { break; }

                                Data strData = listing.getDataAt(target);
                                if (strData != null && strData.hasStringValue()) {
                                    // Add reference from MOVW instruction
                                    refMgr.addMemoryReference(instr.getMinAddress(), target,
                                        RefType.DATA, SourceType.ANALYSIS, 1);
                                    xrefsCreated++;
                                    movPairs++;
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
                // Stop at branches
                if (smn.startsWith("b") && !smn.equals("bic") && !smn.equals("bfc") && !smn.equals("bfi")) break;
            }
        }
        println("  MOVW/MOVT pairs: " + movPairs);

        // === Pass 3: Pointer table scan ===
        println("--- Pass 3: Pointer tables ---");
        int tablePtrs = 0;
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || block.isVolatile() || block.isExecute()) continue;
            if (block.getSize() > 0x100000) continue;

            byte[] data = new byte[(int) block.getSize()];
            mem.getBytes(block.getStart(), data);
            long blockStart = block.getStart().getOffset();

            // Look for runs of 3+ consecutive pointers to strings
            int consecutiveStringPtrs = 0;
            long tableStart = -1;

            for (int i = 0; i <= data.length - 4; i += 4) {
                long val = ((data[i] & 0xFFL)) |
                          ((data[i+1] & 0xFFL) << 8) |
                          ((data[i+2] & 0xFFL) << 16) |
                          ((data[i+3] & 0xFFL) << 24);

                Address target;
                try {
                    target = space.getAddress(val);
                } catch (Exception e) {
                    consecutiveStringPtrs = 0;
                    continue;
                }

                Data strData = listing.getDataAt(target);
                if (strData != null && strData.hasStringValue()) {
                    if (consecutiveStringPtrs == 0) tableStart = blockStart + i;
                    consecutiveStringPtrs++;
                } else {
                    if (consecutiveStringPtrs >= 3) {
                        // Found a string pointer table
                        for (int j = 0; j < consecutiveStringPtrs; j++) {
                            long ptrOff = (tableStart - blockStart) + j * 4;
                            long pval = ((data[(int)ptrOff] & 0xFFL)) |
                                       ((data[(int)ptrOff+1] & 0xFFL) << 8) |
                                       ((data[(int)ptrOff+2] & 0xFFL) << 16) |
                                       ((data[(int)ptrOff+3] & 0xFFL) << 24);
                            Address from = space.getAddress(tableStart + j * 4);
                            Address to = space.getAddress(pval);
                            refMgr.addMemoryReference(from, to,
                                RefType.DATA, SourceType.ANALYSIS, 0);
                            tablePtrs++;
                            xrefsCreated++;
                        }
                    }
                    consecutiveStringPtrs = 0;
                }
            }
        }
        println("  Pointer table entries: " + tablePtrs);

        // Count after
        int referencedAfter = 0;
        dataIt = listing.getDefinedData(true);
        while (dataIt.hasNext()) {
            Data d = dataIt.next();
            if (d.hasStringValue() && refMgr.getReferenceCountTo(d.getMinAddress()) > 0) {
                referencedAfter++;
            }
        }

        println("\n=== Summary for " + currentProgram.getName() + " ===");
        println("  Total xrefs created: " + xrefsCreated);
        println("  Strings with xrefs: " + referencedBefore + " -> " + referencedAfter +
                " (+" + (referencedAfter - referencedBefore) + ")");
        println("  Still orphaned: " + (totalStrings - referencedAfter));
    }
}
