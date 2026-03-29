// AnnotateMMIO.java — Find and label MMIO register accesses in PSP firmware.
//
// Scans all instructions for memory references to known MMIO regions and
// adds labels + plate comments. Specifically flags mailbox register writes.
//
// Usage:
//   analyzeHeadless ... -process <program> -noanalysis \
//     -postScript AnnotateMMIO.java
//
//@category PSP.Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import java.util.*;

public class AnnotateMMIO extends GhidraScript {

    // Known MMIO regions from memory_layout.json
    private static final long[][] REGIONS = {
        // {start, end, name_index}
        {0x3000000, 0x3001000, 0},  // CCP_Control
        {0x3001000, 0x3006000, 1},  // CCP_Queues
        {0x3006000, 0x3007000, 2},  // CCP_Config
        {0x3010004, 0x30103b0, 3},  // UnknownMMIO
        {0x30103b0, 0x3010400, 4},  // IRQ_Controller
        {0x3010424, 0x3010544, 5},  // Timer
        {0x3010570, 0x301057b, 6},  // Mailbox
        {0x32000e8, 0x3220000, 7},  // STS
        {0x3220000, 0x3220040, 8},  // SMN_MapCtrl
        {0x3230000, 0x32303e0, 9},  // x86_MapCtrl
        {0x32303e0, 0x32305f0, 10}, // x86_MapCtrl2
    };

    private static final String[] REGION_NAMES = {
        "CCP_Control", "CCP_Queues", "CCP_Config", "UnknownMMIO",
        "IRQ_Controller", "Timer", "Mailbox", "STS",
        "SMN_MapCtrl", "x86_MapCtrl", "x86_MapCtrl2"
    };

    // Mailbox register names (offsets from 0x3010570)
    private static final String[] MAILBOX_REGS = {
        "MBX_CMD",      // +0x0
        "MBX_STS",      // +0x1
        "MBX_IFACE",    // +0x2
        "MBX_03",       // +0x3
        "MBX_DATA_LO",  // +0x4
        "MBX_DATA_HI",  // +0x5
        "MBX_06",       // +0x6
        "MBX_07",       // +0x7
        "MBX_08",       // +0x8
        "MBX_09",       // +0x9
        "MBX_0A",       // +0xa
    };

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        Listing listing = currentProgram.getListing();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        SymbolTable symTable = currentProgram.getSymbolTable();

        Map<String, Integer> regionAccessCount = new LinkedHashMap<>();
        for (String name : REGION_NAMES) regionAccessCount.put(name, 0);

        int totalAnnotated = 0;
        int mailboxWrites = 0;
        Set<Long> labeledAddresses = new HashSet<>();

        // Scan all instructions
        InstructionIterator instrIt = listing.getInstructions(true);
        while (instrIt.hasNext()) {
            Instruction instr = instrIt.next();
            String mnemonic = instr.getMnemonicString().toLowerCase();

            // Look at all operand references and scalar values
            for (int i = 0; i < instr.getNumOperands(); i++) {
                // Check references from this instruction
                ghidra.program.model.symbol.Reference[] refs = instr.getOperandReferences(i);
                for (ghidra.program.model.symbol.Reference ref : refs) {
                    long addr = ref.getToAddress().getOffset();
                    String region = classifyAddress(addr);
                    if (region != null) {
                        annotateAccess(instr, addr, region, mnemonic, symTable, space, labeledAddresses);
                        regionAccessCount.merge(region, 1, Integer::sum);
                        totalAnnotated++;
                        if (region.equals("Mailbox") && isStore(mnemonic)) {
                            mailboxWrites++;
                        }
                    }
                }

                // Also check for immediate/scalar values that look like MMIO addresses
                Object[] opObjects = instr.getOpObjects(i);
                for (Object obj : opObjects) {
                    if (obj instanceof Scalar) {
                        long val = ((Scalar) obj).getUnsignedValue();
                        String region = classifyAddress(val);
                        if (region != null) {
                            annotateAccess(instr, val, region, mnemonic, symTable, space, labeledAddresses);
                            regionAccessCount.merge(region, 1, Integer::sum);
                            totalAnnotated++;
                            if (region.equals("Mailbox") && isStore(mnemonic)) {
                                mailboxWrites++;
                            }
                        }
                    }
                }
            }
        }

        // Also scan for indirect MMIO access patterns:
        // LDR Rn, =0x3010570  (load MMIO base into register)
        // Then STR Rm, [Rn, #offset]
        // We already catch the LDR via scalar operands above.

        // Print summary
        println("\n=== MMIO Access Summary for " + currentProgram.getName() + " ===");
        for (Map.Entry<String, Integer> e : regionAccessCount.entrySet()) {
            if (e.getValue() > 0) {
                println(String.format("  %-20s %d access(es)", e.getKey(), e.getValue()));
            }
        }
        println("  Total annotated: " + totalAnnotated);
        println("  Mailbox writes:  " + mailboxWrites);
    }

    private String classifyAddress(long addr) {
        for (int i = 0; i < REGIONS.length; i++) {
            if (addr >= REGIONS[i][0] && addr < REGIONS[i][1]) {
                return REGION_NAMES[(int) REGIONS[i][2]];
            }
        }
        return null;
    }

    private boolean isStore(String mnemonic) {
        return mnemonic.startsWith("str") || mnemonic.startsWith("stm") ||
               mnemonic.startsWith("push");
    }

    private void annotateAccess(Instruction instr, long mmioAddr, String region,
                                 String mnemonic, SymbolTable symTable,
                                 AddressSpace space, Set<Long> labeled) {
        // Add label at the MMIO address if not already labeled
        if (!labeled.contains(mmioAddr)) {
            try {
                Address addr = space.getAddress(mmioAddr);
                String labelName;
                if (region.equals("Mailbox")) {
                    int offset = (int)(mmioAddr - 0x3010570);
                    if (offset >= 0 && offset < MAILBOX_REGS.length) {
                        labelName = MAILBOX_REGS[offset];
                    } else {
                        labelName = "MBX_" + String.format("%02X", offset);
                    }
                } else {
                    int offset = (int)(mmioAddr - getRegionStart(region));
                    labelName = region + "_" + String.format("%03X", offset);
                }

                Symbol existing = symTable.getPrimarySymbol(addr);
                if (existing == null || existing.getSource() == SourceType.DEFAULT) {
                    symTable.createLabel(addr, labelName, SourceType.USER_DEFINED);
                    labeled.add(mmioAddr);
                }
            } catch (Exception e) {
                // Address might not be in a memory block
            }
        }

        // Add plate comment at the instruction
        String accessType = isStore(mnemonic) ? "WRITE" : "READ";
        String comment = String.format("[%s] %s @ 0x%08X", accessType, region, mmioAddr);
        String existing = instr.getComment(CodeUnit.PLATE_COMMENT);
        if (existing == null || !existing.contains(region)) {
            if (existing != null) {
                comment = existing + "\n" + comment;
            }
            instr.setComment(CodeUnit.PLATE_COMMENT, comment);
        }
    }

    private long getRegionStart(String region) {
        for (int i = 0; i < REGIONS.length; i++) {
            if (REGION_NAMES[(int) REGIONS[i][2]].equals(region)) {
                return REGIONS[i][0];
            }
        }
        return 0;
    }
}
