// FindMailboxPatterns.java — Find and report mailbox register access patterns.
//
// Searches for functions that interact with the PSP mailbox registers
// (0x3010570-0x301057B) via:
//   1. Direct references / scalar operands containing mailbox addresses
//   2. MOVW/MOVT pairs that construct mailbox base address in a register
//   3. LDR from literal pools that contain mailbox addresses
//
// Then reports shift/mask/compare patterns in a window around each access
// to reconstruct the message type dispatch logic.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name>/<folder> \
//     -recursive -process -noanalysis -readOnly \
//     -scriptPath ghidra_scripts/analysis \
//     -postScript FindMailboxPatterns.java [--verbose]
//
//@category PSP.Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.Memory;
import java.util.*;

public class FindMailboxPatterns extends GhidraScript {

    // Mailbox MMIO range
    private static final long MBX_BASE = 0x3010570L;
    private static final long MBX_END  = 0x301057BL;
    // Wider range to catch base+offset patterns (e.g. LDR [Rn, #4] from base 0x3010570)
    private static final long MBX_REGION_START = 0x3010560L;
    private static final long MBX_REGION_END   = 0x3010580L;

    private static final String[] MBX_REG_NAMES = {
        "MBX_CMD", "MBX_STS", "MBX_IFACE", "MBX_03",
        "MBX_DATA_LO", "MBX_DATA_HI", "MBX_06", "MBX_07",
        "MBX_08", "MBX_09", "MBX_0A"
    };

    private boolean verbose = false;

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        String[] args = getScriptArgs();
        for (String arg : args) {
            if (arg.equals("--verbose")) verbose = true;
        }

        Listing listing = currentProgram.getListing();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Memory memory = currentProgram.getMemory();

        // Phase 1: Find all instructions referencing mailbox addresses
        // via direct references, scalar operands, or MOVW/MOVT construction
        Map<Function, List<MailboxAccess>> funcAccesses = new LinkedHashMap<>();
        Set<Address> movwMovtFuncAddrs = new HashSet<>();

        InstructionIterator instrIt = listing.getInstructions(true);
        while (instrIt.hasNext()) {
            Instruction instr = instrIt.next();
            String mn = instr.getMnemonicString().toLowerCase();

            // Check 1: Direct references / scalar operands
            Long mbxAddr = findMailboxReference(instr);
            if (mbxAddr != null) {
                recordAccess(funcMgr, funcAccesses, instr, mbxAddr, "direct");
                continue;
            }

            // Check 2: MOVW with low 16 bits of a mailbox address
            if (mn.equals("movw")) {
                Scalar s = findScalar(instr);
                if (s != null) {
                    long val = s.getUnsignedValue();
                    // Low 16 bits of 0x03010570 = 0x0570
                    // Also check nearby: 0x0574 (DATA_LO), 0x0578 (MBX_08)
                    if (val >= 0x0560 && val <= 0x0580) {
                        // Look forward for MOVT with 0x0301
                        Instruction next = findNextInstr(listing, instr, 3);
                        if (next != null) {
                            String nextMn = next.getMnemonicString().toLowerCase();
                            if (nextMn.equals("movt")) {
                                Scalar nextS = findScalar(next);
                                if (nextS != null && nextS.getUnsignedValue() == 0x0301) {
                                    long fullAddr = (0x0301L << 16) | val;
                                    recordAccess(funcMgr, funcAccesses, instr, fullAddr, "movw/movt");
                                }
                            }
                        }
                    }
                }
            }

            // Check 3: LDR from literal pool — check if the loaded constant
            // is a mailbox address
            if (mn.startsWith("ldr") && !mn.contains("str")) {
                Reference[] refs = instr.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isData()) {
                        try {
                            Address dataAddr = ref.getToAddress();
                            // Read the 4-byte value at the literal pool address
                            int val = memory.getInt(dataAddr);
                            long uval = val & 0xFFFFFFFFL;
                            if (uval >= MBX_BASE && uval <= MBX_END) {
                                recordAccess(funcMgr, funcAccesses, instr, uval, "litpool");
                            }
                        } catch (Exception e) {
                            // Can't read memory here
                        }
                    }
                }
            }
        }

        if (funcAccesses.isEmpty()) {
            println("No mailbox accesses found in " + currentProgram.getName());
            return;
        }

        println("=== Mailbox Patterns in " + currentProgram.getName() + " ===");
        println("  Functions with mailbox access: " + funcAccesses.size());
        println("");

        // Phase 2: For each function, analyze shift/mask patterns and
        // string references for protocol context
        int totalPatterns = 0;

        for (Map.Entry<Function, List<MailboxAccess>> entry : funcAccesses.entrySet()) {
            Function func = entry.getKey();
            List<MailboxAccess> accesses = entry.getValue();

            String funcName = func.getName();
            SourceType src = func.getSymbol().getSource();
            String nameTag = (src == SourceType.DEFAULT) ? funcName : funcName + " (named)";
            long bodySize = func.getBody().getNumAddresses();

            // Collect string references in this function for context
            List<String> funcStrings = collectFunctionStrings(func, listing);

            println("--- " + nameTag + " @ 0x" +
                    Long.toHexString(func.getEntryPoint().getOffset()) +
                    " (size=" + bodySize + ")" +
                    " accesses=" + accesses.size() + " ---");

            if (!funcStrings.isEmpty()) {
                println("  Strings:");
                for (String s : funcStrings) {
                    println("    \"" + s + "\"");
                }
            }

            // Deduplicate accesses by instruction address
            Set<Address> seen = new HashSet<>();
            for (MailboxAccess access : accesses) {
                if (!seen.add(access.instrAddr)) continue;

                String accessType = access.isWrite ? "WRITE" :
                                    (access.isRead ? "READ" : "REF");
                println(String.format("  [%s] %s @ 0x%08X  (%s, %s @ 0x%s)",
                    accessType, access.regName, access.mmioAddr,
                    access.source, access.mnemonic, access.instrAddr));

                // Search in a window around this instruction for patterns
                List<String> patterns = findShiftMaskPatterns(listing, access.instrAddr, 20);
                for (String p : patterns) {
                    println("    " + p);
                    totalPatterns++;
                }
            }
            println("");
        }

        println("=== Summary ===");
        println("  Functions:           " + funcAccesses.size());
        println("  Shift/mask patterns: " + totalPatterns);
    }

    private void recordAccess(FunctionManager funcMgr,
                               Map<Function, List<MailboxAccess>> map,
                               Instruction instr, long mbxAddr, String source) {
        Function func = funcMgr.getFunctionContaining(instr.getAddress());
        if (func == null) return;

        String mn = instr.getMnemonicString().toLowerCase();
        boolean isWrite = mn.startsWith("str") || mn.startsWith("stm");
        boolean isRead = mn.startsWith("ldr") || mn.startsWith("ldm");

        MailboxAccess access = new MailboxAccess(
            instr.getAddress(), mbxAddr, getRegName(mbxAddr),
            isRead, isWrite, mn, source);
        map.computeIfAbsent(func, k -> new ArrayList<>()).add(access);
    }

    private Long findMailboxReference(Instruction instr) {
        Reference[] refs = instr.getReferencesFrom();
        for (Reference ref : refs) {
            long addr = ref.getToAddress().getOffset();
            if (addr >= MBX_BASE && addr <= MBX_END) return addr;
        }
        for (int i = 0; i < instr.getNumOperands(); i++) {
            Object[] ops = instr.getOpObjects(i);
            for (Object o : ops) {
                if (o instanceof Scalar) {
                    long val = ((Scalar) o).getUnsignedValue();
                    if (val >= MBX_BASE && val <= MBX_END) return val;
                }
            }
        }
        return null;
    }

    private List<String> findShiftMaskPatterns(Listing listing, Address startAddr, int window) {
        List<String> patterns = new ArrayList<>();
        Address addr = startAddr;

        for (int i = 0; i < window; i++) {
            Instruction instr = listing.getInstructionAfter(addr);
            if (instr == null) break;
            addr = instr.getAddress();

            String mn = instr.getMnemonicString().toLowerCase();

            if (mn.equals("lsr") || mn.equals("lsl") || mn.equals("asr") || mn.equals("ror")) {
                Scalar shift = findScalar(instr);
                if (shift != null) {
                    patterns.add("SHIFT: " + formatInstr(instr) + "  (shift by " + shift.getUnsignedValue() + ")");
                } else {
                    patterns.add("SHIFT: " + formatInstr(instr));
                }
            } else if (mn.equals("ubfx") || mn.equals("sbfx") || mn.equals("bfi") || mn.equals("bfc")) {
                patterns.add("BITFIELD: " + formatInstr(instr));
            } else if (mn.equals("and") || mn.equals("ands") || mn.equals("bic") || mn.equals("bics")) {
                Scalar mask = findScalar(instr);
                if (mask != null) {
                    patterns.add("MASK: " + formatInstr(instr) +
                                 "  (0x" + Long.toHexString(mask.getUnsignedValue()) + ")");
                } else {
                    patterns.add("MASK: " + formatInstr(instr));
                }
            } else if (mn.equals("cmp") || mn.equals("cmn") || mn.equals("tst")) {
                Scalar val = findScalar(instr);
                if (val != null) {
                    patterns.add("CMP: " + formatInstr(instr) +
                                 "  (value=0x" + Long.toHexString(val.getUnsignedValue()) + ")");
                }
            } else if ((mn.equals("mov") || mn.equals("movs")) &&
                       instr.toString().toLowerCase().contains("lsr")) {
                patterns.add("MOV+SHIFT: " + formatInstr(instr));
            }
            // Switch table detection: TBB/TBH (table branch byte/halfword)
            else if (mn.equals("tbb") || mn.equals("tbh")) {
                patterns.add("SWITCH: " + formatInstr(instr) + "  (table branch — dispatch)");
            }
        }
        return patterns;
    }

    private List<String> collectFunctionStrings(Function func, Listing listing) {
        List<String> strings = new ArrayList<>();
        AddressSetView body = func.getBody();
        if (body == null) return strings;

        InstructionIterator it = listing.getInstructions(body, true);
        while (it.hasNext()) {
            Instruction instr = it.next();
            Reference[] refs = instr.getReferencesFrom();
            for (Reference ref : refs) {
                if (!ref.getReferenceType().isData()) continue;
                Data d = listing.getDataAt(ref.getToAddress());
                if (d != null && d.hasStringValue()) {
                    String val = (String) d.getValue();
                    if (val != null && val.length() >= 4 && strings.size() < 20) {
                        // Truncate long strings
                        if (val.length() > 80) val = val.substring(0, 80) + "...";
                        if (!strings.contains(val)) {
                            strings.add(val);
                        }
                    }
                }
            }
        }
        return strings;
    }

    private Instruction findNextInstr(Listing listing, Instruction instr, int maxForward) {
        Address addr = instr.getAddress();
        for (int i = 0; i < maxForward; i++) {
            Instruction next = listing.getInstructionAfter(addr);
            if (next == null) return null;
            addr = next.getAddress();
            // Return first instruction that isn't a NOP
            String mn = next.getMnemonicString().toLowerCase();
            if (!mn.equals("nop")) return next;
        }
        return null;
    }

    private Scalar findScalar(Instruction instr) {
        for (int i = 0; i < instr.getNumOperands(); i++) {
            Object[] ops = instr.getOpObjects(i);
            for (Object o : ops) {
                if (o instanceof Scalar) return (Scalar) o;
            }
        }
        return null;
    }

    private String formatInstr(Instruction instr) {
        return String.format("0x%s: %s",
            instr.getAddress().toString().replaceAll("^0+", ""),
            instr.toString());
    }

    private String getRegName(long addr) {
        int offset = (int)(addr - MBX_BASE);
        if (offset >= 0 && offset < MBX_REG_NAMES.length) {
            return MBX_REG_NAMES[offset];
        }
        return "MBX_" + String.format("%02X", offset);
    }

    static class MailboxAccess {
        Address instrAddr;
        long mmioAddr;
        String regName;
        boolean isRead;
        boolean isWrite;
        String mnemonic;
        String source; // "direct", "movw/movt", "litpool"

        MailboxAccess(Address instrAddr, long mmioAddr, String regName,
                      boolean isRead, boolean isWrite, String mnemonic, String source) {
            this.instrAddr = instrAddr;
            this.mmioAddr = mmioAddr;
            this.regName = regName;
            this.isRead = isRead;
            this.isWrite = isWrite;
            this.mnemonic = mnemonic;
            this.source = source;
        }
    }
}
