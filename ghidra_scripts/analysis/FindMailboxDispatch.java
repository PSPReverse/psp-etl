// FindMailboxDispatch.java — Find mailbox command dispatch logic by tracing
// string references, SVC patterns, and call chains.
//
// In newer firmware (zen5+), mailbox access may be abstracted behind helper
// functions. This script finds the dispatch logic by:
//   1. Finding functions with mailbox-related strings
//   2. Finding functions that call the direct-mailbox-access functions
//   3. Looking for switch/dispatch patterns (TBB/TBH, compare chains)
//   4. Reporting the full call context
//
// Usage:
//   analyzeHeadless ... -process <program> -noanalysis -readOnly \
//     -scriptPath ghidra_scripts/analysis \
//     -postScript FindMailboxDispatch.java
//
//@category PSP.Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.*;

public class FindMailboxDispatch extends GhidraScript {

    private static final long MBX_BASE = 0x3010570L;
    private static final long MBX_END  = 0x301057BL;

    // Strings that indicate mailbox/BIOS/x86 communication
    private static final String[] MBX_KEYWORDS = {
        "mailbox", "mbox", "mbx", "bios", "x86",
        "message", "command", "cmd_id", "msg_id",
        "request", "response", "dispatch", "handler",
        "steady", "release", "gasket", "smu",
        "Unrecognized command", "msg failed"
    };

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        Listing listing = currentProgram.getListing();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        println("=== Mailbox Dispatch Analysis: " + currentProgram.getName() + " ===\n");

        // === Phase 1: Find direct mailbox accessor functions ===
        Set<Function> directAccessors = new HashSet<>();
        InstructionIterator allInstr = listing.getInstructions(true);
        while (allInstr.hasNext()) {
            Instruction instr = allInstr.next();
            if (referencesMailbox(instr)) {
                Function f = funcMgr.getFunctionContaining(instr.getAddress());
                if (f != null) directAccessors.add(f);
            }
        }

        println("Phase 1: Direct mailbox accessor functions: " + directAccessors.size());
        for (Function f : directAccessors) {
            println("  0x" + Long.toHexString(f.getEntryPoint().getOffset()) +
                    " " + f.getName() + " (size=" + f.getBody().getNumAddresses() + ")");
        }
        println("");

        // === Phase 2: Find callers of direct accessor functions ===
        Set<Function> callers = new LinkedHashSet<>();
        Set<Function> callerOfCallers = new LinkedHashSet<>();

        for (Function accessor : directAccessors) {
            ReferenceIterator refs = refMgr.getReferencesTo(accessor.getEntryPoint());
            while (refs.hasNext()) { Reference ref = refs.next();
                if (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) {
                    Function caller = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (caller != null && !directAccessors.contains(caller)) {
                        callers.add(caller);
                    }
                }
            }
        }

        println("Phase 2: Callers of mailbox functions: " + callers.size());
        for (Function f : callers) {
            List<String> strings = collectStrings(f, listing);
            long size = f.getBody().getNumAddresses();
            println("  0x" + Long.toHexString(f.getEntryPoint().getOffset()) +
                    " " + f.getName() + " (size=" + size + ")");
            for (String s : strings) {
                println("    \"" + s + "\"");
            }

            // Find callers of callers (one more level)
            ReferenceIterator refs2 = refMgr.getReferencesTo(f.getEntryPoint());
            while (refs2.hasNext()) { Reference ref = refs2.next();
                if (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) {
                    Function c2 = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (c2 != null && !directAccessors.contains(c2) && !callers.contains(c2)) {
                        callerOfCallers.add(c2);
                    }
                }
            }
        }
        println("");

        println("Phase 2b: Callers-of-callers: " + callerOfCallers.size());
        for (Function f : callerOfCallers) {
            List<String> strings = collectStrings(f, listing);
            long size = f.getBody().getNumAddresses();
            if (!strings.isEmpty() || size > 200) {
                println("  0x" + Long.toHexString(f.getEntryPoint().getOffset()) +
                        " " + f.getName() + " (size=" + size + ")");
                for (String s : strings) {
                    println("    \"" + s + "\"");
                }
            }
        }
        println("");

        // === Phase 3: Find functions with mailbox-related strings ===
        Map<Function, List<String>> stringFunctions = new LinkedHashMap<>();
        FunctionIterator funcIt = funcMgr.getFunctions(true);
        while (funcIt.hasNext()) {
            Function f = funcIt.next();
            List<String> strings = collectStrings(f, listing);
            List<String> mbxStrings = new ArrayList<>();
            for (String s : strings) {
                String lower = s.toLowerCase();
                for (String kw : MBX_KEYWORDS) {
                    if (lower.contains(kw.toLowerCase())) {
                        mbxStrings.add(s);
                        break;
                    }
                }
            }
            if (!mbxStrings.isEmpty()) {
                stringFunctions.put(f, mbxStrings);
            }
        }

        println("Phase 3: Functions with mailbox-related strings: " + stringFunctions.size());
        for (Map.Entry<Function, List<String>> entry : stringFunctions.entrySet()) {
            Function f = entry.getKey();
            long size = f.getBody().getNumAddresses();
            println("  0x" + Long.toHexString(f.getEntryPoint().getOffset()) +
                    " " + f.getName() + " (size=" + size + ")");
            for (String s : entry.getValue()) {
                println("    \"" + s + "\"");
            }

            // Look for dispatch patterns in these functions
            List<String> dispatches = findDispatchPatterns(listing, f);
            for (String d : dispatches) {
                println("    " + d);
            }
        }
        println("");

        // === Phase 4: Large compare chains (potential dispatch tables) ===
        println("Phase 4: Functions with dense compare chains (>=4 CMPs):");
        funcIt = funcMgr.getFunctions(true);
        while (funcIt.hasNext()) {
            Function f = funcIt.next();
            AddressSetView body = f.getBody();
            if (body == null) continue;

            int cmpCount = 0;
            Set<Long> cmpValues = new TreeSet<>();
            InstructionIterator it = listing.getInstructions(body, true);
            while (it.hasNext()) {
                Instruction instr = it.next();
                String mn = instr.getMnemonicString().toLowerCase();
                if (mn.equals("cmp") || mn.equals("tst")) {
                    Scalar s = findScalar(instr);
                    if (s != null && s.getUnsignedValue() > 0 && s.getUnsignedValue() < 0x100) {
                        cmpCount++;
                        cmpValues.add(s.getUnsignedValue());
                    }
                }
            }

            if (cmpCount >= 4 && cmpValues.size() >= 4) {
                long size = body.getNumAddresses();
                // Check if this function also has UBFX or shift patterns
                boolean hasShift = false;
                it = listing.getInstructions(body, true);
                while (it.hasNext()) {
                    String mn = it.next().getMnemonicString().toLowerCase();
                    if (mn.equals("ubfx") || mn.equals("lsr") || mn.equals("sbfx")) {
                        hasShift = true;
                        break;
                    }
                }

                List<String> strings = collectStrings(f, listing);
                boolean inCallChain = directAccessors.contains(f) ||
                                      callers.contains(f) || callerOfCallers.contains(f);

                // Only report if it's in the call chain or has relevant strings or shifts
                if (inCallChain || hasShift || !strings.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("  0x").append(Long.toHexString(f.getEntryPoint().getOffset()));
                    sb.append(" ").append(f.getName());
                    sb.append(" (size=").append(size).append(")");
                    sb.append(" CMPs=").append(cmpCount);
                    if (hasShift) sb.append(" HAS_SHIFT");
                    if (inCallChain) sb.append(" IN_CALLCHAIN");
                    println(sb.toString());

                    // Print compare values
                    StringBuilder vals = new StringBuilder("    values: ");
                    for (Long v : cmpValues) {
                        vals.append("0x").append(Long.toHexString(v)).append(" ");
                    }
                    println(vals.toString());

                    for (String s : strings) {
                        println("    \"" + s + "\"");
                    }
                }
            }
        }

        println("\n=== Analysis Complete ===");
    }

    private boolean referencesMailbox(Instruction instr) {
        Reference[] refs = instr.getReferencesFrom();
        for (Reference ref : refs) {
            long addr = ref.getToAddress().getOffset();
            if (addr >= MBX_BASE && addr <= MBX_END) return true;
        }
        for (int i = 0; i < instr.getNumOperands(); i++) {
            Object[] ops = instr.getOpObjects(i);
            for (Object o : ops) {
                if (o instanceof Scalar) {
                    long val = ((Scalar) o).getUnsignedValue();
                    if (val >= MBX_BASE && val <= MBX_END) return true;
                }
            }
        }
        return false;
    }

    private List<String> findDispatchPatterns(Listing listing, Function func) {
        List<String> results = new ArrayList<>();
        AddressSetView body = func.getBody();
        if (body == null) return results;

        InstructionIterator it = listing.getInstructions(body, true);
        while (it.hasNext()) {
            Instruction instr = it.next();
            String mn = instr.getMnemonicString().toLowerCase();

            if (mn.equals("ubfx") || mn.equals("sbfx")) {
                results.add("  BITFIELD: " + instr.toString());
            } else if (mn.equals("tbb") || mn.equals("tbh")) {
                results.add("  SWITCH TABLE: " + instr.toString());
            }
        }
        return results;
    }

    private List<String> collectStrings(Function func, Listing listing) {
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
                    if (val != null && val.length() >= 4 && strings.size() < 15) {
                        if (val.length() > 80) val = val.substring(0, 80) + "...";
                        if (!strings.contains(val)) strings.add(val);
                    }
                }
            }
        }
        return strings;
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
}
