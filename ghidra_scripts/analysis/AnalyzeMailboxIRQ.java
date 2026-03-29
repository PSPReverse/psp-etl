// AnalyzeMailboxIRQ.java — Trace the mailbox interrupt → dispatch chain.
//
// Finds the interrupt handler by looking for:
//   1. The direct mailbox accessor function and its context
//   2. Functions that access the IRQ controller (0x30103B0)
//   3. The large dispatch function (most CMPs with command-range values)
//   4. Shared state variables between the IRQ handler and dispatcher
//
// Dumps detailed instruction listings for key functions to support
// manual analysis of the command protocol.
//
// Usage:
//   analyzeHeadless ... -process <program> -noanalysis -readOnly \
//     -scriptPath ghidra_scripts/analysis \
//     -postScript AnalyzeMailboxIRQ.java
//
//@category PSP.Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.Memory;
import java.util.*;

public class AnalyzeMailboxIRQ extends GhidraScript {

    private static final long MBX_BASE = 0x3010570L;
    private static final long MBX_END  = 0x301057BL;
    private static final long IRQ_BASE = 0x30103B0L;
    private static final long IRQ_END  = 0x3010400L;

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        Listing listing = currentProgram.getListing();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Memory memory = currentProgram.getMemory();

        println("=== Mailbox IRQ Chain Analysis: " + currentProgram.getName() + " ===\n");

        // === Find direct mailbox accessors ===
        Set<Function> mbxFuncs = new LinkedHashSet<>();
        Set<Function> irqFuncs = new LinkedHashSet<>();

        InstructionIterator allInstr = listing.getInstructions(true);
        while (allInstr.hasNext()) {
            Instruction instr = allInstr.next();
            Long addr = findMMIORef(instr, MBX_BASE, MBX_END);
            if (addr != null) {
                Function f = funcMgr.getFunctionContaining(instr.getAddress());
                if (f != null) mbxFuncs.add(f);
            }
            addr = findMMIORef(instr, IRQ_BASE, IRQ_END);
            if (addr != null) {
                Function f = funcMgr.getFunctionContaining(instr.getAddress());
                if (f != null) irqFuncs.add(f);
            }
        }

        println("=== Direct Mailbox Accessors (" + mbxFuncs.size() + ") ===");
        for (Function f : mbxFuncs) {
            println("\n--- " + f.getName() + " @ 0x" +
                    Long.toHexString(f.getEntryPoint().getOffset()) +
                    " (size=" + f.getBody().getNumAddresses() + ") ---");
            dumpFunction(listing, f, 60);
        }

        println("\n=== IRQ Controller Accessors (" + irqFuncs.size() + ") ===");
        for (Function f : irqFuncs) {
            println("  0x" + Long.toHexString(f.getEntryPoint().getOffset()) +
                    " " + f.getName() + " (size=" + f.getBody().getNumAddresses() + ")");
        }

        // === Find the big dispatch function ===
        // Look for the function with the most small-value CMPs + shifts
        Function bestDispatch = null;
        int bestScore = 0;
        Map<Function, Set<Long>> funcCmpValues = new LinkedHashMap<>();

        FunctionIterator funcIt = funcMgr.getFunctions(true);
        while (funcIt.hasNext()) {
            Function f = funcIt.next();
            AddressSetView body = f.getBody();
            if (body == null) continue;

            Set<Long> cmpVals = new TreeSet<>();
            boolean hasShift = false;

            InstructionIterator it = listing.getInstructions(body, true);
            while (it.hasNext()) {
                Instruction instr = it.next();
                String mn = instr.getMnemonicString().toLowerCase();

                if (mn.equals("cmp")) {
                    Scalar s = findScalar(instr);
                    if (s != null && s.getUnsignedValue() > 0 && s.getUnsignedValue() < 0x100) {
                        cmpVals.add(s.getUnsignedValue());
                    }
                }
                if (mn.equals("ubfx") || mn.equals("lsr") || mn.equals("sbfx")) {
                    hasShift = true;
                }
            }

            if (hasShift && cmpVals.size() >= 8) {
                int score = cmpVals.size();
                funcCmpValues.put(f, cmpVals);
                if (score > bestScore) {
                    bestScore = score;
                    bestDispatch = f;
                }
            }
        }

        if (bestDispatch != null) {
            Set<Long> vals = funcCmpValues.get(bestDispatch);
            println("\n=== Main Dispatch Function ===");
            println("  " + bestDispatch.getName() + " @ 0x" +
                    Long.toHexString(bestDispatch.getEntryPoint().getOffset()) +
                    " (size=" + bestDispatch.getBody().getNumAddresses() + ")");
            println("  Unique command IDs (" + vals.size() + "):");

            StringBuilder sb = new StringBuilder("    ");
            for (Long v : vals) {
                sb.append(String.format("0x%02X ", v));
            }
            println(sb.toString());

            // Dump the function
            println("\n  --- Full Listing ---");
            dumpFunction(listing, bestDispatch, 300);

            // Find callers of the dispatch function
            println("\n  --- Callers ---");
            ReferenceIterator refs = refMgr.getReferencesTo(bestDispatch.getEntryPoint());
            while (refs.hasNext()) {
                Reference ref = refs.next();
                if (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) {
                    Function caller = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        println("  Called by: " + caller.getName() + " @ 0x" +
                                Long.toHexString(caller.getEntryPoint().getOffset()) +
                                " (size=" + caller.getBody().getNumAddresses() + ")");
                    }
                }
            }

            // Find what the dispatch function calls (handler targets)
            println("\n  --- Callees (handler functions) ---");
            Set<Function> callees = new TreeSet<>(
                Comparator.comparing(f -> f.getEntryPoint().getOffset()));
            AddressSetView body = bestDispatch.getBody();
            InstructionIterator it = listing.getInstructions(body, true);
            while (it.hasNext()) {
                Instruction instr = it.next();
                String mn = instr.getMnemonicString().toLowerCase();
                if (mn.startsWith("bl")) {
                    Reference[] callRefs = instr.getReferencesFrom();
                    for (Reference ref : callRefs) {
                        if (ref.getReferenceType().isCall()) {
                            Function callee = funcMgr.getFunctionAt(ref.getToAddress());
                            if (callee != null) callees.add(callee);
                        }
                    }
                }
            }
            for (Function callee : callees) {
                List<String> strings = collectStrings(callee, listing);
                println("  → " + callee.getName() + " @ 0x" +
                        Long.toHexString(callee.getEntryPoint().getOffset()) +
                        " (size=" + callee.getBody().getNumAddresses() + ")");
                for (String s : strings) {
                    println("      \"" + s + "\"");
                }
            }
        }

        // === Other dispatch candidates ===
        println("\n=== Other Dispatch Candidates ===");
        for (Map.Entry<Function, Set<Long>> entry : funcCmpValues.entrySet()) {
            Function f = entry.getKey();
            if (f.equals(bestDispatch)) continue;
            Set<Long> vals = entry.getValue();
            println("  " + f.getName() + " @ 0x" +
                    Long.toHexString(f.getEntryPoint().getOffset()) +
                    " (size=" + f.getBody().getNumAddresses() +
                    ") IDs=" + vals.size());
            StringBuilder sv = new StringBuilder("    ");
            for (Long v : vals) {
                sv.append(String.format("0x%02X ", v));
            }
            println(sv.toString());
        }

        println("\n=== Analysis Complete ===");
    }

    private void dumpFunction(Listing listing, Function func, int maxLines) {
        AddressSetView body = func.getBody();
        if (body == null) return;
        int lines = 0;
        InstructionIterator it = listing.getInstructions(body, true);
        while (it.hasNext() && lines < maxLines) {
            Instruction instr = it.next();
            String comment = "";
            // Annotate interesting instructions
            String mn = instr.getMnemonicString().toLowerCase();
            Long mmio = findMMIORef(instr, MBX_BASE, MBX_END);
            if (mmio != null) {
                int off = (int)(mmio - MBX_BASE);
                String[] names = {"CMD","STS","IFACE","03","DATA_LO","DATA_HI",
                                  "06","07","08","09","0A"};
                comment = " ; <<< MBX_" + (off < names.length ? names[off] : String.format("%02X",off)) + " >>>";
            }
            Long irq = findMMIORef(instr, IRQ_BASE, IRQ_END);
            if (irq != null) {
                comment = " ; <<< IRQ_" + String.format("%03X", irq - IRQ_BASE) + " >>>";
            }
            if (mn.equals("ubfx") || mn.equals("sbfx")) {
                comment += " ; <<< BITFIELD >>>";
            }
            if (mn.equals("tbb") || mn.equals("tbh")) {
                comment += " ; <<< SWITCH TABLE >>>";
            }

            println("  " + String.format("0x%08X", instr.getAddress().getOffset()) +
                    ": " + instr.toString() + comment);
            lines++;
        }
        if (it.hasNext()) println("  ... (truncated)");
    }

    private Long findMMIORef(Instruction instr, long rangeStart, long rangeEnd) {
        Reference[] refs = instr.getReferencesFrom();
        for (Reference ref : refs) {
            long addr = ref.getToAddress().getOffset();
            if (addr >= rangeStart && addr <= rangeEnd) return addr;
        }
        for (int i = 0; i < instr.getNumOperands(); i++) {
            Object[] ops = instr.getOpObjects(i);
            for (Object o : ops) {
                if (o instanceof Scalar) {
                    long val = ((Scalar) o).getUnsignedValue();
                    if (val >= rangeStart && val <= rangeEnd) return val;
                }
            }
        }
        return null;
    }

    private List<String> collectStrings(Function func, Listing listing) {
        List<String> strings = new ArrayList<>();
        AddressSetView body = func.getBody();
        if (body == null) return strings;
        InstructionIterator it = listing.getInstructions(body, true);
        while (it.hasNext()) {
            Instruction instr = it.next();
            for (Reference ref : instr.getReferencesFrom()) {
                if (!ref.getReferenceType().isData()) continue;
                Data d = listing.getDataAt(ref.getToAddress());
                if (d != null && d.hasStringValue()) {
                    String val = (String) d.getValue();
                    if (val != null && val.length() >= 4 && strings.size() < 10) {
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
