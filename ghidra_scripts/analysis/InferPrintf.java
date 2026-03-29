// InferPrintf.java — Find functions called with format string arguments and
// retype them as printf-like (varargs) with correct signatures.
//
// Strategy:
// 1. Scan all defined strings for format specifiers (%s, %d, %x, %08x, etc.)
// 2. For each format string, find code references TO that string
// 3. At each reference site, find the CALL instruction that uses the string as an arg
// 4. Track which functions receive format strings as arguments
// 5. Functions called with format strings in >N call sites → likely printf/log
// 6. Apply "int fname(char *fmt, ...)" signature
//
// Usage:
//   analyzeHeadless ... -process <program> \
//     -postScript InferPrintf.java [min_callsites]
//
//@category PSP.Analysis
// Default min_callsites = 3

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.*;
import java.util.*;
import java.util.regex.*;

public class InferPrintf extends GhidraScript {

    private static final Pattern FMT_RE = Pattern.compile(
        "%[-+0 #]*(\\d+|\\*)?(\\.\\d+|\\*)?[hlLqjzt]*[diouxXeEfFgGaAcspn%]");

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        String[] args = getScriptArgs();
        int minCalls = (args.length >= 1) ? Integer.parseInt(args[0]) : 3;

        Listing listing = currentProgram.getListing();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        // Step 1: Find all addresses containing format strings
        println("--- Scanning for format strings ---");
        Map<Address, String> fmtStrings = new LinkedHashMap<>();
        DataIterator dataIt = listing.getDefinedData(true);
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (!data.hasStringValue()) continue;
            String val = (String) data.getValue();
            if (val == null || val.length() < 4) continue;
            if (FMT_RE.matcher(val).find()) {
                fmtStrings.put(data.getMinAddress(), val);
            }
        }

        // Also scan raw bytes for format strings not yet defined as Data
        if (fmtStrings.isEmpty()) {
            println("No defined format strings found. Scanning raw bytes...");
            scanRawFormatStrings(fmtStrings);
        }

        println("Found " + fmtStrings.size() + " format string(s).");
        if (fmtStrings.isEmpty()) return;

        // Step 2: For each format string, find what function is called with it
        // Map: callee function -> list of call sites where a fmt string is passed
        Map<Function, List<CallSite>> calleeFmtCalls = new LinkedHashMap<>();

        for (Map.Entry<Address, String> entry : fmtStrings.entrySet()) {
            Address strAddr = entry.getKey();

            // Find references TO this string address
            ReferenceIterator refIt = refMgr.getReferencesTo(strAddr);
            while (refIt.hasNext()) {
                Reference ref = refIt.next();
                Address fromAddr = ref.getFromAddress();
                Function caller = funcMgr.getFunctionContaining(fromAddr);
                if (caller == null) continue;

                // Walk forward from the reference to find the next CALL instruction
                Instruction instr = listing.getInstructionAt(fromAddr);
                if (instr == null) {
                    instr = listing.getInstructionContaining(fromAddr);
                }
                if (instr == null) continue;

                // Search forward up to 10 instructions for a call
                Function callee = null;
                int argPosition = -1;
                int instrCount = 0;

                // First, figure out which register gets the string address
                // ARM: typically LDR Rn, =string_addr or MOV Rn, string_addr
                // then BL target
                String destReg = null;
                if (instr.getMnemonicString().startsWith("ldr") ||
                    instr.getMnemonicString().startsWith("mov") ||
                    instr.getMnemonicString().startsWith("adr")) {
                    if (instr.getNumOperands() > 0) {
                        destReg = instr.getDefaultOperandRepresentation(0);
                    }
                }

                // Map register to argument position (ARM calling convention)
                if (destReg != null) {
                    if (destReg.equals("r0")) argPosition = 0;
                    else if (destReg.equals("r1")) argPosition = 1;
                    else if (destReg.equals("r2")) argPosition = 2;
                    else if (destReg.equals("r3")) argPosition = 3;
                }

                // Walk forward to find BL/BLX
                Instruction scan = instr;
                for (int i = 0; i < 10 && scan != null; i++) {
                    scan = listing.getInstructionAfter(scan.getMaxAddress());
                    if (scan == null) break;
                    String mnemonic = scan.getMnemonicString();
                    if (mnemonic.equals("bl") || mnemonic.equals("blx")) {
                        // Found a call
                        Reference[] callRefs = scan.getReferencesFrom();
                        for (Reference cr : callRefs) {
                            if (cr.getReferenceType().isCall()) {
                                callee = funcMgr.getFunctionAt(cr.getToAddress());
                                break;
                            }
                        }
                        break;
                    }
                    // Stop if we hit another branch/return
                    if (mnemonic.startsWith("b") && !mnemonic.equals("bic") &&
                        !mnemonic.equals("bfc") && !mnemonic.equals("bfi")) break;
                }

                if (callee != null) {
                    calleeFmtCalls.computeIfAbsent(callee, k -> new ArrayList<>())
                        .add(new CallSite(fromAddr, entry.getValue(), argPosition));
                }
            }
        }

        // Step 3: Rank callees by number of format string call sites
        println("\n--- Printf-like function candidates ---");
        List<Map.Entry<Function, List<CallSite>>> ranked = new ArrayList<>(calleeFmtCalls.entrySet());
        ranked.sort((a, b) -> b.getValue().size() - a.getValue().size());

        int applied = 0;
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType charPtr = new PointerDataType(new CharDataType(), currentProgram.getDataTypeManager());
        DataType intType = new IntegerDataType();

        for (Map.Entry<Function, List<CallSite>> e : ranked) {
            Function func = e.getKey();
            List<CallSite> sites = e.getValue();

            if (sites.size() < minCalls) break; // sorted desc, so we can stop

            // Determine which argument position is the format string
            Map<Integer, Integer> posCount = new HashMap<>();
            for (CallSite cs : sites) {
                if (cs.argPos >= 0) {
                    posCount.merge(cs.argPos, 1, Integer::sum);
                }
            }
            int fmtArgPos = 0; // default to r0
            int maxCount = 0;
            for (Map.Entry<Integer, Integer> pc : posCount.entrySet()) {
                if (pc.getValue() > maxCount) {
                    maxCount = pc.getValue();
                    fmtArgPos = pc.getKey();
                }
            }

            String funcName = func.getName();
            boolean isDefault = func.getSymbol().getSource() == SourceType.DEFAULT ||
                                func.getSymbol().getSource() == SourceType.ANALYSIS;

            println(String.format("  %s @ 0x%x: %d call sites, fmt in arg %d%s",
                funcName, func.getEntryPoint().getOffset(),
                sites.size(), fmtArgPos, isDefault ? " [unnamed]" : ""));

            // Show a few example strings
            int shown = 0;
            for (CallSite cs : sites) {
                if (shown >= 3) { println("    ..."); break; }
                String preview = cs.fmtString;
                if (preview.length() > 60) preview = preview.substring(0, 60) + "...";
                println("    \"" + preview + "\"");
                shown++;
            }

            // Apply printf-like signature
            try {
                // Build parameter list: args before fmt are regular, fmt is char*, rest is varargs
                List<ParameterImpl> params = new ArrayList<>();
                for (int i = 0; i < fmtArgPos; i++) {
                    params.add(new ParameterImpl("arg" + i, intType, currentProgram));
                }
                params.add(new ParameterImpl("fmt", charPtr, currentProgram));

                func.replaceParameters(params,
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, // force
                    SourceType.USER_DEFINED);
                func.setVarArgs(true);

                // Rename if it's still a default name
                if (isDefault) {
                    String newName;
                    if (fmtArgPos == 0) {
                        newName = "psp_printf_" + Long.toHexString(func.getEntryPoint().getOffset());
                    } else {
                        newName = "psp_log_" + Long.toHexString(func.getEntryPoint().getOffset());
                    }
                    func.setName(newName, SourceType.USER_DEFINED);
                    println("    -> renamed to " + newName);
                }

                println("    -> applied varargs signature (fmt at arg" + fmtArgPos + ")");
                applied++;
            } catch (Exception ex) {
                printerr("    Failed to apply signature: " + ex.getMessage());
            }
        }

        println("\n=== Summary ===");
        println("Format strings found: " + fmtStrings.size());
        println("Printf-like candidates (>=" + minCalls + " sites): " +
                ranked.stream().filter(e -> e.getValue().size() >= minCalls).count());
        println("Signatures applied: " + applied);
    }

    private void scanRawFormatStrings(Map<Address, String> fmtStrings) throws Exception {
        // Scan initialized memory for ASCII strings containing format specifiers
        ghidra.program.model.mem.Memory mem = currentProgram.getMemory();
        ghidra.program.model.mem.MemoryBlock[] blocks = mem.getBlocks();

        for (ghidra.program.model.mem.MemoryBlock block : blocks) {
            if (!block.isInitialized() || block.isVolatile()) continue;
            if (block.getSize() > 0x100000) continue; // skip huge blocks

            byte[] data = new byte[(int) block.getSize()];
            mem.getBytes(block.getStart(), data);

            // Simple ASCII string scanner
            int strStart = -1;
            for (int i = 0; i < data.length; i++) {
                byte b = data[i];
                if (b >= 0x20 && b < 0x7f) {
                    if (strStart < 0) strStart = i;
                } else if (b == 0 && strStart >= 0) {
                    int len = i - strStart;
                    if (len >= 6) {
                        String s = new String(data, strStart, len, "ASCII");
                        if (FMT_RE.matcher(s).find()) {
                            Address addr = block.getStart().add(strStart);
                            fmtStrings.put(addr, s);
                        }
                    }
                    strStart = -1;
                } else {
                    strStart = -1;
                }
            }
        }
    }

    private static class CallSite {
        final Address refAddr;
        final String fmtString;
        final int argPos;

        CallSite(Address refAddr, String fmtString, int argPos) {
            this.refAddr = refAddr;
            this.fmtString = fmtString;
            this.argPos = argPos;
        }
    }
}
