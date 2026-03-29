// AnalyzePatterns.java — Extract reusable analysis patterns from PSP firmware.
//
// Captures: function signatures, calling conventions, common prologues/epilogues,
// error handling patterns, and structural observations. Outputs JSON for
// crosslink knowledge persistence.
//
//@category PSP.Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.scalar.*;
import java.util.*;
import java.io.*;

public class AnalyzePatterns extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;
        String[] args = getScriptArgs();
        String outFile = (args.length >= 1) ? args[0] : null;

        Listing listing = currentProgram.getListing();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        StringBuilder report = new StringBuilder();
        String progName = currentProgram.getName();
        report.append("## ").append(progName).append("\n\n");

        // === 1. Function statistics ===
        int totalFuncs = 0, namedFuncs = 0, withStrings = 0, withSvc = 0;
        int totalStrings = 0, referencedStrings = 0;
        Map<String, Integer> prologuePatterns = new LinkedHashMap<>();
        Map<Integer, Integer> svcCalls = new TreeMap<>();
        Map<String, List<String>> errorStrings = new LinkedHashMap<>();

        FunctionIterator funcIt = funcMgr.getFunctions(true);
        while (funcIt.hasNext()) {
            Function func = funcIt.next();
            totalFuncs++;
            if (func.getSymbol().getSource() != SourceType.DEFAULT) namedFuncs++;

            AddressSetView body = func.getBody();
            if (body == null) continue;

            // Prologue pattern (first 3 mnemonics)
            StringBuilder prologue = new StringBuilder();
            Instruction instr = listing.getInstructionAt(func.getEntryPoint());
            for (int i = 0; i < 3 && instr != null; i++) {
                if (i > 0) prologue.append(" ");
                prologue.append(instr.getMnemonicString());
                Address next = instr.getFallThrough();
                instr = (next != null) ? listing.getInstructionAt(next) : null;
            }
            prologuePatterns.merge(prologue.toString(), 1, Integer::sum);

            // Check for strings and SVC calls
            boolean hasStr = false;
            InstructionIterator instrIt = listing.getInstructions(body, true);
            while (instrIt.hasNext()) {
                Instruction i = instrIt.next();
                String mn = i.getMnemonicString().toLowerCase();

                // SVC calls
                if (mn.equals("svc") || mn.equals("swi")) {
                    withSvc++;
                    Object[] ops = i.getOpObjects(0);
                    for (Object o : ops) {
                        if (o instanceof Scalar) {
                            svcCalls.merge((int)((Scalar)o).getUnsignedValue(), 1, Integer::sum);
                        }
                    }
                }

                // String references
                for (Reference ref : i.getReferencesFrom()) {
                    Data d = listing.getDataAt(ref.getToAddress());
                    if (d != null && d.hasStringValue()) {
                        hasStr = true;
                        String val = (String) d.getValue();
                        // Collect error-related strings
                        if (val != null && (val.toLowerCase().contains("error") ||
                            val.toLowerCase().contains("fail") ||
                            val.toLowerCase().contains("assert"))) {
                            String fname = func.getName();
                            errorStrings.computeIfAbsent(fname, k -> new ArrayList<>())
                                .add(val.length() > 80 ? val.substring(0, 80) + "..." : val);
                        }
                    }
                }
            }
            if (hasStr) withStrings++;
        }

        // String stats
        DataIterator dataIt = listing.getDefinedData(true);
        while (dataIt.hasNext()) {
            Data d = dataIt.next();
            if (d.hasStringValue()) {
                totalStrings++;
                if (refMgr.getReferenceCountTo(d.getMinAddress()) > 0) referencedStrings++;
            }
        }

        report.append("### Function Statistics\n");
        report.append("- Total functions: ").append(totalFuncs).append("\n");
        report.append("- Named (non-default): ").append(namedFuncs).append("\n");
        report.append("- With string refs: ").append(withStrings).append("\n");
        report.append("- With SVC calls: ").append(withSvc).append("\n");
        report.append("- Defined strings: ").append(totalStrings)
               .append(" (").append(referencedStrings).append(" referenced)\n\n");

        // === 2. Common prologues ===
        report.append("### Common Prologues (top 10)\n");
        prologuePatterns.entrySet().stream()
            .sorted((a, b) -> b.getValue() - a.getValue())
            .limit(10)
            .forEach(e -> report.append("- `").append(e.getKey())
                                .append("` (").append(e.getValue()).append("x)\n"));
        report.append("\n");

        // === 3. SVC call distribution ===
        report.append("### SVC Call Distribution\n");
        for (Map.Entry<Integer, Integer> e : svcCalls.entrySet()) {
            report.append("- SVC 0x").append(Integer.toHexString(e.getKey()))
                   .append(": ").append(e.getValue()).append(" call(s)\n");
        }
        report.append("\n");

        // === 4. Error strings by function ===
        report.append("### Error Strings (first 20 functions)\n");
        int shown = 0;
        for (Map.Entry<String, List<String>> e : errorStrings.entrySet()) {
            if (shown++ >= 20) { report.append("- ...\n"); break; }
            report.append("- **").append(e.getKey()).append("**\n");
            for (String s : e.getValue()) {
                report.append("  - `").append(s).append("`\n");
            }
        }
        report.append("\n");

        // === 5. Memory access patterns ===
        report.append("### MMIO Access Summary\n");
        Map<String, Integer> mmioRegions = new LinkedHashMap<>();
        InstructionIterator allInstr = listing.getInstructions(true);
        while (allInstr.hasNext()) {
            Instruction i = allInstr.next();
            for (Reference ref : i.getReferencesFrom()) {
                long addr = ref.getToAddress().getOffset();
                if (addr >= 0x3000000 && addr < 0x3010000) mmioRegions.merge("CCP", 1, Integer::sum);
                else if (addr >= 0x3010000 && addr < 0x3020000) mmioRegions.merge("PSP_MMIO", 1, Integer::sum);
                else if (addr >= 0x3220000 && addr < 0x3240000) mmioRegions.merge("SMN/x86_Map", 1, Integer::sum);
                else if (addr >= 0x1000000 && addr < 0x3000000) mmioRegions.merge("SMN", 1, Integer::sum);
            }
        }
        for (Map.Entry<String, Integer> e : mmioRegions.entrySet()) {
            report.append("- ").append(e.getKey()).append(": ")
                   .append(e.getValue()).append(" access(es)\n");
        }

        String output = report.toString();
        println(output);

        if (outFile != null) {
            try (FileWriter fw = new FileWriter(outFile, true)) {
                fw.write(output);
                fw.write("\n---\n\n");
            }
        }
    }
}
