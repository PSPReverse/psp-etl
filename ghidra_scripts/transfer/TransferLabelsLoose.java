// TransferLabelsLoose.java — Transfer function names using loose matching.
//
// Strategies (looser than TransferLabelsFuzzy):
// 1. Mnemonic-only hash: hash first 15 instruction mnemonics, ignoring registers
// 2. Size+prologue: match functions within 10% size + same first 5 mnemonics
// 3. Call-graph signature: hash the set of callees (by their relative offset pattern)
//
// Usage:
//   analyzeHeadless ... -process <dest> -noanalysis \
//     -postScript TransferLabelsLoose.java <source_path>
//
//@category PSP.Transfer

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.framework.model.*;
import java.util.*;

public class TransferLabelsLoose extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: TransferLabelsLoose.java <source_program_path>");
            return;
        }

        Program dest = currentProgram;
        DomainFile srcFile = resolveFile(args[0]);
        if (srcFile == null) {
            printerr("Source not found: " + args[0]);
            return;
        }

        Program src = (Program) srcFile.getReadOnlyDomainObject(
            this, DomainFile.DEFAULT_VERSION, monitor);
        if (src == null) {
            printerr("Could not open source: " + args[0]);
            return;
        }

        try {
            // Collect named source functions
            List<Function> namedSrcFuncs = new ArrayList<>();
            FunctionIterator srcIt = src.getFunctionManager().getFunctions(true);
            while (srcIt.hasNext()) {
                Function f = srcIt.next();
                SourceType st = f.getSymbol().getSource();
                if (st == SourceType.USER_DEFINED || st == SourceType.IMPORTED) {
                    namedSrcFuncs.add(f);
                }
            }

            List<Function> destFuncs = new ArrayList<>();
            FunctionIterator destIt = dest.getFunctionManager().getFunctions(true);
            while (destIt.hasNext()) {
                destFuncs.add(destIt.next());
            }

            println("Source: " + namedSrcFuncs.size() + " named, Dest: " + destFuncs.size() + " total");
            Set<String> transferred = new HashSet<>();
            // Load already-transferred names to avoid overwriting
            for (Function df : destFuncs) {
                SourceType st = df.getSymbol().getSource();
                if (st == SourceType.USER_DEFINED || st == SourceType.IMPORTED) {
                    transferred.add(df.getName());
                }
            }

            int mnemonicMatch = 0;
            int sizeMatch = 0;
            int callgraphMatch = 0;

            // === Pass 1: Mnemonic-only hash (ignoring register operands) ===
            println("--- Pass 1: Mnemonic-only hash (15 instrs) ---");
            Map<String, List<Function>> destMnemonicIndex = new HashMap<>();
            for (Function df : destFuncs) {
                String hash = mnemonicHash(dest, df, 15);
                if (hash != null) {
                    destMnemonicIndex.computeIfAbsent(hash, k -> new ArrayList<>()).add(df);
                }
            }

            for (Function sf : namedSrcFuncs) {
                if (transferred.contains(sf.getName())) continue;
                String hash = mnemonicHash(src, sf, 15);
                if (hash == null) continue;
                List<Function> candidates = destMnemonicIndex.get(hash);
                if (candidates != null && candidates.size() == 1) {
                    Function df = candidates.get(0);
                    if (applyName(dest, df, sf.getName(), transferred)) {
                        mnemonicMatch++;
                    }
                }
            }
            println("  Mnemonic-only: " + mnemonicMatch);

            // === Pass 2: Size + prologue (5 mnemonics + size within 10%) ===
            println("--- Pass 2: Size + prologue ---");
            // Build index: prologue_hash -> list of (function, size)
            Map<String, List<FuncWithSize>> destPrologueIndex = new HashMap<>();
            for (Function df : destFuncs) {
                String prologue = mnemonicHash(dest, df, 5);
                long size = getFuncSize(df);
                if (prologue != null && size > 0) {
                    destPrologueIndex.computeIfAbsent(prologue, k -> new ArrayList<>())
                        .add(new FuncWithSize(df, size));
                }
            }

            for (Function sf : namedSrcFuncs) {
                if (transferred.contains(sf.getName())) continue;
                String prologue = mnemonicHash(src, sf, 5);
                long srcSize = getFuncSize(sf);
                if (prologue == null || srcSize == 0) continue;

                List<FuncWithSize> candidates = destPrologueIndex.get(prologue);
                if (candidates == null) continue;

                // Filter by size within 10%
                List<FuncWithSize> sizeMatched = new ArrayList<>();
                for (FuncWithSize c : candidates) {
                    double ratio = (double) c.size / srcSize;
                    if (ratio >= 0.9 && ratio <= 1.1) {
                        sizeMatched.add(c);
                    }
                }

                if (sizeMatched.size() == 1) {
                    Function df = sizeMatched.get(0).func;
                    if (applyName(dest, df, sf.getName(), transferred)) {
                        sizeMatch++;
                    }
                }
            }
            println("  Size+prologue: " + sizeMatch);

            // === Pass 3: Call-graph signature ===
            println("--- Pass 3: Call-graph signature ---");
            Map<String, List<Function>> destCallIndex = new HashMap<>();
            for (Function df : destFuncs) {
                String sig = callSignature(dest, df);
                if (sig != null && sig.length() > 10) {
                    destCallIndex.computeIfAbsent(sig, k -> new ArrayList<>()).add(df);
                }
            }

            for (Function sf : namedSrcFuncs) {
                if (transferred.contains(sf.getName())) continue;
                String sig = callSignature(src, sf);
                if (sig == null || sig.length() <= 10) continue;
                List<Function> candidates = destCallIndex.get(sig);
                if (candidates != null && candidates.size() == 1) {
                    Function df = candidates.get(0);
                    if (applyName(dest, df, sf.getName(), transferred)) {
                        callgraphMatch++;
                    }
                }
            }
            println("  Call-graph: " + callgraphMatch);

            int total = mnemonicMatch + sizeMatch + callgraphMatch;
            println("\n=== Loose Transfer Summary ===");
            println("  Mnemonic-only:  " + mnemonicMatch);
            println("  Size+prologue:  " + sizeMatch);
            println("  Call-graph:     " + callgraphMatch);
            println("  Total new:      " + total);
        } finally {
            src.release(this);
        }
    }

    private String mnemonicHash(Program prog, Function func, int maxInstrs) {
        try {
            Listing listing = prog.getListing();
            Address addr = func.getEntryPoint();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < maxInstrs; i++) {
                Instruction instr = listing.getInstructionAt(addr);
                if (instr == null) break;
                sb.append(instr.getMnemonicString()).append("|");
                addr = instr.getFallThrough();
                if (addr == null) addr = instr.getMaxAddress().next();
            }
            return sb.length() >= 10 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private long getFuncSize(Function func) {
        AddressSetView body = func.getBody();
        return body != null ? body.getNumAddresses() : 0;
    }

    private String callSignature(Program prog, Function func) {
        // Hash the relative offsets of all called functions from this function's entry
        try {
            AddressSetView body = func.getBody();
            if (body == null) return null;

            long entry = func.getEntryPoint().getOffset();
            List<Long> callOffsets = new ArrayList<>();

            Listing listing = prog.getListing();
            InstructionIterator instrIt = listing.getInstructions(body, true);
            while (instrIt.hasNext()) {
                Instruction instr = instrIt.next();
                String mn = instr.getMnemonicString();
                if (mn.equals("bl") || mn.equals("blx")) {
                    ghidra.program.model.symbol.Reference[] refs = instr.getReferencesFrom();
                    for (ghidra.program.model.symbol.Reference ref : refs) {
                        if (ref.getReferenceType().isCall()) {
                            long targetOffset = ref.getToAddress().getOffset() - entry;
                            callOffsets.add(targetOffset);
                        }
                    }
                }
            }

            if (callOffsets.isEmpty()) return null;
            Collections.sort(callOffsets);
            StringBuilder sb = new StringBuilder();
            for (Long off : callOffsets) {
                sb.append(off).append(",");
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean applyName(Program prog, Function func, String name, Set<String> transferred) {
        if (transferred.contains(name)) return false;
        try {
            SourceType st = func.getSymbol().getSource();
            if (st == SourceType.USER_DEFINED || st == SourceType.IMPORTED) return false;
            func.setName(name, SourceType.IMPORTED);
            transferred.add(name);
            println("    " + name + " @ 0x" + Long.toHexString(func.getEntryPoint().getOffset()));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private DomainFile resolveFile(String path) {
        String[] parts = path.split("/");
        DomainFolder folder = state.getProject().getProjectData().getRootFolder();
        for (int i = 0; i < parts.length - 1; i++) {
            if (parts[i].isEmpty()) continue;
            folder = folder.getFolder(parts[i]);
            if (folder == null) return null;
        }
        return folder.getFile(parts[parts.length - 1]);
    }

    private static class FuncWithSize {
        final Function func;
        final long size;
        FuncWithSize(Function func, long size) {
            this.func = func;
            this.size = size;
        }
    }
}
