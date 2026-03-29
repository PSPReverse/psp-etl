// TransferLabelsFuzzy.java — Transfer function names using fuzzy matching.
//
// Three matching strategies, applied in order:
// 1. Exact bytes (first 32 bytes of function body)
// 2. Instruction-hash (disassemble first N instructions, hash mnemonics+operand count)
// 3. String-reference (functions that reference the same unique strings)
//
// Usage:
//   analyzeHeadless ... -process <dest> -noanalysis \
//     -postScript TransferLabelsFuzzy.java <source_path>
//
//@category PSP.Transfer

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.framework.model.*;
import java.util.*;
import java.security.MessageDigest;

public class TransferLabelsFuzzy extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: TransferLabelsFuzzy.java <source_program_path>");
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
            // Collect source functions with user-defined names
            List<Function> namedSrcFuncs = new ArrayList<>();
            FunctionIterator srcIt = src.getFunctionManager().getFunctions(true);
            while (srcIt.hasNext()) {
                Function f = srcIt.next();
                SourceType st = f.getSymbol().getSource();
                if (st == SourceType.USER_DEFINED || st == SourceType.IMPORTED) {
                    namedSrcFuncs.add(f);
                }
            }
            println("Source has " + namedSrcFuncs.size() + " named function(s).");

            // Build destination function index
            List<Function> destFuncs = new ArrayList<>();
            FunctionIterator destIt = dest.getFunctionManager().getFunctions(true);
            while (destIt.hasNext()) {
                destFuncs.add(destIt.next());
            }
            println("Destination has " + destFuncs.size() + " function(s).");

            int exactMatch = 0;
            int instrMatch = 0;
            int stringMatch = 0;
            int skipped = 0;
            Set<String> transferred = new HashSet<>();

            // === Pass 1: Exact byte matching (32 bytes) ===
            println("--- Pass 1: Exact bytes ---");
            Map<String, Address> destByteIndex = new HashMap<>();
            for (Function df : destFuncs) {
                byte[] bytes = getBytes(dest, df.getEntryPoint(), 32);
                if (bytes != null) {
                    destByteIndex.put(bytesToHex(bytes), df.getEntryPoint());
                }
            }

            for (Function sf : namedSrcFuncs) {
                byte[] bytes = getBytes(src, sf.getEntryPoint(), 32);
                if (bytes == null) continue;
                String key = bytesToHex(bytes);
                Address destAddr = destByteIndex.get(key);
                if (destAddr != null && applyName(dest, destAddr, sf.getName(), transferred)) {
                    exactMatch++;
                }
            }
            println("  Exact: " + exactMatch + " matched");

            // === Pass 2: Instruction hash matching ===
            println("--- Pass 2: Instruction hash ---");
            // Build dest index: hash of first 20 instruction mnemonics -> function
            Map<String, List<Function>> destInstrIndex = new HashMap<>();
            for (Function df : destFuncs) {
                String hash = instrHash(dest, df, 20);
                if (hash != null) {
                    destInstrIndex.computeIfAbsent(hash, k -> new ArrayList<>()).add(df);
                }
            }

            for (Function sf : namedSrcFuncs) {
                if (transferred.contains(sf.getName())) continue;
                String hash = instrHash(src, sf, 20);
                if (hash == null) continue;
                List<Function> candidates = destInstrIndex.get(hash);
                if (candidates != null && candidates.size() == 1) {
                    // Unique match
                    Function df = candidates.get(0);
                    if (applyName(dest, df.getEntryPoint(), sf.getName(), transferred)) {
                        instrMatch++;
                    }
                }
            }
            println("  Instruction hash: " + instrMatch + " matched");

            // === Pass 3: String reference matching ===
            println("--- Pass 3: String references ---");
            // Build string->function maps for both programs
            Map<String, Set<Function>> srcStringFuncs = buildStringFuncMap(src);
            Map<String, Set<Function>> destStringFuncs = buildStringFuncMap(dest);

            // For each source function, find unique strings it references
            for (Function sf : namedSrcFuncs) {
                if (transferred.contains(sf.getName())) continue;

                // Find strings unique to this source function
                Set<String> sfStrings = getFunctionStrings(src, sf);
                if (sfStrings.isEmpty()) continue;

                // Find a string that maps to exactly one dest function
                for (String s : sfStrings) {
                    Set<Function> srcUsers = srcStringFuncs.get(s);
                    Set<Function> destUsers = destStringFuncs.get(s);
                    if (srcUsers != null && srcUsers.size() == 1 &&
                        destUsers != null && destUsers.size() == 1) {
                        Function df = destUsers.iterator().next();
                        if (applyName(dest, df.getEntryPoint(), sf.getName(), transferred)) {
                            stringMatch++;
                            break;
                        }
                    }
                }
            }
            println("  String reference: " + stringMatch + " matched");

            // === Transfer non-function labels ===
            int labelCount = 0;
            SymbolIterator srcSyms = src.getSymbolTable().getAllSymbols(true);
            while (srcSyms.hasNext()) {
                Symbol sym = srcSyms.next();
                if (sym.getSource() != SourceType.USER_DEFINED) continue;
                if (sym.getSymbolType() == SymbolType.FUNCTION) continue;
                if (sym.getName().startsWith("DAT_") || sym.getName().startsWith("switchD_")) continue;
                if (transferred.contains(sym.getName())) continue;

                Address srcAddr = sym.getAddress();
                if (!srcAddr.isMemoryAddress()) continue;

                byte[] bytes = getBytes(src, srcAddr, 16);
                if (bytes == null) continue;

                Address destAddr = findBytes(dest, bytes);
                if (destAddr == null) continue;

                Symbol existing = dest.getSymbolTable().getPrimarySymbol(destAddr);
                if (existing != null && existing.getSource() == SourceType.USER_DEFINED) continue;

                dest.getSymbolTable().createLabel(destAddr, sym.getName(), SourceType.IMPORTED);
                transferred.add(sym.getName());
                labelCount++;
            }

            int total = exactMatch + instrMatch + stringMatch + labelCount;
            println("\n=== Transfer Summary ===");
            println("  Exact byte match:   " + exactMatch);
            println("  Instruction hash:   " + instrMatch);
            println("  String reference:   " + stringMatch);
            println("  Data labels:        " + labelCount);
            println("  Total transferred:  " + total);
        } finally {
            src.release(this);
        }
    }

    private boolean applyName(Program prog, Address addr, String name, Set<String> transferred) {
        if (transferred.contains(name)) return false;
        try {
            Function f = prog.getFunctionManager().getFunctionAt(addr);
            if (f != null) {
                SourceType st = f.getSymbol().getSource();
                if (st == SourceType.USER_DEFINED || st == SourceType.IMPORTED) return false;
                f.setName(name, SourceType.IMPORTED);
            } else {
                prog.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
            }
            transferred.add(name);
            println("    " + name + " @ 0x" + Long.toHexString(addr.getOffset()));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String instrHash(Program prog, Function func, int maxInstrs) {
        try {
            Listing listing = prog.getListing();
            Address addr = func.getEntryPoint();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < maxInstrs; i++) {
                Instruction instr = listing.getInstructionAt(addr);
                if (instr == null) break;
                sb.append(instr.getMnemonicString());
                sb.append(instr.getNumOperands());
                sb.append("|");
                addr = instr.getFallThrough();
                if (addr == null) {
                    // Handle branches: use next address
                    addr = instr.getMaxAddress().next();
                }
            }
            if (sb.length() < 20) return null; // too short
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private Set<String> getFunctionStrings(Program prog, Function func) {
        Set<String> strings = new HashSet<>();
        try {
            AddressSetView body = func.getBody();
            if (body == null) return strings;

            ReferenceManager refMgr = prog.getReferenceManager();
            AddressIterator addrIt = body.getAddresses(true);
            while (addrIt.hasNext()) {
                Address addr = addrIt.next();
                for (Reference ref : refMgr.getReferencesFrom(addr)) {
                    Address toAddr = ref.getToAddress();
                    Data data = prog.getListing().getDataAt(toAddr);
                    if (data != null && data.hasStringValue()) {
                        String val = (String) data.getValue();
                        if (val != null && val.length() >= 8) {
                            strings.add(val);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return strings;
    }

    private Map<String, Set<Function>> buildStringFuncMap(Program prog) {
        Map<String, Set<Function>> map = new HashMap<>();
        FunctionIterator funcs = prog.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function f = funcs.next();
            for (String s : getFunctionStrings(prog, f)) {
                map.computeIfAbsent(s, k -> new HashSet<>()).add(f);
            }
        }
        return map;
    }

    private byte[] getBytes(Program prog, Address addr, int len) {
        try {
            byte[] buf = new byte[len];
            int read = prog.getMemory().getBytes(addr, buf);
            if (read < 8) return null;
            if (read < len) {
                byte[] trimmed = new byte[read];
                System.arraycopy(buf, 0, trimmed, 0, read);
                return trimmed;
            }
            return buf;
        } catch (Exception e) {
            return null;
        }
    }

    private Address findBytes(Program prog, byte[] pattern) {
        try {
            return prog.getMemory().findBytes(prog.getMinAddress(), pattern, null, true, monitor);
        } catch (Exception e) {
            return null;
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
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
}
