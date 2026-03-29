// TransferLabels.java — Transfer function names and labels from a source program
// to the current program using byte-matching correlation.
//
// For programs with the same architecture and similar code, this finds functions
// in the source that have user-defined names and applies them to matching
// functions in the destination (current program).
//
// Usage:
//   analyzeHeadless <project_dir> <project_name> \
//     -process <dest_program_path> -noanalysis \
//     -scriptPath /path/to/ghidra_scripts \
//     -postScript TransferLabels.java <source_program_path>
//
//@category PSP.Transfer
//
// Example:
//   -process /zen2/PSP_FW_BOOT_LOADER \
//   -postScript TransferLabels.java /sect/off-chip-bl/Ryzen_Zen2_ver_0d15

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.framework.model.*;
import java.util.*;

public class TransferLabels extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: TransferLabels.java <source_program_path>");
            return;
        }

        String srcPath = args[0];
        Program dest = currentProgram;

        // Open source program read-only
        DomainFile srcFile = state.getProject().getProjectData()
            .getRootFolder().getFile(srcPath.substring(1)); // strip leading /

        if (srcFile == null) {
            // Try resolving path component by component
            srcFile = resolveFile(srcPath);
        }

        if (srcFile == null) {
            printerr("Source program not found: " + srcPath);
            return;
        }

        Program src = (Program) srcFile.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
        if (src == null) {
            printerr("Could not open source program: " + srcPath);
            return;
        }

        try {
            int transferred = 0;
            int skipped = 0;

            // Collect all user-defined function names from source
            FunctionIterator srcFuncs = src.getFunctionManager().getFunctions(true);
            Map<String, List<byte[]>> srcFuncBytes = new LinkedHashMap<>();

            while (srcFuncs.hasNext()) {
                Function f = srcFuncs.next();
                // Skip default names (FUN_xxxx, thunk_FUN_xxxx, etc.)
                if (f.getSymbol().getSource() == SourceType.DEFAULT ||
                    f.getSymbol().getSource() == SourceType.ANALYSIS) {
                    continue;
                }

                String name = f.getName();
                Address addr = f.getEntryPoint();

                // Get the first N bytes of the function for matching
                byte[] bytes = getBytes(src, addr, 32);
                if (bytes == null) continue;

                // Try to find matching bytes in destination
                Address destAddr = findBytes(dest, bytes);
                if (destAddr == null) {
                    skipped++;
                    continue;
                }

                // Check if destination already has a non-default name at this address
                Function destFunc = dest.getFunctionManager().getFunctionAt(destAddr);
                if (destFunc != null &&
                    destFunc.getSymbol().getSource() != SourceType.DEFAULT &&
                    destFunc.getSymbol().getSource() != SourceType.ANALYSIS) {
                    skipped++;
                    continue;
                }

                // Rename existing function, or add a label if no function exists
                if (destFunc != null) {
                    destFunc.setName(name, SourceType.IMPORTED);
                } else {
                    dest.getSymbolTable().createLabel(destAddr, name, SourceType.IMPORTED);
                }

                println("  " + name + " @ 0x" + Long.toHexString(destAddr.getOffset()));
                transferred++;
            }

            // Also transfer non-function labels (data labels, etc.)
            SymbolIterator srcSymbols = src.getSymbolTable().getAllSymbols(true);
            while (srcSymbols.hasNext()) {
                Symbol sym = srcSymbols.next();
                if (sym.getSource() != SourceType.USER_DEFINED) continue;
                if (sym.getSymbolType() == SymbolType.FUNCTION) continue; // already handled
                if (sym.getName().startsWith("DAT_") || sym.getName().startsWith("switchD_")) continue;

                Address srcAddr = sym.getAddress();
                if (!srcAddr.isMemoryAddress()) continue;

                byte[] bytes = getBytes(src, srcAddr, 16);
                if (bytes == null) continue;

                Address destAddr = findBytes(dest, bytes);
                if (destAddr == null) continue;

                // Don't overwrite existing user labels
                Symbol existing = dest.getSymbolTable().getPrimarySymbol(destAddr);
                if (existing != null && existing.getSource() == SourceType.USER_DEFINED) continue;

                dest.getSymbolTable().createLabel(destAddr, sym.getName(), SourceType.IMPORTED);
                println("  label: " + sym.getName() + " @ 0x" + Long.toHexString(destAddr.getOffset()));
                transferred++;
            }

            println("Transfer complete: " + transferred + " transferred, " + skipped + " skipped (no match or already named)");
        } finally {
            src.release(this);
        }
    }

    private byte[] getBytes(Program prog, Address addr, int len) {
        try {
            byte[] buf = new byte[len];
            int read = prog.getMemory().getBytes(addr, buf);
            if (read < 8) return null; // too short to match reliably
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
        Memory mem = prog.getMemory();
        Address start = prog.getMinAddress();
        if (start == null) return null;
        try {
            return mem.findBytes(start, pattern, null, true, monitor);
        } catch (Exception e) {
            return null;
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
}
