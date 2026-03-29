// ImportTypesFromGZF.java — Import data types from packed Ghidra archives (.gzf)
// that are Java serialized DataTypeManager objects.
//
// These are NOT program databases — they're data type archives exported via packFile()
// from Ghidra's DataType manager. We open them as FileDataTypeManager and copy types.
//
// Usage:
//   analyzeHeadless ... -process <dest_program> -noanalysis \
//     -postScript ImportTypesFromGZF.java <gzf_path> [<gzf_path2> ...]
//
//@category PSP.ImportExport

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.app.plugin.core.datamgr.archive.*;
import java.io.File;
import java.util.*;

public class ImportTypesFromGZF extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ImportTypesFromGZF.java <gzf_path> [<gzf_path2> ...]");
            return;
        }

        DataTypeManager destDtm = currentProgram.getDataTypeManager();
        int totalImported = 0;

        for (String gzfPath : args) {
            File gzfFile = new File(gzfPath);
            if (!gzfFile.exists()) {
                println("Not found: " + gzfPath);
                continue;
            }

            println("Opening archive: " + gzfFile.getName());

            try {
                // Open as a FileDataTypeManager (packed archive)
                FileDataTypeManager fdtm = FileDataTypeManager.openFileArchive(gzfFile, false);

                try {
                    Iterator<DataType> it = fdtm.getAllDataTypes();
                    int count = 0;

                    while (it.hasNext()) {
                        DataType dt = it.next();
                        String name = dt.getName();
                        String path = dt.getCategoryPath().getPath();

                        // Skip built-ins
                        if (path.startsWith("/generic_clib") || path.startsWith("/windows")) continue;

                        // Import everything — these are curated PSP types
                        try {
                            DataType existing = destDtm.getDataType(dt.getCategoryPath(), name);
                            if (existing != null) continue;

                            DataType resolved = destDtm.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
                            if (resolved != null) {
                                count++;
                                if (dt instanceof ghidra.program.model.data.Enum) {
                                    ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum) dt;
                                    println("  enum " + name + " (" + e.getCount() + " values) [" + path + "]");
                                } else if (dt instanceof Structure) {
                                    println("  struct " + name + " (size " + dt.getLength() + ") [" + path + "]");
                                } else if (dt instanceof Union) {
                                    println("  union " + name + " [" + path + "]");
                                } else if (dt instanceof TypeDef) {
                                    println("  typedef " + name + " [" + path + "]");
                                } else if (dt instanceof FunctionDefinition) {
                                    println("  funcdef " + name + " [" + path + "]");
                                }
                            }
                        } catch (Exception e) {
                            // Skip unresolvable types
                        }
                    }

                    println("  " + count + " type(s) from " + gzfFile.getName());
                    totalImported += count;
                } finally {
                    fdtm.close();
                }
            } catch (Exception e) {
                println("  Failed to open " + gzfFile.getName() + ": " + e.getMessage());
                // Try alternative: maybe it's actually a packed program, not an archive
                println("  (This file may be a packed program, not a data type archive)");
            }
        }

        println("\nTotal types imported: " + totalImported);

        // List PSPSTATUS if found
        Iterator<DataType> it = destDtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (dt.getName().equals("PSPSTATUS") || dt.getName().equals("PSP_STATUS")) {
                println("\nFound: " + dt.getName());
                if (dt instanceof ghidra.program.model.data.Enum) {
                    ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum) dt;
                    long[] values = e.getValues();
                    for (int i = 0; i < Math.min(values.length, 20); i++) {
                        println("  " + e.getName(values[i]) + " = 0x" + Long.toHexString(values[i]));
                    }
                    if (values.length > 20) println("  ... (" + values.length + " total)");
                }
            }
        }
    }
}
