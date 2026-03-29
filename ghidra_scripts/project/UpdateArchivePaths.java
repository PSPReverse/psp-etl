// UpdateArchivePaths.java — DEPRECATED: Use RelinkArchiveTypes.java instead.
//
// This script uses associateDataTypeWithArchive() which only sets the source
// archive pointer — it does NOT fix the UniversalID mismatch, so Ghidra's
// "sync with archive" still won't work.
//
// Original description:
// Fix broken source archive references by re-associating
// data types with their source .gdt archives.
//
// For FILE-type source archives with null/stale paths, this script:
// 1. Opens the matching .gdt file by name
// 2. Collects all data types linked to the broken archive
// 3. Removes the broken archive reference
// 4. Resolves a fresh archive reference from the .gdt
// 5. Re-associates the data types with the new reference
//
// Usage:
//   analyzeHeadless ... -process <program> -noanalysis \
//     -postScript UpdateArchivePaths.java <gdt_directory>
//
//@category PSP.Project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.util.UniversalID;
import java.io.File;
import java.util.*;

public class UpdateArchivePaths extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: UpdateArchivePaths.java <gdt_directory>");
            return;
        }

        File gdtDir = new File(args[0]);
        if (!gdtDir.isDirectory()) {
            printerr("Not a directory: " + args[0]);
            return;
        }

        // Build map of archive name -> .gdt file path
        Map<String, String> nameToPath = new HashMap<>();
        for (File f : gdtDir.listFiles()) {
            if (f.getName().endsWith(".gdt")) {
                String name = f.getName().replace(".gdt", "");
                nameToPath.put(name, f.getAbsolutePath());
            }
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int fixed = 0;

        // Snapshot the list — we'll be modifying archives during iteration
        List<SourceArchive> archives = new ArrayList<>(dtm.getSourceArchives());

        for (SourceArchive sa : archives) {
            if (sa.getArchiveType() != ArchiveType.FILE) continue;

            String name = sa.getName();
            String path = sa.getDomainFileID();

            // Check if already resolved
            if (path != null && !path.isEmpty()) {
                File existing = new File(path);
                if (existing.exists()) {
                    println("  OK: " + name + " -> " + path);
                    continue;
                }
                println("  STALE: " + name + " -> " + path + " (file not found)");
            } else {
                println("  BROKEN: " + name + " (path=null)");
            }

            // Find matching .gdt
            String gdtPath = nameToPath.get(name);
            if (gdtPath == null) {
                println("    No matching .gdt found for: " + name);
                continue;
            }

            // Re-associate types via remove + resolve cycle
            try {
                UniversalID oldID = sa.getSourceArchiveID();

                FileDataTypeManager fdtm =
                    FileDataTypeManager.openFileArchive(new File(gdtPath), false);
                try {
                    SourceArchive fileArchive = fdtm.getLocalSourceArchive();

                    // Collect types linked to the broken archive
                    Iterator<DataType> it = dtm.getAllDataTypes();
                    List<DataType> toReassociate = new ArrayList<>();
                    while (it.hasNext()) {
                        DataType dt = it.next();
                        if (dt.getSourceArchive() != null &&
                            dt.getSourceArchive().getSourceArchiveID().equals(oldID)) {
                            toReassociate.add(dt);
                        }
                    }

                    // Remove broken archive, resolve fresh one, re-associate types
                    dtm.removeSourceArchive(sa);
                    SourceArchive newSA = dtm.resolveSourceArchive(fileArchive);
                    for (DataType dt : toReassociate) {
                        dtm.associateDataTypeWithArchive(dt, newSA);
                    }

                    println("    FIXED: " + name + " -> " + gdtPath +
                            " (" + toReassociate.size() + " types)");
                    fixed++;
                } finally {
                    fdtm.close();
                }
            } catch (Exception e) {
                println("    FAILED: " + name + ": " + e.getClass().getSimpleName() +
                        ": " + e.getMessage());
            }
        }

        println("Fixed " + fixed + " archive path(s) in " + currentProgram.getName());
    }
}
