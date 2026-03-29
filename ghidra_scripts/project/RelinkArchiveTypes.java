// RelinkArchiveTypes.java — Re-establish proper source archive links for types
// that were previously disassociated (e.g. by SeverArchiveLinks).
//
// After disassociate(), types get new local UniversalIDs that don't match the
// archive's IDs, so Ghidra's "sync with archive" can't match them.
//
// This script fixes that by directly setting each type's source archive pointer
// and UniversalID to match the archive. This is a metadata-only change — type
// content (struct fields, enum values) is not modified.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name>/<folder> \
//     -recursive -process -noanalysis \
//     -scriptPath ghidra_scripts/project \
//     -postScript RelinkArchiveTypes.java <gdt_directory>
//
// Example:
//   -postScript RelinkArchiveTypes.java data/ghidra_archives
//
// Dry-run (report only, no changes):
//   -postScript RelinkArchiveTypes.java data/ghidra_archives --dry-run
//
//@category PSP.Project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.util.UniversalID;
import java.io.File;
import java.lang.reflect.Method;
import java.util.*;

public class RelinkArchiveTypes extends GhidraScript {

    // Primitive/shared types that exist across many archives.
    // Skip these to avoid re-associating built-in types with the wrong archive.
    private static final Set<String> SKIP_TYPE_NAMES = new HashSet<>(Arrays.asList(
        "byte", "char", "uchar", "short", "ushort", "int", "uint", "long", "ulong",
        "longlong", "ulonglong", "float", "double", "bool", "void", "undefined",
        "undefined1", "undefined2", "undefined4", "undefined8",
        "pointer", "pointer8", "pointer16", "pointer32", "pointer64",
        "string", "TerminatedCString", "TerminatedUnicodeString",
        "wchar_t", "wchar16", "ImageBaseOffset32", "ImageBaseOffset64"
    ));

    // Category paths containing only shared/standard types
    private static final String[] SKIP_CATEGORY_PREFIXES = {
        "/generic_clib", "/windows", "/stdint.h", "/stddef.h", "/types.h"
    };

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: RelinkArchiveTypes.java <gdt_directory> [--dry-run]");
            return;
        }

        File gdtDir = new File(args[0]);
        if (!gdtDir.isDirectory()) {
            printerr("Not a directory: " + args[0]);
            return;
        }

        boolean dryRun = false;
        for (String arg : args) {
            if (arg.equals("--dry-run")) dryRun = true;
        }

        if (dryRun) {
            println("=== DRY RUN — no changes will be made ===");
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        SourceArchive programLocalSA = dtm.getLocalSourceArchive();

        // Check if we can set UniversalID via reflection or public API
        Method setUIDMethod = findSetUniversalIDMethod();
        if (setUIDMethod == null && !dryRun) {
            printerr("WARNING: Cannot access setUniversalID — will set source archive only.");
            printerr("  UUID sync may not work. Consider running from Ghidra GUI.");
        }

        // Process each .gdt file
        File[] gdtFiles = gdtDir.listFiles((dir, name) -> name.endsWith(".gdt"));
        if (gdtFiles == null || gdtFiles.length == 0) {
            printerr("No .gdt files found in " + gdtDir);
            return;
        }

        Arrays.sort(gdtFiles, Comparator.comparing(File::getName));

        int totalRelinked = 0;
        int totalSkipped = 0;
        int totalPrimitiveSkipped = 0;

        for (File gdtFile : gdtFiles) {
            FileDataTypeManager fdtm = null;
            try {
                fdtm = FileDataTypeManager.openFileArchive(gdtFile, false);
            } catch (Exception e) {
                println("  SKIP (can't open): " + gdtFile.getName() + ": " + e.getMessage());
                continue;
            }

            try {
                String archiveName = gdtFile.getName().replace(".gdt", "");
                SourceArchive archiveLocalSA = fdtm.getLocalSourceArchive();

                // Ensure the program has a source archive entry for this .gdt
                SourceArchive programSA = null;
                if (!dryRun) {
                    programSA = dtm.resolveSourceArchive(archiveLocalSA);
                }

                int relinked = 0;
                int skipped = 0;
                int primitiveSkipped = 0;
                List<String> details = new ArrayList<>();

                Iterator<DataType> archiveIt = fdtm.getAllDataTypes();
                while (archiveIt.hasNext()) {
                    DataType archiveDt = archiveIt.next();
                    String catPath = archiveDt.getCategoryPath().getPath();
                    String name = archiveDt.getName();

                    // Skip primitive/shared types
                    if (isPrimitiveOrShared(catPath, name)) {
                        primitiveSkipped++;
                        continue;
                    }

                    // Skip derived types (pointers, arrays, function defs) —
                    // their identity derives from the base type, so fixing the
                    // base type is sufficient. setUniversalID doesn't work on
                    // these anyway (they're not DataTypeDB instances).
                    if (archiveDt instanceof Pointer || archiveDt instanceof Array ||
                        archiveDt instanceof FunctionDefinition) {
                        primitiveSkipped++;
                        continue;
                    }

                    // Find matching program type
                    DataType programDt = dtm.getDataType(archiveDt.getCategoryPath(), name);
                    if (programDt == null) continue;

                    // Check if already properly linked
                    SourceArchive progTypeSA = programDt.getSourceArchive();
                    UniversalID progUID = programDt.getUniversalID();
                    UniversalID archiveUID = archiveDt.getUniversalID();

                    if (progTypeSA != null && archiveUID != null && progUID != null &&
                        progTypeSA.getSourceArchiveID().equals(archiveLocalSA.getSourceArchiveID()) &&
                        progUID.equals(archiveUID)) {
                        skipped++;
                        continue;
                    }

                    // Determine what's wrong
                    String issue;
                    boolean isOrphaned = (progTypeSA == null ||
                        progTypeSA.getSourceArchiveID().equals(programLocalSA.getSourceArchiveID()));
                    if (isOrphaned) {
                        issue = "orphaned";
                    } else if (progTypeSA.getSourceArchiveID().equals(archiveLocalSA.getSourceArchiveID())) {
                        // Linked to THIS archive but UUID doesn't match
                        issue = "uuid_mismatch";
                    } else {
                        // Linked to a DIFFERENT valid archive — leave it alone.
                        // Types like ccp5_desc exist in multiple archives;
                        // whichever one owns it is fine.
                        skipped++;
                        continue;
                    }

                    if (!dryRun) {
                        // Strategy: use associateDataTypeWithArchive to set the
                        // source archive pointer (this is known to persist), then
                        // fix the UniversalID to match the archive type.
                        dtm.associateDataTypeWithArchive(programDt, programSA);

                        // Set UniversalID to match archive
                        boolean uidSet = false;
                        if (setUIDMethod != null && archiveUID != null) {
                            try {
                                setUIDMethod.invoke(programDt, archiveUID);
                                // Verify it stuck
                                UniversalID check = programDt.getUniversalID();
                                uidSet = (check != null && check.equals(archiveUID));
                            } catch (Exception e) {
                                println("      setUID failed: " + e.getClass().getSimpleName() +
                                        ": " + e.getMessage());
                            }
                        }

                        relinked++;
                        String uidStatus = uidSet ? " [uid OK]" : " [uid FAILED]";
                        details.add("    FIXED (" + issue + "): " + catPath + "/" + name + uidStatus);
                    } else {
                        relinked++;
                        details.add("    [would fix " + issue + "] " + catPath + "/" + name);
                    }
                }

                if (relinked > 0 || skipped > 0) {
                    println("  " + archiveName + ": " + relinked + " relinked, " +
                            skipped + " already OK" +
                            (primitiveSkipped > 0 ? ", " + primitiveSkipped + " primitives skipped" : ""));
                    for (String d : details) {
                        println(d);
                    }
                }
                totalRelinked += relinked;
                totalSkipped += skipped;
                totalPrimitiveSkipped += primitiveSkipped;

            } finally {
                fdtm.close();
            }
        }

        println("\n=== RelinkArchiveTypes Summary for " + currentProgram.getName() + " ===");
        println("  Types relinked:         " + totalRelinked);
        println("  Types already OK:       " + totalSkipped);
        println("  Primitives skipped:     " + totalPrimitiveSkipped);
        println("  setUniversalID access:  " + (setUIDMethod != null ? "YES" : "NO (source archive only)"));
        if (dryRun) {
            println("  (dry run — no changes made)");
        }
    }

    private boolean isPrimitiveOrShared(String catPath, String name) {
        // Skip well-known primitive type names regardless of category
        if (SKIP_TYPE_NAMES.contains(name)) return true;

        // Skip types from standard library categories
        for (String prefix : SKIP_CATEGORY_PREFIXES) {
            if (catPath.startsWith(prefix)) return true;
        }

        // Skip pointer/array variants of primitives (e.g. "uint32_t[4]", "char *")
        String baseName = name.replaceAll("\\s*\\*+$", "").replaceAll("\\[\\d+\\]$", "").trim();
        if (SKIP_TYPE_NAMES.contains(baseName)) return true;

        return false;
    }

    /**
     * Try to find a way to set UniversalID on DataType objects.
     * Ghidra's DataTypeDB has setUniversalID() but it may not be publicly accessible.
     */
    private Method findSetUniversalIDMethod() {
        // Try the direct approach: DataTypeDB.setUniversalID(UniversalID)
        try {
            Class<?> dtdbClass = Class.forName("ghidra.program.database.data.DataTypeDB");
            Method m = dtdbClass.getMethod("setUniversalID", UniversalID.class);
            m.setAccessible(true);
            return m;
        } catch (Exception e) {
            // Not accessible
        }

        // Try declared methods (may be package-private)
        try {
            Class<?> dtdbClass = Class.forName("ghidra.program.database.data.DataTypeDB");
            Method m = dtdbClass.getDeclaredMethod("setUniversalID", UniversalID.class);
            m.setAccessible(true);
            return m;
        } catch (Exception e) {
            // Not accessible
        }

        return null;
    }
}
