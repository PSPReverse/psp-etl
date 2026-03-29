// AuditArchiveLinks.java — Report the state of source archive links in a program.
//
// For each source archive reference, shows: name, type (FILE/PROJECT/PROGRAM),
// path, and how many types are linked to it. Then reports types that appear to
// be from a known PSP archive but are currently local (orphaned).
//
// Usage:
//   analyzeHeadless <project_dir> <project_name>/<folder> \
//     -recursive -process -noanalysis -readOnly \
//     -scriptPath ghidra_scripts/diagnostics \
//     -postScript AuditArchiveLinks.java [gdt_directory]
//
// If gdt_directory is provided, also checks UUID match between program types
// and archive types to detect "cosmetic" links (pointer set but UUID mismatch).
//
//@category PSP.Diagnostics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.io.File;
import java.util.*;

public class AuditArchiveLinks extends GhidraScript {

    private static final Set<String> PSP_ARCHIVE_NAMES = new HashSet<>(Arrays.asList(
        "ArXbShared", "CcpIf", "PspHw", "PspSev", "PspSvcIf",
        "SecOS", "TE", "TrustedOsInterface", "VMSA", "common"
    ));

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        String[] args = getScriptArgs();
        File gdtDir = null;
        if (args.length >= 1 && !args[0].isEmpty()) {
            gdtDir = new File(args[0]);
            if (!gdtDir.isDirectory()) {
                println("Warning: " + args[0] + " is not a directory, skipping UUID check");
                gdtDir = null;
            }
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // === Section 1: Source archive inventory ===
        println("=== Source Archives in " + currentProgram.getName() + " ===");

        Map<String, Integer> archiveTypeCounts = new LinkedHashMap<>();
        Map<String, SourceArchive> archiveByID = new HashMap<>();

        for (SourceArchive sa : dtm.getSourceArchives()) {
            String id = sa.getSourceArchiveID().toString();
            archiveByID.put(id, sa);
            archiveTypeCounts.put(id, 0);
        }

        // Count types per archive
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        int totalTypes = 0;
        int localTypes = 0;
        SourceArchive programSA = dtm.getLocalSourceArchive();

        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            totalTypes++;
            SourceArchive sa = dt.getSourceArchive();
            if (sa == null || sa.getSourceArchiveID().equals(programSA.getSourceArchiveID())) {
                localTypes++;
            } else {
                String id = sa.getSourceArchiveID().toString();
                archiveTypeCounts.merge(id, 1, Integer::sum);
            }
        }

        println(String.format("  Total types: %d, Local (no archive link): %d", totalTypes, localTypes));
        println("");

        for (SourceArchive sa : dtm.getSourceArchives()) {
            if (sa.getArchiveType() == ArchiveType.PROGRAM) continue;
            if (sa.getArchiveType() == ArchiveType.BUILT_IN) continue;

            String id = sa.getSourceArchiveID().toString();
            int count = archiveTypeCounts.getOrDefault(id, 0);
            println(String.format("  %-25s type=%-8s path=%-40s types=%d",
                sa.getName(), sa.getArchiveType(), sa.getDomainFileID(), count));
        }

        // === Section 2: Orphaned PSP types (local but should be from archive) ===
        if (gdtDir != null) {
            println("\n=== UUID Match Audit ===");

            File[] gdtFiles = gdtDir.listFiles((d, n) -> n.endsWith(".gdt"));
            if (gdtFiles == null || gdtFiles.length == 0) {
                println("  No .gdt files found in " + gdtDir);
                return;
            }

            for (File gdtFile : gdtFiles) {
                FileDataTypeManager fdtm = null;
                try {
                    fdtm = FileDataTypeManager.openFileArchive(gdtFile, false);
                } catch (Exception e) {
                    println("  SKIP: " + gdtFile.getName() + ": " + e.getMessage());
                    continue;
                }

                try {
                    String archiveName = gdtFile.getName().replace(".gdt", "");
                    SourceArchive archiveLocalSA = fdtm.getLocalSourceArchive();

                    int matched = 0;
                    int uuidMismatch = 0;
                    int orphaned = 0;
                    int notInProgram = 0;

                    Iterator<DataType> archiveIt = fdtm.getAllDataTypes();
                    while (archiveIt.hasNext()) {
                        DataType archiveDt = archiveIt.next();
                        String catPath = archiveDt.getCategoryPath().getPath();
                        if (catPath.startsWith("/generic_clib") || catPath.startsWith("/windows")) continue;

                        String name = archiveDt.getName();
                        DataType progDt = dtm.getDataType(archiveDt.getCategoryPath(), name);

                        if (progDt == null) {
                            notInProgram++;
                            continue;
                        }

                        SourceArchive progSA = progDt.getSourceArchive();
                        boolean isLocal = (progSA == null ||
                            progSA.getSourceArchiveID().equals(programSA.getSourceArchiveID()));

                        if (isLocal) {
                            orphaned++;
                            continue;
                        }

                        // Type has an archive link — check if UUID matches
                        if (progDt.getUniversalID() != null &&
                            archiveDt.getUniversalID() != null &&
                            progDt.getUniversalID().equals(archiveDt.getUniversalID())) {
                            matched++;
                        } else {
                            uuidMismatch++;
                        }
                    }

                    if (matched > 0 || uuidMismatch > 0 || orphaned > 0) {
                        println(String.format("  %-25s matched=%d  uuid_mismatch=%d  orphaned=%d  not_in_program=%d",
                            archiveName, matched, uuidMismatch, orphaned, notInProgram));
                    }

                } finally {
                    fdtm.close();
                }
            }
        }

        println("\n=== Audit Complete ===");
    }
}
