// ResolveProjectArchives.java — DEPRECATED: Use RelinkArchiveTypes.java instead.
//
// This script uses associateDataTypeWithArchive() which only sets the source
// archive pointer — it does NOT fix the UniversalID mismatch, so Ghidra's
// "sync with archive" still won't work.
//
// Original description:
// Convert FILE-type source archive references to
// PROJECT-type references by resolving against project-internal DataTypeArchive
// domain objects.
//
// The 9 data type archives (PspSvcIf, PspHw, etc.) live in the project under
// /sect/ as Archive domain objects. Programs imported from the original SECT
// project have FILE-type source archive references with null paths. This script
// re-associates those types with the project-internal archives so they resolve
// automatically when opening any program.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name> -noanalysis \
//     -recursive -process \
//     -scriptPath ghidra_scripts/project \
//     -postScript ResolveProjectArchives.java [archive_folder]
//
//@category PSP.Project
//
// archive_folder defaults to "sect" (i.e. /sect/ in the project).

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.data.*;
import ghidra.util.UniversalID;
import java.util.*;

public class ResolveProjectArchives extends GhidraScript {

    // The 9 data type archive names
    private static final String[] ARCHIVE_NAMES = {
        "ArXbShared", "CcpIf", "PspHw", "PspSev", "PspSvcIf",
        "SecOS", "TE", "TrustedOsInterface", "VMSA"
    };

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        String[] args = getScriptArgs();
        String folderName = (args.length >= 1 && !args[0].isEmpty()) ? args[0] : "sect";

        Project project = state.getProject();
        if (project == null) {
            printerr("No project open.");
            return;
        }

        DomainFolder root = project.getProjectData().getRootFolder();
        DomainFolder archiveFolder = root.getFolder(folderName);
        if (archiveFolder == null) {
            printerr("Archive folder /" + folderName + " not found in project.");
            return;
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Set<String> archiveSet = new HashSet<>(Arrays.asList(ARCHIVE_NAMES));

        // Snapshot source archives — we modify during iteration
        List<SourceArchive> archives = new ArrayList<>(dtm.getSourceArchives());
        int fixed = 0;

        for (SourceArchive sa : archives) {
            String name = sa.getName();
            if (!archiveSet.contains(name)) continue;

            // Skip if already a PROJECT archive
            if (sa.getArchiveType() == ArchiveType.PROJECT) {
                println("  OK (project): " + name + " path=" + sa.getDomainFileID());
                continue;
            }

            // Only fix FILE archives
            if (sa.getArchiveType() != ArchiveType.FILE) {
                println("  SKIP (type=" + sa.getArchiveType() + "): " + name);
                continue;
            }

            // Look up the project-level archive domain file
            DomainFile domainFile = archiveFolder.getFile(name);
            if (domainFile == null) {
                println("  NOT FOUND in project: /" + folderName + "/" + name);
                continue;
            }

            // Open the DataTypeArchive
            DomainObject domainObj = null;
            try {
                domainObj = domainFile.getDomainObject(this, true, false, monitor);
                if (!(domainObj instanceof ghidra.program.model.listing.DataTypeArchive)) {
                    println("  NOT AN ARCHIVE: /" + folderName + "/" + name +
                            " (type=" + domainObj.getClass().getSimpleName() + ")");
                    continue;
                }

                ghidra.program.model.listing.DataTypeArchive archive =
                    (ghidra.program.model.listing.DataTypeArchive) domainObj;
                DataTypeManager archiveDtm = archive.getDataTypeManager();
                SourceArchive archiveLocalSA = archiveDtm.getLocalSourceArchive();

                // Collect all data types in the program linked to the old FILE archive
                UniversalID oldID = sa.getSourceArchiveID();
                Iterator<DataType> it = dtm.getAllDataTypes();
                List<DataType> toReassociate = new ArrayList<>();
                while (it.hasNext()) {
                    DataType dt = it.next();
                    if (dt.getSourceArchive() != null &&
                        dt.getSourceArchive().getSourceArchiveID().equals(oldID)) {
                        toReassociate.add(dt);
                    }
                }

                if (toReassociate.isEmpty()) {
                    println("  NO TYPES linked to FILE archive: " + name);
                    // Still remove the stale reference
                    dtm.removeSourceArchive(sa);
                    continue;
                }

                // Remove old FILE archive reference, resolve PROJECT archive
                dtm.removeSourceArchive(sa);
                SourceArchive newSA = dtm.resolveSourceArchive(archiveLocalSA);

                // Re-associate data types with the project archive
                for (DataType dt : toReassociate) {
                    dtm.associateDataTypeWithArchive(dt, newSA);
                }

                println("  FIXED: " + name + " FILE -> PROJECT (" +
                        toReassociate.size() + " types, domainFileID=" +
                        domainFile.getFileID() + ")");
                fixed++;

            } catch (Exception e) {
                println("  FAILED: " + name + ": " + e.getClass().getSimpleName() +
                        ": " + e.getMessage());
            } finally {
                if (domainObj != null) {
                    domainObj.release(this);
                }
            }
        }

        println("Resolved " + fixed + " archive(s) to project in " + currentProgram.getName());
    }
}
