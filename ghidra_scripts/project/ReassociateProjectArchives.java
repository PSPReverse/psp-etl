// ReassociateProjectArchives.java — DEPRECATED: Use RelinkArchiveTypes.java instead.
//
// This script uses associateDataTypeWithArchive() which only sets the source
// archive pointer — it does NOT fix the UniversalID mismatch, so Ghidra's
// "sync with archive" still won't work.
//
// Original description:
// Force-associate program data types with
// project-internal DataTypeArchive objects by matching on name + category path.
//
// Use this after types have been disassociated (e.g. by SeverArchiveLinks) and
// need to be re-linked to the project archives.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name> -noanalysis \
//     -recursive -process <program> \
//     -scriptPath ghidra_scripts/project \
//     -postScript ReassociateProjectArchives.java [archive_folder]
//
// archive_folder defaults to "sect".
//
//@category PSP.Project

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.data.*;
import ghidra.util.UniversalID;
import java.util.*;

public class ReassociateProjectArchives extends GhidraScript {

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
        DomainFolder root = project.getProjectData().getRootFolder();
        DomainFolder archiveFolder = root.getFolder(folderName);
        if (archiveFolder == null) {
            printerr("Archive folder /" + folderName + " not found.");
            return;
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int totalAssociated = 0;

        for (String archiveName : ARCHIVE_NAMES) {
            DomainFile domainFile = archiveFolder.getFile(archiveName);
            if (domainFile == null) {
                println("  NOT FOUND: /" + folderName + "/" + archiveName);
                continue;
            }

            DomainObject domainObj = null;
            try {
                domainObj = domainFile.getDomainObject(this, true, false, monitor);
                if (!(domainObj instanceof ghidra.program.model.listing.DataTypeArchive)) {
                    continue;
                }

                ghidra.program.model.listing.DataTypeArchive archive =
                    (ghidra.program.model.listing.DataTypeArchive) domainObj;
                DataTypeManager archiveDtm = archive.getDataTypeManager();

                // Build a set of (categoryPath, name) pairs from the archive
                Set<String> archiveTypeKeys = new HashSet<>();
                Iterator<DataType> archiveIt = archiveDtm.getAllDataTypes();
                while (archiveIt.hasNext()) {
                    DataType dt = archiveIt.next();
                    archiveTypeKeys.add(dt.getCategoryPath().getPath() + "/" + dt.getName());
                }

                // Resolve the project archive as a source archive in the program
                SourceArchive archiveLocalSA = archiveDtm.getLocalSourceArchive();
                SourceArchive projectSA = dtm.resolveSourceArchive(archiveLocalSA);

                // Find program types that match archive types and are currently local
                Iterator<DataType> progIt = dtm.getAllDataTypes();
                int count = 0;
                while (progIt.hasNext()) {
                    DataType dt = progIt.next();
                    String key = dt.getCategoryPath().getPath() + "/" + dt.getName();
                    if (archiveTypeKeys.contains(key)) {
                        // Check if already associated with this archive
                        SourceArchive currentSA = dt.getSourceArchive();
                        if (currentSA != null &&
                            currentSA.getSourceArchiveID().equals(projectSA.getSourceArchiveID())) {
                            continue; // already correct
                        }
                        // Check if it's local (program's own)
                        SourceArchive progLocal = dtm.getLocalSourceArchive();
                        if (currentSA == null || currentSA.getSourceArchiveID().equals(
                                progLocal.getSourceArchiveID())) {
                            dtm.associateDataTypeWithArchive(dt, projectSA);
                            count++;
                        }
                    }
                }

                if (count > 0) {
                    println("  ASSOCIATED: " + archiveName + " (" + count + " types)");
                    totalAssociated += count;
                }

            } catch (Exception e) {
                println("  FAILED: " + archiveName + ": " + e.getMessage());
            } finally {
                if (domainObj != null) {
                    domainObj.release(this);
                }
            }
        }

        println("Re-associated " + totalAssociated + " types in " + currentProgram.getName());
    }
}
