// ExportArchivesOnly.java — Export only DataTypeArchive files (not programs) from a project.
//
// In the SECT project, items like PspSvcIf, PspHw, CcpIf etc. are DataTypeArchive
// domain objects, not programs. This script exports only those as .gdt files.
//
// Usage (GUI against SECT project):
//   Run from Script Manager. Argument = output directory.
//   Example: <repo>/data/ghidra_archives
//
// Usage (headless):
//   analyzeHeadless <sect_project_dir> <sect_project_name> -noanalysis \
//     -scriptPath /path/to/ghidra_scripts \
//     -postScript ExportArchivesOnly.java /path/to/output_dir
//
//@category PSP.ImportExport

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import java.io.File;

public class ExportArchivesOnly extends GhidraScript {

    private int exported = 0;
    private int skipped = 0;
    private int programs = 0;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ExportArchivesOnly.java <output_directory>");
            return;
        }

        File outDir = new File(args[0]);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        Project project = state.getProject();
        if (project == null) {
            printerr("No project open.");
            return;
        }

        DomainFolder root = project.getProjectData().getRootFolder();
        scanFolder(root, outDir);

        println("\nExport complete:");
        println("  Archives exported: " + exported);
        println("  Archives skipped (exist): " + skipped);
        println("  Programs ignored: " + programs);
    }

    private void scanFolder(DomainFolder folder, File outDir) throws Exception {
        for (DomainFile file : folder.getFiles()) {
            String contentType = file.getContentType();

            if (contentType.contains("Data Type Archive") ||
                contentType.contains("DataTypeArchive") ||
                contentType.equals("Archive")) {
                // This is a data type archive — export it
                File dest = new File(outDir, file.getName() + ".gdt");
                if (dest.exists()) {
                    println("  SKIP (exists): " + file.getName());
                    skipped++;
                    continue;
                }

                println("  Exporting archive: " + file.getName() +
                        " (type=" + contentType + ") -> " + dest.getName());
                file.packFile(dest, monitor);
                exported++;
            } else {
                // Log what we're skipping (for debugging content type detection)
                programs++;
            }
        }

        for (DomainFolder sub : folder.getFolders()) {
            scanFolder(sub, outDir);
        }
    }
}
