// ImportGZF.java — Import .gzf packed files into the current project.
//
// Usage (headless):
//   analyzeHeadless <project_dir> <project_name> -noanalysis \
//     -scriptPath /path/to/ghidra_scripts \
//     -preScript ImportGZF.java /path/to/gzf_directory [target_folder]
//
// All .gzf files in the input directory are unpacked into the project.
// Optional target_folder (e.g. "sect") creates a subfolder in the project.
// Files already present in the project (by name) are skipped.
//
//@category PSP.ImportExport

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import java.io.File;

public class ImportGZF extends GhidraScript {

    private int imported = 0;
    private int skipped = 0;
    private int failed = 0;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ImportGZF.java <gzf_directory> [target_folder]");
            return;
        }

        File gzfDir = new File(args[0]);
        if (!gzfDir.isDirectory()) {
            printerr("Not a directory: " + gzfDir);
            return;
        }

        Project project = state.getProject();
        if (project == null) {
            printerr("No project open.");
            return;
        }

        DomainFolder root = project.getProjectData().getRootFolder();
        DomainFolder target = root;

        if (args.length >= 2 && !args[1].isEmpty()) {
            String folderName = args[1];
            DomainFolder existing = root.getFolder(folderName);
            if (existing != null) {
                target = existing;
            } else {
                target = root.createFolder(folderName);
            }
            println("Target folder: /" + folderName);
        }

        File[] gzfFiles = gzfDir.listFiles((dir, name) -> name.endsWith(".gzf"));
        if (gzfFiles == null || gzfFiles.length == 0) {
            println("No .gzf files found in " + gzfDir);
            return;
        }

        println("Found " + gzfFiles.length + " .gzf file(s) to import.");

        for (File gzf : gzfFiles) {
            String progName = gzf.getName().replaceFirst("\\.gzf$", "");

            // Check if already exists
            if (target.getFile(progName) != null) {
                println("  SKIP (exists): " + progName);
                skipped++;
                continue;
            }

            try {
                println("  Importing: " + gzf.getName() + " -> /" + target.getName() + "/" + progName);
                target.createFile(progName, gzf, monitor);
                imported++;
            } catch (Exception e) {
                printerr("  FAILED: " + gzf.getName() + " — " + e.getMessage());
                failed++;
            }
        }

        println("Import complete: " + imported + " imported, " + skipped + " skipped, " + failed + " failed.");
    }
}
