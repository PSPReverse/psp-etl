// ImportGZFTree.java — Import .gzf files into subfolders based on "Category__Name" filenames.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name> -noanalysis \
//     -scriptPath /path/to/ghidra_scripts \
//     -preScript ImportGZFTree.java <gzf_directory> [root_folder]
//
// "off-chip-bl__Epyc_Zen2_ver_0c75.gzf" -> /sect/off-chip-bl/Epyc_Zen2_ver_0c75
// Files without "__" go directly into the root folder.
//
//@category PSP.ImportExport

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import java.io.File;

public class ImportGZFTree extends GhidraScript {

    private int imported = 0;
    private int skipped = 0;
    private int failed = 0;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ImportGZFTree.java <gzf_directory> [root_folder]");
            return;
        }

        File gzfDir = new File(args[0]);
        if (!gzfDir.isDirectory()) {
            printerr("Not a directory: " + gzfDir);
            return;
        }

        DomainFolder root = state.getProject().getProjectData().getRootFolder();
        DomainFolder target = root;

        if (args.length >= 2 && !args[1].isEmpty()) {
            String folderName = args[1];
            DomainFolder existing = root.getFolder(folderName);
            target = (existing != null) ? existing : root.createFolder(folderName);
            println("Root folder: /" + folderName);
        }

        File[] gzfFiles = gzfDir.listFiles((dir, name) -> name.endsWith(".gzf"));
        if (gzfFiles == null || gzfFiles.length == 0) {
            println("No .gzf files found in " + gzfDir);
            return;
        }

        println("Found " + gzfFiles.length + " .gzf file(s) to import.");

        for (File gzf : gzfFiles) {
            String baseName = gzf.getName().replaceFirst("\\.gzf$", "");

            // Split on first "__" to get category/name
            int sep = baseName.indexOf("__");
            DomainFolder dest;
            String progName;

            if (sep > 0) {
                String category = baseName.substring(0, sep);
                progName = baseName.substring(sep + 2);

                DomainFolder sub = target.getFolder(category);
                dest = (sub != null) ? sub : target.createFolder(category);
            } else {
                dest = target;
                progName = baseName;
            }

            // Skip if already exists
            if (dest.getFile(progName) != null) {
                println("  SKIP (exists): " + dest.getName() + "/" + progName);
                skipped++;
                continue;
            }

            try {
                dest.createFile(progName, gzf, monitor);
                println("  " + gzf.getName() + " -> " + dest.getName() + "/" + progName);
                imported++;
            } catch (Exception e) {
                printerr("  FAILED: " + gzf.getName() + " — " + e.getMessage());
                failed++;
            }
        }

        println("Import complete: " + imported + " imported, " + skipped + " skipped, " + failed + " failed.");
    }
}
