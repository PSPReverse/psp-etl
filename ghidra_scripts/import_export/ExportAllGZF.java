// ExportAllGZF.java — Export all programs in the current project as .gzf packed files.
//
// Usage (GUI):   Run from Script Manager. First argument = output directory.
// Usage (headless):
//   analyzeHeadless <project_dir> <project_name> -noanalysis \
//     -scriptPath /path/to/ghidra_scripts \
//     -postScript ExportAllGZF.java /path/to/output_dir
//
// Each program "folder/name" becomes "folder__name.gzf" in the output directory.
// Existing .gzf files are skipped (idempotent).
//
//@category PSP.ImportExport

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import java.io.File;

public class ExportAllGZF extends GhidraScript {

    private int exported = 0;
    private int skipped = 0;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ExportAllGZF.java <output_directory>");
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
        exportFolder(root, "", outDir);

        println("Export complete: " + exported + " exported, " + skipped + " skipped (already exist).");
    }

    private void exportFolder(DomainFolder folder, String prefix, File outDir) throws Exception {
        for (DomainFile file : folder.getFiles()) {
            String safeName = (prefix + file.getName()).replace("/", "__").replace("\\", "__");
            File dest = new File(outDir, safeName + ".gzf");

            if (dest.exists()) {
                println("  SKIP (exists): " + dest.getName());
                skipped++;
                continue;
            }

            println("  Exporting: " + prefix + file.getName() + " -> " + dest.getName());
            file.packFile(dest, monitor);
            exported++;
        }

        for (DomainFolder sub : folder.getFolders()) {
            String subPrefix = prefix.isEmpty() ? sub.getName() + "/" : prefix + sub.getName() + "/";
            exportFolder(sub, subPrefix, outDir);
        }
    }
}
