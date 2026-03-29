// ReorganizeSect.java — Move flat "Category__Name" files into Category/Name subfolders.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name> -noanalysis \
//     -scriptPath /path/to/ghidra_scripts \
//     -preScript ReorganizeSect.java [folder_name]
//
// Default folder: "sect". Converts "off-chip-bl__Epyc_Zen2_ver_0c75" into
// "off-chip-bl/Epyc_Zen2_ver_0c75" within the target folder.
//
//@category PSP.Project

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import java.util.ArrayList;

public class ReorganizeSect extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String folderName = (args.length >= 1 && !args[0].isEmpty()) ? args[0] : "sect";

        DomainFolder root = state.getProject().getProjectData().getRootFolder();
        DomainFolder target = root.getFolder(folderName);
        if (target == null) {
            printerr("Folder /" + folderName + " not found in project.");
            return;
        }

        // Collect names first to avoid modifying the folder while iterating
        ArrayList<String> names = new ArrayList<>();
        for (DomainFile f : target.getFiles()) {
            names.add(f.getName());
        }
        println("Found " + names.size() + " file(s) in /" + folderName);

        int moved = 0;
        int skipped = 0;

        for (String name : names) {
            int sep = name.indexOf("__");
            if (sep <= 0) {
                println("  SKIP (no __): " + name);
                skipped++;
                continue;
            }

            String category = name.substring(0, sep);
            String remainder = name.substring(sep + 2);

            // Re-fetch the file by name (safe after prior moves)
            DomainFile file = target.getFile(name);
            if (file == null) {
                println("  SKIP (gone): " + name);
                skipped++;
                continue;
            }

            // Get or create subfolder
            DomainFolder sub = target.getFolder(category);
            if (sub == null) {
                sub = target.createFolder(category);
            }

            // Check for name collision
            if (sub.getFile(remainder) != null) {
                println("  SKIP (exists): " + category + "/" + remainder);
                skipped++;
                continue;
            }

            // Rename first (while still in parent folder), then move
            try {
                file.setName(remainder);
                file.moveTo(sub);
                println("  " + name + " -> " + category + "/" + remainder);
                moved++;
            } catch (Exception e) {
                printerr("  FAILED: " + name + " — " + e.getMessage());
            }
        }

        println("Reorganize complete: " + moved + " moved, " + skipped + " skipped.");
    }
}
