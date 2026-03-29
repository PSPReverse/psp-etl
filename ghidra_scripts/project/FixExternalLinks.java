// FixExternalLinks.java — Fix broken external program references after folder reorganization.
//
// Paths like "/Tesla/foo" become "/sect/Tesla/foo" since all SECT programs
// are now under /sect/.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name>/<folder> \
//     -recursive -process \
//     -scriptPath /path/to/ghidra_scripts \
//     -postScript FixExternalLinks.java
//
//@category PSP.Project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class FixExternalLinks extends GhidraScript {

    // Top-level folder names that were moved under /sect/
    private static final String[] SECT_FOLDERS = {
        "off-chip-bl", "on-chip-bl", "Tesla", "Tesla-PPC", "SecureOS",
        "fTPM", "SevApp", "Other", "Uefi", "Graka", "TrustedOs",
        "PSP-Applications", "Pluton HSP"
    };

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        ExternalManager extMgr = currentProgram.getExternalManager();
        String[] extNames = extMgr.getExternalLibraryNames();
        int fixed = 0;

        for (String extName : extNames) {
            String path = extMgr.getExternalLibraryPath(extName);
            if (path == null || path.isEmpty()) continue;

            // Check if path starts with a known SECT folder but not /sect/
            for (String folder : SECT_FOLDERS) {
                String prefix = "/" + folder + "/";
                if (path.startsWith(prefix)) {
                    String newPath = "/sect" + path;
                    extMgr.setExternalPath(extName, newPath, true);
                    println("  Fixed: " + extName + ": " + path + " -> " + newPath);
                    fixed++;
                    break;
                }
            }
        }

        if (fixed > 0) {
            println("Fixed " + fixed + " external link(s) in " + currentProgram.getName());
        }
    }
}
