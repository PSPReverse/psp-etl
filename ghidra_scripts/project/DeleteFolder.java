// DeleteFolder.java — Delete a project folder and all its contents.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name> -noanalysis \
//     -scriptPath /path/to/ghidra_scripts \
//     -preScript DeleteFolder.java <folder_name>
//
//@category PSP.Project

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;

public class DeleteFolder extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: DeleteFolder.java <folder_name>");
            return;
        }

        DomainFolder root = state.getProject().getProjectData().getRootFolder();
        DomainFolder target = root.getFolder(args[0]);
        if (target == null) {
            println("Folder /" + args[0] + " not found — nothing to delete.");
            return;
        }

        int files = countFiles(target);
        println("Deleting /" + args[0] + " (" + files + " file(s))...");
        deleteRecursive(target);
        println("Done.");
    }

    private int countFiles(DomainFolder folder) {
        int count = folder.getFiles().length;
        for (DomainFolder sub : folder.getFolders()) {
            count += countFiles(sub);
        }
        return count;
    }

    private void deleteRecursive(DomainFolder folder) throws Exception {
        for (DomainFile file : folder.getFiles()) {
            file.delete();
        }
        for (DomainFolder sub : folder.getFolders()) {
            deleteRecursive(sub);
        }
        folder.delete();
    }
}
