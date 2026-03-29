// RenamePrograms.java — Rename programs in a project folder using a TSV mapping file.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name> -noanalysis \
//     -scriptPath /path/to/ghidra_scripts \
//     -preScript RenamePrograms.java <mapping_file> [folder]
//
// Mapping file is TSV: <current_name>\t<new_name>
// Lines starting with # are ignored. Folder defaults to project root.
// Programs not in the mapping are left unchanged.
//
//@category PSP.Project

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import java.io.*;
import java.util.*;

public class RenamePrograms extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: RenamePrograms.java <mapping_file> [folder]");
            return;
        }

        File mapFile = new File(args[0]);
        if (!mapFile.exists()) {
            printerr("Mapping file not found: " + mapFile);
            return;
        }

        // Parse mapping
        Map<String, String> mapping = new LinkedHashMap<>();
        try (BufferedReader br = new BufferedReader(new FileReader(mapFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\t", 2);
                if (parts.length == 2) {
                    mapping.put(parts[0].trim(), parts[1].trim());
                }
            }
        }
        println("Loaded " + mapping.size() + " rename mapping(s).");

        DomainFolder root = state.getProject().getProjectData().getRootFolder();
        DomainFolder target = root;
        if (args.length >= 2 && !args[1].isEmpty()) {
            target = resolveFolder(root, args[1]);
            if (target == null) {
                printerr("Folder /" + args[1] + " not found.");
                return;
            }
        }

        int renamed = 0;
        int notFound = 0;

        for (Map.Entry<String, String> entry : mapping.entrySet()) {
            String oldName = entry.getKey();
            String newName = entry.getValue();

            DomainFile file = target.getFile(oldName);
            if (file == null) {
                println("  NOT FOUND: " + oldName);
                notFound++;
                continue;
            }

            try {
                file.setName(newName);
                println("  " + oldName + " -> " + newName);
                renamed++;
            } catch (Exception e) {
                printerr("  FAILED: " + oldName + " -> " + newName + " — " + e.getMessage());
            }
        }

        println("Rename complete: " + renamed + " renamed, " + notFound + " not found.");
    }

    private DomainFolder resolveFolder(DomainFolder root, String path) {
        DomainFolder current = root;
        for (String part : path.split("/")) {
            if (part.isEmpty()) continue;
            current = current.getFolder(part);
            if (current == null) return null;
        }
        return current;
    }
}
