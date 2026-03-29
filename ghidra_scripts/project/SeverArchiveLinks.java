// SeverArchiveLinks.java — DEPRECATED: Do not use.
//
// This script calls dtm.disassociate() which assigns new local UniversalIDs,
// permanently breaking Ghidra's "sync with archive" feature. Once severed,
// types can only be re-linked by re-resolving from the archive (RelinkArchiveTypes.java).
//
// If you're seeing "archive not found" errors, install the .gdt files to
// ~/.config/ghidra/ghidra_<version>_NIX/data/ instead of severing links.
//
// This script now requires --force to run as a safety measure.
//
// Usage:
//   analyzeHeadless ... -process <program> -noanalysis \
//     -postScript SeverArchiveLinks.java --force
//
//@category PSP.Project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.*;

public class SeverArchiveLinks extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        String[] args = getScriptArgs();
        boolean force = false;
        for (String arg : args) {
            if (arg.equals("--force")) force = true;
        }
        if (!force) {
            printerr("REFUSED: SeverArchiveLinks is deprecated — it permanently breaks");
            printerr("archive sync by assigning new local UniversalIDs to all types.");
            printerr("Use RelinkArchiveTypes.java to fix link issues instead.");
            printerr("Pass --force to override this safety check.");
            return;
        }

        println("WARNING: Severing archive links — this is destructive and irreversible.");

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        List<SourceArchive> archives = dtm.getSourceArchives();

        int severed = 0;
        for (SourceArchive sa : archives) {
            // Skip the program's own archive and the built-in archive
            if (sa.getArchiveType() == ArchiveType.PROGRAM) continue;
            if (sa.getArchiveType() == ArchiveType.BUILT_IN) continue;

            String name = sa.getName();
            println("  Severing: " + name + " (type=" + sa.getArchiveType() + ")");

            // Disassociate all data types from this source archive
            // This makes them local to the program
            Iterator<DataType> it = dtm.getAllDataTypes();
            int typesDisassociated = 0;
            while (it.hasNext()) {
                DataType dt = it.next();
                if (dt.getSourceArchive() != null &&
                    dt.getSourceArchive().getSourceArchiveID().equals(sa.getSourceArchiveID())) {
                    dtm.disassociate(dt);
                    typesDisassociated++;
                }
            }

            println("    Disassociated " + typesDisassociated + " type(s)");

            // Now remove the source archive reference
            try {
                dtm.removeSourceArchive(sa);
                println("    Removed archive reference");
                severed++;
            } catch (Exception e) {
                println("    Could not remove archive ref: " + e.getMessage());
            }
        }

        println("Severed " + severed + " archive link(s) from " + currentProgram.getName());
    }
}
