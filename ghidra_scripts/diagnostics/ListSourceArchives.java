// ListSourceArchives.java — Show all source archive references and their resolution status.
//
//@category PSP.Diagnostics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.*;

public class ListSourceArchives extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        for (SourceArchive sa : dtm.getSourceArchives()) {
            String id = sa.getSourceArchiveID().toString();
            println("  ARCHIVE: name=" + sa.getName() +
                    " type=" + sa.getArchiveType() +
                    " id=" + id +
                    " path=" + sa.getDomainFileID());
        }
    }
}
