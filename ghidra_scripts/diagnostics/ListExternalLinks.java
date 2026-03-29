// ListExternalLinks.java — Dump all external library names and paths.
//
//@category PSP.Diagnostics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class ListExternalLinks extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;
        ExternalManager extMgr = currentProgram.getExternalManager();
        String[] names = extMgr.getExternalLibraryNames();
        if (names.length == 0) return;
        for (String name : names) {
            String path = extMgr.getExternalLibraryPath(name);
            println("  EXT: name=\"" + name + "\" path=\"" + (path != null ? path : "<null>") + "\"");
        }
    }
}
