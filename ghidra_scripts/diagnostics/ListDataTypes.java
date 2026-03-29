// ListDataTypes.java — List all user-defined data types, enums, and structs.
// Searches both the program's data type manager and any open archives.
//
//@category PSP.Diagnostics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.*;

public class ListDataTypes extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        println("=== Data Types in " + currentProgram.getName() + " ===");
        println("Archives:");
        for (SourceArchive sa : dtm.getSourceArchives()) {
            println("  " + sa.getName() + " (type: " + sa.getArchiveType() + ")");
        }

        println("\nEnums:");
        Iterator<DataType> it = dtm.getAllDataTypes();
        List<String> enums = new ArrayList<>();
        List<String> structs = new ArrayList<>();
        List<String> typedefs = new ArrayList<>();

        while (it.hasNext()) {
            DataType dt = it.next();
            String path = dt.getCategoryPath().getPath();
            if (dt instanceof ghidra.program.model.data.Enum) {
                ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum) dt;
                enums.add("  " + path + "/" + dt.getName() + " (" + e.getCount() + " values)");
            } else if (dt instanceof Structure) {
                structs.add("  " + path + "/" + dt.getName() + " (size " + dt.getLength() + ")");
            } else if (dt instanceof TypeDef) {
                String name = dt.getName().toLowerCase();
                if (name.contains("psp") || name.contains("status") ||
                    name.contains("svc") || name.contains("ccp") ||
                    name.contains("mailbox") || name.contains("mbx")) {
                    typedefs.add("  " + path + "/" + dt.getName());
                }
            }
        }

        // Filter for PSP-relevant items
        for (String s : enums) {
            if (s.toLowerCase().contains("psp") || s.toLowerCase().contains("status") ||
                s.toLowerCase().contains("svc") || s.toLowerCase().contains("ccp") ||
                s.toLowerCase().contains("error") || s.toLowerCase().contains("ret")) {
                println(s);
            }
        }

        println("\nPSP-relevant structs:");
        for (String s : structs) {
            if (s.toLowerCase().contains("psp") || s.toLowerCase().contains("ccp") ||
                s.toLowerCase().contains("mailbox") || s.toLowerCase().contains("svc") ||
                s.toLowerCase().contains("boot") || s.toLowerCase().contains("header")) {
                println(s);
            }
        }

        println("\nPSP-relevant typedefs:");
        for (String s : typedefs) {
            println(s);
        }

        // Also dump ALL enums to help the user find what they're looking for
        println("\nAll enums (" + enums.size() + " total):");
        for (String s : enums) {
            println(s);
        }
    }
}
