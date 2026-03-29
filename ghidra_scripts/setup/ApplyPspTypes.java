// ApplyPspTypes.java — Copy PSP-specific data types (enums, structs) from
// a type library program into the current program, then apply PSP_STATUS
// as return type where appropriate.
//
// Usage:
//   analyzeHeadless ... -process <dest> -noanalysis \
//     -postScript ApplyPspTypes.java <type_library_path> [<type_library_path2> ...]
//
// Example:
//   -postScript ApplyPspTypes.java /sect/PspSvcIf /sect/PspHw /sect/CcpIf
//
//@category PSP.Setup

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.model.*;
import java.util.*;

public class ApplyPspTypes extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ApplyPspTypes.java <type_lib_path> [<type_lib_path2> ...]");
            return;
        }

        DataTypeManager destDtm = currentProgram.getDataTypeManager();
        int typesImported = 0;
        DataType pspStatusType = null;

        // Phase 1: Import types from each library
        for (String libPath : args) {
            DomainFile libFile = resolveFile(libPath);
            if (libFile == null) {
                println("Library not found: " + libPath + ", skipping.");
                continue;
            }

            ghidra.program.model.listing.Program libProg =
                (ghidra.program.model.listing.Program) libFile.getReadOnlyDomainObject(
                    this, DomainFile.DEFAULT_VERSION, monitor);
            if (libProg == null) {
                println("Could not open: " + libPath);
                continue;
            }

            try {
                DataTypeManager srcDtm = libProg.getDataTypeManager();
                println("Scanning types in " + libPath + "...");

                Iterator<DataType> it = srcDtm.getAllDataTypes();
                while (it.hasNext()) {
                    DataType dt = it.next();
                    String name = dt.getName();
                    String path = dt.getCategoryPath().getPath();

                    // Skip built-in / generic types
                    if (path.startsWith("/generic") || path.startsWith("/windows") ||
                        path.startsWith("/Demangler") || name.startsWith("_")) continue;

                    // Import enums, structs, typedefs that look PSP-relevant
                    boolean relevant = false;
                    String lname = name.toLowerCase();
                    if (dt instanceof ghidra.program.model.data.Enum) {
                        // Import ALL enums from PSP type libraries
                        relevant = true;
                    } else if (dt instanceof Structure) {
                        relevant = true;
                    } else if (dt instanceof TypeDef) {
                        relevant = lname.contains("psp") || lname.contains("ccp") ||
                                   lname.contains("svc") || lname.contains("status") ||
                                   lname.contains("sev") || lname.contains("mbx");
                    }

                    if (!relevant) continue;

                    // Check if already exists in dest
                    DataType existing = destDtm.getDataType(dt.getCategoryPath(), name);
                    if (existing != null) continue;

                    // Resolve (deep copy) into destination
                    try {
                        DataType resolved = destDtm.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
                        if (resolved != null) {
                            typesImported++;
                            if (dt instanceof ghidra.program.model.data.Enum) {
                                ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum) dt;
                                println("  enum " + name + " (" + e.getCount() + " values)");
                            } else if (dt instanceof Structure) {
                                println("  struct " + name + " (size " + dt.getLength() + ")");
                            } else {
                                println("  typedef " + name);
                            }
                        }

                        // Track PSP_STATUS specifically
                        if (name.equals("PSP_STATUS") || name.equals("PSPSTATUS") ||
                            name.equals("PspStatus") || name.equals("PSP_STS")) {
                            pspStatusType = resolved;
                        }
                    } catch (Exception e) {
                        // Skip types that can't be resolved
                    }
                }
            } finally {
                libProg.release(this);
            }
        }

        println("\nImported " + typesImported + " type(s).");

        // Phase 2: If we found PSP_STATUS, apply it as return type to functions
        // that compare their return value against known status codes
        if (pspStatusType == null) {
            // Try to find it in the dest DTM (might have been imported under a different category)
            Iterator<DataType> it = destDtm.getAllDataTypes();
            while (it.hasNext()) {
                DataType dt = it.next();
                String name = dt.getName().toLowerCase();
                if ((name.contains("psp") && name.contains("status")) ||
                    name.equals("pspstatus") || name.equals("psp_sts")) {
                    pspStatusType = dt;
                    break;
                }
            }
        }

        if (pspStatusType != null) {
            println("\nFound PSP_STATUS type: " + pspStatusType.getName());
            println("Applying as return type to functions that use it...");

            int applied = 0;
            FunctionIterator funcIt = currentProgram.getFunctionManager().getFunctions(true);
            while (funcIt.hasNext()) {
                Function func = funcIt.next();

                // Heuristic: functions named with common PSP patterns likely return PSP_STATUS
                String fname = func.getName().toLowerCase();
                if (fname.contains("init") || fname.contains("verify") ||
                    fname.contains("validate") || fname.contains("check") ||
                    fname.contains("load") || fname.contains("decrypt") ||
                    fname.contains("svc_") || fname.contains("handle_svc")) {
                    try {
                        func.setReturnType(pspStatusType, SourceType.IMPORTED);
                        applied++;
                    } catch (Exception e) {
                        // Skip
                    }
                }
            }
            println("Applied PSP_STATUS return type to " + applied + " function(s).");
        } else {
            println("PSP_STATUS type not found in any library. Listing all enums for reference:");
            Iterator<DataType> it = destDtm.getAllDataTypes();
            while (it.hasNext()) {
                DataType dt = it.next();
                if (dt instanceof ghidra.program.model.data.Enum) {
                    println("  " + dt.getCategoryPath().getPath() + "/" + dt.getName());
                }
            }
        }
    }

    private DomainFile resolveFile(String path) {
        String[] parts = path.split("/");
        DomainFolder folder = state.getProject().getProjectData().getRootFolder();
        for (int i = 0; i < parts.length - 1; i++) {
            if (parts[i].isEmpty()) continue;
            folder = folder.getFolder(parts[i]);
            if (folder == null) return null;
        }
        return folder.getFile(parts[parts.length - 1]);
    }
}
