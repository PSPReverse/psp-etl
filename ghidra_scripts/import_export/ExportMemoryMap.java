// ExportMemoryMap.java — Export memory blocks from all programs in a folder as JSON.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name> -noanalysis -readOnly \
//     -scriptPath /path/to/ghidra_scripts \
//     -recursive -process \
//     -postScript ExportMemoryMap.java <output_file>
//
// Appends one JSON object per program to the output file.
//
//@category PSP.ImportExport

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class ExportMemoryMap extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ExportMemoryMap.java <output_file>");
            return;
        }

        Program program = currentProgram;
        if (program == null) {
            println("No program loaded, skipping.");
            return;
        }

        Memory memory = program.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();

        StringBuilder sb = new StringBuilder();
        sb.append("{\"program\": \"").append(escapeJson(program.getName())).append("\", ");
        sb.append("\"path\": \"").append(escapeJson(program.getDomainFile().getPathname())).append("\", ");
        sb.append("\"blocks\": [");

        boolean first = true;
        for (MemoryBlock block : blocks) {
            if (!first) sb.append(", ");
            first = false;
            sb.append("{");
            sb.append("\"name\": \"").append(escapeJson(block.getName())).append("\", ");
            sb.append("\"start\": \"0x").append(Long.toHexString(block.getStart().getOffset())).append("\", ");
            sb.append("\"end\": \"0x").append(Long.toHexString(block.getEnd().getOffset())).append("\", ");
            sb.append("\"size\": ").append(block.getSize()).append(", ");
            sb.append("\"type\": \"").append(block.getType().name()).append("\", ");
            sb.append("\"read\": ").append(block.isRead()).append(", ");
            sb.append("\"write\": ").append(block.isWrite()).append(", ");
            sb.append("\"execute\": ").append(block.isExecute()).append(", ");
            sb.append("\"volatile\": ").append(block.isVolatile()).append(", ");
            sb.append("\"initialized\": ").append(block.isInitialized());
            sb.append("}");
        }

        sb.append("]}");

        try (FileWriter fw = new FileWriter(args[0], true)) {
            fw.write(sb.toString());
            fw.write("\n");
        }

        println("Exported " + blocks.length + " block(s) for " + program.getName());
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
