// ApplyZen2MemoryMap.java — Add PSP memory regions to Zen2 programs.
//
// Adds non-initialized memory blocks for SRAM, SMN, MMIO sub-regions, x86 mapping,
// and ROM areas. Sources: SECT Zen2 off-chip-bl maps + memory_layout.json.
//
// Usage:
//   analyzeHeadless <project_dir> <project_name>/<folder> \
//     -recursive -process \
//     -scriptPath /path/to/ghidra_scripts \
//     -postScript ApplyZen2MemoryMap.java
//
// Idempotent: skips blocks that already exist (by name).
//
//@category PSP.Setup

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;

public class ApplyZen2MemoryMap extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        Memory mem = currentProgram.getMemory();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        int added = 0;
        int skipped = 0;

        // --- SRAM regions (from memory_layout.json + SECT) ---
        added += addBlock(mem, space, "UserModeCode",       0x15000,  0x6000, false, true, true, false, false);
        added += addBlock(mem, space, "ABL0",               0x1b000,  0x6800, false, true, true, false, false);
        added += addBlock(mem, space, "ABLStage",           0x21800, 0x15a00, false, true, true, true,  false);
        added += addBlock(mem, space, "ABLServicePage",     0x37200,   0x15a, false, true, true, false, false);
        added += addBlock(mem, space, "ABLHeap",            0x37400, 0x11c00, false, true, true, false, false);
        added += addBlock(mem, space, "UserModeStack",      0x4b000,  0x2000, false, true, true, false, false);
        added += addBlock(mem, space, "BootROMServicePage", 0x4f000,  0x1000, false, true, true, false, false);

        // --- SMN ---
        added += addBlock(mem, space, "SMN",       0x1000000, 0x2000000, true, true, true, false, false);

        // --- MMIO sub-regions (from memory_layout.json) ---
        added += addBlock(mem, space, "CCP_Control",    0x3000000, 0x1000, true, true, true, false, false);
        added += addBlock(mem, space, "CCP_Queues",     0x3001000, 0x5000, true, true, true, false, false);
        added += addBlock(mem, space, "CCP_Config",     0x3006000, 0x1000, true, true, true, false, false);
        added += addBlock(mem, space, "UnknownMMIO_1",  0x3010004,  0x3ac, true, true, true, false, false);
        added += addBlock(mem, space, "IRQ_Controller", 0x30103b0,   0x50, true, true, true, false, false);
        added += addBlock(mem, space, "Timer",          0x3010424,  0x120, true, true, true, false, false);
        added += addBlock(mem, space, "Mailbox",        0x3010570,    0xb, true, true, true, false, false);
        added += addBlock(mem, space, "STS",            0x32000e8, 0x1ff18, true, true, true, false, false);
        added += addBlock(mem, space, "SMN_MapCtrl",    0x3220000,   0x40, true, true, true, false, false);
        added += addBlock(mem, space, "x86_MapCtrl",    0x3230000,  0x3e0, true, true, true, false, false);
        added += addBlock(mem, space, "x86_MapCtrl2",   0x32303e0,  0x210, true, true, true, false, false);

        // --- x86 mapping ---
        // Too large for a single block; just add a marker region
        // added += addBlock(mem, space, "x86_Mapping", 0x4000000, 0xf8000000, true, true, true, false, false);

        // --- ROM ---
        added += addBlock(mem, space, "OnChipBL_ROM", 0xffff0000, 0x10000, false, true, false, false, false);

        println("Applied memory map to " + currentProgram.getName() +
                ": " + added + " added, " + (added == 0 ? "all" : "") + " blocks");
    }

    /**
     * Add a non-initialized memory block. Returns 1 if added, 0 if skipped.
     */
    private int addBlock(Memory mem, AddressSpace space, String name,
                         long offset, long size,
                         boolean isVolatile, boolean read, boolean write,
                         boolean execute, boolean initialized) {
        // Check if block name already exists
        if (mem.getBlock(name) != null) {
            return 0;
        }

        // Check for overlap with existing blocks
        Address start = space.getAddress(offset);
        Address end = space.getAddress(offset + size - 1);
        if (mem.intersects(start, end)) {
            // Don't add if it overlaps existing blocks
            return 0;
        }

        try {
            MemoryBlock block;
            if (initialized) {
                block = mem.createInitializedBlock(name, start, size, (byte) 0, monitor, false);
            } else {
                block = mem.createUninitializedBlock(name, start, size, false);
            }
            block.setRead(read);
            block.setWrite(write);
            block.setExecute(execute);
            block.setVolatile(isVolatile);
            return 1;
        } catch (Exception e) {
            printerr("  Failed to add " + name + ": " + e.getMessage());
            return 0;
        }
    }
}
