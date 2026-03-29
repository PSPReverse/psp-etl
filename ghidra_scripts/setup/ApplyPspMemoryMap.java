// ApplyPspMemoryMap.java — Add PSP memory regions for any generation/platform.
//
// The PSP MMIO layout (CCP, IRQ, Timer, Mailbox, SMN map controls) is stable
// across zen1-zen5. SRAM layout varies by generation and platform (Ryzen vs Epyc).
//
// Usage:
//   analyzeHeadless ... -recursive -process \
//     -scriptPath ghidra_scripts/setup \
//     -postScript ApplyPspMemoryMap.java [generation] [platform]
//
//   generation: zen1, zen2, zen3, zen4, zen5 (default: zen2)
//   platform:   ryzen, epyc (default: ryzen)
//
// Examples:
//   -postScript ApplyPspMemoryMap.java                    # zen2 ryzen (default)
//   -postScript ApplyPspMemoryMap.java zen4               # zen4 ryzen
//   -postScript ApplyPspMemoryMap.java zen5 ryzen         # zen5 ryzen
//   -postScript ApplyPspMemoryMap.java zen2 epyc          # zen2 epyc
//
// Idempotent: skips blocks that already exist (by name).
//
//@category PSP.Setup

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;

public class ApplyPspMemoryMap extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        String[] args = getScriptArgs();
        String generation = (args.length >= 1 && !args[0].isEmpty()) ? args[0].toLowerCase() : "zen2";
        String platform = (args.length >= 2 && !args[1].isEmpty()) ? args[1].toLowerCase() : "ryzen";

        Memory mem = currentProgram.getMemory();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        int added = 0;

        // ================================================================
        // MMIO — stable across all generations (zen1-zen5, ryzen+epyc)
        // Source: SECT memory_layout.json + cross-gen validation
        // ================================================================

        // CCP (Cryptographic Coprocessor)
        added += addBlock(mem, space, "CCP_Control",    0x3000000, 0x1000, true, true, true, false);
        added += addBlock(mem, space, "CCP_Queues",     0x3001000, 0x5000, true, true, true, false);
        added += addBlock(mem, space, "CCP_Config",     0x3006000, 0x1000, true, true, true, false);

        // Misc MMIO
        added += addBlock(mem, space, "UnknownMMIO_1",  0x3010004,  0x3ac, true, true, true, false);
        added += addBlock(mem, space, "IRQ_Controller", 0x30103b0,   0x50, true, true, true, false);
        added += addBlock(mem, space, "Timer",          0x3010424,  0x120, true, true, true, false);
        added += addBlock(mem, space, "Mailbox",        0x3010570,    0xb, true, true, true, false);

        // STS (Status registers)
        added += addBlock(mem, space, "STS",            0x32000e8, 0x1ff18, true, true, true, false);

        // SMN and x86 map controls
        added += addBlock(mem, space, "SMN_MapCtrl",    0x3220000,   0x40, true, true, true, false);
        added += addBlock(mem, space, "x86_MapCtrl",    0x3230000,  0x3e0, true, true, true, false);
        added += addBlock(mem, space, "x86_MapCtrl2",   0x32303e0,  0x210, true, true, true, false);

        // SMN address space
        added += addBlock(mem, space, "SMN",            0x1000000, 0x2000000, true, true, true, false);

        // On-chip bootloader ROM
        added += addBlock(mem, space, "OnChipBL_ROM",   0xffff0000, 0x10000, false, true, false, false);

        // ================================================================
        // SRAM — varies by generation and platform
        // ================================================================

        switch (generation) {
            case "zen1":
                if (platform.equals("epyc")) {
                    addZen1EpycSram(mem, space);
                } else {
                    addZen1RyzenSram(mem, space);
                }
                break;
            case "zen2":
                if (platform.equals("epyc")) {
                    addZen2EpycSram(mem, space);
                } else {
                    addZen2RyzenSram(mem, space);
                }
                break;
            case "zen3":
                // Zen3 uses same SRAM layout as zen2 (confirmed via analysis)
                if (platform.equals("epyc")) {
                    addZen2EpycSram(mem, space);
                } else {
                    addZen2RyzenSram(mem, space);
                }
                break;
            case "zen4":
            case "zen5":
                // Zen4/5 SRAM layout — larger ABLStage, no separate ABL0
                if (platform.equals("epyc")) {
                    addZen4EpycSram(mem, space);
                } else {
                    addZen4RyzenSram(mem, space);
                }
                break;
            default:
                println("WARNING: Unknown generation '" + generation + "', using zen2 SRAM layout");
                addZen2RyzenSram(mem, space);
                break;
        }

        println("Applied " + generation + "/" + platform + " memory map to " +
                currentProgram.getName() + ": " + added + " blocks added");
    }

    // === SRAM layouts by generation ===

    private int addZen1RyzenSram(Memory mem, AddressSpace space) {
        int added = 0;
        // Zen1 Ryzen has smaller SRAM than zen2
        added += addBlock(mem, space, "UserModeCode",       0x15000,  0x6000, false, true, true, false);
        added += addBlock(mem, space, "ABL0",               0x1b000,  0x5000, false, true, true, false);
        added += addBlock(mem, space, "ABLStage",           0x20000, 0x10000, false, true, true, true);
        added += addBlock(mem, space, "ABLServicePage",     0x30000,   0x200, false, true, true, false);
        added += addBlock(mem, space, "ABLHeap",            0x30200,  0xfc00, false, true, true, false);
        added += addBlock(mem, space, "UserModeStack",      0x40000,  0x2000, false, true, true, false);
        added += addBlock(mem, space, "BootROMServicePage", 0x4f000,  0x1000, false, true, true, false);
        return added;
    }

    private int addZen1EpycSram(Memory mem, AddressSpace space) {
        // Epyc (Naples/Rome) has same base layout as Ryzen for zen1
        return addZen1RyzenSram(mem, space);
    }

    private int addZen2RyzenSram(Memory mem, AddressSpace space) {
        int added = 0;
        // Source: SECT Zen2 off-chip-bl maps + memory_layout.json
        added += addBlock(mem, space, "UserModeCode",       0x15000,  0x6000, false, true, true, false);
        added += addBlock(mem, space, "ABL0",               0x1b000,  0x6800, false, true, true, false);
        added += addBlock(mem, space, "ABLStage",           0x21800, 0x15a00, false, true, true, true);
        added += addBlock(mem, space, "ABLServicePage",     0x37200,   0x15a, false, true, true, false);
        added += addBlock(mem, space, "ABLHeap",            0x37400, 0x11c00, false, true, true, false);
        added += addBlock(mem, space, "UserModeStack",      0x4b000,  0x2000, false, true, true, false);
        added += addBlock(mem, space, "BootROMServicePage", 0x4f000,  0x1000, false, true, true, false);
        return added;
    }

    private int addZen2EpycSram(Memory mem, AddressSpace space) {
        int added = 0;
        // Epyc (Rome) — SRAM boundaries from H11DSU9 analysis
        added += addBlock(mem, space, "UserModeCode",       0x15000,  0x6000, false, true, true, false);
        added += addBlock(mem, space, "ABL0",               0x1b000,  0x6800, false, true, true, false);
        added += addBlock(mem, space, "ABLStage",           0x21800, 0x15a00, false, true, true, true);
        added += addBlock(mem, space, "ABLServicePage",     0x37200,   0x15a, false, true, true, false);
        added += addBlock(mem, space, "ABLHeap",            0x37400, 0x11c00, false, true, true, false);
        added += addBlock(mem, space, "UserModeStack",      0x4b000,  0x2000, false, true, true, false);
        added += addBlock(mem, space, "BootROMServicePage", 0x4f000,  0x1000, false, true, true, false);
        return added;
    }

    private int addZen4RyzenSram(Memory mem, AddressSpace space) {
        int added = 0;
        // Zen4/5 — larger firmware, expanded SRAM regions
        // ABL stages consolidated into single larger region
        added += addBlock(mem, space, "UserModeCode",       0x15000,  0x6000, false, true, true, false);
        added += addBlock(mem, space, "ABL0",               0x1b000,  0x6800, false, true, true, false);
        added += addBlock(mem, space, "ABLStage",           0x21800, 0x1e800, false, true, true, true);
        added += addBlock(mem, space, "ABLServicePage",     0x40000,   0x200, false, true, true, false);
        added += addBlock(mem, space, "ABLHeap",            0x40200, 0x0de00, false, true, true, false);
        added += addBlock(mem, space, "UserModeStack",      0x4e000,  0x2000, false, true, true, false);
        added += addBlock(mem, space, "BootROMServicePage", 0x4f000,  0x1000, false, true, true, false);
        return added;
    }

    private int addZen4EpycSram(Memory mem, AddressSpace space) {
        // Zen4 Epyc (Genoa) — same SRAM layout as Ryzen zen4
        return addZen4RyzenSram(mem, space);
    }

    private int addBlock(Memory mem, AddressSpace space, String name,
                         long offset, long size,
                         boolean isVolatile, boolean read, boolean write,
                         boolean execute) {
        if (mem.getBlock(name) != null) return 0;

        Address start = space.getAddress(offset);
        Address end = space.getAddress(offset + size - 1);
        if (mem.intersects(start, end)) return 0;

        try {
            MemoryBlock block = mem.createUninitializedBlock(name, start, size, false);
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
