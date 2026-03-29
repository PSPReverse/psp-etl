// ApplyPspAddressSpaces.java — Add overlay address spaces for SMN and x86,
// then convert the existing X86PADDR / SMNADDR / PSPPHYSADDR typedefs to
// PointerTypedefs that target those spaces. Existing data and parameters
// already typed as X86PADDR / SMNADDR become alt-clickable into the new
// spaces with no further annotation work.
//
// Spaces:
//   SMN  — overlay of the default (32-bit ARM) space; SMN addresses are 32-bit.
//   X86  — overlay of the OTHER (64-bit) space, subdivided into named regions
//          per data/x86_memory_layout.json: X86_DRAM, X86_MMIO, plus a System
//          Address Mapping (SAM_*) cluster for POST/USB-PHY/UART/PCI-cfg.
//
// Typedef remapping:
//   SMNADDR     -> PointerTypedef(void, 4, dtm).addressSpace(SMN)
//   X86PADDR    -> PointerTypedef(void, 8, dtm).addressSpace(X86)
//   PSPPHYSADDR -> PointerTypedef(void, 4, dtm).addressSpace(ram)   (annotative only)
//
// Idempotent. Run before any analysis that needs typedef-aware references.
//
// Usage:
//   analyzeHeadless ... -recursive -process \
//     -scriptPath ghidra_scripts/setup \
//     -postScript ApplyPspAddressSpaces.java
//
//@category PSP.Setup

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class ApplyPspAddressSpaces extends GhidraScript {

    // SMN: 32-bit address space — cover the full 4 GB minus a top guard page
    // so we don't run into wraparound edge cases. Uninitialized blocks don't
    // consume host memory.
    private static final long SMN_SIZE  = 0xFFFF0000L;

    // X86: 64-bit physical addresses — subdivided per data/x86_memory_layout.json.
    // begin/end follow that file: end is exclusive for ranges, but for a register
    // entry begin == end means a single byte.
    private static final long X86_PLACEHOLDER_SIZE = 0x100000000L;
    // isVolatile: false for plain DRAM so the decompiler can treat repeated
    // loads as cacheable; true for MMIO and System Address Mapping registers
    // (POST status, UART, PCI cfg, USB-PHY FW).
    private static final X86Region[] X86_LAYOUT = {
        new X86Region("X86_DRAM",        0x0L,             0xd0000000L,    false), // DRAM
        new X86Region("X86_MMIO",        0xd0000000L,      0x100000000L,   true),  // DRAM/MMIO
        new X86Region("SAM_USB_PHY_FW",  0xfffdfb000000L,  0xfffdfbc80000L, true), // System Address Mapping
        new X86Region("SAM_POST_STATUS", 0xfffdfc000080L,  0xfffdfc000080L, true),
        new X86Region("SAM_UART",        0xfffdfc0003f8L,  0xfffdfc0003fbL, true),
        new X86Region("SAM_PCI_CFG",     0xfffe00000000L,  0xfffe00000000L, true),
    };

    private static final class X86Region {
        final String name;
        final long begin;
        final long end;
        final boolean isVolatile;
        X86Region(String name, long begin, long end, boolean isVolatile) {
            this.name = name; this.begin = begin; this.end = end; this.isVolatile = isVolatile;
        }
        long size() {
            return (begin == end) ? 1L : (end - begin);
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        Memory mem = currentProgram.getMemory();
        AddressFactory af = currentProgram.getAddressFactory();
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // ── Phase 1: ensure SMN and X86 overlay spaces exist ──
        AddressSpace smnSpace = ensureSmnOverlay(mem, af);
        AddressSpace x86Space = ensureX86Overlay(mem, af);

        // ── Phase 2: build / replace the address-aware typedefs ──
        DataType voidT = DataType.VOID;

        TypeDef smnPtr = makePointerTypedef(dtm, "SMN_Pointer", voidT, 4, smnSpace);
        TypeDef x86Ptr = makePointerTypedef(dtm, "X86_Pointer", voidT, 8, x86Space);
        println("Registered SMN_Pointer / X86_Pointer typedefs.");

        // ── Phase 3: rebind the legacy plain typedefs to the new pointer types,
        //            preserving existing applications.
        replaceWithPointerTypedef(dtm, "SMNADDR",     voidT, 4, smnSpace);
        replaceWithPointerTypedef(dtm, "X86PADDR",    voidT, 8, x86Space);
        // PSPPHYSADDR points back into PSP RAM. Make it navigable too.
        replaceWithPointerTypedef(dtm, "PSPPHYSADDR", voidT, 4, af.getDefaultAddressSpace());

        println("Done.");
    }

    private AddressSpace ensureSmnOverlay(Memory mem, AddressFactory af) throws Exception {
        AddressSpace existing = af.getAddressSpace("SMN");
        if (existing != null) {
            println("SMN overlay already present: " + existing);
            return existing;
        }
        AddressSpace ram = af.getDefaultAddressSpace();
        Address start = ram.getAddress(0L);
        MemoryBlock block = mem.createUninitializedBlock("SMN", start, SMN_SIZE, true);
        block.setRead(true);
        block.setWrite(true);
        block.setExecute(false);
        block.setVolatile(true);
        AddressSpace smn = block.getStart().getAddressSpace();
        println("Created SMN overlay (" + smn + ", size 0x" + Long.toHexString(SMN_SIZE) + ").");
        return smn;
    }

    private AddressSpace ensureX86Overlay(Memory mem, AddressFactory af) throws Exception {
        // ── Recovery: clean up bad state from earlier versions of this script. ──

        // 1. A previous version named the first block X86_DRAM, which became
        //    the overlay SPACE name. Wipe any blocks remaining in that space.
        AddressSpace stale = af.getAddressSpace("X86_DRAM");
        if (stale != null && stale.isOverlaySpace()) {
            int wiped = 0;
            for (MemoryBlock b : new ArrayList<>(Arrays.asList(mem.getBlocks()))) {
                if (stale.equals(b.getStart().getAddressSpace())) {
                    mem.removeBlock(b, monitor);
                    wiped++;
                }
            }
            if (wiped > 0) {
                println("Wiped " + wiped + " block(s) from mis-named X86_DRAM overlay.");
            }
        }

        // 2. The narrow X86_DRAM overlay caused subsequent blocks to land in
        //    OTHER (range fall-through). Remove any X86 region block that
        //    ended up there.
        Set<String> regionNames = new HashSet<>();
        for (X86Region r : X86_LAYOUT) regionNames.add(r.name);
        for (MemoryBlock b : new ArrayList<>(Arrays.asList(mem.getBlocks()))) {
            if (b.getStart().getAddressSpace() == AddressSpace.OTHER_SPACE
                    && regionNames.contains(b.getName())) {
                mem.removeBlock(b, monitor);
                println("Removed stray block " + b.getName() + " from OTHER space.");
            }
        }

        // 3. Drop the very first version's single 0x100000000 placeholder block.
        MemoryBlock placeholder = mem.getBlock("X86");
        if (placeholder != null
                && "X86".equals(placeholder.getStart().getAddressSpace().getName())
                && placeholder.getSize() == X86_PLACEHOLDER_SIZE) {
            println("Removing legacy single-block X86 placeholder.");
            mem.removeBlock(placeholder, monitor);
        }

        // ── Ensure the X86 overlay space exists and spans enough range to
        //    accommodate every region we want to create. If a prior run created
        //    a narrow overlay (because the seeding block was small), wipe it. ──
        long needsMax = 0L;
        for (X86Region r : X86_LAYOUT) {
            long top = r.end == r.begin ? r.begin : r.end - 1;
            if (top > needsMax) needsMax = top;
        }
        AddressSpace x86 = af.getAddressSpace("X86");
        if (x86 != null) {
            long haveMax = x86.getMaxAddress().getOffset();
            // Treat as unsigned for 64-bit comparison.
            boolean tooNarrow = Long.compareUnsigned(haveMax, needsMax) < 0;
            if (tooNarrow) {
                println("Existing X86 overlay range too narrow"
                        + " (max=0x" + Long.toHexString(haveMax)
                        + ", need >= 0x" + Long.toHexString(needsMax) + "); wiping.");
                int wiped = 0;
                for (MemoryBlock b : new ArrayList<>(Arrays.asList(mem.getBlocks()))) {
                    if (x86.equals(b.getStart().getAddressSpace())) {
                        mem.removeBlock(b, monitor);
                        wiped++;
                    }
                }
                println("Wiped " + wiped + " block(s) from narrow X86 overlay.");
                x86 = af.getAddressSpace("X86");  // may have been removed with last block
            }
        }
        if (x86 == null) {
            x86 = currentProgram.createOverlaySpace("X86", AddressSpace.OTHER_SPACE);
            println("Created X86 overlay space (over OTHER); range max=0x"
                    + Long.toHexString(x86.getMaxAddress().getOffset()));
        }

        // ── Lay down regions. getAddressInThisSpaceOnly avoids the overlay's
        //    fall-through-to-underlying behavior for offsets not yet covered
        //    by any block — that fall-through was sending these blocks back
        //    into OTHER. ──
        for (X86Region r : X86_LAYOUT) {
            MemoryBlock b = mem.getBlock(r.name);
            if (b == null) {
                Address start = x86.getAddressInThisSpaceOnly(r.begin);
                b = mem.createUninitializedBlock(r.name, start, r.size(), false);
                println("Added X86 region " + r.name
                        + " @ X86::0x" + Long.toHexString(r.begin)
                        + " size 0x" + Long.toHexString(r.size())
                        + (r.isVolatile ? " (volatile)" : " (non-volatile)"));
            }
            // Apply attrs every run so re-runs repair volatile flags after a fix.
            applyBlockAttrs(b, r.isVolatile);
        }
        return x86;
    }

    private void applyBlockAttrs(MemoryBlock b, boolean isVolatile) {
        b.setRead(true);
        b.setWrite(true);
        b.setExecute(false);
        b.setVolatile(isVolatile);
    }

    private TypeDef makePointerTypedef(DataTypeManager dtm, String name,
                                       DataType referenced, int pointerSize,
                                       AddressSpace space) throws Exception {
        DataType existing = findFirstByName(dtm, name);
        if (isPointerTypedefTargeting(existing, space)) {
            return (TypeDef) existing;
        }

        PointerTypedefBuilder b = new PointerTypedefBuilder(referenced, pointerSize, dtm)
                .name(name)
                .addressSpace(space);
        TypeDef td = b.build();
        return (TypeDef) dtm.resolve(td, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    /**
     * Replace every typedef named {@code name} in the program with a PointerTypedef
     * of the given target space, preserving the original category path so that
     * subsequent archive relinking still finds the type. All existing uses inherit
     * the new behavior because we use replaceDataType().
     */
    private void replaceWithPointerTypedef(DataTypeManager dtm, String name,
                                           DataType referenced, int pointerSize,
                                           AddressSpace space) throws Exception {
        List<DataType> hits = findAllByName(dtm, name);
        if (hits.isEmpty()) {
            println("  (no existing " + name + " — skipping rebind)");
            return;
        }

        for (DataType hit : hits) {
            if (isPointerTypedefTargeting(hit, space)) {
                println("  " + hit.getCategoryPath() + "/" + hit.getName()
                        + " already targets " + space.getName() + " — skipping");
                continue;
            }

            CategoryPath cat = hit.getCategoryPath();
            String hitName = hit.getName(); // may be name or name.conflict*

            // Build a fresh replacement at the hit's exact category, with a
            // throwaway name so resolve() doesn't merge with the original.
            PointerTypedefBuilder b = new PointerTypedefBuilder(referenced, pointerSize, dtm)
                    .name(hitName + "__rebind_tmp")
                    .addressSpace(space);
            TypeDef tmp = b.build();
            try {
                tmp.setCategoryPath(cat);
            } catch (Exception ignore) {
                // category move only fails on duplicate name; the temp name
                // makes that effectively impossible
            }
            TypeDef replacement = (TypeDef) dtm.resolve(tmp, DataTypeConflictHandler.DEFAULT_HANDLER);

            try {
                dtm.replaceDataType(hit, replacement, false);
                replacement.setName(hitName);
                println("  rebound " + cat + "/" + hitName
                        + " -> PointerTypedef(space=" + space.getName() + ")");
            } catch (Exception e) {
                printerr("  failed to rebind " + cat + "/" + hitName + ": " + e.getMessage());
                // best-effort cleanup of the temp
                try { dtm.remove(replacement, monitor); } catch (Exception ignore) {}
            }
        }
    }

    private boolean isPointerTypedefTargeting(DataType dt, AddressSpace space) {
        if (!(dt instanceof TypeDef)) return false;
        TypeDef td = (TypeDef) dt;
        if (!(td.getDataType() instanceof Pointer)) return false;
        String s = AddressSpaceSettingsDefinition.DEF.getValue(td.getDefaultSettings());
        return space.getName().equals(s);
    }

    private DataType findFirstByName(DataTypeManager dtm, String name) {
        ArrayList<DataType> out = new ArrayList<>();
        dtm.findDataTypes(name, out);
        return out.isEmpty() ? null : out.get(0);
    }

    private List<DataType> findAllByName(DataTypeManager dtm, String name) {
        ArrayList<DataType> out = new ArrayList<>();
        dtm.findDataTypes(name, out);
        // Also include name.conflict variants — the importer creates these freely.
        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            String n = dt.getName();
            if (n.equals(name)) continue; // already in `out`
            if (n.startsWith(name + ".conflict")) {
                out.add(dt);
            }
        }
        return out;
    }
}
