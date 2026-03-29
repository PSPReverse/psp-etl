// LabelMailboxHandlers.java — Find the mailbox dispatch function and label
// all handler targets with their command IDs.
//
// Identifies the dispatch function by looking for the pattern:
//   UBFX Rd, Rn, #16, #8   (extract message type byte)
//   followed by dense CMP/BEQ chains and TBB switch tables
//
// Then traces each compare value to its branch target and labels the
// target function as mbx_cmd_0xNN.
//
// Usage:
//   analyzeHeadless ... -process <program> -noanalysis \
//     -scriptPath ghidra_scripts/analysis \
//     -postScript LabelMailboxHandlers.java
//
//@category PSP.Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import java.util.*;

public class LabelMailboxHandlers extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;

        Listing listing = currentProgram.getListing();
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        println("=== Label Mailbox Handlers: " + currentProgram.getName() + " ===\n");

        // Phase 1: Find the dispatch function
        // Look for UBFX Rd, Rn, #16, #8 followed by many CMPs
        Function dispatchFunc = null;
        Address ubfxAddr = null;
        int bestCmpCount = 0;

        FunctionIterator funcIt = funcMgr.getFunctions(true);
        while (funcIt.hasNext()) {
            Function f = funcIt.next();
            AddressSetView body = f.getBody();
            if (body == null || body.getNumAddresses() < 200) continue;

            boolean hasUbfx16_8 = false;
            int cmpCount = 0;
            Address foundUbfx = null;

            InstructionIterator it = listing.getInstructions(body, true);
            while (it.hasNext()) {
                Instruction instr = it.next();
                String mn = instr.getMnemonicString().toLowerCase();

                if (mn.equals("ubfx")) {
                    // Check for ubfx Rd, Rn, #16, #8
                    String repr = instr.toString();
                    if (repr.contains("#0x10") && repr.contains("#0x8")) {
                        hasUbfx16_8 = true;
                        foundUbfx = instr.getAddress();
                    }
                }
                if (mn.equals("cmp")) {
                    Scalar s = findScalar(instr);
                    if (s != null && s.getUnsignedValue() > 0 && s.getUnsignedValue() < 0x100) {
                        cmpCount++;
                    }
                }
            }

            if (hasUbfx16_8 && cmpCount > bestCmpCount) {
                bestCmpCount = cmpCount;
                dispatchFunc = f;
                ubfxAddr = foundUbfx;
            }
        }

        if (dispatchFunc == null) {
            println("No mailbox dispatch function found (no UBFX #16, #8 with dense CMPs)");
            return;
        }

        println("Dispatch function: " + dispatchFunc.getName() + " @ 0x" +
                Long.toHexString(dispatchFunc.getEntryPoint().getOffset()) +
                " (size=" + dispatchFunc.getBody().getNumAddresses() +
                ", CMPs=" + bestCmpCount + ")");
        println("UBFX at: 0x" + ubfxAddr.toString());

        // Identify which register holds the command ID after UBFX
        Instruction ubfxInstr = listing.getInstructionAt(ubfxAddr);
        // The destination register of UBFX is operand 0
        // We'll track CMPs against this register
        String ubfxDest = ubfxInstr.getRegister(0) != null ?
            ubfxInstr.getRegister(0).getName() : null;
        println("Command register: " + ubfxDest + "\n");

        // Phase 2: Scan all CMPs in the function to build command→target mapping
        // Pattern: CMP r4, #0xNN followed by BEQ <target>
        Map<Long, Address> cmdToTarget = new TreeMap<>();
        AddressSetView body = dispatchFunc.getBody();
        InstructionIterator it = listing.getInstructions(body, true);

        while (it.hasNext()) {
            Instruction instr = it.next();
            String mn = instr.getMnemonicString().toLowerCase();

            if (!mn.equals("cmp")) continue;

            // Check if this CMP uses the command register
            boolean usesCmd = false;
            if (ubfxDest != null && instr.getRegister(0) != null &&
                instr.getRegister(0).getName().equals(ubfxDest)) {
                usesCmd = true;
            }
            // Also check SUB+CMP patterns (sub r0, r4, #base; cmp r0, #range)
            // These are handled by looking at the branch targets

            if (!usesCmd) continue;

            Scalar val = null;
            for (int i = 1; i < instr.getNumOperands(); i++) {
                Object[] ops = instr.getOpObjects(i);
                for (Object o : ops) {
                    if (o instanceof Scalar) {
                        val = (Scalar) o;
                        break;
                    }
                }
                if (val != null) break;
            }
            if (val == null) continue;
            long cmdId = val.getUnsignedValue();
            if (cmdId == 0 || cmdId > 0xFF) continue;

            // Find the next conditional branch (BEQ, BNE, etc.)
            Address searchAddr = instr.getAddress();
            for (int i = 0; i < 3; i++) {
                Instruction next = listing.getInstructionAfter(searchAddr);
                if (next == null) break;
                searchAddr = next.getAddress();
                String nextMn = next.getMnemonicString().toLowerCase();

                if (nextMn.startsWith("b") && !nextMn.equals("bl") && !nextMn.equals("blx")) {
                    // It's a branch — get target
                    Reference[] refs = next.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isFlow()) {
                            Address target = ref.getToAddress();
                            // Only record if it branches to somewhere meaningful
                            if (body.contains(target) || funcMgr.getFunctionAt(target) != null) {
                                cmdToTarget.put(cmdId, target);
                            }
                            break;
                        }
                    }
                    break;
                }
            }
        }

        println("Command → Target mapping (" + cmdToTarget.size() + " commands):");

        // Phase 3: Resolve targets to handler functions and apply labels
        int labeled = 0;
        Map<Address, List<Long>> handlerToCmds = new LinkedHashMap<>();

        for (Map.Entry<Long, Address> entry : cmdToTarget.entrySet()) {
            long cmdId = entry.getKey();
            Address target = entry.getValue();

            // The target might be within the dispatch function (jump to a BL)
            // Follow it to find the actual handler
            Address handlerAddr = resolveHandler(listing, funcMgr, target, body);

            if (handlerAddr != null) {
                handlerToCmds.computeIfAbsent(handlerAddr, k -> new ArrayList<>()).add(cmdId);
            }

            println(String.format("  cmd 0x%02X → 0x%s → handler 0x%s",
                cmdId, target.toString().replaceAll("^0+", ""),
                handlerAddr != null ? handlerAddr.toString().replaceAll("^0+", "") : "?"));
        }

        // Apply labels to handler functions
        println("\nLabeling handlers:");
        for (Map.Entry<Address, List<Long>> entry : handlerToCmds.entrySet()) {
            Address addr = entry.getKey();
            List<Long> cmds = entry.getValue();

            Function handler = funcMgr.getFunctionAt(addr);
            if (handler == null) continue;

            // Skip if already has a user-defined name
            if (handler.getSymbol().getSource() == SourceType.USER_DEFINED) {
                println("  SKIP (already named): " + handler.getName() + " @ 0x" +
                        Long.toHexString(addr.getOffset()));
                continue;
            }

            // Build name from command IDs
            StringBuilder name = new StringBuilder("mbx_cmd");
            for (Long cmd : cmds) {
                name.append(String.format("_0x%02X", cmd));
            }

            try {
                handler.setName(name.toString(), SourceType.USER_DEFINED);
                println("  LABELED: " + name + " @ 0x" + Long.toHexString(addr.getOffset()));
                labeled++;
            } catch (Exception e) {
                println("  FAILED: " + name + " @ 0x" + Long.toHexString(addr.getOffset()) +
                        ": " + e.getMessage());
            }
        }

        // Label the dispatch function itself
        if (dispatchFunc.getSymbol().getSource() == SourceType.DEFAULT) {
            try {
                dispatchFunc.setName("mbx_dispatch", SourceType.USER_DEFINED);
                println("  LABELED: mbx_dispatch @ 0x" +
                        Long.toHexString(dispatchFunc.getEntryPoint().getOffset()));
                labeled++;
            } catch (Exception e) {
                // ignore
            }
        }

        println("\n=== Summary ===");
        println("  Commands found:     " + cmdToTarget.size());
        println("  Handlers labeled:   " + labeled);
    }

    /**
     * Follow a branch target within the dispatch function to find the
     * actual BL handler call. Returns the function address of the handler.
     */
    private Address resolveHandler(Listing listing, FunctionManager funcMgr,
                                    Address target, AddressSetView dispatchBody) {
        // If target is a function entry, return it directly
        Function targetFunc = funcMgr.getFunctionAt(target);
        if (targetFunc != null && !dispatchBody.contains(target)) {
            return target;
        }

        // Otherwise, scan forward from target for a BL instruction
        Address addr = target;
        for (int i = 0; i < 10; i++) {
            Instruction instr = listing.getInstructionAt(addr);
            if (instr == null) {
                instr = listing.getInstructionAfter(addr);
                if (instr == null) break;
            }
            addr = instr.getAddress();

            String mn = instr.getMnemonicString().toLowerCase();
            if (mn.equals("bl") || mn.equals("blx")) {
                Reference[] refs = instr.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isCall()) {
                        Function callee = funcMgr.getFunctionAt(ref.getToAddress());
                        if (callee != null) return ref.getToAddress();
                    }
                }
            }
            // If we hit an unconditional branch, follow it
            if (mn.equals("b") && !mn.startsWith("bl") && !mn.startsWith("bne") &&
                !mn.startsWith("beq") && !mn.startsWith("bgt") && !mn.startsWith("blt") &&
                !mn.startsWith("bcs") && !mn.startsWith("bcc") && !mn.startsWith("bhi")) {
                Reference[] refs = instr.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isFlow()) {
                        addr = ref.getToAddress();
                        break;
                    }
                }
                continue;
            }

            addr = instr.getMaxAddress().next();
        }
        return null;
    }

    private Scalar findScalar(Instruction instr) {
        for (int i = 0; i < instr.getNumOperands(); i++) {
            Object[] ops = instr.getOpObjects(i);
            for (Object o : ops) {
                if (o instanceof Scalar) return (Scalar) o;
            }
        }
        return null;
    }
}
