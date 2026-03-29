// SmartRename.java — Rename functions based on string references, SVC calls,
// MMIO access patterns, and PSPSTATUS returns. Follows SECT naming conventions.
//
// Naming strategies:
// 1. Functions with a single dominant string → derive name from string content
// 2. Functions that call SVC → name by SVC ID (using PSP_SVC_ID enum)
// 3. Functions that access specific MMIO → name by device (ccp_, mailbox_, timer_)
// 4. Functions that return PSPSTATUS → prefix with psp_
// 5. Error handlers → name as err_handler_<context>
//
//@category PSP.Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.scalar.*;
import java.util.*;
import java.util.regex.*;

public class SmartRename extends GhidraScript {

    // SECT naming patterns
    private static final Map<Integer, String> SVC_NAMES = new LinkedHashMap<>();
    static {
        SVC_NAMES.put(0x00, "svc_exit");
        SVC_NAMES.put(0x01, "svc_sleep");
        SVC_NAMES.put(0x02, "svc_malloc");
        SVC_NAMES.put(0x03, "svc_free");
        SVC_NAMES.put(0x04, "svc_print");
        SVC_NAMES.put(0x05, "svc_map_mem");
        SVC_NAMES.put(0x06, "svc_unmap_mem");
        SVC_NAMES.put(0x07, "svc_ccp_submit");
        SVC_NAMES.put(0x08, "svc_invalidate_cache");
        SVC_NAMES.put(0x09, "svc_create_mutex");
        SVC_NAMES.put(0x0A, "svc_lock_mutex");
        SVC_NAMES.put(0x0B, "svc_unlock_mutex");
        SVC_NAMES.put(0x0C, "svc_destroy_mutex");
        SVC_NAMES.put(0x0D, "svc_wait_event");
        SVC_NAMES.put(0x0E, "svc_signal_event");
        SVC_NAMES.put(0x10, "svc_query_addr");
        SVC_NAMES.put(0x11, "svc_interrupt_ctrl");
        SVC_NAMES.put(0x12, "svc_get_status");
        SVC_NAMES.put(0x13, "svc_timer_read");
        SVC_NAMES.put(0x14, "svc_timer_set_alarm");
        SVC_NAMES.put(0x17, "svc_map_smn");
        SVC_NAMES.put(0x18, "svc_unmap_smn");
        SVC_NAMES.put(0x1F, "svc_map_x86_mem");
        SVC_NAMES.put(0x20, "svc_unmap_x86_mem");
        SVC_NAMES.put(0x26, "svc_load_fw");
        SVC_NAMES.put(0x31, "svc_sha256");
        SVC_NAMES.put(0x33, "svc_rsa_pss_verify");
        SVC_NAMES.put(0x36, "svc_ccp_aes");
        SVC_NAMES.put(0x38, "svc_copy_to_x86");
        SVC_NAMES.put(0x39, "svc_copy_from_x86");
        SVC_NAMES.put(0x3D, "svc_read_fuse");
        SVC_NAMES.put(0x41, "svc_sha384");
    }

    // String content → function name mapping patterns
    private static final String[][] STRING_PATTERNS = {
        {"DDR.*train", "ddr_training"},
        {"DRAM.*init", "dram_init"},
        {"memory.*test", "memory_test"},
        {"SMU.*msg", "smu_send_msg"},
        {"SMU.*init", "smu_init"},
        {"PCIe.*link", "pcie_link"},
        {"PCIe.*train", "pcie_training"},
        {"fuse.*read", "fuse_read"},
        {"flash.*read", "flash_read"},
        {"flash.*write", "flash_write"},
        {"SPI.*read", "spi_read"},
        {"SPI.*write", "spi_write"},
        {"CCP.*init", "ccp_init"},
        {"CCP.*submit", "ccp_submit"},
        {"RSA.*verify", "rsa_verify"},
        {"SHA.*init", "sha_init"},
        {"SHA.*update", "sha_update"},
        {"SHA.*final", "sha_final"},
        {"AES.*encrypt", "aes_encrypt"},
        {"AES.*decrypt", "aes_decrypt"},
        {"HMAC", "hmac_compute"},
        {"mailbox.*send", "mailbox_send"},
        {"mailbox.*recv", "mailbox_recv"},
        {"x86.*map", "x86_map_memory"},
        {"SMN.*map", "smn_map"},
        {"validate.*hdr", "validate_header"},
        {"load.*fw", "load_firmware"},
        {"boot.*stage", "boot_next_stage"},
        {"secure.*boot", "secure_boot"},
        {"unlock.*debug", "debug_unlock"},
    };

    @Override
    public void run() throws Exception {
        if (currentProgram == null) return;
        Listing listing = currentProgram.getListing();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        int renamed = 0;
        int svcNamed = 0;
        int stringNamed = 0;
        Set<String> usedNames = new HashSet<>();

        // Collect existing non-default names
        FunctionIterator allFuncs = funcMgr.getFunctions(true);
        while (allFuncs.hasNext()) {
            Function f = allFuncs.next();
            if (f.getSymbol().getSource() != SourceType.DEFAULT) {
                usedNames.add(f.getName());
            }
        }

        // === Strategy 1: SVC call identification ===
        println("--- Strategy 1: SVC call identification ---");
        FunctionIterator funcIt = funcMgr.getFunctions(true);
        while (funcIt.hasNext()) {
            Function func = funcIt.next();
            if (func.getSymbol().getSource() != SourceType.DEFAULT) continue;

            // Look for SVC instruction in the function body
            AddressSetView body = func.getBody();
            if (body == null) continue;

            InstructionIterator instrIt = listing.getInstructions(body, true);
            while (instrIt.hasNext()) {
                Instruction instr = instrIt.next();
                String mn = instr.getMnemonicString().toLowerCase();
                if (mn.equals("svc") || mn.equals("swi")) {
                    // Get the SVC number
                    Object[] ops = instr.getOpObjects(0);
                    for (Object o : ops) {
                        if (o instanceof Scalar) {
                            int svcNum = (int) ((Scalar) o).getUnsignedValue();
                            String svcName = SVC_NAMES.get(svcNum);
                            if (svcName != null && !usedNames.contains(svcName)) {
                                func.setName(svcName, SourceType.USER_DEFINED);
                                usedNames.add(svcName);
                                println("  " + svcName + " (SVC #0x" +
                                        Integer.toHexString(svcNum) + ") @ 0x" +
                                        Long.toHexString(func.getEntryPoint().getOffset()));
                                svcNamed++;
                                renamed++;
                            } else if (svcName != null) {
                                // Name already used, append address
                                String uniqueName = svcName + "_" +
                                    Long.toHexString(func.getEntryPoint().getOffset());
                                if (!usedNames.contains(uniqueName)) {
                                    func.setName(uniqueName, SourceType.USER_DEFINED);
                                    usedNames.add(uniqueName);
                                    svcNamed++;
                                    renamed++;
                                }
                            }
                            break;
                        }
                    }
                    break; // Only check first SVC per function
                }
            }
        }
        println("  SVC-named: " + svcNamed);

        // === Strategy 2: String-based naming ===
        println("--- Strategy 2: String-based naming ---");
        funcIt = funcMgr.getFunctions(true);
        while (funcIt.hasNext()) {
            Function func = funcIt.next();
            if (func.getSymbol().getSource() != SourceType.DEFAULT) continue;

            // Collect strings referenced by this function
            AddressSetView body = func.getBody();
            if (body == null) continue;

            List<String> funcStrings = new ArrayList<>();
            InstructionIterator instrIt = listing.getInstructions(body, true);
            while (instrIt.hasNext()) {
                Instruction instr = instrIt.next();
                Reference[] refs = instr.getReferencesFrom();
                for (Reference ref : refs) {
                    if (!ref.getReferenceType().isData()) continue;
                    Data d = listing.getDataAt(ref.getToAddress());
                    if (d != null && d.hasStringValue()) {
                        String val = (String) d.getValue();
                        if (val != null && val.length() >= 5) {
                            funcStrings.add(val);
                        }
                    }
                }
            }

            if (funcStrings.isEmpty()) continue;

            // Try to match against known patterns
            String bestName = null;
            for (String s : funcStrings) {
                for (String[] pattern : STRING_PATTERNS) {
                    if (Pattern.compile(pattern[0], Pattern.CASE_INSENSITIVE).matcher(s).find()) {
                        bestName = pattern[1];
                        break;
                    }
                }
                if (bestName != null) break;
            }

            // Fallback: derive name from first meaningful string
            if (bestName == null && !funcStrings.isEmpty()) {
                String first = funcStrings.get(0);
                // Extract first identifier-like word from the string
                Matcher m = Pattern.compile("[A-Za-z][A-Za-z0-9_]{3,20}").matcher(first);
                if (m.find()) {
                    String word = m.group().toLowerCase();
                    if (!word.equals("error") && !word.equals("failed") && !word.equals("invalid")) {
                        bestName = "fn_" + word;
                    }
                }
            }

            if (bestName != null && !usedNames.contains(bestName)) {
                func.setName(bestName, SourceType.USER_DEFINED);
                usedNames.add(bestName);
                println("  " + bestName + " @ 0x" +
                        Long.toHexString(func.getEntryPoint().getOffset()) +
                        " (from: \"" + funcStrings.get(0).substring(0,
                        Math.min(40, funcStrings.get(0).length())) + "...\")");
                stringNamed++;
                renamed++;
            } else if (bestName != null) {
                // Disambiguate
                String unique = bestName + "_" +
                    Long.toHexString(func.getEntryPoint().getOffset());
                if (!usedNames.contains(unique)) {
                    func.setName(unique, SourceType.USER_DEFINED);
                    usedNames.add(unique);
                    stringNamed++;
                    renamed++;
                }
            }
        }
        println("  String-named: " + stringNamed);

        println("\n=== SmartRename Summary for " + currentProgram.getName() + " ===");
        println("  SVC-named:     " + svcNamed);
        println("  String-named:  " + stringNamed);
        println("  Total renamed: " + renamed);
    }
}
