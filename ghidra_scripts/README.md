# Ghidra Scripts for PSP Firmware Analysis

Headless and GUI scripts for importing, analyzing, and annotating AMD PSP firmware in Ghidra. All scripts extend `GhidraScript` and work with both `analyzeHeadless` and the Ghidra Script Manager.

## Directory Layout

```
ghidra_scripts/
├── analysis/        Function renaming, MMIO annotation, string xref recovery
├── transfer/        Cross-program label and name transfer (fuzzy matching)
├── import_export/   GZF pack/unpack, type import, memory map export
├── setup/           Memory maps, PSP types, entry point configuration
├── project/         Rename, reorganize, fix archives and external links
└── diagnostics/     Read-only inspection (list types, archives, links)
```

Each script has a `//@category PSP.<Subcategory>` tag so they appear grouped under **PSP** in the Ghidra Script Manager.

## Quick Start — Full Pipeline

```bash
# Run the complete analysis pipeline on a folder of imported programs:
./ghidra_scripts/run_full_analysis.sh <folder> --gen <generation> [--platform <platform>] [--reference <source_path>]

# Examples:
./ghidra_scripts/run_full_analysis.sh zen2_test --gen zen2
./ghidra_scripts/run_full_analysis.sh zen5 --gen zen5 --reference /zen5/PSP_FW_TRUSTED_OS_v0.2B.0.49
```

This runs 8 steps in order: memory map → type linking → label transfer → SmartRename → InferPrintf → AnnotateMMIO → RecoverStringXrefs → LabelMailboxHandlers.

## Prerequisites (NixOS)

`analyzeHeadless` is not directly on `$PATH` from the Nix Ghidra package. Locate it relative to the Ghidra installation:

```bash
GHIDRA_HOME="$(dirname "$(dirname "$(readlink -f "$(which ghidra)")")")"
ANALYZE="${GHIDRA_HOME}/lib/ghidra/support/analyzeHeadless"
```

Or use the full Nix store path directly (find it with `which ghidra` and navigate to `support/analyzeHeadless`).

## Local Project

The local Ghidra project lives at `data/ghidra/psp-etl.gpr` (gitignored). Programs are organized under generation subfolders (`/zen2/`, `/zen4/`, etc.).

## Data Type Archives (.gdt) — Proprietary

The `.gdt` files referenced throughout these scripts (e.g. `PspSvcIf.gdt`, `PspHw.gdt`, `CcpIf.gdt`) are **proprietary to SECT and will not be redistributed**. They are gitignored project-wide via `*.gdt`. Scripts may reference them by name, but the archives themselves must be obtained separately and placed in `data/ghidra_archives/` (or wherever `GDT_DIR` points). Public/CI runs of the analysis pipeline will not have these archives available — pipeline steps that require them (`RelinkArchiveTypes`, `ImportTypesFromGZF`) will degrade or skip cleanly when no `.gdt` files are found.

## Running Scripts

### General Pattern

```bash
# Scripts that operate on individual programs (-postScript):
$ANALYZE "$(pwd)/data/ghidra" psp-etl/<folder> \
  -process <program_name> -noanalysis \
  -scriptPath "$(pwd)/ghidra_scripts/<category>" \
  -postScript ScriptName.java [args...]

# Scripts that operate on the project itself (-preScript):
$ANALYZE "$(pwd)/data/ghidra" psp-etl -noanalysis \
  -scriptPath "$(pwd)/ghidra_scripts/<category>" \
  -preScript ScriptName.java [args...]

# Scripts that run on all programs in a folder:
$ANALYZE "$(pwd)/data/ghidra" psp-etl/<folder> \
  -recursive -process -noanalysis \
  -scriptPath "$(pwd)/ghidra_scripts/<category>" \
  -postScript ScriptName.java [args...]
```

Multiple `-scriptPath` flags can be combined when using scripts from different categories in one invocation.

### Import Pipeline

The proven import sequence for new firmware blobs:

```bash
SCRIPTS="$(pwd)/ghidra_scripts"

# 1. Import a raw blob as ARM 32-bit little-endian
$ANALYZE "$(pwd)/data/ghidra" psp-etl/zen2 \
  -import "data/blobs/${SHA256}.bin" \
  -processor "ARM:LE:32:v7" \
  -loader BinaryLoader \
  -loader-baseAddr "${LOAD_ADDRESS}" \
  -analysisTimeoutPerFile 300 \
  -scriptPath "$SCRIPTS/setup" \
  -postScript ApplyZen2MemoryMap.java

# 2. Rename from SHA256 to human-readable names (via TSV mapping)
$ANALYZE "$(pwd)/data/ghidra" psp-etl -noanalysis \
  -scriptPath "$SCRIPTS/project" \
  -preScript RenamePrograms.java mapping.tsv zen2

# 3. Apply PSP data types from archives
$ANALYZE "$(pwd)/data/ghidra" psp-etl/zen2 \
  -recursive -process -noanalysis \
  -scriptPath "$SCRIPTS/import_export" \
  -postScript ImportTypesFromGZF.java data/ghidra_archives/PspSvcIf.gdt \
    data/ghidra_archives/PspHw.gdt data/ghidra_archives/CcpIf.gdt

# 4. Transfer labels from a reference program
$ANALYZE "$(pwd)/data/ghidra" psp-etl/zen2 \
  -process TARGET_PROGRAM -noanalysis \
  -scriptPath "$SCRIPTS/transfer" \
  -postScript TransferLabelsFuzzy.java /zen2/SOURCE_PROGRAM

# 5. Loose transfer for remaining unnamed functions
$ANALYZE "$(pwd)/data/ghidra" psp-etl/zen2 \
  -process TARGET_PROGRAM -noanalysis \
  -scriptPath "$SCRIPTS/transfer" \
  -postScript TransferLabelsLoose.java /zen2/SOURCE_PROGRAM

# 6. Auto-analysis: SVC naming, printf inference, MMIO annotation
$ANALYZE "$(pwd)/data/ghidra" psp-etl/zen2 \
  -recursive -process -noanalysis \
  -scriptPath "$SCRIPTS/analysis" \
  -postScript SmartRename.java \
  -postScript InferPrintf.java \
  -postScript AnnotateMMIO.java
```

Each invocation takes ~7s per blob (JVM startup dominates).

### Export for Sharing

```bash
# Export all programs as .gzf packed files
$ANALYZE "$(pwd)/data/ghidra" psp-etl -noanalysis \
  -scriptPath "$SCRIPTS/import_export" \
  -postScript ExportAllGZF.java /tmp/gzf_export

# Export only data type archives as .gdt
$ANALYZE "$(pwd)/data/ghidra" psp-etl -noanalysis \
  -scriptPath "$SCRIPTS/import_export" \
  -postScript ExportArchivesOnly.java data/ghidra_archives
```

## Script Reference

### analysis/

| Script | Purpose |
|--------|---------|
| SmartRename.java | Auto-name functions via SVC IDs and string content patterns |
| InferPrintf.java | Identify printf-like functions via format string analysis |
| AnnotateMMIO.java | Label MMIO register accesses with PSP hardware region names |
| AnalyzePatterns.java | Extract reusable patterns (prologues, SVC distribution, error strings) |
| RecoverStringXrefs.java | Recover missing string xrefs via literal pools, MOVW/MOVT pairs, pointer tables |
| FindMailboxPatterns.java | Find mailbox register access patterns (direct, MOVW/MOVT, literal pool) |
| FindMailboxDispatch.java | Trace mailbox interrupt → dispatch chain via call graph and strings |
| LabelMailboxHandlers.java | Auto-label mailbox command handlers from UBFX dispatch tables |
| AnalyzeMailboxIRQ.java | Deep analysis of mailbox IRQ chain with full instruction dump |

### transfer/

| Script | Purpose |
|--------|---------|
| TransferLabels.java | Base transfer using exact byte matching |
| TransferLabelsFuzzy.java | 3-pass: exact bytes, instruction hash, string references |
| TransferLabelsLoose.java | 3-pass: mnemonic-only hash, size+prologue, call-graph signature |

### import_export/

| Script | Purpose |
|--------|---------|
| ExportAllGZF.java | Export all programs as .gzf packed files |
| ExportArchivesOnly.java | Export DataTypeArchive objects as .gdt files |
| ExportMemoryMap.java | Export memory blocks as JSON |
| ImportGZF.java | Import .gzf packed files into a project |
| ImportGZFTree.java | Import .gzf files with `Category__Name` folder mapping |
| ImportTypesFromGZF.java | Import data types from .gdt archives into programs |

### setup/

| Script | Purpose |
|--------|---------|
| ApplyPspMemoryMap.java | **Unified** memory map for any generation/platform (`zen1`-`zen5`, `ryzen`/`epyc`) |
| ApplyZen2MemoryMap.java | Zen2-only memory map — **use ApplyPspMemoryMap.java instead** |
| ApplyPspTypes.java | Apply PSP hardware type definitions from type library programs |
| SetupOffChipBL.java | Configure entry point at 0x100 for off-chip bootloader |

### project/

| Script | Purpose |
|--------|---------|
| RelinkArchiveTypes.java | **Re-establish proper archive links** by re-resolving types from .gdt files (fixes UUID mismatch after disassociate) |
| RenamePrograms.java | Batch rename programs via TSV mapping |
| DeleteFolder.java | Recursively delete a project folder |
| ReorganizeSect.java | Move `Category__Name` files into `Category/Name` subfolders |
| FixExternalLinks.java | Fix broken external program references after reorganization |
| SeverArchiveLinks.java | Remove source archive references (makes types local) — **destructive, breaks sync** |
| ResolveProjectArchives.java | Convert FILE-type archive refs to PROJECT-type — **known broken**: sets pointer but not UUID |
| ReassociateProjectArchives.java | Re-link disassociated types to project archives — **known broken**: same UUID issue |
| UpdateArchivePaths.java | Fix broken FILE-type archive refs via .gdt re-resolution — **known broken**: same UUID issue |

> **Archive link repair**: After `SeverArchiveLinks` was used, types became local with
> new UniversalIDs that don't match the archive. `ResolveProjectArchives`,
> `ReassociateProjectArchives`, and `UpdateArchivePaths` all tried to fix this via
> `associateDataTypeWithArchive()`, but that only sets the source archive pointer —
> it doesn't restore the UUID match that Ghidra needs for "sync with archive".
> Use `RelinkArchiveTypes.java` instead, which re-resolves types from the .gdt
> with `REPLACE_HANDLER` to get correct UUIDs.

### diagnostics/

| Script | Purpose |
|--------|---------|
| AuditArchiveLinks.java | Report archive link health: linked vs orphaned vs UUID-mismatched types |
| ListSourceArchives.java | Show source archive references and resolution status |
| ListExternalLinks.java | Dump external library names and paths |
| ListDataTypes.java | List all enums/structs in a program |

## Known Gotchas

- **Lock contention**: `analyzeHeadless` and the Ghidra GUI cannot access the same project simultaneously. Close the GUI before running headless scripts.
- **Symlink resolution**: `-import` resolves symlinks, so program names come from the resolved path. Use hardlinks or rename after import.
- **GZF ambiguity**: Both programs and data type archives use `.gzf` extension. `FileDataTypeManager.openFileArchive()` requires `.gdt` extension.
- **DomainFolder.getFile()**: Unreliable after file operations in headless mode. Collect names first, then re-fetch.
- **Source archive errors**: Imported types reference source archive UUIDs. If the archive isn't found on open, Ghidra shows error dialogs. **Do not use `SeverArchiveLinks.java`** — it destroys UUID-based sync permanently. Instead, install .gdt files in `~/.config/ghidra/ghidra_<version>_NIX/data/` so Ghidra auto-discovers them. If links are already severed, use `RelinkArchiveTypes.java` to repair.
- **Archive link lifecycle**: `dtm.resolve(archiveType)` creates proper links (UUID match + source archive ref). `dtm.disassociate()` destroys them (new local UUID). `dtm.associateDataTypeWithArchive()` only sets the pointer, not the UUID — it does NOT restore sync capability.
- **-process paths**: Takes a filename relative to the project subfolder. No `/` allowed in the name. Use the subfolder as part of the project path instead.
