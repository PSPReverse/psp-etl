# Ghidra scripts triage

Classification of the 37 scripts under `ghidra_scripts/`. "Pipeline" = invoked by
`run_full_analysis.sh`. Evidence is references in `run_full_analysis.sh`, `README.md`
and cross-references between scripts; nothing here has been deleted yet.

## Keep: in the pipeline (11)
`setup/ApplyPspMemoryMap`, `setup/ApplyZen2MemoryMap`, `project/RelinkArchiveTypes`,
`transfer/TransferLabels`, `transfer/TransferLabelsFuzzy`, `transfer/TransferLabelsLoose`,
`analysis/SmartRename`, `analysis/InferPrintf`, `analysis/RecoverStringXrefs`,
`analysis/AnnotateMMIO`, `analysis/LabelMailboxHandlers`.

## Delete: deprecated (4)
Each header says to use `RelinkArchiveTypes` instead (or "do not use"):
`project/ReassociateProjectArchives`, `project/ResolveProjectArchives`,
`project/UpdateArchivePaths`, `project/SeverArchiveLinks`.
`SeverArchiveLinks` is referenced by 3 other scripts' comments (as the cause of the
orphaned links `RelinkArchiveTypes` repairs): fix those comments when deleting.

## Merge / decide: overlapping (4, plus ApplyZen2MemoryMap above)
- `setup/ApplyZen2MemoryMap` vs `setup/ApplyPspMemoryMap`: both add PSP memory regions;
  the generic one takes `<gen> <platform>`. Pipeline step 1 is documented as the Zen2 one
  but the invocation at `run_full_analysis.sh:61` uses the generic one. Likely the Zen2
  script is now redundant. Checked statically (block lists compared, not run): the Zen2 SRAM
  blocks are identical to the generic zen2 ryzen/epyc ones; the only difference is the
  extra `SMN_MapCtrl` block (0x3220000, 0x40) in the Zen2 script. To merge: add
  `SMN_MapCtrl` to `ApplyPspMemoryMap`, delete `ApplyZen2MemoryMap`, fix the stale step 1
  comment in `run_full_analysis.sh`.
- Both scripts place `IRQ_Controller` at 0x030103b0 (the Zen1 base). The off-chip BL on
  Zen2/3/4/5 uses 0x030102b0 for ACK/PEN/ID (`secos-irq-mailbox-notes.md`), which both
  scripts leave inside `UnknownMMIO_1`: the block label is wrong for Zen2+ and should be
  generation-dependent.
- `analysis/AnalyzeMailboxIRQ`, `FindMailboxDispatch`, `FindMailboxPatterns`: three
  exploratory mailbox tracers, none in the pipeline, all superseded in practice by
  `LabelMailboxHandlers` plus the static findings in `secos-irq-mailbox-notes.md`.
  Keep one (most general) as a diagnostic, move to `diagnostics/`, delete the rest.
- `analysis/AnalyzePatterns`: one-off pattern extraction, no pipeline use; candidate to delete.

## Keep: documented setup, not in the pipeline (2)
`setup/ApplyPspTypes` (see Known defect), `setup/SetupOffChipBL`.

## Not documented (2)
`setup/ApplyPspAddressSpaces` has no reference anywhere (not in the README or the
pipeline): either wire it into setup or delete. `setup/SeedRawPrologues` is new and
documented only in its header: add it to the README (raw-blob import recipe).

## Candidates to port to re-reuse (4)
Generic naming and annotation passes that are not psp-etl specific:
`SmartRename`, `InferPrintf`, `RecoverStringXrefs`, `AnnotateMMIO`. The re-reuse role is
implementor/maintainer of such rules; ask in topic `re-reuse` with a self-contained
request (inputs: these files; output: equivalent rule or template; check: same renames
on a Zen2 blob) before removing them here.

## Keep as housekeeping (14)
Project/import/export utilities with no pipeline role but no replacement:
`import_export/*` (6), `project/DeleteFolder`, `FixExternalLinks`, `RenamePrograms`,
`ReorganizeSect`, and the four `diagnostics/*` read-only scripts. Low value, low cost.

## Known defect
`setup/ApplyPspTypes` step 2 of the pipeline logs
`IllegalAccessException ... BadDataType (FileDataTypeManager)` while opening the `.gdt`
archives and relinks 0 types (seen on the Zen2 driver blob). The exception is raised
inside Ghidra's archive loader, not in script code; reproduce with a minimal
`openFileArchive` call before changing anything.
