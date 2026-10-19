# tools

Standalone analysis helpers. None are imported by `psp_etl`. They need
`capstone` (not a project dependency): run them with
`uv run --with capstone python tools/<script>.py ...` from the repo root.

| Script | Purpose |
|--------|---------|
| `armdump.py` | Disassemble a range of a raw ARM/Thumb binary, resolving pc-relative literals. |
| `kernel_offsets.py` | Locate SecOS kernel landmarks (FIQ loop, idle WFI, irq_attach, mailbox/timer pools) by signature. |
| `irq_attach_scan.py` | List the interrupt ids a userland blob attaches via `movs r0,#id; svc #N`. |
| `cov_overlay.py` | Overlay a DrCov file on a symbol map: unreached functions, call frontier, half-taken branches. |
| `compare_ingest.py` | Ingest corpus ROMs into a scratch DB and dump rows, to compare two parser builds. |
| `manual_image_hints.py` | Vendor/board/build-date hints for images without provenance. |

Output directories (`scratch/`, extracted dumps) stay out of git.
