# Feature: Firmware Knowledge TOML Format

## Summary
A layered, TOML-based format for encoding known PSP firmware properties: memory maps, entry points, inter-stage function pointer table layouts, and board-variable constants. Files can reference parent files and override their values. The same format is consumed by Ghidra export (for analysis enrichment) and by the emulator/fuzzer export (for dynamic configuration).

## Requirements

- REQ-1: A knowledge file specifies a filter (`generation`, `socket`, `board`, `version`, any combination) that determines which images it applies to. An unfiltered file (no filter block) applies to all images.
- REQ-2: A knowledge file may list parent files by path. All parent properties are inherited. A child may override any parent property.
- REQ-3: If two parents define the same named property (e.g., same region name, same constant name), loading is aborted with an error identifying the conflicting parents and property.
- REQ-4: Memory regions are defined as named blocks with start address, size, and kind (`ram`, `mmio`, `rom`, `unknown`).
- REQ-5: Entry points are defined per firmware type (`type_id`), with address and kind (`reset`, `irq`, `fiq`, `thumb`).
- REQ-6: Inter-stage function pointer tables are described: which type_id writes the table, at what address, and which type_id each slot points into. This enables automated cross-stage load address propagation once the writer stage has been analyzed.
- REQ-7: Named constants are defined with address, value, and a `varies_by` field (`"constant"`, `"board"`, `"version"`, `"board_and_version"`). Constants marked non-`"constant"` become configurable parameters in the emulator/fuzzer export.
- REQ-8: The Python loader (`src/psp_etl/knowledge.py`) resolves the applicable knowledge for a given `(generation, socket, board, version)` tuple by: collecting all files whose filters match, merging them with parent resolution, and returning a single merged `FirmwareKnowledge` object.
- REQ-9: The format is round-trippable: a `FirmwareKnowledge` object can be serialized back to canonical TOML.

## Acceptance Criteria

- [ ] AC-1 (REQ-1): A knowledge file with `[filter] generation = "zen2"` is selected for a zen2 image and not for a zen1 image.
- [ ] AC-2 (REQ-1): A knowledge file with no `[filter]` block is selected for every image.
- [ ] AC-3 (REQ-2): A child file declaring `parents = ["zen2-base.toml"]` inherits all regions and entry points from the parent without re-declaring them.
- [ ] AC-4 (REQ-3): Loading two parent files that both define a memory region named `"PSP_SRAM"` raises `KnowledgeConflictError` naming both parent files and the conflicting key.
- [ ] AC-5 (REQ-4): After loading, `knowledge.memory_regions` contains `MemoryRegion(name, start, size, kind)` objects for all defined regions (parent + child, child overrides applied).
- [ ] AC-6 (REQ-5): After loading, `knowledge.entry_points[type_id]` is a list of `EntryPoint(address, kind)` for each defined type.
- [ ] AC-7 (REQ-6): After loading, `knowledge.fp_tables` contains `FpTable(written_by, address, entries=[FpSlot(offset, points_to_type)])` objects.
- [ ] AC-8 (REQ-7): `knowledge.constants` contains `Constant(name, address, value, varies_by)` and `varies_by` is validated against the allowed set at load time.
- [ ] AC-9 (REQ-8): `knowledge.load(gen="zen2", socket="am4", board="PRIME X570-PRO", version="3402")` returns a merged `FirmwareKnowledge` with all matching file contributions resolved.
- [ ] AC-10 (REQ-9): `knowledge.to_toml()` round-trips through `knowledge.from_toml()` with no data loss.

## Architecture

### File format

```toml
# zen2-am4-asus-prime-x570.toml

[meta]
description = "Zen2 AM4 ASUS PRIME X570-PRO board-specific overrides"
parents = [
    "zen2-base.toml",
    "am4-base.toml",
]

[filter]
generation = "zen2"
socket     = "am4"
board      = "PRIME X570-PRO"
# version  = "3402"   # omit to match all versions

[[memory_regions]]
name  = "PSP_SRAM"
start = 0x00000000
size  = 0x00080000
kind  = "ram"       # "ram" | "mmio" | "rom" | "unknown"

[[memory_regions]]
name  = "MMIO_SMN"
start = 0x01000000
size  = 0x01000000
kind  = "mmio"

[[entry_points]]
type_id = 0x01   # off-chip BL
address = 0x0000_0100
kind    = "reset"   # "reset" | "irq" | "fiq" | "thumb"

[[fp_tables]]
written_by = 0x01    # type_id that writes this table
address    = 0x0003_F800
[[fp_tables.entries]]
offset          = 0
points_to_type  = 0x02   # type_id that gets loaded at this pointer

[[fp_tables.entries]]
offset          = 4
points_to_type  = 0x22   # Secure OS

[[constants]]
name      = "SMU_MSG_REGISTER"
address   = 0x0003_B000
value     = 0x3B10028
varies_by = "board"   # "constant" | "board" | "version" | "board_and_version"
```

### Knowledge directory

Knowledge files live in `data/knowledge/` by convention (under `--data-dir`). The loader discovers all `.toml` files in that directory. Parent references are resolved relative to the same directory.

### Python module: `src/psp_etl/knowledge.py`

Key types:

```python
@dataclass
class MemoryRegion:
    name: str
    start: int
    size: int
    kind: str  # "ram" | "mmio" | "rom" | "unknown"

@dataclass
class EntryPoint:
    address: int
    kind: str  # "reset" | "irq" | "fiq" | "thumb"

@dataclass
class FpSlot:
    offset: int
    points_to_type: int

@dataclass
class FpTable:
    written_by: int   # type_id
    address: int
    entries: list[FpSlot]

@dataclass
class Constant:
    name: str
    address: int
    value: int
    varies_by: str  # "constant" | "board" | "version" | "board_and_version"

@dataclass
class FirmwareKnowledge:
    memory_regions: dict[str, MemoryRegion]   # keyed by name
    entry_points: dict[int, list[EntryPoint]] # keyed by type_id
    fp_tables: list[FpTable]
    constants: dict[str, Constant]            # keyed by name

    @classmethod
    def load(
        cls,
        knowledge_dir: Path,
        *,
        generation: str | None = None,
        socket: str | None = None,
        board: str | None = None,
        version: str | None = None,
    ) -> "FirmwareKnowledge": ...

    def to_toml(self) -> str: ...
```

### Merge algorithm

1. Collect all `.toml` files in `knowledge_dir` whose `[filter]` matches the query (all filter fields present in the file must match; omitted fields are wildcards).
2. For each collected file, recursively load its `parents` list (depth-first, deduplicated).
3. Merge parents first: build a merged dict for each property category (regions, entry points, etc.). If two parents define the same named key, raise `KnowledgeConflictError`.
4. Apply child values on top of the merged parents (child always wins).
5. Return the merged `FirmwareKnowledge`.

### Emulator/fuzzer integration

The `constants` table with `varies_by != "constant"` is the primary interface to the emulator. The emulator export (`psp-etl export emulator`) serializes these as a JSON/TOML config with placeholder ranges for `varies_by = "board"` entries, populated from the known values across the corpus.

## Open Questions

<!-- OPEN: Q1 -->
### Q1: Knowledge file discovery and shipping
Should knowledge files be shipped inside the `psp-etl` Python package (under `src/psp_etl/knowledge_data/`) so they're always available, or should they only live in `data/knowledge/` and be user-managed?

**To resolve**: Decide whether the base gen-level files (e.g. `zen2-base.toml`) should be versioned in the repo. Board-specific files should definitely be user-managed. A hybrid approach (package ships base files, user directory overlays) is possible.
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: FP table population workflow
The `fp_tables` entries encode knowledge that comes from OCB reversing. This must be hand-authored. Should there be a `psp-etl knowledge edit` command to scaffold a new file, or is direct TOML editing sufficient for a single-user tool?

**To resolve**: Decide at first use. Likely direct editing is fine initially.
<!-- /OPEN -->

<!-- OPEN: Q3 -->
### Q3: Address variance corpus analysis
To populate `varies_by = "board"` constants, we need to compare values across multiple images. Should `psp-etl knowledge scan --gen zen2` be a future command that reads analyzed Ghidra projects and auto-detects address variance, or is this always manual?

**To resolve**: Deferred until Ghidra export is working and at least two boards' Zen2 images are analyzed.
<!-- /OPEN -->

## Out of Scope

- Automatic FP table extraction without user-provided seed knowledge
- Schema versioning beyond TOML syntax validation
- Non-PSP ARM firmware (other architectures, other vendors)
- GUI editor for knowledge files
