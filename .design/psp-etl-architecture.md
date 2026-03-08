# Feature: PSP-ETL Core Architecture

## Summary

PSP-ETL is an automated pipeline that scrapes motherboard vendor websites for AMD BIOS firmware, extracts PSP (Platform Security Processor) firmware entries using PSPTool, analyzes debug string richness across vendor builds, and selects the "best" (most debug-string-rich) build per firmware version. The key insight is that vendors compile PSP firmware themselves and sometimes leave debug mode enabled, producing builds with far richer debug strings than others for the same firmware version.

## Requirements

- REQ-1: The `default.nix` must produce both a buildable nix package (`nix-build -A psp-etl`) and a dev shell (`nix-shell -A shell`) with Python 3.12, all runtime dependencies (psptool, click, httpx, beautifulsoup4, rich), and dev tools (ruff, npins). nixpkgs is pinned via npins.
- REQ-2: All runtime data (ROMs, blobs, SQLite database) is stored in a configurable `--data-dir` (default `./data`), passed as a click context object to all subcommands. The data directory is never committed to version control.
- REQ-3: `src/psp_etl/db.py` provides a `Database` class that creates/migrates the SQLite schema (6 tables: `images`, `entries`, `string_analysis`, `strings`, `primary_images`, `parse_errors` plus indexes) and exposes parameterized insert/query methods.
- REQ-4: `src/psp_etl/ingest.py` parses ROM files via `PSPTool.from_file()`, iterates `psp.blob.roms` → `rom.directories` → `directory.files`, extracts body bytes to content-addressed blobs at `{data_dir}/blobs/{sha256}.bin`, and populates `images`/`entries` tables. PSPTool exceptions are caught per-ROM and logged to `parse_errors`.
- REQ-5: `src/psp_etl/strings.py` performs blob-centric string analysis: each unique `blob_sha256` is analyzed once. Strings are classified into categories (format_string, function_name, error_message, postcode, descriptive, other) with weighted scoring. Analysis results are stored in `string_analysis` (keyed by `blob_sha256`) and `strings` tables.
- REQ-6: All CLI output that references blobs must display a human-readable label (type_name + version from the entries table) alongside or instead of raw SHA-256 hashes, so users never need to work with hashes directly.
- REQ-7: Vendor scrapers use sync httpx (`httpx.Client`), implement a common `VendorScraper` base class in `src/psp_etl/scrape/base.py`, and support rate limiting, retry with backoff, and SHA-256 deduplication of downloaded ROMs.
- REQ-8: The CLI is built with click (not typer), using `@click.group()` in `src/psp_etl/cli.py` as the entry point registered as `psp-etl` in `pyproject.toml`.
- REQ-9: A `research/` directory is symlinked from the parent project (`../../research`) and contains domain knowledge files. A `psp-etl.md` file in the project root describes the tool for cross-project/cross-session reference.
- REQ-10: Shannon entropy is computed for blobs that PSPTool flags as unencrypted but that produce zero strings during analysis, to detect mis-classified encrypted blobs (entropy ~8.0 = encrypted, ~6-7 = compressed, ~4-5 = plaintext).

## Acceptance Criteria

- [ ] AC-1: `nix-build -A psp-etl` succeeds and produces a working `psp-etl` binary. `nix-shell -A shell` drops into a shell with python3.12, psptool, click, httpx, beautifulsoup4, rich, and ruff available. (REQ-1)
- [ ] AC-2: `psp-etl --data-dir /tmp/test ingest <rom>` creates `/tmp/test/blobs/`, `/tmp/test/roms/`, and `/tmp/test/psp-etl.db`. Running without `--data-dir` uses `./data`. (REQ-2)
- [ ] AC-3: Importing `psp_etl.db.Database` and calling `Database(path).create_schema()` creates all 6 tables and 9 indexes. All insert methods use parameterized SQL (no string interpolation). (REQ-3)
- [ ] AC-4: `psp-etl ingest <rom>` populates `images` and `entries` tables, writes at least one blob to `{data_dir}/blobs/{sha256}.bin`, and the entry count matches PSPTool's output for that ROM. (REQ-4)
- [ ] AC-5: `psp-etl ingest <corrupt_rom>` logs an error to `parse_errors` table and exits with code 0 (does not crash). (REQ-4)
- [ ] AC-6: `psp-etl analyze` analyzes each unique `blob_sha256` exactly once. Running it twice with no new blobs produces no new `string_analysis` rows. (REQ-5)
- [ ] AC-7: `psp-etl query --has-strings` output shows columns like `type_name`, `version`, `vendor`, `score` — no raw SHA-256 hashes in default table output. (REQ-6)
- [ ] AC-8: `psp-etl best --gen zen2` shows the highest-scoring entry per (type_id, version) with human-readable labels. (REQ-5, REQ-6)
- [ ] AC-9: `psp-etl scrape asrock --socket am4 --limit 2 --dry-run` lists download URLs without downloading. Re-running `psp-etl scrape asrock --limit 1` after a successful download skips already-downloaded ROMs. (REQ-7)
- [ ] AC-10: Blobs with zero strings and `encrypted=False` have their Shannon entropy stored, and `psp-etl query` can filter by entropy range. (REQ-10)
- [ ] AC-11: `psp-etl --help` prints a help message listing all subcommands (ingest, analyze, query, best, stats, select, scrape, export). The entry point is `psp_etl.cli:cli` as registered in `pyproject.toml`. (REQ-8)
- [ ] AC-12: `research/` symlink resolves correctly and `psp-etl.md` exists at the project root. (REQ-9)

## Architecture

### Package Layout

The project follows a `src/` layout at `/home/vringar/projects/AMD-PSP/psp-etl/`:

```
psp-etl/
├── default.nix              # Nix package + dev shell
├── pyproject.toml            # Python package metadata (setuptools)
├── npins/                    # Pinned nixpkgs
├── psp-etl.md                # Cross-project tool description
├── DESIGN.md                 # Original design document
├── research/ → ../../research  # Symlink to shared research notes
├── src/psp_etl/
│   ├── __init__.py
│   ├── cli.py                # Click CLI entry point
│   ├── db.py                 # SQLite schema + Database class
│   ├── ingest.py             # PSPTool ROM parsing
│   ├── strings.py            # String extraction/classification/scoring
│   ├── export.py             # Ghidra/emulator/fuzzer export (M4)
│   └── scrape/
│       ├── __init__.py
│       ├── base.py           # VendorScraper ABC + BoardInfo/BiosUpdate
│       ├── extract.py        # Vendor wrapper unwrapping (CAP, ZIP)
│       ├── asrock.py
│       ├── gigabyte.py
│       ├── asus.py
│       └── msi.py
└── data/                     # Runtime data (gitignored)
    ├── psp-etl.db
    ├── roms/{sha256}.rom
    └── blobs/{sha256}.bin
```

### Data Flow

1. **Scrape** (M2): `VendorScraper.list_boards()` → `list_bios_updates()` → `download()` → raw ROM in `data/roms/`
2. **Ingest** (M1): `ingest.ingest_rom()` → PSPTool parses ROM → entries + blobs in `data/blobs/`, metadata in `entries` table
3. **Analyze** (M1): `strings.analyze_blob()` iterates unique `blob_sha256` values from `entries` → scores + strings in `string_analysis`/`strings` tables
4. **Select** (M3): `select` groups entries by `(zen_generation, type_id, version)`, picks highest-scoring blob per group → `primary_images` table
5. **Export** (M4): reads `primary_images` + `entries` + blob files → Ghidra/emulator/fuzzer output

### Key Design Decisions

**Blob-centric analysis**: The `string_analysis` table is keyed by `blob_sha256` (not `entry_id`). This avoids redundant analysis when multiple entries share an extracted body. The tradeoff is that queries joining entries to their analysis need a `blob_sha256` join rather than a direct foreign key. Every user-facing output resolves blob hashes to human-readable labels (`type_name`, `version`, `vendor`) via the `entries` table.

**Sync HTTP**: Scrapers use `httpx.Client` (sync) rather than `httpx.AsyncClient`. Click integration is straightforward without `asyncio.run()` wrappers. Throughput is acceptable since scraping is I/O-bound against rate limits anyway.

**Configurable data directory**: The `--data-dir` option is a click context parameter on the top-level group, passed down to all subcommands. Default is `./data` relative to CWD.

**Nix packaging**: `default.nix` packages psptool from PyPI (not in nixpkgs) and psp-etl as a pyproject build. The `format` for psptool must be `"pyproject"` (it ships `pyproject.toml`, not `setup.py`). npins pins nixpkgs for reproducibility.

**Schema change from DESIGN.md**: `string_analysis.entry_id` becomes `string_analysis.blob_sha256` to support blob-centric analysis. The UNIQUE constraint changes from `entry_id` to `blob_sha256`.

### Modified Schema (vs DESIGN.md)

```sql
CREATE TABLE string_analysis (
    id INTEGER PRIMARY KEY,
    blob_sha256 TEXT NOT NULL UNIQUE,  -- changed from entry_id
    total_strings INTEGER,
    unique_strings INTEGER,
    format_strings INTEGER,
    function_names INTEGER,
    error_messages INTEGER,
    postcode_strings INTEGER,
    descriptive_strings INTEGER,
    entropy REAL,                      -- added: Shannon entropy
    score REAL
);
```

All other tables remain as specified in DESIGN.md.

## Resolved Questions

### Q1: Research directory strategy
**Decision**: Symlink + document. `ln -s ../../research research/` in the project root. The README/psp-etl.md must document that this repo is expected to live inside `AMD-PSP/` and that the symlink targets `../../research/`. Standalone clones will have a broken symlink — this is acceptable for a single-user research tool.

### Q2: Test strategy for ingest.py
**Decision**: Mock PSPTool for unit tests + real ROMs for integration tests. Unit tests mock PSPTool's API objects (ROM, Directory, File) so they run fast in CI with no network or ROM files. A separate integration test suite uses real ROMs from `data/roms/` when available and is skipped (via pytest marker) when ROMs are absent.

### Q3: Database migration strategy
**Decision**: Recreate the DB on schema version mismatch. `db.py` stores a `PRAGMA user_version` integer. On open, if the version doesn't match the expected schema version, the DB is dropped and recreated. This is acceptable because all data is re-derivable from ROMs in `data/roms/` via `psp-etl ingest` + `psp-etl analyze`.

## Out of Scope

- MSI scraper browser automation (deferred to after the other three vendors work)
- UEFI capsule parsing beyond ASUS CAP headers (BIOSUtilities integration deferred)
- Automatic upstream PSPTool bug reporting
- Web UI or API server (CLI-only tool)
- Firmware redistribution or hosting
- Support for non-AMD platforms (Intel ME, etc.)
- Incremental/partial ROM re-ingestion (full re-ingest is acceptable)
