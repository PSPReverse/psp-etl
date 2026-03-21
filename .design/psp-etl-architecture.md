# ADR: PSP-ETL Core Architecture

**Status**: Accepted
**Date**: 2026-03-08

## Context

PSP-ETL is a single-user research pipeline. DESIGN.md specifies the goal, schema, CLI, and vendor details. This ADR records decisions made during initial implementation that deviate from or extend DESIGN.md, plus resolved open questions.

## Decisions

### Blob-centric string analysis

`string_analysis` is keyed by `blob_sha256`, not `entry_id` as in DESIGN.md. Multiple entries often share identical extracted bodies (same firmware compiled identically by different vendors). Analyzing per-blob avoids redundant work and correctly deduplicates scores. Queries joining entries to their analysis use a `blob_sha256` join rather than a direct foreign key. Every user-facing output resolves blob hashes to human-readable labels (`type_name`, `version`, `vendor`) via the `entries` table — raw SHA-256 hashes are never exposed in default CLI output.

Modified schema (replaces DESIGN.md Phase 4 `string_analysis` table):

```sql
CREATE TABLE string_analysis (
    id INTEGER PRIMARY KEY,
    blob_sha256 TEXT NOT NULL UNIQUE,  -- was entry_id REFERENCES entries(id)
    total_strings INTEGER,
    unique_strings INTEGER,
    format_strings INTEGER,
    function_names INTEGER,
    error_messages INTEGER,
    postcode_strings INTEGER,
    descriptive_strings INTEGER,
    entropy REAL,                      -- added: Shannon entropy fallback
    score REAL
);
```

### Async HTTP

Scrapers use `httpx.AsyncClient` with `async def` methods in the `VendorScraper` ABC. CLI scrape commands wrap with `asyncio.run()`. This matches the implemented `base.py` interface.

### Configurable data directory

`--data-dir` is a top-level Click group option passed via context object to all subcommands. Default is `./data` relative to CWD. Never committed to version control.

### CLI framework

Click (`@click.group()`), not typer as DESIGN.md specified. The existing `cli.py` stub used Click; keeping it avoids churn and Click is sufficient for this tool's complexity.

### DB migration strategy

`PRAGMA user_version` stores a schema version integer. On open, if the stored version doesn't match the expected version, the DB is dropped and recreated. Acceptable because all data is re-derivable from ROMs via `psp-etl ingest` + `psp-etl analyze`.

### Nix packaging

psptool is not in nixpkgs — packaged from PyPI using `format = "pyproject"` (it ships `pyproject.toml`, not `setup.py`). nixpkgs pinned via npins.

### Shannon entropy fallback

Blobs flagged `encrypted=False` by PSPTool that produce zero strings during analysis have Shannon entropy computed and stored in `string_analysis.entropy`. Entropy ~8.0 = likely encrypted (PSPTool mis-detection), ~6-7 = compressed, ~4-5 = plaintext. Enables filtering and debugging of PSPTool classification errors.

## Resolved Questions (from DESIGN.md)

**Q1 — Research directory**: `ln -s ../../research research/` at project root. This repo is expected to live inside `AMD-PSP/`. Standalone clones will have a broken symlink — acceptable for a single-user research tool. Document in `psp-etl.md`.

**Q2 — Test strategy for ingest.py**: Mock PSPTool API objects (ROM, Directory, File) for unit tests so they run in CI without ROM files. Integration tests use real ROMs from `data/roms/` and are skipped via pytest marker when absent.

**Q3 — PSPTool failures**: Skip and log to `parse_errors` table. Contribute fixes upstream if patterns emerge. No forking.

## Out of Scope

- MSI scraper (session-based downloads, may need browser automation — deferred)
- UEFI capsule parsing beyond ASUS CAP headers
- Web UI or API server
- Firmware redistribution or hosting
- Non-AMD platforms
- Incremental/partial ROM re-ingestion
