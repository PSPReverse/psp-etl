# ADR: PSP-ETL Core Architecture

**Status**: Accepted
**Date**: 2026-03-08

## Context

PSP-ETL is a research pipeline for collecting and analysing AMD PSP firmware. This ADR records the architecture decisions made during initial implementation, and resolves the open questions that came out of that design phase.

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

## Resolved Questions

**Q1 — Test strategy for ingest.py**: Mock PSPTool API objects (ROM, Directory, File) for unit tests so they run in CI without ROM files. Integration tests use real ROMs from `data/roms/` and are skipped via pytest marker when absent.

**Q2 — PSPTool failures**: Skip and log to `parse_errors` table. Contribute fixes upstream if patterns emerge. No forking.

**Q3 — MSI scraper**: Originally deferred under the assumption that downloads were session-based. Resolved by switching to the Wayback Machine CDX API to enumerate `download.msi.com/bos_exe/mb/*` URLs and identifying boards via HTTP Range requests on the first 8 KB of each ZIP. See `src/psp_etl/scrape/msi.py`.

## Out of Scope

- UEFI capsule parsing beyond ASUS CAP headers
- Web UI or API server
- Firmware redistribution or hosting
- Non-AMD platforms
- Incremental/partial ROM re-ingestion
