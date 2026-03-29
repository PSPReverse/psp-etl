# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- MSI scraper via CDX API + CDN range-request board identification (#12)
- Design docs: ghidra export, firmware knowledge TOML, ghidra MCP server
- Typst presentation slides and interactive demo script
- Folder-vs-best comparison script
- `best --folder` and `--format json` CLI options
- Smoke tests for all CLI commands (ingest, analyze, query, select, best, stats, scrape)
- Shannon entropy fallback scoring for encrypted blobs with no extractable strings
- Rate limiting and retry strategy for vendor scrapers
- CLI commands: ingest, analyze, select, query, best, stats, scrape (#5)
- Human-readable labels instead of raw SHA-256 hashes in CLI output
- Vendor wrapper extraction — extract.py (#11)
- ASRock (#8), ASUS (#10), Gigabyte (#9) scrapers
- Scraper base class and data models (#7)
- String extraction, classification, and scoring — strings.py (#4)
- ROM parsing with PSPTool — ingest.py (#3)
- SQLite schema and query layer — db.py (#2)
- Stats dashboard and string search (#15)
- Primary image selection (#14)
- .gitignore entries for data/ and Python artifacts (#6)

### Fixed
- ingest: handle 'Zen 4/5' slash-separated generation notation
- ingest: multi-generation PSP directory strings only capture first generation
- ingest: BIOS-side directories ($BHD/$BL2) always get NULL zen_generation
- GigabyteScraper: async methods block event loop with sync httpx.Client
- ASUS scraper: board names contain raw HTML tags
- scrape command crashes: scrapers require async context manager
- cli: psp-etl ingest missing --vendor and --model options

### Changed
- Model SMN/x86 as Ghidra address spaces with resolvable pointer typedefs (#74)
- Drop version from select group key; add get_best_folders, get_entries_for_folder
- Nix: drop setuptools-scm, use nix-gitignore, add dev shell hook
