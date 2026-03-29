# psp-etl

AMD PSP firmware extraction, transformation, and loading pipeline. Scrapes motherboard vendor websites for BIOS update packages, extracts PSP firmware entries using [PSPTool](https://github.com/PSPReverse/PSPTool), analyzes debug string richness across vendor builds, and identifies which vendor build contains the most debug symbols for each firmware version.

This tool lives inside the `AMD-PSP/` project directory and expects a `research/` symlink pointing to `../../research/`.

## Background

Motherboard vendors (ASUS, MSI, Gigabyte, ASRock) receive AMD's ComboPI/AGESA source and compile PSP firmware themselves. Vendors sometimes leave debug mode enabled, producing builds with far richer debug strings than others for the same firmware version. This pipeline finds those golden images.

## Building

This project uses [Nix](https://nixos.org/) for reproducible builds and [uv](https://github.com/astral-sh/uv) for development.

### Nix (recommended)

```sh
# Enter development shell (Python 3.12 + all deps + ruff + uv + npins)
nix-shell -A shell

# Build the package
nix-build -A psp-etl
./result/bin/psp-etl --help
```

### uv (without Nix)

Requires Python 3.12+ and psptool installed separately.

```sh
uv sync --extra dev
uv run psp-etl --help
```

## Running tests

```sh
uv run --extra dev pytest
```

## Usage

```
psp-etl --data-dir ./data <command>
```

`--data-dir` defaults to `./data`. The data directory is never committed to version control and contains:

```
data/
├── psp-etl.db       # SQLite database
├── roms/            # Downloaded BIOS ROMs ({sha256}.rom)
└── blobs/           # Extracted PSP firmware blobs ({sha256}.bin)
```

### Planned commands

```
psp-etl scrape <vendor|all>      # Scrape and download BIOS updates
    --socket am4|am5|all
    --limit N
    --dry-run

psp-etl ingest <rom|directory>   # Parse ROM(s), extract PSP entries and blobs

psp-etl analyze                  # Run string analysis on unanalyzed blobs
    --reanalyze

psp-etl select                   # Recompute primary image selections

psp-etl query                    # Query the database
    --gen zen1|zen2|zen3|zen4|zen5
    --type <hex_type_id>
    --vendor <name>
    --min-score <float>
    --has-strings
    --string <pattern>
    --format table|json|csv

psp-etl best                     # Show best (highest-scoring) images
    --gen zen1|zen2|zen3|zen4|zen5
    --type <hex_type_id>
    --export-dir <path>

psp-etl stats                    # Per-generation summary dashboard
```

## Supported vendors

| Vendor | Socket | Status |
|--------|--------|--------|
| ASRock | AM4, AM5 | Scraper implemented |
| Gigabyte | AM4, AM5 | Scraper implemented |
| ASUS | AM4, AM5 | Scraper in progress |
| MSI | AM4, AM5 | Planned (session-based CDN, deferred) |

## Project structure

```
psp-etl/
├── default.nix
├── pyproject.toml
├── DESIGN.md                  # Full pipeline specification
├── .design/                   # Architecture decision records
├── ghidra_scripts/            # Ghidra headless/GUI scripts (see ghidra_scripts/README.md)
│   ├── analysis/              #   Function renaming, MMIO annotation, string xref recovery
│   ├── transfer/              #   Cross-program label transfer (fuzzy matching)
│   ├── import_export/         #   GZF pack/unpack, type import, memory map export
│   ├── setup/                 #   Memory maps, PSP types, entry point config
│   ├── project/               #   Rename, reorganize, fix archives and links
│   └── diagnostics/           #   Read-only inspection (list types, archives, links)
├── data/
│   ├── ghidra_archives/       # PSP data type archives (.gdt)
│   ├── ghidra/                # Local Ghidra project (gitignored)
│   ├── roms/                  # Downloaded BIOS ROMs (gitignored)
│   └── blobs/                 # Extracted PSP firmware blobs (gitignored)
├── src/psp_etl/
│   ├── cli.py
│   ├── db.py                  # SQLite schema and Database class
│   ├── ingest.py              # PSPTool ROM parsing
│   ├── strings.py             # String extraction and scoring
│   └── scrape/
│       ├── base.py            # VendorScraper ABC
│       ├── extract.py         # ZIP extraction, CAP header stripping
│       ├── asrock.py
│       └── gigabyte.py
└── tests/
```

## Dependencies

| Package | Purpose |
|---------|---------|
| [psptool](https://github.com/PSPReverse/PSPTool) | PSP firmware parsing |
| httpx | Async HTTP for scraping |
| beautifulsoup4 | HTML parsing |
| click | CLI framework |
| rich | Terminal output formatting |
