# psp-etl

> [!WARNING]
> **No human has reviewed this implementation end-to-end.**
> Like all GPL-3.0 software, `psp-etl` ships with no warranty and no fitness
> for any particular purpose (see [`LICENSE`](LICENSE)). On top of that
> baseline, you should treat this repo as *less* trustworthy than most:
> the code was written by an AI agent under loose human supervision and
> has not been audited line-by-line. The outputs look reasonable on the
> test corpus, but assume any claim from this tool needs independent
> verification before you build on it. Bug reports — including
> "this whole module is wrong" — are welcome.

AMD PSP firmware extraction, transformation, and loading pipeline. Scrapes motherboard vendor websites for BIOS update packages, extracts PSP firmware entries using [PSPTool](https://github.com/PSPReverse/PSPTool), analyzes debug string richness across vendor builds, and identifies which vendor build contains the most debug symbols for each firmware version.

The repository also ships a library of Ghidra scripts (`ghidra_scripts/`) for analysing the extracted blobs — see [`ghidra_scripts/README.md`](ghidra_scripts/README.md). The two halves share a corpus but are otherwise independent.

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

### Commands

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
    --board-class Ryzen|EPYC|Threadripper|ThreadripperPro|Embedded
    --type <hex_type_id>
    --vendor <name>
    --min-score <float>
    --has-strings
    --string <pattern>
    --format table|json|csv

psp-etl best                     # Show best (highest-scoring) images
    --gen zen1|zen2|zen3|zen4|zen5
    --board-class Ryzen|EPYC|Threadripper|ThreadripperPro|Embedded
    --type <hex_type_id>
    --folder
    --export-dir <path>
    --format table|json

psp-etl stats                    # Per-generation summary dashboard
    --gen zen1|zen2|zen3|zen4|zen5
```

## Supported vendors

| Vendor | Socket | Status |
|--------|--------|--------|
| ASRock | AM4, AM5 | Implemented (Wayback CDX → CDN) |
| ASUS | AM4, AM5 | Implemented (odinapi + support webapi) |
| Gigabyte | AM4, AM5 | Implemented (HTML scrape — Akamai-protected, requires residential IP) |
| MSI | AM4, AM5 | Implemented (Wayback CDX + range-request board ID) |

Note: Gigabyte's main site is behind Akamai Bot Manager. The scraper sends a Chrome-like User-Agent and works from residential or office IPs; from datacenter IPs it will see HTTP 403. The CDN itself is unrestricted once download URLs are known.

## Known limitations

- **No EPYC (server) coverage yet.** All scrapers target consumer Ryzen
  motherboards on AM4 and AM5. EPYC server platforms (SP3 for Naples/
  Rome/Milan, SP5 for Genoa/Bergamo/Turin, etc.) ship via system OEMs
  (Supermicro, Dell, HPE, Lenovo) and AMD reference releases, none of
  which are scraped today. Manual ingest still works (`psp-etl ingest
  <rom>`), but `scrape` will never find an EPYC ROM. The pipeline,
  schema, and analysis layer are platform-agnostic — only the scrapers
  are consumer-only.
- **Some Zen 4/5 ROMs trigger PSPTool warnings** (FET/ROM-size mismatch).
  Output is still produced; tracked in issue #58.
- **`data/` directories grow large.** A full multi-vendor scrape is on
  the order of 20–40 GB of ROMs and extracted blobs. Plan storage
  accordingly; nothing under `data/` is committed to git.
- **No schema migrations.** `data/psp-etl.db` is treated as fully
  rebuildable from `data/roms/{sha256}.rom`. When the schema changes
  (e.g. adding `images.board_class` in issue #77), delete the DB and
  re-run `psp-etl ingest && psp-etl analyze && psp-etl select`. ROMs
  do not need to be re-fetched — they are content-addressed on disk.

## Project structure

```
psp-etl/
├── AGENTS.md                  # Project conventions (style, layout, build)
├── LICENSE                    # GPL-3.0-only
├── default.nix
├── pyproject.toml
├── .design/                   # Architecture decision records
├── ghidra_scripts/            # Ghidra headless/GUI scripts (see ghidra_scripts/README.md)
│   ├── analysis/              #   Function renaming, MMIO annotation, string xref recovery
│   ├── transfer/              #   Cross-program label transfer (fuzzy matching)
│   ├── import_export/         #   GZF pack/unpack, type import, memory map export
│   ├── setup/                 #   Memory maps, PSP types, entry point config
│   ├── project/               #   Rename, reorganize, fix archives and links
│   └── diagnostics/           #   Read-only inspection (list types, archives, links)
├── data/                      # Runtime data, gitignored — never committed
│   ├── psp-etl.db             #   SQLite database
│   ├── roms/                  #   Downloaded BIOS ROMs ({sha256}.rom)
│   ├── blobs/                 #   Extracted PSP firmware blobs ({sha256}.bin)
│   ├── ghidra/                #   Local Ghidra project
│   └── ghidra_archives/       #   PSP data type archives (.gdt)
├── src/psp_etl/
│   ├── cli.py
│   ├── db.py                  # SQLite schema and Database class
│   ├── ingest.py              # PSPTool ROM parsing
│   ├── strings.py             # String extraction and scoring
│   └── scrape/
│       ├── base.py            # VendorScraper ABC
│       ├── extract.py         # ZIP extraction, CAP header stripping
│       ├── asrock.py
│       ├── asus.py
│       ├── gigabyte.py
│       └── msi.py
└── tests/
```

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).

## Dependencies

| Package | Purpose |
|---------|---------|
| [psptool](https://github.com/PSPReverse/PSPTool) | PSP firmware parsing |
| httpx | Async HTTP for scraping |
| beautifulsoup4 | HTML parsing |
| click | CLI framework |
| rich | Terminal output formatting |
