# PSP-ETL: AMD PSP Firmware Extraction, Transformation & Loading Pipeline

## Goal

Build an automated pipeline that:
1. **Scrapes** motherboard vendor websites for AMD BIOS firmware update packages (ASUS, MSI, Gigabyte, ASRock — AM4 and AM5 platforms)
2. **Downloads** and **unwraps** vendor-specific packaging (CAP headers, ZIP archives, etc.)
3. **Extracts** PSP firmware entries using PSPTool's Python API
4. **Classifies** entries by processor generation (Zen 1–5) and platform
5. **Analyzes** debug string richness per firmware entry
6. **Selects** the "best" (most debug-string-rich) vendor build for each firmware version
7. Stores everything in a **searchable SQLite database** with all extracted blobs on disk

## Why This Matters

PSP firmware with debug strings dramatically accelerates reverse engineering — function names, error messages, boot postcodes, and format strings make the difference between months and weeks of RE work.

**Critical insight**: Motherboard vendors receive AMD's ComboPI/AGESA source and compile the PSP firmware themselves, patching in their board-specific quirks. This means **vendors sometimes leave debug mode enabled**, producing builds with far richer debug strings than the reference AMD build. The same firmware version from MSI may have debug strings that the ASRock build lacks. This pipeline finds those golden images.

## Directory Layout

All data lives inside the project directory:

```
AMD-PSP/
├── PSP-ETL.md              # This document
├── psp-etl/                 # Python package source
│   ├── pyproject.toml
│   ├── src/
│   │   └── psp_etl/
│   │       ├── __init__.py
│   │       ├── cli.py       # CLI entry point (typer)
│   │       ├── db.py        # SQLite schema + queries
│   │       ├── ingest.py    # ROM parsing + PSPTool extraction
│   │       ├── strings.py   # String extraction, classification, scoring
│   │       ├── scrape/      # Per-vendor scrapers
│   │       │   ├── __init__.py
│   │       │   ├── base.py  # Abstract scraper interface
│   │       │   ├── asus.py
│   │       │   ├── msi.py
│   │       │   ├── gigabyte.py
│   │       │   ├── asrock.py
│   │       │   └── extract.py  # Vendor wrapper extraction (CAP, etc.)
│   │       └── export.py    # Export for emulator/fuzzer/Ghidra
│   └── tests/
├── data/                    # Runtime data (gitignored)
│   ├── psp-etl.db           # SQLite database
│   ├── roms/                # Downloaded BIOS ROMs (content-addressed: sha256.rom)
│   └── blobs/               # Extracted PSP firmware blobs (sha256.bin)
└── research/                # Research notes (checked in)
    ├── psptool-internals.md
    ├── firmware-sourcing.md
    ├── debug-strings-research.md
    └── ghidra-research.md
```

## Architecture

```
┌─────────────┐    ┌───────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐
│   Scrapers   │───▶│ Downloader│───▶│ Extractor │───▶│ Analyzer │───▶│ Database │
│  (per-vendor)│    │  + Unwrap │    │ (PSPTool) │    │ (strings)│    │ (SQLite) │
└─────────────┘    └───────────┘    └───────────┘    └──────────┘    └──────────┘
      │                  │                │                │               │
      │            data/roms/       data/blobs/      string_analysis   psp-etl.db
      │           sha256.rom        sha256.bin          table
      └── Vendor support pages (ASUS, MSI, Gigabyte, ASRock)
```

### Phase 1: Scraping & Downloading

**Input**: Vendor support pages for AM4 and AM5 motherboards
**Output**: Raw BIOS ROM images in `data/roms/`, provenance metadata in DB

#### Vendor Scrapers

All four major AM4/AM5 vendors, scraped broadly:

| Vendor | CDN/Source | Package Format | Unwrap Method |
|--------|-----------|----------------|---------------|
| ASUS | `dlcdnets.asus.com` | ZIP → .CAP | Strip 0x800-byte ASUS capsule header |
| MSI | `download.msi.com` | ZIP → .ROM/.BIN | Direct (raw ROM inside ZIP) |
| Gigabyte | `download.gigabyte.com` | ZIP → raw ROM | Direct |
| ASRock | `download.asrock.com` | ZIP → raw ROM/BIN | Direct |

Each scraper must:
1. Enumerate all AM4 and AM5 motherboard models from the vendor's product pages
2. For each model, find all available BIOS update download links
3. Download the archive, extract the ROM image
4. Unwrap vendor-specific packaging (ASUS CAP header, etc.)
5. Compute SHA-256, store ROM in `data/roms/{sha256}.rom`
6. Record provenance in `images` table (vendor, model, BIOS version, URL)
7. Skip already-downloaded ROMs (dedup by sha256)

#### Scraper Interface

```python
class VendorScraper(ABC):
    """Abstract base for vendor-specific BIOS scrapers."""

    @abstractmethod
    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate all AM4/AM5 motherboard models."""
        ...

    @abstractmethod
    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """List all available BIOS updates for a board."""
        ...

    @abstractmethod
    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download and unwrap a BIOS update, return path to raw ROM."""
        ...

@dataclass
class BoardInfo:
    vendor: str
    model: str
    socket: str        # 'AM4' or 'AM5'
    url: str           # vendor support page URL

@dataclass
class BiosUpdate:
    board: BoardInfo
    bios_version: str
    download_url: str
    release_date: str | None
    agesa_version: str | None  # if listed in release notes
```

### Phase 2: PSP Extraction & Classification

**Input**: Raw BIOS ROM images in `data/roms/`
**Output**: Extracted blobs in `data/blobs/`, entry metadata in `entries` table

#### PSPTool Integration

```python
from psptool import PSPTool

def ingest_rom(rom_path: Path, image_id: int, db: Database) -> None:
    psp = PSPTool.from_file(str(rom_path))
    for rom_idx, rom in enumerate(psp.blob.roms):
        for dir_idx, directory in enumerate(rom.directories):
            for f in directory.files:
                # Extract body bytes
                try:
                    if hasattr(f, 'get_decrypted_decompressed_body'):
                        body = f.get_decrypted_decompressed_body()
                    else:
                        body = f.get_bytes()
                except Exception:
                    body = f.get_bytes()

                # Content-address the blob
                blob_hash = hashlib.sha256(body).hexdigest()
                blob_path = data_dir / "blobs" / f"{blob_hash}.bin"
                if not blob_path.exists():
                    blob_path.write_bytes(body)

                entry = Entry(
                    image_id=image_id,
                    rom_index=rom_idx,
                    directory_index=dir_idx,
                    directory_magic=directory.magic.decode(errors='replace'),
                    zen_generation=directory.zen_generation or classify_by_agesa(rom.agesa_version),
                    type_id=f.type,
                    type_name=f.get_readable_type(),
                    subprogram=getattr(f, 'subprogram', 0),
                    instance=getattr(f, 'instance', 0),
                    version=f.get_readable_version(),
                    firmware_md5=f.md5(),
                    blob_sha256=blob_hash,
                    body_size=len(body),
                    encrypted=getattr(f, 'encrypted', False),
                    compressed=getattr(f, 'compressed', False),
                    signed=getattr(f, 'is_signed', False),
                    load_address=getattr(f, 'load_address', None),
                )
                db.insert_entry(entry)
```

#### Error Handling

PSPTool has known parsing issues with Zen 5 and some Zen 4 images. The pipeline must:
- Catch and log all PSPTool exceptions per-ROM (don't abort the entire batch)
- Record failed ROMs in a `parse_errors` table with the exception message
- Compute Shannon entropy for blobs that PSPTool flags as unencrypted but produce no strings (may be mis-detected encrypted blobs)

### Phase 3: String Analysis & Scoring

**Input**: Extracted blobs in `data/blobs/`
**Output**: String analysis results in `string_analysis` table, individual strings in `strings` table

#### String Extraction & Classification

```python
import re

MIN_STRING_LENGTH = 6
# Match printable ASCII runs
STRING_PATTERN = re.compile(rb'[\x20-\x7e]{%d,}' % MIN_STRING_LENGTH)

CATEGORIES = {
    'format_string':  re.compile(r'%[0-9]*[sdxXpuiolcfFeEgG]'),      # weight 3
    'function_name':  re.compile(r'\w{3,}\(\)|AMD_\w+:'),             # weight 2
    'error_message':  re.compile(r'(?:ERROR|FAIL|INVALID|ERR_)', re.I), # weight 2
    'postcode':       re.compile(r'(?:PSPSTATUS|ABLSTATUS)_\w+'),     # weight 1
}
WEIGHTS = {'format_string': 3, 'function_name': 2, 'error_message': 2, 'postcode': 1, 'descriptive': 0.5, 'other': 0.1}

def classify_string(s: str) -> str:
    for category, pattern in CATEGORIES.items():
        if pattern.search(s):
            return category
    if len(s) > 20:
        return 'descriptive'
    return 'other'

def analyze_blob(blob_path: Path) -> StringAnalysis:
    data = blob_path.read_bytes()
    raw_strings = [m.group().decode('ascii') for m in STRING_PATTERN.finditer(data)]
    unique = list(set(raw_strings))

    counts = Counter(classify_string(s) for s in unique)
    score = sum(counts.get(cat, 0) * w for cat, w in WEIGHTS.items())

    return StringAnalysis(
        total_strings=len(raw_strings),
        unique_strings=len(unique),
        format_strings=counts.get('format_string', 0),
        function_names=counts.get('function_name', 0),
        error_messages=counts.get('error_message', 0),
        postcode_strings=counts.get('postcode', 0),
        descriptive_strings=counts.get('descriptive', 0),
        score=score,
        strings=unique,  # stored in strings table
    )
```

#### Primary Image Selection

For each unique `(zen_generation, type_id, version)` triple:
1. Group all entries by `firmware_md5` — same md5 = identical AMD build, no string difference possible
2. For entries with different md5 but same version: these are different vendor compilations — compare scores
3. Select the entry with the highest score as "primary"
4. Log when different vendors produce different md5s for the same (type, version) — these are the interesting cases where vendor compilation differences matter

### Phase 4: Database Schema

```sql
CREATE TABLE images (
    id INTEGER PRIMARY KEY,
    sha256 TEXT UNIQUE NOT NULL,
    vendor TEXT NOT NULL,
    model TEXT,
    socket TEXT,                     -- 'AM4', 'AM5'
    bios_version TEXT,
    agesa_version TEXT,
    download_url TEXT,
    file_size INTEGER,
    download_date TEXT,
    rom_count INTEGER DEFAULT 1
);

CREATE TABLE entries (
    id INTEGER PRIMARY KEY,
    image_id INTEGER REFERENCES images(id),
    rom_index INTEGER DEFAULT 0,
    directory_index INTEGER,
    directory_magic TEXT,
    zen_generation TEXT,
    type_id INTEGER NOT NULL,
    type_name TEXT,
    subprogram INTEGER DEFAULT 0,
    instance INTEGER DEFAULT 0,
    version TEXT,
    firmware_md5 TEXT,              -- md5 of entry as PSPTool sees it
    blob_sha256 TEXT,               -- sha256 of extracted body (references data/blobs/)
    body_size INTEGER,
    encrypted BOOLEAN DEFAULT FALSE,
    compressed BOOLEAN DEFAULT FALSE,
    signed BOOLEAN DEFAULT FALSE,
    load_address INTEGER,
    UNIQUE(image_id, rom_index, directory_index, type_id, subprogram, instance)
);

CREATE TABLE string_analysis (
    id INTEGER PRIMARY KEY,
    entry_id INTEGER REFERENCES entries(id) UNIQUE,
    total_strings INTEGER,
    unique_strings INTEGER,
    format_strings INTEGER,
    function_names INTEGER,
    error_messages INTEGER,
    postcode_strings INTEGER,
    descriptive_strings INTEGER,
    score REAL
);

-- Individual strings for searchability
CREATE TABLE strings (
    id INTEGER PRIMARY KEY,
    blob_sha256 TEXT NOT NULL,       -- references data/blobs/
    string TEXT NOT NULL,
    category TEXT,                   -- 'format_string', 'function_name', etc.
    UNIQUE(blob_sha256, string)
);

CREATE TABLE primary_images (
    id INTEGER PRIMARY KEY,
    zen_generation TEXT NOT NULL,
    type_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    best_entry_id INTEGER REFERENCES entries(id),
    best_image_id INTEGER REFERENCES images(id),
    score REAL,
    UNIQUE(zen_generation, type_id, version)
);

CREATE TABLE parse_errors (
    id INTEGER PRIMARY KEY,
    image_id INTEGER REFERENCES images(id),
    error_message TEXT,
    traceback TEXT,
    timestamp TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_entries_gen ON entries(zen_generation);
CREATE INDEX idx_entries_type ON entries(type_id);
CREATE INDEX idx_entries_md5 ON entries(firmware_md5);
CREATE INDEX idx_entries_blob ON entries(blob_sha256);
CREATE INDEX idx_entries_version ON entries(version);
CREATE INDEX idx_analysis_score ON string_analysis(score DESC);
CREATE INDEX idx_strings_blob ON strings(blob_sha256);
CREATE INDEX idx_strings_text ON strings(string);
CREATE INDEX idx_strings_category ON strings(category);
```

## CLI Interface

```
psp-etl scrape <vendor|all>           # Scrape and download BIOS updates
    --socket am4|am5|all              # Filter by socket (default: all)
    --limit N                         # Max boards to scrape per vendor
    --dry-run                         # List URLs without downloading

psp-etl ingest <rom_path|directory>   # Parse ROM(s) and extract PSP entries
    --vendor <name>                   # Override vendor metadata
    --model <name>                    # Override model metadata

psp-etl analyze                       # Run string analysis on all unanalyzed blobs
    --reanalyze                       # Re-analyze already-analyzed blobs

psp-etl select                        # Recompute primary image selections

psp-etl query                         # Query the database
    --gen zen1|zen2|zen3|zen4|zen5
    --type <hex_type_id>
    --vendor <name>
    --min-score <float>
    --has-strings                     # Only entries with score > 0
    --format table|json|csv

psp-etl best                          # Show best available images
    --gen zen1|zen2|zen3|zen4|zen5
    --type <hex_type_id>
    --export-dir <path>               # Copy best blobs to directory

psp-etl stats                         # Summary dashboard
    --gen zen1|zen2|zen3|zen4|zen5

psp-etl export                        # Export for downstream tools
    --format ghidra|emulator|fuzzer
    --gen <generation>
    --output-dir <path>
```

## Implementation Plan

### Milestone 1: Core Pipeline

**Goal**: Given a ROM file on disk, extract all PSP entries, analyze strings, store in DB.

Steps:
1. Set up Python project: `pyproject.toml`, `src/psp_etl/`, dependencies
2. Implement `db.py`: SQLite schema creation, insert/query methods
3. Implement `ingest.py`: PSPTool-based ROM parsing → entries + blobs
4. Implement `strings.py`: string extraction, classification, scoring
5. Implement `cli.py`: `ingest`, `analyze`, `query`, `best`, `stats` commands
6. Test manually with a few downloaded ROMs

**Acceptance criteria**:
- `psp-etl ingest <rom>` populates `images`, `entries` tables, writes blobs to `data/blobs/`
- `psp-etl analyze` populates `string_analysis` and `strings` tables
- `psp-etl query --gen zen2 --has-strings` returns entries with debug strings
- `psp-etl best --gen zen2` shows the highest-scoring image per firmware version
- PSPTool parse errors are caught and logged, not fatal

### Milestone 2: Vendor Scrapers

**Goal**: Automatically discover and download BIOS updates from all four vendors.

Steps:
1. Implement `scrape/base.py`: abstract scraper interface
2. Implement ASRock scraper (easiest — predictable CDN URLs)
3. Implement Gigabyte scraper
4. Implement ASUS scraper (needs CAP header stripping)
5. Implement MSI scraper (hardest — session-based downloads)
6. Implement `scrape/extract.py`: vendor wrapper unwrapping
7. Wire up `psp-etl scrape` CLI command
8. Add rate limiting, retry logic, progress reporting

**Acceptance criteria**:
- `psp-etl scrape asrock --socket am4 --limit 5` downloads BIOS updates for 5 ASRock AM4 boards
- Deduplication works: re-running doesn't re-download
- Wrapper extraction produces valid ROMs that PSPTool can parse

### Milestone 3: Analysis & Reporting

**Goal**: Cross-vendor comparison, primary image selection, reporting.

Steps:
1. Implement primary image selection (`select` command)
2. Implement `stats` command: per-generation dashboard
3. Implement string search: `psp-etl query --string "spiRead"`
4. Implement cross-vendor diff: same firmware version, different md5 → compare string sets
5. Track vendor-specific compilation differences

**Acceptance criteria**:
- `psp-etl stats` shows: images per vendor, entries per generation, encryption rates, string score distributions
- Can identify cases where vendor X has debug strings for a firmware version that vendor Y doesn't

### Milestone 4: Integration Exports

**Goal**: Export data for downstream tools (emulator, fuzzer, Ghidra).

Steps:
1. Ghidra export: list of blobs with load addresses and `ARM:LE:32:v7` config
2. Emulator export: directory layout matching PSPEmu expectations
3. Fuzzer export: ASPFuzz YAML config generation per firmware image

## Technical Decisions

- **Language**: Python (matches PSPTool, enables direct API use)
- **CLI**: typer (auto-generated help, type hints)
- **HTTP**: httpx (async, connection pooling)
- **HTML parsing**: beautifulsoup4
- **Database**: SQLite (zero-config, portable)
- **Blob storage**: content-addressed filesystem (`data/blobs/{sha256}.bin`)
- **ROM storage**: content-addressed filesystem (`data/roms/{sha256}.rom`)
- **No firmware redistribution**: only metadata/hashes in version control; raw data in gitignored `data/`

## Open Questions

1. **PSPTool failures on Zen 4/5**: Skip and log, contribute fixes upstream, or fork? Start with skip-and-log, contribute fixes if patterns emerge.

2. **Entropy fallback**: For blobs flagged unencrypted but with no strings, compute Shannon entropy. Entropy ~8.0 = encrypted, ~6-7 = compressed, ~4-5 = plaintext. Useful for catching PSPTool's mis-classifications.

3. **Cross-vendor firmware identity**: Same `firmware_md5` across vendors = identical AMD base build. Different `firmware_md5` with same `(type_id, version)` = vendor-specific compilation. The latter is where debug string differences hide. The `blob_sha256` field tracks the actual extracted body for comparison.

4. **MSI scraper difficulty**: MSI uses session-based download links. May need browser automation (playwright) or API reverse-engineering. Defer if too complex, prioritize the other three vendors first.

## Dependencies

| Package | Purpose |
|---------|---------|
| psptool | PSP firmware parsing and extraction |
| httpx | Async HTTP client for scraping/downloading |
| beautifulsoup4 | HTML parsing for vendor page scraping |
| typer | CLI framework with auto-generated help |
| rich | Terminal output formatting (tables, progress bars) |

## References

- [PSPReverse/PSPTool](https://github.com/PSPReverse/PSPTool) — core extraction library
- [amd/firmware_binaries](https://github.com/amd/firmware_binaries) — official AMD blobs (useful for cross-referencing)
- [platomav/BIOSUtilities](https://github.com/platomav/BIOSUtilities) — vendor wrapper extraction
- [eigenform/amdpsp-re](https://github.com/eigenform/amdpsp-re) — Family 17h RE notes
- [dayzerosec blog](https://dayzerosec.com/blog/2023/04/17/reversing-the-amd-secure-processor-psp.html) — PSP RE methodology, string-based function identification
- [coreboot PSP integration docs](https://doc.coreboot.org/soc/amd/psp_integration.html) — directory structure reference
- See also: `research/psptool-internals.md`, `research/firmware-sourcing.md`, `research/debug-strings-research.md`
