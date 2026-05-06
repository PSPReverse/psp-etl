# Feature: Schema — separate Zen generation from board class

## Summary

Split today's conflated `zen_generation` axis into two orthogonal columns.
Keep `entries.zen_generation` (zen1..zen5) for the Zen microarchitecture,
and add `images.board_class` for the board family
(`Ryzen` / `EPYC` / `Threadripper` / `ThreadripperPro` / `Embedded`).
`board_class` is derived from `images.socket` at ingest time and joins the
uniqueness key for `primary_images`, so a zen2 EPYC ABL5 is no longer
conflated with a zen2 Ryzen ABL5. Tracks crosslink issue #77.

## Requirements

- REQ-1: Add nullable `images.board_class TEXT` column to the schema in
  `src/psp_etl/db.py` and to the `Image` dataclass. Allowed values:
  `Ryzen`, `EPYC`, `Threadripper`, `ThreadripperPro`, `Embedded`, or NULL
  when socket is unknown. NULL semantics mirror today's `socket=NULL`
  behaviour — both columns are unknown together.
- REQ-2: Add `classify_board_class(socket: str | None) -> str | None` in
  `src/psp_etl/ingest.py`, mirroring the shape of `classify_by_agesa`
  (ingest.py:95). Mapping:
  `AM4`/`AM5` → `Ryzen`,
  `SP3`/`SP5`/`SP6` → `EPYC`,
  `sTRX4`/`sTR5` → `Threadripper`,
  `sWRX8` → `ThreadripperPro`,
  any other value or `None` → `None`.
  `Embedded` is reserved in the allowed-value set but no socket maps to it
  yet.
- REQ-3: Call `classify_board_class` from the scrape pipeline
  (cli.py:617, where `Image(...)` is constructed) so every ingested image
  has `board_class` populated alongside `socket`. Scrapers themselves stay
  oblivious — they keep emitting `BoardInfo.socket` only.
- REQ-4: Extend `primary_images` to `UNIQUE(zen_generation, board_class,
  type_id)`. Add `board_class TEXT` column to the table and to the
  `PrimaryImage` dataclass. Update `upsert_primary_image` (db.py:378)
  ON CONFLICT clause and INSERT bindings.
- REQ-5: Update partition / group / order keys in db.py to include
  board_class:
  - `get_best_entries` (db.py:491): GROUP BY adds `pi.board_class`,
    accepts `board_class` filter.
  - `get_best_folders` (db.py:523): `RANK() OVER (PARTITION BY ...)`
    adds `i.board_class`; SELECT and GROUP BY add it; accepts filter.
  - `get_selection_candidates` (db.py:604): SELECT projects
    `i.board_class`; ORDER BY adds `board_class`.
  - `query_entries` (db.py:424): new `board_class: str | None = None`
    filter.
- REQ-6: The `select` CLI command's `_group_key` (cli.py:658) becomes
  `(row["zen_generation"], row["board_class"], row["type_id"])`. The
  resulting `PrimaryImage` carries `board_class`. Cross-vendor md5
  diff detection groups by the same triple.
- REQ-7: Add `--board-class` option to the `query`, `best`, and `stats`
  CLI commands matching `--gen` ergonomics. `click.Choice` values are the
  five canonical strings; input is case-insensitive and normalised before
  reaching SQL.
- REQ-8: Update export filename pattern in `best --folder --export-dir`
  (cli.py:440) from `{zen_generation}_{type_name}.bin` to
  `{board_class}_{zen_generation}_{type_name}.bin`. Use a sentinel like
  `unknown` when board_class is NULL so filenames never start with `_`.
- REQ-9: Add `board_class` to JSON output for `query`, `best`, and
  `best --folder` so machine consumers see the new dimension.
- REQ-10: No migration code. The schema change requires nuking
  `data/psp-etl.db` and re-running `psp-etl ingest`. ROMs persist under
  `data/roms/{sha256}.rom` (content-addressed) so re-fetch is not
  needed; only the SQLite extraction layer rebuilds. Document this in
  README.md and CLAUDE.md.

## Acceptance Criteria

- [ ] AC-1: `pytest` passes. New `tests/test_board_class.py` covers the
  socket → board_class mapping for each known socket
  (AM4/AM5/SP3/SP5/SP6/sTRX4/sTR5/sWRX8), unknown socket strings, and
  `None`. (REQ-2)
- [ ] AC-2: Existing tests in `tests/test_db.py` (PrimaryImage upsert at
  line 317, dual-vendor scenarios at line 558) and
  `tests/test_cli_best.py` / `tests/test_cli_select.py` are updated to
  include `board_class` in their fixtures and pass. (REQ-4, REQ-5, REQ-6)
- [ ] AC-3: After ingesting a fresh corpus, every row in `images` where
  `socket IS NOT NULL` has a non-NULL `board_class`. SQL check:
  `SELECT COUNT(*) FROM images WHERE socket IS NOT NULL AND board_class
  IS NULL` returns 0. (REQ-3)
- [ ] AC-4: Synthetic test inserts two images with overlapping zen4
  entries — one with socket=AM5 (→ Ryzen) and one with socket=SP5
  (→ EPYC) — runs `psp-etl select`, then asserts `SELECT COUNT(*) FROM
  primary_images WHERE zen_generation='zen4'` is 2 (not 1). (REQ-4, REQ-6)
- [ ] AC-5: `psp-etl query --board-class EPYC --gen zen4` returns only
  rows whose `images.board_class = 'EPYC'`. `psp-etl query --board-class
  Ryzen` excludes them. Case-insensitive input (`epyc`, `EPYC`, `Epyc`)
  all behave identically. (REQ-7)
- [ ] AC-6: `psp-etl best --folder --format json` output includes a
  `board_class` field on every record. `psp-etl best --format json`
  likewise. (REQ-9)
- [ ] AC-7: `psp-etl stats` output groups entries by `(zen_generation,
  board_class)` — either as a new column on the existing per-generation
  table, or as a second table. (REQ-7)
- [ ] AC-8: Two synthetic primary_images covering the same
  `(zen_generation, type_id)` but different board_class produce two
  distinct export files (e.g. `Ryzen_zen4_ABL5.bin` and
  `EPYC_zen4_ABL5.bin`) with no collision. (REQ-8)
- [ ] AC-9: README.md and CLAUDE.md mention `board_class` and the
  no-migration policy ("schema changes require deleting
  `data/psp-etl.db` and re-ingesting"). (REQ-10)
- [ ] AC-10: `ruff check .` and `ruff format --check .` pass.

## Architecture

### Schema (`src/psp_etl/db.py`)

Add `board_class TEXT` to the `images` CREATE TABLE block (db.py:88-101)
and to the `Image` dataclass (db.py:14-26). Update `insert_image`
(db.py:220-251) to bind the new column.

For `primary_images` (db.py:145-154 and the `PrimaryImage` dataclass at
db.py:73-81), add `board_class TEXT` column and replace
`UNIQUE(zen_generation, type_id)` with `UNIQUE(zen_generation,
board_class, type_id)`. Update `upsert_primary_image` (db.py:378-407)
ON CONFLICT clause to match, and the INSERT column list to bind
board_class.

`entries.zen_generation` and `idx_entries_unique` (db.py:167-173) stay
exactly as they are. Board class lives on the image, not the entry — the
join already exposes it to entry-level queries.

### Derivation (`src/psp_etl/ingest.py`)

New helper, sibling to `classify_by_agesa`:

```python
_SOCKET_TO_BOARD_CLASS: dict[str, str] = {
    "AM4": "Ryzen", "AM5": "Ryzen",
    "SP3": "EPYC", "SP5": "EPYC", "SP6": "EPYC",
    "sTRX4": "Threadripper", "sTR5": "Threadripper",
    "sWRX8": "ThreadripperPro",
}

def classify_board_class(socket: str | None) -> str | None:
    if socket is None:
        return None
    return _SOCKET_TO_BOARD_CLASS.get(socket)
```

Pure function, constant dict, no side effects. Mirrors the testing
shape of `classify_by_agesa`. `Embedded` is reserved in
documentation/CLI choices but absent from the mapping until an embedded
scraper exists.

### Call site (`src/psp_etl/cli.py`)

The `_scrape_async` body constructs `Image(...)` at cli.py:617 from a
`BoardInfo` plus scraped metadata. Wrap that construction:

```python
db.insert_image(Image(
    sha256=...,
    vendor=board.vendor,
    model=board.model,
    socket=board.socket,
    board_class=classify_board_class(board.socket),
    bios_version=...,
    ...
))
```

This is the only ingest entry point in the codebase — no other writer
exists for `images`. Centralising the mapping here keeps scrapers as
pure socket producers.

### Selection (`db.get_selection_candidates` at db.py:604)

Today the SELECT projects `e.zen_generation` and ORDER BY uses
`(zen_generation, type_id, version, score DESC)`. Change: the join to
`images` already exists for `vendor`; add `i.board_class` to the
projection. Extend ORDER BY to `(zen_generation, board_class, type_id,
version, score DESC NULLS LAST, e.id)`.

In `cli.py select` (cli.py:636-738), `_group_key` (cli.py:658) becomes
`(row["zen_generation"], row["board_class"], row["type_id"])`. Each
`PrimaryImage` carries `board_class` from `best_entry["board_class"]`.
Cross-vendor md5 diff detection (cli.py:688-707) keys the same triple
in its log message.

### Best entries / folders (db.py:491, db.py:523)

`get_best_entries` (db.py:491-521): GROUP BY changes from
`(pi.zen_generation, pi.type_id)` to
`(pi.zen_generation, pi.board_class, pi.type_id)`; HAVING and ORDER BY
follow. Accept `board_class: str | None = None` filter parameter.

`get_best_folders` (db.py:523-570): the window function `RANK() OVER
(PARTITION BY e.zen_generation ORDER BY SUM(...) DESC)` becomes
`PARTITION BY e.zen_generation, i.board_class`. SELECT and GROUP BY
add `i.board_class`; accept filter.

### Query (`db.query_entries` at db.py:424)

Add `board_class: str | None = None` parameter. The conditions block
gets:

```python
if board_class is not None:
    conditions.append("i.board_class = ?")
    params.append(board_class)
```

The SELECT already projects `i.socket`; add `i.board_class` next to it.

### Stats (db.py:632, db.py:650, cli.py:746)

`stats_entries_by_generation` (db.py:650-665) currently groups by
`zen_generation`. Either:
(a) replace with grouping by `(zen_generation, board_class)`, or
(b) add a new `stats_entries_by_generation_and_class` and render two
    tables.

Option (b) preserves backward compat for any external consumer of
`Database.stats()` (which is called from `psp-etl stats` only — no other
caller). Going with (b) is safer; revisit if it adds clutter.

`Database.stats()` (db.py:779-809) gains `by_board_class` and
`by_generation_class` keys; `stats` CLI (cli.py:753-789) renders an
extra table.

### CLI choices

A module-level constant in cli.py:

```python
_BOARD_CLASSES = ("Ryzen", "EPYC", "Threadripper", "ThreadripperPro", "Embedded")
```

Reused by every `click.option("--board-class", type=click.Choice(...,
case_sensitive=False))`. Click normalises case for `Choice` when
`case_sensitive=False`, so `--board-class epyc` and `--board-class EPYC`
both pass through as the canonical capitalised form.

### Scrapers

No changes. `BoardInfo.socket` (scrape/base.py:12) docstring stays
`'AM4' or 'AM5'` because that is what current scrapers emit. The
docstring will broaden when EPYC/TR scrapers land (issue L4).

### Migration

None. `data/psp-etl.db` is rebuildable from `data/roms/{sha256}.rom`
(content-addressed). The user's workflow on this change is:

```sh
rm data/psp-etl.db
psp-etl ingest
psp-etl analyze
psp-etl select
```

No `ALTER TABLE`, no `psp-etl migrate` command, no version stamp on the
schema. The `_init_schema` block remains pure `CREATE TABLE IF NOT
EXISTS`. Re-fetch (`psp-etl scrape`) is not required.

### Tests

New `tests/test_board_class.py` — pure unit tests for
`classify_board_class`. ~10 lines.

Updated tests:
- `tests/test_db.py` line 317 (PrimaryImage upsert): add `board_class`
  to fixture.
- `tests/test_db.py` line 558 (dual-image scenario): include
  board_class.
- `tests/test_cli_best.py` line 83: same.
- `tests/test_cli_select.py` line 119 (`test_select_populates_primary_images`):
  assert primary_images now key on the triple.

New integration test: insert two images, one AM5 / one SP5, with
overlapping zen4 entries. Run `select`. Confirm two distinct
primary_images rows. (Backs AC-4.)

## Open Questions

(none — all five Phase-1 questions resolved with the user)

## Out of Scope

- EPYC scraper implementation (tracked separately as L4).
- Threadripper / Threadripper Pro / Embedded scraper implementations.
- Adding new socket choices to `psp-etl scrape --socket` (cli.py:537);
  the `--socket` choice list stays AM4/AM5 until scrapers exist for the
  new platforms.
- Per-blob string tracking (#69). That issue benefits from this one
  landing first because superset analysis becomes meaningfully grouped
  only when board_class is queryable.
- Renaming `zen_generation` or splitting it further.
- A formal migration framework. The codebase intentionally treats
  `data/psp-etl.db` as rebuildable from `data/roms/`.
- Backfilling `agesa_version`-derived board_class. AGESA strings encode
  CPU family but not always the board package; the socket column is the
  authoritative source and the only one used.
