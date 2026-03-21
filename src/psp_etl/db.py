"""SQLite schema and query layer for psp-etl."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Image:
    sha256: str
    vendor: str
    model: str | None = None
    socket: str | None = None
    bios_version: str | None = None
    agesa_version: str | None = None
    download_url: str | None = None
    file_size: int | None = None
    download_date: str | None = None
    rom_count: int = 1
    id: int | None = None


@dataclass
class Entry:
    image_id: int
    type_id: int
    rom_index: int = 0
    directory_index: int | None = None
    directory_magic: str | None = None
    zen_generation: str | None = None
    type_name: str | None = None
    subprogram: int = 0
    instance: int = 0
    version: str | None = None
    firmware_md5: str | None = None
    blob_sha256: str | None = None
    body_size: int | None = None
    encrypted: bool = False
    compressed: bool = False
    signed: bool = False
    load_address: int | None = None
    id: int | None = None


@dataclass
class StringAnalysis:
    entry_id: int
    total_strings: int
    unique_strings: int
    format_strings: int
    function_names: int
    error_messages: int
    postcode_strings: int
    descriptive_strings: int
    score: float
    id: int | None = None


@dataclass
class ParseError:
    image_id: int
    error_message: str | None = None
    traceback: str | None = None
    id: int | None = None


@dataclass
class PrimaryImage:
    zen_generation: str
    type_id: int
    version: str
    best_entry_id: int | None = None
    best_image_id: int | None = None
    score: float | None = None
    id: int | None = None


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

# Migration: replaces the inline UNIQUE constraint on entries with an
# expression-based index that uses COALESCE so that NULL zen_generation values
# are treated as equal (SQLite normally considers NULL != NULL in UNIQUE
# constraints, which would allow duplicate "unknown-generation" entries).
_MIGRATE_ENTRIES_UNIQUE = """
BEGIN;
CREATE TABLE entries_new (
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
    firmware_md5 TEXT,
    blob_sha256 TEXT,
    body_size INTEGER,
    encrypted BOOLEAN DEFAULT FALSE,
    compressed BOOLEAN DEFAULT FALSE,
    signed BOOLEAN DEFAULT FALSE,
    load_address INTEGER
);
INSERT OR IGNORE INTO entries_new SELECT * FROM entries;
DROP TABLE entries;
ALTER TABLE entries_new RENAME TO entries;
COMMIT;
"""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS images (
    id INTEGER PRIMARY KEY,
    sha256 TEXT UNIQUE NOT NULL,
    vendor TEXT NOT NULL,
    model TEXT,
    socket TEXT,
    bios_version TEXT,
    agesa_version TEXT,
    download_url TEXT,
    file_size INTEGER,
    download_date TEXT,
    rom_count INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS entries (
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
    firmware_md5 TEXT,
    blob_sha256 TEXT,
    body_size INTEGER,
    encrypted BOOLEAN DEFAULT FALSE,
    compressed BOOLEAN DEFAULT FALSE,
    signed BOOLEAN DEFAULT FALSE,
    load_address INTEGER
);

CREATE TABLE IF NOT EXISTS string_analysis (
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

CREATE TABLE IF NOT EXISTS strings (
    id INTEGER PRIMARY KEY,
    blob_sha256 TEXT NOT NULL,
    string TEXT NOT NULL,
    category TEXT,
    UNIQUE(blob_sha256, string)
);

CREATE TABLE IF NOT EXISTS primary_images (
    id INTEGER PRIMARY KEY,
    zen_generation TEXT NOT NULL,
    type_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    best_entry_id INTEGER REFERENCES entries(id),
    best_image_id INTEGER REFERENCES images(id),
    score REAL,
    UNIQUE(zen_generation, type_id, version)
);

CREATE TABLE IF NOT EXISTS parse_errors (
    id INTEGER PRIMARY KEY,
    image_id INTEGER REFERENCES images(id),
    error_message TEXT,
    traceback TEXT,
    timestamp TEXT DEFAULT (datetime('now'))
);

-- Expression-based unique index for entries.  COALESCE normalises NULL values
-- so that two rows with zen_generation=NULL (or directory_index=NULL) are
-- treated as equal and trigger the ON CONFLICT / OR IGNORE path.
CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_unique
ON entries(
    image_id, rom_index,
    COALESCE(directory_index, -1),
    type_id, subprogram, instance,
    COALESCE(zen_generation, '')
);

CREATE INDEX IF NOT EXISTS idx_entries_gen ON entries(zen_generation);
CREATE INDEX IF NOT EXISTS idx_entries_type ON entries(type_id);
CREATE INDEX IF NOT EXISTS idx_entries_md5 ON entries(firmware_md5);
CREATE INDEX IF NOT EXISTS idx_entries_blob ON entries(blob_sha256);
CREATE INDEX IF NOT EXISTS idx_entries_version ON entries(version);
CREATE INDEX IF NOT EXISTS idx_analysis_score ON string_analysis(score DESC);
CREATE INDEX IF NOT EXISTS idx_strings_blob ON strings(blob_sha256);
CREATE INDEX IF NOT EXISTS idx_strings_text ON strings(string);
CREATE INDEX IF NOT EXISTS idx_strings_category ON strings(category);
"""


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------


class Database:
    """SQLite-backed store for psp-etl pipeline data."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _init_schema(self) -> None:
        self._maybe_migrate_entries_constraint()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _maybe_migrate_entries_constraint(self) -> None:
        """Migrate entries to drop the inline UNIQUE and switch to idx_entries_unique.

        Old databases had ``UNIQUE(image_id, rom_index, directory_index,
        type_id, subprogram, instance)`` inline in the CREATE TABLE.  This
        causes duplicate rows when zen_generation is NULL because SQLite treats
        each NULL as distinct.  The replacement is an expression-based unique
        index using COALESCE to normalise NULLs.
        """
        # If the expression-based index already exists, we're done.
        idx = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_entries_unique'"
        ).fetchone()
        if idx is not None:
            return
        # If entries table doesn't exist yet, _init_schema will create it fresh.
        table = self._conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='entries'").fetchone()
        if table is None:
            return
        # Old table exists without the expression index — recreate it.
        self._conn.executescript(_MIGRATE_ENTRIES_UNIQUE)

    # ------------------------------------------------------------------
    # Insert methods
    # ------------------------------------------------------------------

    def insert_image(self, image: Image) -> int:
        """Insert an image record, ignoring conflicts on sha256.

        Returns the id of the inserted or existing row.
        """
        cur = self._conn.execute(
            """
            INSERT INTO images
                (sha256, vendor, model, socket, bios_version, agesa_version,
                 download_url, file_size, download_date, rom_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO NOTHING
            """,
            (
                image.sha256,
                image.vendor,
                image.model,
                image.socket,
                image.bios_version,
                image.agesa_version,
                image.download_url,
                image.file_size,
                image.download_date,
                image.rom_count,
            ),
        )
        self._conn.commit()
        if cur.lastrowid:
            return cur.lastrowid
        # Row already existed — fetch its id
        row = self._conn.execute("SELECT id FROM images WHERE sha256 = ?", (image.sha256,)).fetchone()
        return row["id"]

    def insert_entry(self, entry: Entry) -> int:
        """Insert an entry record, ignoring conflicts on the unique key.

        Returns the id of the inserted or existing row.
        """
        cur = self._conn.execute(
            """
            INSERT OR IGNORE INTO entries
                (image_id, rom_index, directory_index, directory_magic,
                 zen_generation, type_id, type_name, subprogram, instance,
                 version, firmware_md5, blob_sha256, body_size,
                 encrypted, compressed, signed, load_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.image_id,
                entry.rom_index,
                entry.directory_index,
                entry.directory_magic,
                entry.zen_generation,
                entry.type_id,
                entry.type_name,
                entry.subprogram,
                entry.instance,
                entry.version,
                entry.firmware_md5,
                entry.blob_sha256,
                entry.body_size,
                entry.encrypted,
                entry.compressed,
                entry.signed,
                entry.load_address,
            ),
        )
        self._conn.commit()
        if cur.lastrowid:
            return cur.lastrowid
        row = self._conn.execute(
            """
            SELECT id FROM entries
            WHERE image_id = ? AND rom_index = ? AND directory_index IS ?
              AND type_id = ? AND subprogram = ? AND instance = ?
              AND zen_generation IS ?
            """,
            (
                entry.image_id,
                entry.rom_index,
                entry.directory_index,
                entry.type_id,
                entry.subprogram,
                entry.instance,
                entry.zen_generation,
            ),
        ).fetchone()
        return row["id"]

    def insert_string_analysis(self, analysis: StringAnalysis) -> int:
        """Insert or replace a string_analysis record.

        Returns the row id.
        """
        cur = self._conn.execute(
            """
            INSERT INTO string_analysis
                (entry_id, total_strings, unique_strings, format_strings,
                 function_names, error_messages, postcode_strings,
                 descriptive_strings, score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entry_id) DO UPDATE SET
                total_strings      = excluded.total_strings,
                unique_strings     = excluded.unique_strings,
                format_strings     = excluded.format_strings,
                function_names     = excluded.function_names,
                error_messages     = excluded.error_messages,
                postcode_strings   = excluded.postcode_strings,
                descriptive_strings= excluded.descriptive_strings,
                score              = excluded.score
            """,
            (
                analysis.entry_id,
                analysis.total_strings,
                analysis.unique_strings,
                analysis.format_strings,
                analysis.function_names,
                analysis.error_messages,
                analysis.postcode_strings,
                analysis.descriptive_strings,
                analysis.score,
            ),
        )
        self._conn.commit()
        return (
            cur.lastrowid
            or self._conn.execute("SELECT id FROM string_analysis WHERE entry_id = ?", (analysis.entry_id,)).fetchone()[
                "id"
            ]
        )

    def insert_strings(self, blob_sha256: str, strings: list[tuple[str, str]]) -> None:
        """Insert (string, category) pairs for a blob, ignoring duplicates.

        ``strings`` is a list of (text, category) tuples.
        """
        self._conn.executemany(
            """
            INSERT INTO strings (blob_sha256, string, category)
            VALUES (?, ?, ?)
            ON CONFLICT(blob_sha256, string) DO NOTHING
            """,
            [(blob_sha256, text, category) for text, category in strings],
        )
        self._conn.commit()

    def insert_parse_error(self, error: ParseError) -> int:
        """Insert a parse_error record. Returns the row id."""
        cur = self._conn.execute(
            """
            INSERT INTO parse_errors (image_id, error_message, traceback)
            VALUES (?, ?, ?)
            """,
            (error.image_id, error.error_message, error.traceback),
        )
        self._conn.commit()
        return cur.lastrowid

    def upsert_primary_image(self, primary: PrimaryImage) -> int:
        """Insert or update a primary_images record. Returns the row id."""
        cur = self._conn.execute(
            """
            INSERT INTO primary_images
                (zen_generation, type_id, version, best_entry_id, best_image_id, score)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(zen_generation, type_id, version) DO UPDATE SET
                best_entry_id = excluded.best_entry_id,
                best_image_id = excluded.best_image_id,
                score         = excluded.score
            """,
            (
                primary.zen_generation,
                primary.type_id,
                primary.version,
                primary.best_entry_id,
                primary.best_image_id,
                primary.score,
            ),
        )
        self._conn.commit()
        return (
            cur.lastrowid
            or self._conn.execute(
                """
            SELECT id FROM primary_images
            WHERE zen_generation = ? AND type_id = ? AND version = ?
            """,
                (primary.zen_generation, primary.type_id, primary.version),
            ).fetchone()["id"]
        )

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_image_by_sha256(self, sha256: str) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM images WHERE sha256 = ?", (sha256,)).fetchone()

    def get_entry_by_id(self, entry_id: int) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()

    def query_entries(
        self,
        *,
        zen_generation: str | None = None,
        type_id: int | None = None,
        vendor: str | None = None,
        min_score: float | None = None,
        has_strings: bool = False,
        string_pattern: str | None = None,
    ) -> list[sqlite3.Row]:
        """Return entries matching the given filters.

        Joins with images (for vendor filter) and string_analysis (for score
        filters).  Entries without a string_analysis row are included unless
        ``has_strings`` or ``min_score`` is set.

        When *string_pattern* is given, only entries whose blobs contain a
        matching string (SQL LIKE substring match) are returned.
        """
        conditions: list[str] = []
        params: list[object] = []

        if zen_generation is not None:
            conditions.append("e.zen_generation = ?")
            params.append(zen_generation)

        if type_id is not None:
            conditions.append("e.type_id = ?")
            params.append(type_id)

        if vendor is not None:
            conditions.append("i.vendor = ?")
            params.append(vendor)

        if has_strings or min_score is not None:
            conditions.append("sa.score > 0")

        if min_score is not None:
            conditions.append("sa.score >= ?")
            params.append(min_score)

        if string_pattern is not None:
            conditions.append(
                "EXISTS (SELECT 1 FROM strings s WHERE s.blob_sha256 = e.blob_sha256 AND s.string LIKE ?)"
            )
            params.append(f"%{string_pattern}%")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        join_type = "INNER" if (has_strings or min_score is not None) else "LEFT"

        sql = f"""
            SELECT e.*, i.vendor, i.model, i.socket, sa.score
            FROM entries e
            JOIN images i ON i.id = e.image_id
            {join_type} JOIN string_analysis sa ON sa.entry_id = e.id
            {where}
            ORDER BY sa.score DESC NULLS LAST, e.id
        """
        return self._conn.execute(sql, params).fetchall()

    def get_best_entries(
        self,
        zen_generation: str | None = None,
        type_id: int | None = None,
    ) -> list[sqlite3.Row]:
        """Return primary_images rows joined with entry and image details."""
        conditions: list[str] = []
        params: list[object] = []

        if zen_generation is not None:
            conditions.append("pi.zen_generation = ?")
            params.append(zen_generation)

        if type_id is not None:
            conditions.append("pi.type_id = ?")
            params.append(type_id)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sql = f"""
            SELECT pi.*, e.blob_sha256, e.type_name, e.version,
                   i.vendor, i.model, i.socket
            FROM primary_images pi
            LEFT JOIN entries e ON e.id = pi.best_entry_id
            LEFT JOIN images i ON i.id = pi.best_image_id
            {where}
            ORDER BY pi.zen_generation, pi.type_id, pi.score DESC NULLS LAST
        """
        return self._conn.execute(sql, params).fetchall()

    def get_unanalyzed_entries(self) -> list[sqlite3.Row]:
        """Return entries that have a blob but no string_analysis row yet."""
        return self._conn.execute(
            """
            SELECT e.*
            FROM entries e
            LEFT JOIN string_analysis sa ON sa.entry_id = e.id
            WHERE e.blob_sha256 IS NOT NULL
              AND sa.id IS NULL
            """
        ).fetchall()

    def get_selection_candidates(self) -> list[sqlite3.Row]:
        """Return entries suitable for primary image selection.

        Returns all entries with zen_generation and version set, joined with
        images (vendor) and string_analysis (score). Ordered for groupby:
        (zen_generation, type_id, version, score DESC).
        """
        return self._conn.execute(
            """
            SELECT e.id AS entry_id, e.image_id, e.zen_generation, e.type_id,
                   e.version, e.firmware_md5, e.type_name, e.blob_sha256,
                   i.vendor, i.model,
                   COALESCE(sa.score, 0.0) AS score
            FROM entries e
            JOIN images i ON i.id = e.image_id
            LEFT JOIN string_analysis sa ON sa.entry_id = e.id
            WHERE e.zen_generation IS NOT NULL
              AND e.version IS NOT NULL
            ORDER BY e.zen_generation, e.type_id, e.version,
                     sa.score DESC NULLS LAST, e.id
            """
        ).fetchall()

    def stats_images_by_vendor(self, gen: str | None = None) -> list[sqlite3.Row]:
        """Return image counts per vendor, optionally filtered by entries' generation."""
        if gen is not None:
            return self._conn.execute(
                """
                SELECT i.vendor, COUNT(DISTINCT i.id) AS cnt
                FROM images i
                JOIN entries e ON e.image_id = i.id
                WHERE e.zen_generation = ?
                GROUP BY i.vendor
                ORDER BY cnt DESC
                """,
                (gen,),
            ).fetchall()
        return self._conn.execute(
            "SELECT vendor, COUNT(*) AS cnt FROM images GROUP BY vendor ORDER BY cnt DESC"
        ).fetchall()

    def stats_entries_by_generation(self, gen: str | None = None) -> list[sqlite3.Row]:
        """Return per-generation entry and encryption counts."""
        where = "WHERE zen_generation = ?" if gen is not None else ""
        params = (gen,) if gen is not None else ()
        return self._conn.execute(
            f"""
            SELECT zen_generation,
                   COUNT(*) AS total,
                   SUM(CASE WHEN encrypted THEN 1 ELSE 0 END) AS encrypted_count
            FROM entries
            {where}
            GROUP BY zen_generation
            ORDER BY zen_generation
            """,
            params,
        ).fetchall()

    def stats_scores_by_generation(self, gen: str | None = None) -> dict[str, list[float]]:
        """Return all scores grouped by generation for distribution analysis."""
        where = "WHERE e.zen_generation = ?" if gen is not None else ""
        params = (gen,) if gen is not None else ()
        rows = self._conn.execute(
            f"""
            SELECT e.zen_generation, sa.score
            FROM entries e
            JOIN string_analysis sa ON sa.entry_id = e.id
            {where}
            ORDER BY e.zen_generation, sa.score
            """,
            params,
        ).fetchall()
        result: dict[str, list[float]] = {}
        for row in rows:
            key = row["zen_generation"] or "unknown"
            result.setdefault(key, []).append(row["score"])
        return result

    def stats_score_nonzero(self, gen: str | None = None) -> tuple[int, int]:
        """Return (with_strings, without_strings) counts across all entries."""
        where = "WHERE e.zen_generation = ?" if gen is not None else ""
        params = (gen,) if gen is not None else ()
        row = self._conn.execute(
            f"""
            SELECT
                COUNT(CASE WHEN sa.score > 0 THEN 1 END) AS with_strings,
                SUM(CASE WHEN sa.score IS NULL OR sa.score = 0 THEN 1 ELSE 0 END) AS without_strings
            FROM entries e
            LEFT JOIN string_analysis sa ON sa.entry_id = e.id
            {where}
            """,
            params,
        ).fetchone()
        return (row["with_strings"] or 0, row["without_strings"] or 0)

    def get_strings_for_blob(self, blob_sha256: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM strings WHERE blob_sha256 = ? ORDER BY category, string",
            (blob_sha256,),
        ).fetchall()

    def get_parse_errors(self, image_id: int | None = None) -> list[sqlite3.Row]:
        if image_id is not None:
            return self._conn.execute(
                "SELECT * FROM parse_errors WHERE image_id = ? ORDER BY id",
                (image_id,),
            ).fetchall()
        return self._conn.execute("SELECT * FROM parse_errors ORDER BY id").fetchall()

    def backfill_zen_generation(self, image_id: int) -> int:
        """Assign zen_generation to NULL entries by inferring from ROM context.

        For each entry with ``zen_generation IS NULL``, looks at all other
        entries with the same ``(image_id, rom_index)`` that already have a
        generation set, picks the most common one, and applies it.  This
        recovers generation information for BIOS-side directories (``$BHD``,
        ``$BL2``) that PSPTool does not annotate with PSP IDs.

        Returns the number of rows updated.
        """
        cur = self._conn.execute(
            """
            UPDATE entries
            SET zen_generation = (
                SELECT zen_generation
                FROM entries e2
                WHERE e2.image_id  = entries.image_id
                  AND e2.rom_index = entries.rom_index
                  AND e2.zen_generation IS NOT NULL
                GROUP BY zen_generation
                ORDER BY COUNT(*) DESC
                LIMIT 1
            )
            WHERE image_id = ?
              AND zen_generation IS NULL
              AND EXISTS (
                    SELECT 1 FROM entries e3
                    WHERE e3.image_id  = entries.image_id
                      AND e3.rom_index = entries.rom_index
                      AND e3.zen_generation IS NOT NULL
              )
            """,
            (image_id,),
        )
        self._conn.commit()
        return cur.rowcount

    def stats(self) -> dict:
        """Return a summary dict for the `psp-etl stats` command."""
        result: dict = {}

        result["images"] = self._conn.execute("SELECT COUNT(*) FROM images").fetchone()[0]
        result["entries"] = self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        result["analyzed"] = self._conn.execute("SELECT COUNT(*) FROM string_analysis").fetchone()[0]
        result["parse_errors"] = self._conn.execute("SELECT COUNT(*) FROM parse_errors").fetchone()[0]

        result["by_vendor"] = {
            row["vendor"]: row["cnt"]
            for row in self._conn.execute(
                "SELECT vendor, COUNT(*) AS cnt FROM images GROUP BY vendor ORDER BY cnt DESC"
            ).fetchall()
        }
        result["by_generation"] = {
            row["zen_generation"]: row["cnt"]
            for row in self._conn.execute(
                """
                SELECT zen_generation, COUNT(*) AS cnt
                FROM entries
                GROUP BY zen_generation
                ORDER BY zen_generation
                """
            ).fetchall()
        }
        result["encrypted_count"] = self._conn.execute(
            "SELECT COUNT(*) FROM entries WHERE encrypted = TRUE"
        ).fetchone()[0]

        return result
