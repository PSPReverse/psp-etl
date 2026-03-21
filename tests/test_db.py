"""Tests for db.py: schema creation, insert/query methods."""

import pytest

from psp_etl.db import (
    Database,
    Entry,
    Image,
    ParseError,
    PrimaryImage,
    StringAnalysis,
)


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "test.db") as database:
        yield database


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_creates_tables(db):
    tables = {row[0] for row in db._conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"images", "entries", "string_analysis", "strings", "primary_images", "parse_errors"} <= tables


def test_schema_creates_indexes(db):
    indexes = {row[0] for row in db._conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
    expected = {
        "idx_entries_gen",
        "idx_entries_type",
        "idx_entries_md5",
        "idx_entries_blob",
        "idx_entries_version",
        "idx_analysis_score",
        "idx_strings_blob",
        "idx_strings_text",
        "idx_strings_category",
    }
    assert expected <= indexes


# ---------------------------------------------------------------------------
# Image
# ---------------------------------------------------------------------------


def test_insert_image_returns_id(db):
    img = Image(sha256="abc123", vendor="ASUS", model="PRIME X570-P", socket="AM4")
    row_id = db.insert_image(img)
    assert isinstance(row_id, int)
    assert row_id > 0


def test_insert_image_dedup_by_sha256(db):
    img = Image(sha256="abc123", vendor="ASUS")
    id1 = db.insert_image(img)
    id2 = db.insert_image(img)
    assert id1 == id2


def test_get_image_by_sha256(db):
    img = Image(sha256="deadbeef", vendor="MSI", model="B550 TOMAHAWK")
    db.insert_image(img)
    row = db.get_image_by_sha256("deadbeef")
    assert row is not None
    assert row["vendor"] == "MSI"
    assert row["model"] == "B550 TOMAHAWK"


def test_get_image_by_sha256_missing(db):
    assert db.get_image_by_sha256("nonexistent") is None


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------


def _make_image(db, sha256="img1", vendor="ASUS"):
    return db.insert_image(Image(sha256=sha256, vendor=vendor))


def test_insert_entry_returns_id(db):
    image_id = _make_image(db)
    entry = Entry(image_id=image_id, type_id=1, zen_generation="zen2", version="1.0.0")
    row_id = db.insert_entry(entry)
    assert isinstance(row_id, int)
    assert row_id > 0


def test_insert_entry_dedup(db):
    image_id = _make_image(db)
    entry = Entry(
        image_id=image_id,
        type_id=1,
        rom_index=0,
        directory_index=0,
        subprogram=0,
        instance=0,
    )
    id1 = db.insert_entry(entry)
    id2 = db.insert_entry(entry)
    assert id1 == id2


def test_get_entry_by_id(db):
    image_id = _make_image(db)
    entry = Entry(
        image_id=image_id,
        type_id=0x1,
        zen_generation="zen3",
        blob_sha256="blobhash",
        body_size=4096,
        encrypted=True,
    )
    entry_id = db.insert_entry(entry)
    row = db.get_entry_by_id(entry_id)
    assert row is not None
    assert row["zen_generation"] == "zen3"
    assert row["encrypted"] == 1
    assert row["body_size"] == 4096


# ---------------------------------------------------------------------------
# Entry – multi-generation fan-out and backfill
# ---------------------------------------------------------------------------


def test_insert_entry_different_gens_are_separate_rows(db):
    """Two entries identical except for zen_generation must be distinct rows."""
    image_id = _make_image(db)
    base = dict(image_id=image_id, type_id=1, rom_index=0, directory_index=0, subprogram=0, instance=0, version="1.0")
    id1 = db.insert_entry(Entry(**base, zen_generation="zen1"))
    id2 = db.insert_entry(Entry(**base, zen_generation="zen2"))
    assert id1 != id2
    count = db._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    assert count == 2


def test_insert_entry_null_gen_dedup(db):
    """Two entries with zen_generation=None must deduplicate to one row."""
    image_id = _make_image(db)
    entry = Entry(
        image_id=image_id, type_id=1, rom_index=0, directory_index=0, subprogram=0, instance=0, zen_generation=None
    )
    id1 = db.insert_entry(entry)
    id2 = db.insert_entry(entry)
    assert id1 == id2
    count = db._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    assert count == 1


def test_backfill_zen_generation(db):
    """NULL-gen entries adopt the dominant gen from the same ROM segment."""
    image_id = _make_image(db)
    # Two zen3 entries in rom_index=0
    db.insert_entry(Entry(image_id=image_id, type_id=1, rom_index=0, directory_index=0, zen_generation="zen3"))
    db.insert_entry(Entry(image_id=image_id, type_id=2, rom_index=0, directory_index=0, zen_generation="zen3"))
    # One NULL-gen entry (BHD-style) in rom_index=0
    null_id = db.insert_entry(Entry(image_id=image_id, type_id=3, rom_index=0, directory_index=1, zen_generation=None))

    updated = db.backfill_zen_generation(image_id)

    assert updated == 1
    row = db.get_entry_by_id(null_id)
    assert row["zen_generation"] == "zen3"


def test_backfill_no_op_when_no_known_gen(db):
    """Backfill leaves entries unchanged when no gen is known in the segment."""
    image_id = _make_image(db)
    null_id = db.insert_entry(Entry(image_id=image_id, type_id=1, rom_index=0, directory_index=0, zen_generation=None))
    updated = db.backfill_zen_generation(image_id)
    assert updated == 0
    row = db.get_entry_by_id(null_id)
    assert row["zen_generation"] is None


def test_backfill_skips_already_classified(db):
    """Backfill does not overwrite entries that already have a generation."""
    image_id = _make_image(db)
    db.insert_entry(Entry(image_id=image_id, type_id=1, rom_index=0, directory_index=0, zen_generation="zen2"))
    known_id = db.insert_entry(
        Entry(image_id=image_id, type_id=2, rom_index=0, directory_index=0, zen_generation="zen1")
    )
    db.backfill_zen_generation(image_id)
    row = db.get_entry_by_id(known_id)
    assert row["zen_generation"] == "zen1"


# ---------------------------------------------------------------------------
# StringAnalysis
# ---------------------------------------------------------------------------


def test_insert_string_analysis(db):
    image_id = _make_image(db)
    entry_id = db.insert_entry(Entry(image_id=image_id, type_id=1))
    sa = StringAnalysis(
        entry_id=entry_id,
        total_strings=100,
        unique_strings=80,
        format_strings=10,
        function_names=5,
        error_messages=3,
        postcode_strings=2,
        descriptive_strings=15,
        score=42.5,
    )
    sa_id = db.insert_string_analysis(sa)
    assert sa_id > 0


def test_insert_string_analysis_upserts(db):
    image_id = _make_image(db)
    entry_id = db.insert_entry(Entry(image_id=image_id, type_id=1))
    sa = StringAnalysis(
        entry_id=entry_id,
        total_strings=10,
        unique_strings=8,
        format_strings=1,
        function_names=0,
        error_messages=0,
        postcode_strings=0,
        descriptive_strings=2,
        score=5.0,
    )
    db.insert_string_analysis(sa)
    sa.score = 99.0
    db.insert_string_analysis(sa)
    row = db._conn.execute("SELECT score FROM string_analysis WHERE entry_id = ?", (entry_id,)).fetchone()
    assert row["score"] == 99.0


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------


def test_insert_strings(db):
    db.insert_strings("blob1", [("spiRead()", "function_name"), ("ERROR: bad cmd", "error_message")])
    rows = db.get_strings_for_blob("blob1")
    assert len(rows) == 2
    texts = {r["string"] for r in rows}
    assert "spiRead()" in texts


def test_insert_strings_dedup(db):
    db.insert_strings("blob1", [("hello", "other")])
    db.insert_strings("blob1", [("hello", "other")])
    rows = db.get_strings_for_blob("blob1")
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# ParseError
# ---------------------------------------------------------------------------


def test_insert_parse_error(db):
    image_id = _make_image(db)
    err = ParseError(image_id=image_id, error_message="PSPTool crashed", traceback="...")
    err_id = db.insert_parse_error(err)
    assert err_id > 0
    rows = db.get_parse_errors(image_id)
    assert len(rows) == 1
    assert rows[0]["error_message"] == "PSPTool crashed"


def test_get_parse_errors_all(db):
    id1 = _make_image(db, sha256="img1")
    id2 = _make_image(db, sha256="img2")
    db.insert_parse_error(ParseError(image_id=id1, error_message="err1"))
    db.insert_parse_error(ParseError(image_id=id2, error_message="err2"))
    assert len(db.get_parse_errors()) == 2


# ---------------------------------------------------------------------------
# PrimaryImage
# ---------------------------------------------------------------------------


def test_upsert_primary_image(db):
    image_id = _make_image(db)
    entry_id = db.insert_entry(Entry(image_id=image_id, type_id=1))
    pi = PrimaryImage(
        zen_generation="zen2",
        type_id=1,
        version="1.0.0",
        best_entry_id=entry_id,
        best_image_id=image_id,
        score=42.0,
    )
    pi_id = db.upsert_primary_image(pi)
    assert pi_id > 0


def test_upsert_primary_image_updates(db):
    image_id = _make_image(db)
    e1 = db.insert_entry(Entry(image_id=image_id, type_id=1, rom_index=0, directory_index=0, subprogram=0, instance=0))
    e2 = db.insert_entry(Entry(image_id=image_id, type_id=1, rom_index=0, directory_index=0, subprogram=0, instance=1))
    pi = PrimaryImage(
        zen_generation="zen3", type_id=1, version="2.0", best_entry_id=e1, best_image_id=image_id, score=10.0
    )
    db.upsert_primary_image(pi)
    pi.best_entry_id = e2
    pi.score = 99.0
    db.upsert_primary_image(pi)
    row = db._conn.execute(
        "SELECT score, best_entry_id FROM primary_images WHERE zen_generation='zen3' AND type_id=1 AND version='2.0'"
    ).fetchone()
    assert row["score"] == 99.0
    assert row["best_entry_id"] == e2


# ---------------------------------------------------------------------------
# query_entries
# ---------------------------------------------------------------------------


def _populate(db):
    """Return (image_id, entry_ids) for a small test dataset."""
    img1 = db.insert_image(Image(sha256="img1", vendor="ASUS", socket="AM4"))
    img2 = db.insert_image(Image(sha256="img2", vendor="MSI", socket="AM4"))

    e1 = db.insert_entry(
        Entry(
            image_id=img1,
            type_id=1,
            zen_generation="zen2",
            version="1.0",
            rom_index=0,
            directory_index=0,
            subprogram=0,
            instance=0,
            blob_sha256="b1",
        )
    )
    e2 = db.insert_entry(
        Entry(
            image_id=img2,
            type_id=1,
            zen_generation="zen2",
            version="1.0",
            rom_index=0,
            directory_index=0,
            subprogram=0,
            instance=0,
            blob_sha256="b2",
        )
    )
    e3 = db.insert_entry(
        Entry(
            image_id=img1,
            type_id=2,
            zen_generation="zen3",
            version="2.0",
            rom_index=0,
            directory_index=1,
            subprogram=0,
            instance=0,
            blob_sha256="b3",
        )
    )

    db.insert_string_analysis(
        StringAnalysis(
            entry_id=e1,
            total_strings=50,
            unique_strings=40,
            format_strings=5,
            function_names=2,
            error_messages=1,
            postcode_strings=0,
            descriptive_strings=8,
            score=20.0,
        )
    )
    db.insert_string_analysis(
        StringAnalysis(
            entry_id=e2,
            total_strings=5,
            unique_strings=4,
            format_strings=0,
            function_names=0,
            error_messages=0,
            postcode_strings=0,
            descriptive_strings=1,
            score=0.5,
        )
    )
    # e3 has no string_analysis

    return img1, img2, e1, e2, e3


def test_query_entries_no_filter(db):
    _populate(db)
    rows = db.query_entries()
    assert len(rows) == 3


def test_query_entries_by_generation(db):
    _populate(db)
    rows = db.query_entries(zen_generation="zen2")
    assert len(rows) == 2
    assert all(r["zen_generation"] == "zen2" for r in rows)


def test_query_entries_by_type(db):
    _populate(db)
    rows = db.query_entries(type_id=2)
    assert len(rows) == 1
    assert rows[0]["type_id"] == 2


def test_query_entries_by_vendor(db):
    _populate(db)
    rows = db.query_entries(vendor="MSI")
    assert len(rows) == 1
    assert rows[0]["vendor"] == "MSI"


def test_query_entries_has_strings(db):
    _populate(db)
    # e1 score=20, e2 score=0.5, e3 has no analysis — has_strings excludes e3
    rows = db.query_entries(has_strings=True)
    assert len(rows) == 2


def test_query_entries_min_score(db):
    _populate(db)
    rows = db.query_entries(min_score=10.0)
    assert len(rows) == 1
    assert rows[0]["score"] == 20.0


def test_get_unanalyzed_entries(db):
    _populate(db)
    # e3 has blob_sha256 but no string_analysis
    rows = db.get_unanalyzed_entries()
    assert len(rows) == 1
    assert rows[0]["blob_sha256"] == "b3"


def test_get_best_entries(db):
    img1, img2, e1, e2, e3 = _populate(db)
    db.upsert_primary_image(
        PrimaryImage(zen_generation="zen2", type_id=1, version="1.0", best_entry_id=e1, best_image_id=img1, score=20.0)
    )
    rows = db.get_best_entries()
    assert len(rows) == 1
    assert rows[0]["zen_generation"] == "zen2"


def test_get_best_entries_filter_by_gen(db):
    img1, img2, e1, e2, e3 = _populate(db)
    db.upsert_primary_image(
        PrimaryImage(zen_generation="zen2", type_id=1, version="1.0", best_entry_id=e1, best_image_id=img1, score=20.0)
    )
    db.upsert_primary_image(
        PrimaryImage(zen_generation="zen3", type_id=2, version="2.0", best_entry_id=e3, best_image_id=img1, score=0.0)
    )
    rows = db.get_best_entries(zen_generation="zen3")
    assert len(rows) == 1
    assert rows[0]["zen_generation"] == "zen3"


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


def test_stats(db):
    _populate(db)
    s = db.stats()
    assert s["images"] == 2
    assert s["entries"] == 3
    assert s["analyzed"] == 2
    assert s["parse_errors"] == 0
    assert s["by_vendor"]["ASUS"] == 1
    assert s["by_vendor"]["MSI"] == 1
    assert s["by_generation"]["zen2"] == 2
    assert s["by_generation"]["zen3"] == 1
