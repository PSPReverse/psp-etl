"""Tests for the 'psp-etl select' CLI command."""

import logging

import pytest
from click.testing import CliRunner

from psp_etl.cli import cli
from psp_etl.db import Database, Entry, Image, StringAnalysis


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    return d


def _populate(db: Database) -> dict:
    img_asus = db.insert_image(Image(sha256="asus1", vendor="ASUS", socket="AM4"))
    img_msi = db.insert_image(Image(sha256="msi1", vendor="MSI", socket="AM4"))
    img_giga = db.insert_image(Image(sha256="giga1", vendor="Gigabyte", socket="AM5"))

    # Group 1: (zen2, type=1, v1.0.0) — ASUS scores higher
    e1 = db.insert_entry(
        Entry(
            image_id=img_asus,
            type_id=1,
            zen_generation="zen2",
            version="1.0.0",
            firmware_md5="md5_a",
            type_name="PSP_FW",
            rom_index=0,
            directory_index=0,
            subprogram=0,
            instance=0,
            blob_sha256="blob_a",
        )
    )
    e2 = db.insert_entry(
        Entry(
            image_id=img_msi,
            type_id=1,
            zen_generation="zen2",
            version="1.0.0",
            firmware_md5="md5_b",
            type_name="PSP_FW",
            rom_index=0,
            directory_index=0,
            subprogram=0,
            instance=0,
            blob_sha256="blob_b",
        )
    )
    db.insert_string_analysis(
        StringAnalysis(
            entry_id=e1,
            total_strings=100,
            unique_strings=80,
            format_strings=10,
            function_names=5,
            error_messages=3,
            postcode_strings=2,
            descriptive_strings=15,
            score=42.5,
        )
    )
    db.insert_string_analysis(
        StringAnalysis(
            entry_id=e2,
            total_strings=20,
            unique_strings=15,
            format_strings=1,
            function_names=0,
            error_messages=0,
            postcode_strings=0,
            descriptive_strings=3,
            score=5.0,
        )
    )

    # Group 2: (zen3, type=2, v2.0.0) — single entry
    e3 = db.insert_entry(
        Entry(
            image_id=img_giga,
            type_id=2,
            zen_generation="zen3",
            version="2.0.0",
            firmware_md5="md5_c",
            type_name="SMU_FW",
            rom_index=0,
            directory_index=0,
            subprogram=0,
            instance=0,
            blob_sha256="blob_c",
        )
    )
    db.insert_string_analysis(
        StringAnalysis(
            entry_id=e3,
            total_strings=10,
            unique_strings=8,
            format_strings=2,
            function_names=1,
            error_messages=0,
            postcode_strings=0,
            descriptive_strings=1,
            score=8.5,
        )
    )
    return {"e1": e1, "e2": e2, "e3": e3, "img_asus": img_asus}


def test_select_populates_primary_images(runner, data_dir):
    with Database(data_dir / "psp-etl.db") as db:
        _populate(db)

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "select"])
    assert result.exit_code == 0

    with Database(data_dir / "psp-etl.db") as db:
        rows = db._conn.execute("SELECT * FROM primary_images ORDER BY zen_generation, type_id").fetchall()
    assert len(rows) == 2
    assert rows[0]["zen_generation"] == "zen2" and rows[0]["score"] == 42.5
    assert rows[1]["zen_generation"] == "zen3" and rows[1]["score"] == 8.5


def test_select_detects_cross_vendor_md5(runner, data_dir, caplog):
    with Database(data_dir / "psp-etl.db") as db:
        _populate(db)

    with caplog.at_level(logging.INFO, logger="psp_etl.cli"):
        result = runner.invoke(cli, ["--data-dir", str(data_dir), "select"])

    assert result.exit_code == 0
    assert any("Cross-vendor md5 difference" in r.message for r in caplog.records)


def test_select_upsert_idempotent(runner, data_dir):
    with Database(data_dir / "psp-etl.db") as db:
        _populate(db)

    runner.invoke(cli, ["--data-dir", str(data_dir), "select"])
    runner.invoke(cli, ["--data-dir", str(data_dir), "select"])

    with Database(data_dir / "psp-etl.db") as db:
        count = db._conn.execute("SELECT COUNT(*) FROM primary_images").fetchone()[0]
    assert count == 2


def test_select_empty_db(runner, data_dir):
    Database(data_dir / "psp-etl.db").close()
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "select"])
    assert result.exit_code == 0
    assert "No entries" in result.output


def test_select_entries_without_analysis(runner, data_dir):
    with Database(data_dir / "psp-etl.db") as db:
        img_id = db.insert_image(Image(sha256="img1", vendor="ASUS"))
        db.insert_entry(
            Entry(
                image_id=img_id,
                type_id=5,
                zen_generation="zen4",
                version="3.0.0",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "select"])
    assert result.exit_code == 0

    with Database(data_dir / "psp-etl.db") as db:
        row = db._conn.execute("SELECT * FROM primary_images WHERE zen_generation='zen4'").fetchone()
    assert row is not None
    assert row["score"] == 0.0


def test_select_shows_summary_table(runner, data_dir):
    with Database(data_dir / "psp-etl.db") as db:
        _populate(db)

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "select"])
    assert result.exit_code == 0
    assert "Primary Image Selections" in result.output
    assert "2" in result.output and "primary images selected" in result.output


def test_select_same_md5_no_cross_vendor(runner, data_dir, caplog):
    with Database(data_dir / "psp-etl.db") as db:
        img1 = db.insert_image(Image(sha256="img1", vendor="ASUS"))
        img2 = db.insert_image(Image(sha256="img2", vendor="MSI"))
        db.insert_entry(
            Entry(
                image_id=img1,
                type_id=1,
                zen_generation="zen2",
                version="1.0.0",
                firmware_md5="same_md5",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )
        db.insert_entry(
            Entry(
                image_id=img2,
                type_id=1,
                zen_generation="zen2",
                version="1.0.0",
                firmware_md5="same_md5",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=1,
            )
        )

    with caplog.at_level(logging.INFO, logger="psp_etl.cli"):
        result = runner.invoke(cli, ["--data-dir", str(data_dir), "select"])

    assert result.exit_code == 0
    assert not any("Cross-vendor" in r.message for r in caplog.records)


def test_select_no_db(runner, tmp_path):
    result = runner.invoke(cli, ["--data-dir", str(tmp_path / "noexist"), "select"])
    assert result.exit_code != 0


def test_select_best_entry_id_is_higher_scoring_vendor(runner, data_dir):
    """Integration test: the best_entry_id in primary_images must point to the
    higher-scoring entry across two vendors."""
    with Database(data_dir / "psp-etl.db") as db:
        img_asus = db.insert_image(Image(sha256="asus_hi", vendor="ASUS"))
        img_msi = db.insert_image(Image(sha256="msi_lo", vendor="MSI"))

        # Both entries belong to the same group (zen_generation, type_id, version)
        e_high = db.insert_entry(
            Entry(
                image_id=img_asus,
                type_id=10,
                zen_generation="zen4",
                version="5.0.0",
                firmware_md5="md5_hi",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )
        e_low = db.insert_entry(
            Entry(
                image_id=img_msi,
                type_id=10,
                zen_generation="zen4",
                version="5.0.0",
                firmware_md5="md5_lo",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=1,
            )
        )
        db.insert_string_analysis(
            StringAnalysis(
                entry_id=e_high,
                total_strings=200,
                unique_strings=150,
                format_strings=20,
                function_names=10,
                error_messages=5,
                postcode_strings=3,
                descriptive_strings=30,
                score=75.0,
            )
        )
        db.insert_string_analysis(
            StringAnalysis(
                entry_id=e_low,
                total_strings=10,
                unique_strings=8,
                format_strings=1,
                function_names=0,
                error_messages=0,
                postcode_strings=0,
                descriptive_strings=1,
                score=3.0,
            )
        )

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "select"])
    assert result.exit_code == 0

    with Database(data_dir / "psp-etl.db") as db:
        row = db._conn.execute(
            "SELECT best_entry_id, score FROM primary_images"
            " WHERE zen_generation='zen4' AND type_id=10 AND version='5.0.0'"
        ).fetchone()

    assert row is not None
    assert row["best_entry_id"] == e_high
    assert row["score"] == 75.0


def test_select_partitions_by_board_class(runner, data_dir):
    """Same (zen_generation, type_id) under Ryzen vs EPYC must produce 2 primary_images."""
    with Database(data_dir / "psp-etl.db") as db:
        img_ryz = db.insert_image(Image(sha256="ryz1", vendor="ASUS", socket="AM5", board_class="Ryzen"))
        img_epy = db.insert_image(Image(sha256="epy1", vendor="ASUS", socket="SP5", board_class="EPYC"))

        e_ryz = db.insert_entry(
            Entry(
                image_id=img_ryz,
                type_id=7,
                zen_generation="zen4",
                version="1.0.0",
                firmware_md5="md5_ryz",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )
        e_epy = db.insert_entry(
            Entry(
                image_id=img_epy,
                type_id=7,
                zen_generation="zen4",
                version="1.0.0",
                firmware_md5="md5_epy",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )
        db.insert_string_analysis(
            StringAnalysis(
                entry_id=e_ryz,
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
                entry_id=e_epy,
                total_strings=30,
                unique_strings=25,
                format_strings=2,
                function_names=1,
                error_messages=0,
                postcode_strings=0,
                descriptive_strings=4,
                score=12.0,
            )
        )

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "select"])
    assert result.exit_code == 0

    with Database(data_dir / "psp-etl.db") as db:
        rows = db._conn.execute(
            "SELECT board_class, score FROM primary_images "
            "WHERE zen_generation='zen4' AND type_id=7 ORDER BY board_class"
        ).fetchall()

    assert len(rows) == 2
    boards = {r["board_class"] for r in rows}
    assert boards == {"Ryzen", "EPYC"}


def test_select_skips_null_zen_generation(runner, data_dir):
    """Entries with NULL zen_generation must be excluded from select.
    Entries with NULL version are now included (version is not a selection key)."""
    with Database(data_dir / "psp-etl.db") as db:
        img = db.insert_image(Image(sha256="null_test", vendor="ASUS"))

        # Entry with NULL zen_generation — must be excluded
        db.insert_entry(
            Entry(
                image_id=img,
                type_id=20,
                zen_generation=None,
                version="1.0.0",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )
        # Entry with NULL version — now included
        db.insert_entry(
            Entry(
                image_id=img,
                type_id=20,
                zen_generation="zen5",
                version=None,
                rom_index=0,
                directory_index=1,
                subprogram=0,
                instance=0,
            )
        )

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "select"])
    assert result.exit_code == 0

    with Database(data_dir / "psp-etl.db") as db:
        count = db._conn.execute("SELECT COUNT(*) FROM primary_images").fetchone()[0]

    assert count == 1  # only the zen5/NULL-version entry, not the NULL-gen entry
