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
