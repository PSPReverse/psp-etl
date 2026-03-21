"""Tests for the 'psp-etl stats' CLI command."""

import pytest
from click.testing import CliRunner

from psp_etl.cli import cli
from psp_etl.db import Database, Entry, Image, StringAnalysis


@pytest.fixture
def runner():
    return CliRunner(env={"COLUMNS": "200"})


def test_stats_empty_db(runner, tmp_path):
    """Empty DB: all four tables render with 'no data' placeholders, exit 0."""
    d = tmp_path / "data"
    d.mkdir()
    Database(d / "psp-etl.db").close()

    result = runner.invoke(cli, ["--data-dir", str(d), "stats"])
    assert result.exit_code == 0, result.output

    assert "Images per Vendor" in result.output
    assert "Entries per Generation" in result.output
    assert "String Score Distribution" in result.output
    assert "Score Summary" in result.output
    # Three tables (vendor, generation, score distribution) show no-data placeholders
    assert result.output.count("no data") >= 3


def test_stats_populated(runner, tmp_path):
    """Populated DB: vendor names and generation names appear in output."""
    d = tmp_path / "data"
    d.mkdir()

    with Database(d / "psp-etl.db") as db:
        img1 = db.insert_image(Image(sha256="sha1", vendor="ASUS"))
        img2 = db.insert_image(Image(sha256="sha2", vendor="MSI"))
        db.insert_entry(
            Entry(
                image_id=img1,
                type_id=0x08,
                zen_generation="zen2",
                version="1.0",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )
        db.insert_entry(
            Entry(
                image_id=img2,
                type_id=0x08,
                zen_generation="zen3",
                version="2.0",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )

    result = runner.invoke(cli, ["--data-dir", str(d), "stats"])
    assert result.exit_code == 0, result.output

    assert "ASUS" in result.output
    assert "MSI" in result.output
    assert "zen2" in result.output
    assert "zen3" in result.output


def test_stats_with_string_analysis(runner, tmp_path):
    """Score distribution table shows Min/Mean/P90/Max values when data is present."""
    d = tmp_path / "data"
    d.mkdir()

    with Database(d / "psp-etl.db") as db:
        img1 = db.insert_image(Image(sha256="sha1", vendor="ASUS"))
        e1 = db.insert_entry(
            Entry(
                image_id=img1,
                type_id=0x08,
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
                image_id=img1,
                type_id=0x09,
                zen_generation="zen2",
                version="1.0",
                rom_index=0,
                directory_index=1,
                subprogram=0,
                instance=0,
                blob_sha256="b2",
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
                score=10.0,
            )
        )
        db.insert_string_analysis(
            StringAnalysis(
                entry_id=e2,
                total_strings=20,
                unique_strings=15,
                format_strings=2,
                function_names=1,
                error_messages=0,
                postcode_strings=0,
                descriptive_strings=5,
                score=20.0,
            )
        )

    result = runner.invoke(cli, ["--data-dir", str(d), "stats"])
    assert result.exit_code == 0, result.output

    # Column headers
    assert "Min" in result.output
    assert "Mean" in result.output
    assert "P90" in result.output
    assert "Max" in result.output
    # Computed values: min=10.0, mean=15.0, p90/max=20.0
    assert "10.0" in result.output
    assert "15.0" in result.output
    assert "20.0" in result.output


def test_stats_gen_filter(runner, tmp_path):
    """--gen zen2 filter: zen3 does not appear in output."""
    d = tmp_path / "data"
    d.mkdir()

    with Database(d / "psp-etl.db") as db:
        img1 = db.insert_image(Image(sha256="sha1", vendor="ASUS"))
        img2 = db.insert_image(Image(sha256="sha2", vendor="MSI"))
        db.insert_entry(
            Entry(
                image_id=img1,
                type_id=0x08,
                zen_generation="zen2",
                version="1.0",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )
        db.insert_entry(
            Entry(
                image_id=img2,
                type_id=0x08,
                zen_generation="zen3",
                version="2.0",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )

    result = runner.invoke(cli, ["--data-dir", str(d), "stats", "--gen", "zen2"])
    assert result.exit_code == 0, result.output

    assert "zen2" in result.output
    assert "zen3" not in result.output
