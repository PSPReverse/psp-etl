"""Tests for the 'psp-etl analyze' CLI command."""

import pytest
from click.testing import CliRunner

from psp_etl.cli import cli
from psp_etl.db import Database, Entry, Image, StringAnalysis


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def data_dir(tmp_path):
    """data_dir with a populated db and two blobs (A shared by 2 entries, B alone)."""
    d = tmp_path / "data"
    d.mkdir()
    blobs_dir = d / "blobs"
    blobs_dir.mkdir()

    with Database(d / "psp-etl.db") as db:
        img_id = db.insert_image(Image(sha256="img1", vendor="ASUS"))
        db.insert_entry(
            Entry(
                image_id=img_id,
                type_id=1,
                blob_sha256="blobA",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )
        db.insert_entry(
            Entry(
                image_id=img_id,
                type_id=2,
                blob_sha256="blobA",
                rom_index=0,
                directory_index=1,
                subprogram=0,
                instance=0,
            )
        )
        db.insert_entry(
            Entry(
                image_id=img_id,
                type_id=3,
                blob_sha256="blobB",
                rom_index=0,
                directory_index=2,
                subprogram=0,
                instance=0,
            )
        )

    (blobs_dir / "blobA.bin").write_bytes(b"\x00spiRead()\x00ERROR: bad\x00")
    (blobs_dir / "blobB.bin").write_bytes(b"\x00" * 64)
    return d


def test_analyze_populates_string_analysis(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "analyze"])
    assert result.exit_code == 0, result.output

    with Database(data_dir / "psp-etl.db") as db:
        rows = db._conn.execute("SELECT * FROM string_analysis").fetchall()
        assert len(rows) == 3  # all three entries get rows
        # blobA entries have real strings
        sa = db._conn.execute(
            "SELECT * FROM string_analysis sa JOIN entries e ON e.id = sa.entry_id WHERE e.type_id = 1"
        ).fetchone()
        assert sa["function_names"] >= 1
        assert sa["error_messages"] >= 1
        assert sa["score"] > 0


def test_analyze_populates_strings_table(runner, data_dir):
    runner.invoke(cli, ["--data-dir", str(data_dir), "analyze"])
    with Database(data_dir / "psp-etl.db") as db:
        rows = db.get_strings_for_blob("blobA")
        texts = {r["string"] for r in rows}
        assert "spiRead()" in texts


def test_analyze_skips_already_analyzed(runner, data_dir):
    # Pre-analyze once
    runner.invoke(cli, ["--data-dir", str(data_dir), "analyze"])

    # Remove blobA.bin to confirm it isn't re-read
    (data_dir / "blobs" / "blobA.bin").unlink()

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "analyze"])
    assert result.exit_code == 0
    assert "Nothing to analyze" in result.output


def test_analyze_reanalyze_flag(runner, data_dir):
    # First pass
    runner.invoke(cli, ["--data-dir", str(data_dir), "analyze"])

    # Corrupt the score
    with Database(data_dir / "psp-etl.db") as db:
        db._conn.execute("UPDATE string_analysis SET total_strings = 999")
        db._conn.commit()

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "analyze", "--reanalyze"])
    assert result.exit_code == 0

    with Database(data_dir / "psp-etl.db") as db:
        row = db._conn.execute(
            "SELECT total_strings FROM string_analysis sa JOIN entries e ON e.id = sa.entry_id WHERE e.type_id = 1"
        ).fetchone()
        assert row["total_strings"] != 999


def test_analyze_nothing_to_analyze(runner, tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    (d / "blobs").mkdir()
    Database(d / "psp-etl.db").close()

    result = runner.invoke(cli, ["--data-dir", str(d), "analyze"])
    assert result.exit_code == 0
    assert "Nothing to analyze" in result.output


def test_analyze_missing_blob_skipped(runner, tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    (d / "blobs").mkdir()

    with Database(d / "psp-etl.db") as db:
        img_id = db.insert_image(Image(sha256="img1", vendor="ASUS"))
        db.insert_entry(
            Entry(
                image_id=img_id,
                type_id=1,
                blob_sha256="missing",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )

    result = runner.invoke(cli, ["--data-dir", str(d), "analyze"])
    assert result.exit_code == 0

    with Database(d / "psp-etl.db") as db:
        count = db._conn.execute("SELECT COUNT(*) FROM string_analysis").fetchone()[0]
        assert count == 0


def test_analyze_no_db(runner, tmp_path):
    result = runner.invoke(cli, ["--data-dir", str(tmp_path / "noexist"), "analyze"])
    assert result.exit_code != 0
