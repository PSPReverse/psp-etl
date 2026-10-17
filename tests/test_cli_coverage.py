"""Tests for the 'psp-etl coverage' CLI command."""

import pytest
from click.testing import CliRunner

from psp_etl.cli import cli
from psp_etl.db import Database, Entry, Image


@pytest.fixture
def runner():
    return CliRunner(env={"COLUMNS": "200"})


def test_coverage_missing_database(runner, tmp_path):
    result = runner.invoke(cli, ["--data-dir", str(tmp_path), "coverage"])
    assert result.exit_code != 0
    assert "Database not found" in result.output


def test_coverage_reports_generation_and_vendor(runner, tmp_path):
    with Database(tmp_path / "psp-etl.db") as db:
        image = db.insert_image(Image(sha256="s1", vendor="ASUS", download_url="u"))
        db.insert_entry(Entry(image_id=image, type_id=1, zen_generation="zen5", blob_sha256="b1"))
        db.insert_image(Image(sha256="m1", vendor="manual"))

    result = runner.invoke(cli, ["--data-dir", str(tmp_path), "coverage"])

    assert result.exit_code == 0, result.output
    assert "Coverage per Generation" in result.output
    assert "zen5" in result.output
    assert "ASUS" in result.output
    assert "manual" in result.output
