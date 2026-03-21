"""Tests for the 'psp-etl query' CLI command."""

import csv
import io
import json

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

    with Database(d / "psp-etl.db") as db:
        img1 = db.insert_image(Image(sha256="img1", vendor="ASUS", model="PRIME X570-P", socket="AM4"))
        img2 = db.insert_image(Image(sha256="img2", vendor="MSI", model="B550 TOMAHAWK", socket="AM4"))

        e1 = db.insert_entry(
            Entry(
                image_id=img1,
                type_id=0x08,
                type_name="SMU_OFFCHIP_FW",
                zen_generation="zen2",
                version="1.0.0",
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
                type_id=0x08,
                type_name="SMU_OFFCHIP_FW",
                zen_generation="zen2",
                version="1.0.0",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
                blob_sha256="b2",
            )
        )
        db.insert_entry(
            Entry(
                image_id=img1,
                type_id=0x12,
                type_name="PSP_SMU_FN_FW",
                zen_generation="zen3",
                version="2.0.0",
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
        db.insert_strings("b1", [("spiRead()", "function_name"), ("ERROR: bad cmd", "error_message")])
        db.insert_strings("b2", [("hello world", "other")])
    return d


def test_query_no_db(runner, tmp_path):
    result = runner.invoke(cli, ["--data-dir", str(tmp_path / "noexist"), "query"])
    assert result.exit_code != 0


def test_query_no_filters_table(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query"])
    assert result.exit_code == 0
    assert "SMU_OFFCHIP_FW" in result.output
    assert "ASUS" in result.output
    assert "MSI" in result.output


def test_query_no_results(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--gen", "zen5"])
    assert result.exit_code == 0
    assert "No entries found" in result.output


def test_query_filter_gen(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--gen", "zen2", "--format", "json"])
    assert result.exit_code == 0
    records = json.loads(result.output)
    assert len(records) == 2
    assert all(r["zen_generation"] == "zen2" for r in records)


def test_query_filter_type_hex(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--type", "12", "--format", "json"])
    assert result.exit_code == 0
    records = json.loads(result.output)
    assert len(records) == 1
    assert records[0]["type_name"] == "PSP_SMU_FN_FW"


def test_query_filter_type_hex_prefix(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--type", "0x12", "--format", "json"])
    assert result.exit_code == 0
    records = json.loads(result.output)
    assert len(records) == 1


def test_query_filter_vendor(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--vendor", "MSI", "--format", "json"])
    assert result.exit_code == 0
    records = json.loads(result.output)
    assert len(records) == 1
    assert records[0]["vendor"] == "MSI"


def test_query_filter_min_score(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--min-score", "10.0", "--format", "json"])
    assert result.exit_code == 0
    records = json.loads(result.output)
    assert len(records) == 1
    assert records[0]["score"] == 20.0


def test_query_filter_has_strings(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--has-strings", "--format", "json"])
    assert result.exit_code == 0
    records = json.loads(result.output)
    assert len(records) == 2  # e1 (20.0) and e2 (0.5) both > 0


def test_query_filter_string_pattern(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--string", "spiRead", "--format", "json"])
    assert result.exit_code == 0
    records = json.loads(result.output)
    assert len(records) == 1
    assert records[0]["vendor"] == "ASUS"


def test_query_filter_string_no_match(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--string", "nonexistent"])
    assert result.exit_code == 0
    assert "No entries found" in result.output


def test_query_invalid_type(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--type", "xyz"])
    assert result.exit_code != 0


def test_query_json_no_hashes(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--format", "json"])
    assert result.exit_code == 0
    records = json.loads(result.output)
    expected = {"type_name", "version", "zen_generation", "vendor", "model", "score"}
    assert set(records[0].keys()) == expected


def test_query_csv_format(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--format", "csv"])
    assert result.exit_code == 0
    rows = list(csv.DictReader(io.StringIO(result.output)))
    assert len(rows) == 3
    assert "type_name" in rows[0]
    assert "sha256" not in rows[0]


def test_query_table_no_sha256(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query"])
    assert result.exit_code == 0
    import re

    assert not re.search(r"[0-9a-f]{64}", result.output)


def test_query_combined_filters(runner, data_dir):
    result = runner.invoke(
        cli,
        [
            "--data-dir",
            str(data_dir),
            "query",
            "--gen",
            "zen2",
            "--vendor",
            "ASUS",
            "--has-strings",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    records = json.loads(result.output)
    assert len(records) == 1
    assert records[0]["zen_generation"] == "zen2"
    assert records[0]["vendor"] == "ASUS"
    assert records[0]["score"] > 0


def test_query_csv_exact_columns(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "query", "--format", "csv"])
    assert result.exit_code == 0
    reader = csv.DictReader(io.StringIO(result.output))
    rows = list(reader)
    assert len(rows) > 0
    assert reader.fieldnames == ["type_name", "version", "zen_generation", "vendor", "model", "score"]


def test_query_empty_db(runner, tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    with Database(d / "psp-etl.db"):
        pass  # create empty DB
    result = runner.invoke(cli, ["--data-dir", str(d), "query"])
    assert result.exit_code == 0
    assert "No entries found" in result.output
