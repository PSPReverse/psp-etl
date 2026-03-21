"""Tests for the 'psp-etl best' CLI command."""

import re

import pytest
from click.testing import CliRunner

from psp_etl.cli import cli
from psp_etl.db import Database, Entry, Image, PrimaryImage, StringAnalysis


_WIDE = {"COLUMNS": "200"}  # prevent Rich from wrapping table cells


@pytest.fixture
def runner():
    return CliRunner(env=_WIDE)


@pytest.fixture
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    blobs_dir = d / "blobs"
    blobs_dir.mkdir()

    with Database(d / "psp-etl.db") as db:
        img_id = db.insert_image(Image(sha256="imgabc", vendor="ASUS", model="PRIME X570-P", socket="AM4"))
        e1 = db.insert_entry(
            Entry(
                image_id=img_id,
                type_id=0x01,
                zen_generation="zen2",
                type_name="PSP Boot Loader",
                version="1.5.0",
                blob_sha256="blobhash1",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )
        e2 = db.insert_entry(
            Entry(
                image_id=img_id,
                type_id=0x08,
                zen_generation="zen3",
                type_name="SMU Off Chip Firmware",
                version="2.0.1",
                blob_sha256="blobhash2",
                rom_index=0,
                directory_index=1,
                subprogram=0,
                instance=0,
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
                unique_strings=18,
                format_strings=2,
                function_names=1,
                error_messages=0,
                postcode_strings=0,
                descriptive_strings=5,
                score=8.0,
            )
        )
        db.upsert_primary_image(
            PrimaryImage(
                zen_generation="zen2", type_id=0x01, version="1.5.0", best_entry_id=e1, best_image_id=img_id, score=42.5
            )
        )
        db.upsert_primary_image(
            PrimaryImage(
                zen_generation="zen3", type_id=0x08, version="2.0.1", best_entry_id=e2, best_image_id=img_id, score=8.0
            )
        )

    (blobs_dir / "blobhash1.bin").write_bytes(b"\x00" * 64)
    (blobs_dir / "blobhash2.bin").write_bytes(b"\xff" * 128)
    return d


def test_best_no_db(runner, tmp_path):
    result = runner.invoke(cli, ["--data-dir", str(tmp_path / "noexist"), "best"])
    assert result.exit_code != 0


def test_best_empty_db(runner, tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    Database(d / "psp-etl.db").close()
    result = runner.invoke(cli, ["--data-dir", str(d), "best"])
    assert result.exit_code == 0
    assert "No primary images found" in result.output


def test_best_shows_table(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "best"])
    assert result.exit_code == 0
    assert "PSP Boot Loader" in result.output
    assert "SMU Off Chip Firmware" in result.output
    assert "zen2" in result.output
    assert "0x01" in result.output
    assert "0x08" in result.output
    assert "blobhash1" not in result.output


def test_best_filter_gen(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "best", "--gen", "zen2"])
    assert result.exit_code == 0
    assert "PSP Boot Loader" in result.output
    assert "SMU Off Chip Firmware" not in result.output


def test_best_filter_type_with_prefix(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "best", "--type", "0x08"])
    assert result.exit_code == 0
    assert "SMU Off Chip Firmware" in result.output
    assert "PSP Boot Loader" not in result.output


def test_best_filter_type_without_prefix(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "best", "--type", "08"])
    assert result.exit_code == 0
    assert "SMU Off Chip Firmware" in result.output


def test_best_filter_type_invalid(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "best", "--type", "nothex"])
    assert result.exit_code != 0


def test_best_filter_gen_no_results(runner, data_dir):
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "best", "--gen", "zen5"])
    assert result.exit_code == 0
    assert "No primary images found" in result.output


def test_best_export_dir_creates_files(runner, data_dir, tmp_path):
    export_dir = tmp_path / "export"
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "best", "--export-dir", str(export_dir)])
    assert result.exit_code == 0
    assert export_dir.exists()
    assert len(list(export_dir.iterdir())) == 2


def test_best_export_dir_filenames(runner, data_dir, tmp_path):
    export_dir = tmp_path / "export"
    runner.invoke(cli, ["--data-dir", str(data_dir), "best", "--export-dir", str(export_dir)])
    names = {f.name for f in export_dir.iterdir()}
    assert "PSP_Boot_Loader_1.5.0.bin" in names
    assert "SMU_Off_Chip_Firmware_2.0.1.bin" in names


def test_best_export_dir_blob_contents(runner, data_dir, tmp_path):
    export_dir = tmp_path / "export"
    runner.invoke(cli, ["--data-dir", str(data_dir), "best", "--export-dir", str(export_dir)])
    assert (export_dir / "PSP_Boot_Loader_1.5.0.bin").read_bytes() == b"\x00" * 64
    assert (export_dir / "SMU_Off_Chip_Firmware_2.0.1.bin").read_bytes() == b"\xff" * 128


def test_best_export_missing_blob_warns(runner, data_dir, tmp_path):
    (data_dir / "blobs" / "blobhash2.bin").unlink()
    export_dir = tmp_path / "export"
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "best", "--export-dir", str(export_dir)])
    assert result.exit_code == 0
    assert "Warning" in result.output
    assert len(list(export_dir.iterdir())) == 1


# ---------------------------------------------------------------------------
# New smoke tests
# ---------------------------------------------------------------------------

_REAL_BLOB_SHA256 = "deadbeef" * 8  # 64-char hex — realistic SHA256 stand-in
_REAL_IMAGE_SHA256 = "cafebabe" * 8  # 64-char hex — realistic SHA256 stand-in


@pytest.fixture
def data_dir_real_hashes(tmp_path):
    """Like data_dir but uses 64-char hex SHA256 values to mirror real data."""
    d = tmp_path / "data"
    d.mkdir()
    blobs_dir = d / "blobs"
    blobs_dir.mkdir()

    with Database(d / "psp-etl.db") as db:
        img_id = db.insert_image(Image(sha256=_REAL_IMAGE_SHA256, vendor="ASUS", model="PRIME X570-P", socket="AM4"))
        e1 = db.insert_entry(
            Entry(
                image_id=img_id,
                type_id=0x01,
                zen_generation="zen2",
                type_name="PSP Boot Loader",
                version="1.5.0",
                blob_sha256=_REAL_BLOB_SHA256,
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
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
        db.upsert_primary_image(
            PrimaryImage(
                zen_generation="zen2", type_id=0x01, version="1.5.0", best_entry_id=e1, best_image_id=img_id, score=42.5
            )
        )

    (blobs_dir / f"{_REAL_BLOB_SHA256}.bin").write_bytes(b"\xaa" * 32)
    return d


def test_best_no_hex_hashes_in_output(runner, data_dir_real_hashes):
    """Table output must not expose any 64-character hex hash strings."""
    result = runner.invoke(cli, ["--data-dir", str(data_dir_real_hashes), "best"])
    assert result.exit_code == 0
    assert re.search(r"[0-9a-f]{64}", result.output) is None


def test_best_export_dir_real_blob_content(runner, data_dir_real_hashes, tmp_path):
    """--export-dir writes {type_name}_{version}.bin with exact blob bytes."""
    export_dir = tmp_path / "export"
    result = runner.invoke(cli, ["--data-dir", str(data_dir_real_hashes), "best", "--export-dir", str(export_dir)])
    assert result.exit_code == 0
    exported = export_dir / "PSP_Boot_Loader_1.5.0.bin"
    assert exported.exists()
    assert exported.read_bytes() == b"\xaa" * 32


def test_best_primary_images_not_selected(runner, tmp_path):
    """Images/entries exist but 'select' was never run — primary_images is empty."""
    d = tmp_path / "data"
    d.mkdir()
    (d / "blobs").mkdir()

    with Database(d / "psp-etl.db") as db:
        img_id = db.insert_image(Image(sha256="imgabc", vendor="ASUS", model="PRIME X570-P", socket="AM4"))
        db.insert_entry(
            Entry(
                image_id=img_id,
                type_id=0x01,
                zen_generation="zen2",
                type_name="PSP Boot Loader",
                version="1.5.0",
                blob_sha256="blobhash1",
                rom_index=0,
                directory_index=0,
                subprogram=0,
                instance=0,
            )
        )
        # Deliberately omit upsert_primary_image — simulates 'select' not having been run.

    result = runner.invoke(cli, ["--data-dir", str(d), "best"])
    assert result.exit_code == 0
    assert "No primary images found" in result.output
