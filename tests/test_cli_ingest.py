"""CLI-level smoke tests for `psp-etl ingest`."""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from psp_etl.cli import cli
from psp_etl.db import Database


# ---------------------------------------------------------------------------
# Helpers: fake PSPTool objects
# ---------------------------------------------------------------------------


def _make_fake_file(
    type_id: int = 0x01,
    body: bytes = b"hello world " * 20,
):
    f = MagicMock()
    f.type = type_id
    f.encrypted = False
    f.compressed = False
    f.is_signed = False
    f.load_addr = None
    f.get_readable_type.return_value = "PSP_FW_BOOT_LOADER~0x1"
    f.get_readable_version.return_value = "1.0.0"
    f.md5.return_value = hashlib.md5(body).hexdigest()
    f.get_bytes.return_value = body
    f.get_decrypted_decompressed_body.return_value = body

    fake_entry = MagicMock()
    fake_entry.subprogram = 0
    fake_entry.instance = 0
    f.entry = fake_entry

    return f


def _make_fake_psp(body: bytes = b"hello world " * 20):
    f = _make_fake_file(body=body)
    d = MagicMock()
    d.files = [f]
    d.zen_generation = "Zen 2"
    d.magic = b"$PSP"
    r = MagicMock()
    r.directories = [d]
    r.agesa_version = "AGESA!.. CBP-RN-V1"
    psp = MagicMock()
    psp.blob.roms = [r]
    return psp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_ingest_happy_path(runner, data_dir, tmp_path):
    rom_path = tmp_path / "fake.rom"
    rom_path.write_bytes(b"\xff" * 256)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=_make_fake_psp()):
        result = runner.invoke(cli, ["--data-dir", str(data_dir), "ingest", str(rom_path)])

    assert result.exit_code == 0, result.output
    assert (data_dir / "psp-etl.db").exists()

    with Database(data_dir / "psp-etl.db") as db:
        rows = db._conn.execute("SELECT * FROM entries").fetchall()
        assert len(rows) >= 1

    blobs_dir = data_dir / "blobs"
    assert blobs_dir.is_dir()
    assert len(list(blobs_dir.iterdir())) >= 1


def test_ingest_creates_roms_dir(runner, data_dir, tmp_path):
    rom_bytes = b"\xab" * 256
    rom_path = tmp_path / "fake.rom"
    rom_path.write_bytes(rom_bytes)
    sha256 = hashlib.sha256(rom_bytes).hexdigest()

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=_make_fake_psp()):
        result = runner.invoke(cli, ["--data-dir", str(data_dir), "ingest", str(rom_path)])

    assert result.exit_code == 0, result.output
    assert (data_dir / "roms" / f"{sha256}.rom").exists()


def test_ingest_duplicate_is_idempotent(runner, data_dir, tmp_path):
    rom_path = tmp_path / "fake.rom"
    rom_path.write_bytes(b"\xcd" * 256)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=_make_fake_psp()):
        result1 = runner.invoke(cli, ["--data-dir", str(data_dir), "ingest", str(rom_path)])
    with patch("psp_etl.ingest.PSPTool.from_file", return_value=_make_fake_psp()):
        result2 = runner.invoke(cli, ["--data-dir", str(data_dir), "ingest", str(rom_path)])

    assert result1.exit_code == 0, result1.output
    assert result2.exit_code == 0, result2.output

    with Database(data_dir / "psp-etl.db") as db:
        image_count = db._conn.execute("SELECT COUNT(*) FROM images").fetchone()[0]
        assert image_count == 1


def test_ingest_corrupt_rom(runner, data_dir, tmp_path):
    rom_path = tmp_path / "corrupt.rom"
    rom_path.write_bytes(b"\x00" * 256)

    with patch("psp_etl.ingest.PSPTool.from_file", side_effect=Exception("corrupt")):
        result = runner.invoke(cli, ["--data-dir", str(data_dir), "ingest", str(rom_path)])

    assert result.exit_code == 0, result.output

    with Database(data_dir / "psp-etl.db") as db:
        errors = db._conn.execute("SELECT * FROM parse_errors").fetchall()
        assert len(errors) >= 1


def test_ingest_directory(runner, data_dir, tmp_path):
    rom_dir = tmp_path / "roms_input"
    rom_dir.mkdir()
    (rom_dir / "a.rom").write_bytes(b"\x01" * 256)
    (rom_dir / "b.rom").write_bytes(b"\x02" * 256)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=_make_fake_psp()):
        result = runner.invoke(cli, ["--data-dir", str(data_dir), "ingest", str(rom_dir)])

    assert result.exit_code == 0, result.output

    with Database(data_dir / "psp-etl.db") as db:
        image_count = db._conn.execute("SELECT COUNT(*) FROM images").fetchone()[0]
        assert image_count == 2


def test_ingest_no_roms_in_directory(runner, data_dir, tmp_path):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "ingest", str(empty_dir)])

    assert result.exit_code == 0, result.output
    assert "No ROM files found" in result.output
