"""Tests for the 'psp-etl scrape' CLI command."""

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from psp_etl.cli import cli
from psp_etl.db import Database
from psp_etl.scrape.base import BiosUpdate, BoardInfo


@pytest.fixture
def runner():
    return CliRunner()


class _MockScraper:
    """Simulates real scraper lifecycle: methods raise unless entered via async context manager."""

    _board = BoardInfo(vendor="ASRock", model="B550 Steel Legend", socket="AM4", url="https://example.com")
    _update = BiosUpdate(
        board=_board,
        bios_version="1.80",
        download_url="https://fake.example.com/bios.zip",
        release_date=None,
        agesa_version=None,
    )

    def __init__(self):
        self._entered = False

    async def __aenter__(self):
        self._entered = True
        return self

    async def __aexit__(self, *args):
        self._entered = False

    def _require_client(self):
        if not self._entered:
            raise RuntimeError("Use 'async with _MockScraper() as s:' to manage the client lifecycle")

    async def list_boards(self):
        self._require_client()
        return [self._board]

    async def list_bios_updates(self, board):
        self._require_client()
        return [self._update]


def test_scrape_dry_run_exits_zero(runner, tmp_path):
    with patch("psp_etl.cli._VENDOR_SCRAPERS", {"asrock": _MockScraper}):
        result = runner.invoke(
            cli,
            ["--data-dir", str(tmp_path), "scrape", "asrock", "--dry-run"],
        )

    assert result.exit_code == 0, result.output
    assert "DRY-RUN" in result.output


def _make_vendor_scraper(vendor, model, socket="AM4", boards=None, download_bytes=b""):
    """Return a mock scraper class for the given vendor configuration."""
    if boards is None:
        boards = [BoardInfo(vendor=vendor, model=model, socket=socket, url="https://example.com")]
    _boards = list(boards)
    _download_bytes = download_bytes

    class _Scraper:
        def __init__(self):
            self._entered = False

        async def __aenter__(self):
            self._entered = True
            return self

        async def __aexit__(self, *args):
            self._entered = False

        async def list_boards(self):
            return list(_boards)

        async def list_bios_updates(self, board):
            return [
                BiosUpdate(
                    board=board,
                    bios_version="1.80",
                    download_url=f"https://example.com/{board.model}.zip",
                    release_date=None,
                    agesa_version=None,
                )
            ]

        async def download(self, update, dest_dir: Path) -> Path:
            rom_path = dest_dir / "firmware.rom"
            rom_path.write_bytes(_download_bytes)
            return rom_path

    return _Scraper


def test_scrape_all_runs_all_vendors(runner, tmp_path):
    """'all' vendor argument invokes all three registered scrapers."""
    scrapers = {
        "asrock": _make_vendor_scraper("ASRock", "B550 Steel Legend"),
        "gigabyte": _make_vendor_scraper("Gigabyte", "B550 AORUS PRO"),
        "asus": _make_vendor_scraper("ASUS", "ROG STRIX B550-F"),
    }
    with patch("psp_etl.cli._VENDOR_SCRAPERS", scrapers):
        result = runner.invoke(
            cli,
            ["--data-dir", str(tmp_path), "scrape", "all", "--dry-run"],
        )

    assert result.exit_code == 0, result.output
    assert "asrock" in result.output
    assert "gigabyte" in result.output
    assert "asus" in result.output


def test_scrape_limit_restricts_boards(runner, tmp_path):
    """--limit 1 restricts processing to at most 1 board per vendor."""
    boards = [
        BoardInfo(vendor="ASRock", model="B550 Steel Legend", socket="AM4", url="https://example.com"),
        BoardInfo(vendor="ASRock", model="X570 Phantom Gaming", socket="AM4", url="https://example.com"),
        BoardInfo(vendor="ASRock", model="B450 Pro4", socket="AM4", url="https://example.com"),
    ]
    scraper_cls = _make_vendor_scraper("ASRock", "", boards=boards)
    with patch("psp_etl.cli._VENDOR_SCRAPERS", {"asrock": scraper_cls}):
        result = runner.invoke(
            cli,
            ["--data-dir", str(tmp_path), "scrape", "asrock", "--dry-run", "--limit", "1"],
        )

    assert result.exit_code == 0, result.output
    assert "B550 Steel Legend" in result.output
    assert "X570 Phantom Gaming" not in result.output
    assert "B450 Pro4" not in result.output


def test_scrape_socket_am4_filters_am5(runner, tmp_path):
    """--socket am4 keeps AM4 boards and excludes AM5 boards."""
    boards = [
        BoardInfo(vendor="ASRock", model="B550 Steel Legend", socket="AM4", url="https://example.com"),
        BoardInfo(vendor="ASRock", model="X670E Taichi", socket="AM5", url="https://example.com"),
    ]
    scraper_cls = _make_vendor_scraper("ASRock", "", boards=boards)
    with patch("psp_etl.cli._VENDOR_SCRAPERS", {"asrock": scraper_cls}):
        result = runner.invoke(
            cli,
            ["--data-dir", str(tmp_path), "scrape", "asrock", "--dry-run", "--socket", "am4"],
        )

    assert result.exit_code == 0, result.output
    assert "B550 Steel Legend" in result.output
    assert "X670E Taichi" not in result.output


_ROM_BYTES = b"\x00\x01\x02\x03" * 64
_ROM_SHA256 = hashlib.sha256(_ROM_BYTES).hexdigest()


def test_scrape_download_writes_rom_and_db(runner, tmp_path):
    """Non-dry-run download writes {sha256}.rom to data/roms/ and inserts an Image row."""
    scraper_cls = _make_vendor_scraper("ASRock", "B550 Steel Legend", download_bytes=_ROM_BYTES)
    with patch("psp_etl.cli._VENDOR_SCRAPERS", {"asrock": scraper_cls}):
        result = runner.invoke(
            cli,
            ["--data-dir", str(tmp_path), "scrape", "asrock"],
        )

    assert result.exit_code == 0, result.output
    rom_path = tmp_path / "roms" / f"{_ROM_SHA256}.rom"
    assert rom_path.exists(), f"Expected {rom_path} to exist"
    assert rom_path.read_bytes() == _ROM_BYTES
    with Database(tmp_path / "psp-etl.db") as db:
        row = db.get_image_by_sha256(_ROM_SHA256)
    assert row is not None, f"No Image row for sha256 {_ROM_SHA256[:12]}…"
    assert row["vendor"] == "ASRock"


def test_scrape_duplicate_skipped(runner, tmp_path):
    """A second download of identical bytes is skipped without inserting a duplicate row."""
    scraper_cls = _make_vendor_scraper("ASRock", "B550 Steel Legend", download_bytes=_ROM_BYTES)
    with patch("psp_etl.cli._VENDOR_SCRAPERS", {"asrock": scraper_cls}):
        result1 = runner.invoke(
            cli,
            ["--data-dir", str(tmp_path), "scrape", "asrock"],
        )
        assert result1.exit_code == 0, result1.output
        assert "NEW" in result1.output

        result2 = runner.invoke(
            cli,
            ["--data-dir", str(tmp_path), "scrape", "asrock"],
        )
    assert result2.exit_code == 0, result2.output
    assert "SKIP" in result2.output
