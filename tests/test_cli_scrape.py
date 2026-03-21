"""Tests for the 'psp-etl scrape' CLI command."""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from psp_etl.cli import cli
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
