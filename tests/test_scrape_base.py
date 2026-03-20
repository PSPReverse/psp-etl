"""Tests for scraper base classes and dataclasses."""

from pathlib import Path

import pytest

from psp_etl.scrape import BiosUpdate, BoardInfo, VendorScraper


def test_board_info_fields():
    board = BoardInfo(vendor="ASUS", model="ROG CROSSHAIR X670E HERO", socket="AM5", url="https://example.com")
    assert board.vendor == "ASUS"
    assert board.model == "ROG CROSSHAIR X670E HERO"
    assert board.socket == "AM5"
    assert board.url == "https://example.com"


def test_bios_update_fields():
    board = BoardInfo(vendor="MSI", model="MEG X570 UNIFY", socket="AM4", url="https://example.com")
    update = BiosUpdate(
        board=board,
        bios_version="7C35v1L",
        download_url="https://download.example.com/bios.zip",
        release_date="2024-01-15",
        agesa_version="1.2.0.2",
    )
    assert update.board is board
    assert update.bios_version == "7C35v1L"
    assert update.download_url == "https://download.example.com/bios.zip"
    assert update.release_date == "2024-01-15"
    assert update.agesa_version == "1.2.0.2"


def test_bios_update_optional_fields():
    board = BoardInfo(vendor="ASRock", model="B550 Steel Legend", socket="AM4", url="https://example.com")
    update = BiosUpdate(
        board=board,
        bios_version="1.80",
        download_url="https://download.example.com/bios.zip",
        release_date=None,
        agesa_version=None,
    )
    assert update.release_date is None
    assert update.agesa_version is None


def test_vendor_scraper_is_abstract():
    with pytest.raises(TypeError):
        VendorScraper()  # type: ignore[abstract]


def test_vendor_scraper_requires_all_methods():
    class PartialScraper(VendorScraper):
        async def list_boards(self):
            return []

    with pytest.raises(TypeError):
        PartialScraper()  # type: ignore[abstract]


def test_vendor_scraper_concrete_subclass():
    class ConcreteScraper(VendorScraper):
        async def list_boards(self) -> list[BoardInfo]:
            return []

        async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
            return []

        async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
            return dest_dir / "firmware.rom"

    scraper = ConcreteScraper()
    assert isinstance(scraper, VendorScraper)
