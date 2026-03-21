"""Tests for the Gigabyte BIOS scraper."""

from __future__ import annotations

import asyncio
import hashlib
import io
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bs4 import BeautifulSoup

from psp_etl.scrape.base import BiosUpdate, BoardInfo
from psp_etl.scrape.gigabyte import (
    GigabyteScraper,
    _extract_date_from_element,
    _extract_rom_from_zip,
    _extract_version_from_element,
    _extract_version_from_url,
    _slug_to_name,
)


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _make_board(model="B550M DS3H", socket="AM4") -> BoardInfo:
    return BoardInfo(
        vendor="Gigabyte",
        model=model,
        socket=socket,
        url="https://www.gigabyte.com/Motherboard/B550M-DS3H-rev-10/support",
    )


def _make_update(version="F15") -> BiosUpdate:
    board = _make_board()
    return BiosUpdate(
        board=board,
        bios_version=version,
        download_url="https://download.gigabyte.com/FileList/BIOS/mb_bios_b550m-ds3h_f15.zip",
        release_date="2022-08-05",
        agesa_version=None,
    )


def _make_zip(filename: str, content: bytes) -> bytes:
    """Create a minimal ZIP archive with one file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Slug-to-name conversion
# ---------------------------------------------------------------------------


def test_slug_to_name_strips_revision():
    assert _slug_to_name("B550M-DS3H-rev-10") == "B550M DS3H"


def test_slug_to_name_strips_multi_revision():
    assert _slug_to_name("B550M-DS3H-rev-10-11") == "B550M DS3H"


def test_slug_to_name_no_revision():
    assert _slug_to_name("X870E-AORUS-MASTER") == "X870E AORUS MASTER"


def test_slug_to_name_complex():
    assert _slug_to_name("Z790-AORUS-ELITE-AX-ICE-rev-10") == "Z790 AORUS ELITE AX ICE"


# ---------------------------------------------------------------------------
# Version extraction from URL
# ---------------------------------------------------------------------------


def test_extract_version_from_url_standard():
    url = "https://download.gigabyte.com/FileList/BIOS/mb_bios_b550m-ds3h_f15.zip"
    assert _extract_version_from_url(url) == "F15"


def test_extract_version_from_url_letter_suffix():
    url = "https://download.gigabyte.com/FileList/BIOS/mb_bios_x870e-aorus-master_f6b.zip"
    assert _extract_version_from_url(url) == "F6B"


def test_extract_version_from_url_no_match():
    assert _extract_version_from_url("https://example.com/file.zip") is None


def test_extract_version_from_url_uppercase():
    url = "https://download.gigabyte.com/FileList/BIOS/mb_bios_b550m-ds3h_F36b.zip"
    result = _extract_version_from_url(url)
    assert result is not None
    assert result.upper() == result


# ---------------------------------------------------------------------------
# Version extraction from HTML element
# ---------------------------------------------------------------------------


def test_extract_version_from_element_link_text():
    soup = BeautifulSoup(
        '<a href="https://download.gigabyte.com/FileList/BIOS/test.zip">F15</a>',
        "html.parser",
    )
    link = soup.find("a")
    assert _extract_version_from_element(link) == "F15"


def test_extract_version_from_element_parent_text():
    soup = BeautifulSoup(
        """
        <tr>
          <td>F36b</td>
          <td>2024-01-01</td>
          <td><a href="https://download.gigabyte.com/FileList/BIOS/test.zip">Download</a></td>
        </tr>
        """,
        "html.parser",
    )
    link = soup.find("a")
    result = _extract_version_from_element(link)
    assert result is not None
    assert "F36B" in result.upper()


# ---------------------------------------------------------------------------
# Date extraction from HTML element
# ---------------------------------------------------------------------------


def test_extract_date_iso_format():
    soup = BeautifulSoup(
        """
        <tr>
          <td>F15</td>
          <td>2022-08-05</td>
          <td><a href="test.zip">Download</a></td>
        </tr>
        """,
        "html.parser",
    )
    link = soup.find("a")
    assert _extract_date_from_element(link) == "2022-08-05"


def test_extract_date_us_format():
    soup = BeautifulSoup(
        """
        <tr>
          <td>F15</td>
          <td>08/05/2022</td>
          <td><a href="test.zip">Download</a></td>
        </tr>
        """,
        "html.parser",
    )
    link = soup.find("a")
    result = _extract_date_from_element(link)
    assert result is not None
    assert "2022" in result


def test_extract_date_not_found():
    soup = BeautifulSoup('<a href="test.zip">Download</a>', "html.parser")
    link = soup.find("a")
    assert _extract_date_from_element(link) is None


# ---------------------------------------------------------------------------
# ZIP ROM extraction
# ---------------------------------------------------------------------------


def test_extract_rom_prefers_rom_extension():
    update = _make_update()
    rom_content = b"\x00" * 16 * 1024 * 1024  # 16 MB dummy ROM
    zip_data = _make_zip("firmware.rom", rom_content)
    result = _extract_rom_from_zip(zip_data, update)
    assert result == rom_content


def test_extract_rom_accepts_bin_extension():
    update = _make_update()
    rom_content = b"\xaa\xbb" * 8 * 1024 * 1024  # 16 MB
    zip_data = _make_zip("bios.bin", rom_content)
    result = _extract_rom_from_zip(zip_data, update)
    assert result == rom_content


def test_extract_rom_version_style_extension():
    update = _make_update()
    rom_content = b"\xff" * 8 * 1024 * 1024
    zip_data = _make_zip("B550M-DS3H.F15", rom_content)
    result = _extract_rom_from_zip(zip_data, update)
    assert result == rom_content


def test_extract_rom_skips_txt_files():
    update = _make_update()
    rom_content = b"\x00" * 1024 * 1024
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as zf:
        zf.writestr("readme.txt", "release notes")
        zf.writestr("firmware.rom", rom_content)
    zip_data = buf.getvalue()
    result = _extract_rom_from_zip(zip_data, update)
    assert result == rom_content


def test_extract_rom_largest_file_fallback():
    update = _make_update()
    small = b"\x11" * 1024
    large = b"\x22" * 1024 * 1024
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as zf:
        zf.writestr("small.dat", small)
        zf.writestr("large.dat", large)
    zip_data = buf.getvalue()
    # Should pick the larger file when no recognized extension
    result = _extract_rom_from_zip(zip_data, update)
    assert result == large


def test_extract_rom_empty_zip_raises():
    update = _make_update()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w"):
        pass
    with pytest.raises(ValueError, match="No ROM file found"):
        _extract_rom_from_zip(buf.getvalue(), update)


# ---------------------------------------------------------------------------
# GigabyteScraper: HTML parsing of board listing
# ---------------------------------------------------------------------------


BOARD_LISTING_HTML = """
<html>
<body>
  <div class="product-list">
    <div class="product-item">
      <a href="/Motherboard/B550M-DS3H-rev-10/support">
        <span class="product-name">B550M DS3H</span>
      </a>
    </div>
    <div class="product-item">
      <a href="/Motherboard/X570-AORUS-MASTER-rev-10/support">
        <span class="product-name">X570 AORUS MASTER</span>
      </a>
    </div>
  </div>
</body>
</html>
"""


def test_parse_board_list_finds_boards():
    scraper = GigabyteScraper()
    soup = BeautifulSoup(BOARD_LISTING_HTML, "html.parser")
    boards = scraper._parse_board_list(soup, "AM4")
    assert len(boards) == 2
    models = [b.model for b in boards]
    assert "B550M DS3H" in models
    assert "X570 AORUS MASTER" in models


def test_parse_board_list_sets_socket():
    scraper = GigabyteScraper()
    soup = BeautifulSoup(BOARD_LISTING_HTML, "html.parser")
    boards = scraper._parse_board_list(soup, "AM5")
    assert all(b.socket == "AM5" for b in boards)


def test_parse_board_list_sets_vendor():
    scraper = GigabyteScraper()
    soup = BeautifulSoup(BOARD_LISTING_HTML, "html.parser")
    boards = scraper._parse_board_list(soup, "AM4")
    assert all(b.vendor == "Gigabyte" for b in boards)


def test_parse_board_list_full_url():
    scraper = GigabyteScraper()
    soup = BeautifulSoup(BOARD_LISTING_HTML, "html.parser")
    boards = scraper._parse_board_list(soup, "AM4")
    for board in boards:
        assert board.url.startswith("https://www.gigabyte.com/Motherboard/")
        assert board.url.endswith("/support")


def test_parse_board_list_deduplicates():
    html = """
    <html><body>
      <a href="/Motherboard/B550M-DS3H-rev-10/support">B550M</a>
      <a href="/Motherboard/B550M-DS3H-rev-10/support">B550M (duplicate)</a>
    </body></html>
    """
    scraper = GigabyteScraper()
    soup = BeautifulSoup(html, "html.parser")
    boards = scraper._parse_board_list(soup, "AM4")
    assert len(boards) == 1


def test_parse_board_list_empty_page():
    scraper = GigabyteScraper()
    soup = BeautifulSoup("<html><body><p>No products</p></body></html>", "html.parser")
    boards = scraper._parse_board_list(soup, "AM4")
    assert boards == []


# ---------------------------------------------------------------------------
# GigabyteScraper: HTML parsing of BIOS downloads
# ---------------------------------------------------------------------------


SUPPORT_PAGE_HTML = """
<html>
<body>
  <div id="support-dl-bios">
    <table>
      <tr>
        <td>F36b</td>
        <td>2024-01-15</td>
        <td>16MB</td>
        <td>
          <a href="https://download.gigabyte.com/FileList/BIOS/mb_bios_b550m-ds3h_f36b.zip">
            Download
          </a>
        </td>
      </tr>
      <tr>
        <td>F15</td>
        <td>2022-08-05</td>
        <td>16MB</td>
        <td>
          <a href="https://download.gigabyte.com/FileList/BIOS/mb_bios_b550m-ds3h_f15.zip">
            Download
          </a>
        </td>
      </tr>
    </table>
  </div>
</body>
</html>
"""


def test_parse_bios_downloads_finds_all_versions():
    scraper = GigabyteScraper()
    soup = BeautifulSoup(SUPPORT_PAGE_HTML, "html.parser")
    board = _make_board()
    updates = scraper._parse_bios_downloads(soup, board)
    assert len(updates) == 2


def test_parse_bios_downloads_extracts_version():
    scraper = GigabyteScraper()
    soup = BeautifulSoup(SUPPORT_PAGE_HTML, "html.parser")
    board = _make_board()
    updates = scraper._parse_bios_downloads(soup, board)
    versions = {u.bios_version for u in updates}
    assert "F36B" in versions
    assert "F15" in versions


def test_parse_bios_downloads_extracts_download_url():
    scraper = GigabyteScraper()
    soup = BeautifulSoup(SUPPORT_PAGE_HTML, "html.parser")
    board = _make_board()
    updates = scraper._parse_bios_downloads(soup, board)
    urls = {u.download_url for u in updates}
    assert "https://download.gigabyte.com/FileList/BIOS/mb_bios_b550m-ds3h_f36b.zip" in urls
    assert "https://download.gigabyte.com/FileList/BIOS/mb_bios_b550m-ds3h_f15.zip" in urls


def test_parse_bios_downloads_extracts_date():
    scraper = GigabyteScraper()
    soup = BeautifulSoup(SUPPORT_PAGE_HTML, "html.parser")
    board = _make_board()
    updates = scraper._parse_bios_downloads(soup, board)
    dates = {u.release_date for u in updates}
    assert "2024-01-15" in dates
    assert "2022-08-05" in dates


def test_parse_bios_downloads_sets_board():
    scraper = GigabyteScraper()
    soup = BeautifulSoup(SUPPORT_PAGE_HTML, "html.parser")
    board = _make_board()
    updates = scraper._parse_bios_downloads(soup, board)
    assert all(u.board is board for u in updates)


def test_parse_bios_downloads_no_links():
    scraper = GigabyteScraper()
    soup = BeautifulSoup("<html><body><p>No downloads</p></body></html>", "html.parser")
    board = _make_board()
    updates = scraper._parse_bios_downloads(soup, board)
    assert updates == []


def test_parse_bios_downloads_data_href_fallback():
    """Test fallback to data-href attribute for lazy-loaded download links."""
    html = """
    <html><body>
      <div id="support-dl-bios">
        <a data-href="https://download.gigabyte.com/FileList/BIOS/mb_bios_b550m-ds3h_f15.zip">
          Download
        </a>
      </div>
    </body></html>
    """
    scraper = GigabyteScraper()
    soup = BeautifulSoup(html, "html.parser")
    board = _make_board()
    updates = scraper._parse_bios_downloads(soup, board)
    assert len(updates) == 1
    assert updates[0].bios_version == "F15"


# ---------------------------------------------------------------------------
# GigabyteScraper: download integration
# ---------------------------------------------------------------------------


def test_download_creates_rom_file(tmp_path):
    """Test that download() creates a .rom file with correct SHA-256 name."""
    rom_content = b"\x11\x22\x33" * (1024 * 1024 // 3 + 1)
    zip_data = _make_zip("firmware.rom", rom_content)

    update = _make_update()
    scraper = GigabyteScraper()
    scraper._client = MagicMock()  # satisfy _require_client()

    mock_response = MagicMock()
    mock_response.content = zip_data
    mock_response.status_code = 200

    with patch.object(scraper, "_get", new=AsyncMock(return_value=mock_response)):
        rom_path = asyncio.run(scraper.download(update, tmp_path))

    assert rom_path.exists()
    assert rom_path.suffix == ".rom"
    expected_hash = hashlib.sha256(rom_content).hexdigest()
    assert rom_path.name == f"{expected_hash}.rom"
    assert rom_path.read_bytes() == rom_content


def test_download_deduplicates(tmp_path):
    """Test that download() returns existing file without re-downloading."""
    rom_content = b"\xaa" * 1024
    zip_data = _make_zip("firmware.rom", rom_content)
    rom_hash = hashlib.sha256(rom_content).hexdigest()

    # Pre-create the ROM file
    existing = tmp_path / f"{rom_hash}.rom"
    existing.write_bytes(rom_content)

    update = _make_update()
    scraper = GigabyteScraper()
    scraper._client = MagicMock()  # satisfy _require_client()

    mock_response = MagicMock()
    mock_response.content = zip_data
    mock_response.status_code = 200

    with patch.object(scraper, "_get", new=AsyncMock(return_value=mock_response)):
        rom_path = asyncio.run(scraper.download(update, tmp_path))

    # File should exist and be returned even if already downloaded
    assert rom_path == existing


# ---------------------------------------------------------------------------
# GigabyteScraper: interface conformance
# ---------------------------------------------------------------------------


def test_gigabyte_scraper_is_vendor_scraper():
    from psp_etl.scrape.base import VendorScraper

    assert isinstance(GigabyteScraper(), VendorScraper)


def test_gigabyte_scraper_default_sockets():
    scraper = GigabyteScraper()
    assert "AM4" in scraper.sockets
    assert "AM5" in scraper.sockets


def test_gigabyte_scraper_custom_sockets():
    scraper = GigabyteScraper(sockets=["AM5"])
    assert scraper.sockets == ["AM5"]
