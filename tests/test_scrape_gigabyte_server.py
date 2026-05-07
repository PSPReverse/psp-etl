"""Tests for the Gigabyte server (EPYC MZ-series) BIOS scraper."""

from __future__ import annotations

import asyncio
import hashlib
import io
import zipfile
from unittest.mock import AsyncMock, MagicMock, patch

from bs4 import BeautifulSoup

from psp_etl.scrape.base import BiosUpdate, BoardInfo
from psp_etl.scrape.gigabyte_server import (
    GigabyteServerScraper,
    _extract_server_version_from_url,
    _slug_to_model,
    _socket_for_model,
)


def _make_board(model="MZ73-LM0", socket="SP5") -> BoardInfo:
    return BoardInfo(
        vendor="Gigabyte",
        model=model,
        socket=socket,
        url=f"https://www.gigabyte.com/Enterprise/Server-Motherboard/{model}-rev-3x/support",
    )


def _make_update(model="MZ73-LM0", version="R07_F33") -> BiosUpdate:
    board = _make_board(model=model)
    return BiosUpdate(
        board=board,
        bios_version=version,
        download_url=f"https://download.gigabyte.com/FileList/BIOS/mb_bios_{model}_{version}.zip",
        release_date="2024-09-12",
        agesa_version=None,
    )


def _make_zip(filename: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_socket_for_model_sp3_naples():
    assert _socket_for_model("MZ31-AR0") == "SP3"
    assert _socket_for_model("MZ32-AR0") == "SP3"
    assert _socket_for_model("MZ72-HB0") == "SP3"
    assert _socket_for_model("MZ01-CE0") == "SP3"


def test_socket_for_model_sp5_genoa():
    assert _socket_for_model("MZ33-AR0") == "SP5"
    assert _socket_for_model("MZ73-LM0") == "SP5"
    assert _socket_for_model("MZ73-LM1") == "SP5"


def test_socket_for_model_sp6_siena():
    assert _socket_for_model("MZ34-AR0") == "SP6"


def test_socket_for_model_unknown_returns_none():
    assert _socket_for_model("X870E-AORUS-MASTER") is None
    assert _socket_for_model("MZ99-FOO") is None


def test_socket_for_model_case_insensitive():
    assert _socket_for_model("mz73-lm0") == "SP5"


def test_slug_to_model_strips_simple_revision():
    assert _slug_to_model("MZ73-LM0-rev-3x") == "MZ73-LM0"


def test_slug_to_model_strips_compound_revision():
    assert _slug_to_model("MZ33-AR0-rev-1x-3x") == "MZ33-AR0"


def test_slug_to_model_strips_numeric_revision():
    assert _slug_to_model("MZ72-HB0-rev-30") == "MZ72-HB0"


def test_slug_to_model_no_revision():
    assert _slug_to_model("MZ73-LM0") == "MZ73-LM0"


def test_slug_to_model_uppercases():
    assert _slug_to_model("mz73-lm0-rev-3x") == "MZ73-LM0"


# ---------------------------------------------------------------------------
# Server URL version extraction
# ---------------------------------------------------------------------------


def test_extract_server_version_from_url_standard():
    url = "https://download.gigabyte.com/FileList/BIOS/mb_bios_MZ73-LM0_R07_F33.zip"
    assert _extract_server_version_from_url(url) == "R07_F33"


def test_extract_server_version_from_url_with_query():
    url = "https://download.gigabyte.com/FileList/BIOS/mb_bios_MZ33-AR1_R05_F04.zip?v=abcdef0123"
    assert _extract_server_version_from_url(url) == "R05_F04"


def test_extract_server_version_from_url_double_digit_rev():
    url = "https://download.gigabyte.com/FileList/BIOS/mb_bios_MZ73-LM1_R10_F36.zip"
    assert _extract_server_version_from_url(url) == "R10_F36"


def test_extract_server_version_from_url_fallback_no_rev():
    url = "https://download.gigabyte.com/FileList/BIOS/mb_bios_MZ73-LM0_F33.zip"
    assert _extract_server_version_from_url(url) == "F33"


def test_extract_server_version_from_url_no_match():
    assert _extract_server_version_from_url("https://example.com/file.tgz") is None


# ---------------------------------------------------------------------------
# _parse_board_list
# ---------------------------------------------------------------------------


CATALOG_HTML = """
<html>
<body>
  <div class="product-list">
    <div class="product-item">
      <a href="/Enterprise/Server-Motherboard/MZ73-LM0-rev-3x">
        <span class="product-name">MZ73-LM0</span>
      </a>
    </div>
    <div class="product-item">
      <a href="/Enterprise/Server-Motherboard/MZ33-AR0-rev-1x-3x">MZ33-AR0</a>
    </div>
    <div class="product-item">
      <a href="/Enterprise/Server-Motherboard/MZ34-AR0-rev-10">MZ34-AR0</a>
    </div>
    <div class="product-item">
      <a href="/Enterprise/Server-Motherboard/MZ31-AR0-rev-3x">MZ31-AR0</a>
    </div>
    <div class="product-item">
      <a href="/Enterprise/x86-Server/R182-Z90-rev-100">R182-Z90 (irrelevant)</a>
    </div>
  </div>
</body>
</html>
"""


def test_parse_board_list_finds_mz_boards():
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(CATALOG_HTML, "html.parser")
    boards = scraper._parse_board_list(soup)
    models = {b.model for b in boards}
    assert {"MZ73-LM0", "MZ33-AR0", "MZ34-AR0", "MZ31-AR0"} <= models


def test_parse_board_list_skips_non_motherboard_links():
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(CATALOG_HTML, "html.parser")
    boards = scraper._parse_board_list(soup)
    models = {b.model for b in boards}
    assert "R182-Z90" not in models


def test_parse_board_list_assigns_socket_per_model():
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(CATALOG_HTML, "html.parser")
    boards = {b.model: b for b in scraper._parse_board_list(soup)}
    assert boards["MZ73-LM0"].socket == "SP5"
    assert boards["MZ33-AR0"].socket == "SP5"
    assert boards["MZ34-AR0"].socket == "SP6"
    assert boards["MZ31-AR0"].socket == "SP3"


def test_parse_board_list_full_url():
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(CATALOG_HTML, "html.parser")
    for board in scraper._parse_board_list(soup):
        assert board.url.startswith("https://www.gigabyte.com/Enterprise/Server-Motherboard/")
        assert board.url.endswith("/support")


def test_parse_board_list_sets_vendor():
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(CATALOG_HTML, "html.parser")
    for board in scraper._parse_board_list(soup):
        assert board.vendor == "Gigabyte"


def test_parse_board_list_deduplicates_by_slug():
    html = """
    <html><body>
      <a href="/Enterprise/Server-Motherboard/MZ73-LM0-rev-3x">a</a>
      <a href="/Enterprise/Server-Motherboard/MZ73-LM0-rev-3x">duplicate</a>
    </body></html>
    """
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(html, "html.parser")
    boards = scraper._parse_board_list(soup)
    assert len(boards) == 1


def test_parse_board_list_keeps_separate_revisions():
    """Different rev slugs of the same model are distinct boards (own BIOS lists)."""
    html = """
    <html><body>
      <a href="/Enterprise/Server-Motherboard/MZ73-LM0-rev-1x">rev1</a>
      <a href="/Enterprise/Server-Motherboard/MZ73-LM0-rev-3x">rev3</a>
    </body></html>
    """
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(html, "html.parser")
    boards = scraper._parse_board_list(soup)
    assert len(boards) == 2
    urls = {b.url for b in boards}
    assert any("rev-1x" in u for u in urls)
    assert any("rev-3x" in u for u in urls)


def test_parse_board_list_skips_unknown_socket_prefix():
    html = """
    <html><body>
      <a href="/Enterprise/Server-Motherboard/MZ99-XYZ-rev-10">unknown</a>
      <a href="/Enterprise/Server-Motherboard/MZ73-LM0-rev-3x">known</a>
    </body></html>
    """
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(html, "html.parser")
    models = {b.model for b in scraper._parse_board_list(soup)}
    assert "MZ73-LM0" in models
    assert "MZ99-XYZ" not in models


def test_parse_board_list_empty_page():
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup("<html><body><p>No products</p></body></html>", "html.parser")
    assert scraper._parse_board_list(soup) == []


# ---------------------------------------------------------------------------
# list_boards (with mocked HTTP)
# ---------------------------------------------------------------------------


def test_list_boards_filters_by_socket():
    scraper = GigabyteServerScraper(sockets=["SP5"])
    scraper._client = MagicMock()

    mock_response = MagicMock()
    mock_response.text = CATALOG_HTML
    mock_response.status_code = 200

    with patch.object(scraper, "_get", new=AsyncMock(return_value=mock_response)):
        boards = asyncio.run(scraper.list_boards())

    sockets = {b.socket for b in boards}
    assert sockets == {"SP5"}
    assert {b.model for b in boards} == {"MZ73-LM0", "MZ33-AR0"}


def test_list_boards_default_includes_all_sockets():
    scraper = GigabyteServerScraper()
    scraper._client = MagicMock()

    mock_response = MagicMock()
    mock_response.text = CATALOG_HTML
    mock_response.status_code = 200

    with patch.object(scraper, "_get", new=AsyncMock(return_value=mock_response)):
        boards = asyncio.run(scraper.list_boards())

    assert {b.socket for b in boards} == {"SP3", "SP5", "SP6"}


# ---------------------------------------------------------------------------
# _parse_bios_downloads
# ---------------------------------------------------------------------------


SUPPORT_PAGE_HTML = """
<html>
<body>
  <div id="support-dl-bios">
    <table>
      <tr>
        <td>R07_F33</td>
        <td>2024-09-12</td>
        <td>32MB</td>
        <td>
          <a href="https://download.gigabyte.com/FileList/BIOS/mb_bios_MZ73-LM0_R07_F33.zip?v=abc123">
            Download
          </a>
        </td>
      </tr>
      <tr>
        <td>R04_F32</td>
        <td>2024-04-01</td>
        <td>32MB</td>
        <td>
          <a href="https://download.gigabyte.com/FileList/BIOS/mb_bios_MZ73-LM0_R04_F32.zip">
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
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(SUPPORT_PAGE_HTML, "html.parser")
    updates = scraper._parse_bios_downloads(soup, _make_board())
    assert len(updates) == 2


def test_parse_bios_downloads_extracts_versions():
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(SUPPORT_PAGE_HTML, "html.parser")
    updates = scraper._parse_bios_downloads(soup, _make_board())
    versions = {u.bios_version for u in updates}
    assert "R07_F33" in versions
    assert "R04_F32" in versions


def test_parse_bios_downloads_extracts_urls():
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(SUPPORT_PAGE_HTML, "html.parser")
    updates = scraper._parse_bios_downloads(soup, _make_board())
    urls = {u.download_url for u in updates}
    assert any("mb_bios_MZ73-LM0_R07_F33.zip" in u for u in urls)
    assert any("mb_bios_MZ73-LM0_R04_F32.zip" in u for u in urls)


def test_parse_bios_downloads_extracts_dates():
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(SUPPORT_PAGE_HTML, "html.parser")
    updates = scraper._parse_bios_downloads(soup, _make_board())
    dates = {u.release_date for u in updates}
    assert "2024-09-12" in dates
    assert "2024-04-01" in dates


def test_parse_bios_downloads_data_href_fallback():
    html = """
    <html><body>
      <div id="support-dl-bios">
        <a data-href="https://download.gigabyte.com/FileList/BIOS/mb_bios_MZ73-LM0_R07_F33.zip">
          Download
        </a>
      </div>
    </body></html>
    """
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup(html, "html.parser")
    updates = scraper._parse_bios_downloads(soup, _make_board())
    assert len(updates) == 1
    assert updates[0].bios_version == "R07_F33"


def test_parse_bios_downloads_no_links():
    scraper = GigabyteServerScraper()
    soup = BeautifulSoup("<html><body><p>No downloads</p></body></html>", "html.parser")
    assert scraper._parse_bios_downloads(soup, _make_board()) == []


# ---------------------------------------------------------------------------
# Download (uses inherited helper from GigabyteScraper)
# ---------------------------------------------------------------------------


def test_download_extracts_rom_from_zip(tmp_path):
    rom_content = b"\xee\xff" * (1024 * 1024 // 2)  # 1 MiB dummy ROM
    zip_data = _make_zip("MZ73LM0.bin", rom_content)

    update = _make_update()
    scraper = GigabyteServerScraper()
    scraper._client = MagicMock()

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


# ---------------------------------------------------------------------------
# Interface conformance
# ---------------------------------------------------------------------------


def test_gigabyte_server_scraper_is_vendor_scraper():
    from psp_etl.scrape.base import VendorScraper

    assert isinstance(GigabyteServerScraper(), VendorScraper)


def test_gigabyte_server_scraper_default_sockets():
    scraper = GigabyteServerScraper()
    assert set(scraper.sockets) == {"SP3", "SP5", "SP6"}


def test_gigabyte_server_scraper_custom_sockets():
    scraper = GigabyteServerScraper(sockets=["SP5"])
    assert scraper.sockets == ["SP5"]
