"""Tests for ASUS vendor scraper."""

import zipfile
from io import BytesIO
from pathlib import Path

import httpx
import pytest

from psp_etl.scrape.asus import (
    ASUS_CAP_HEADER_SIZE,
    AsusScraper,
    _detect_socket,
    _extract_agesa,
    _strip_html,
)
from psp_etl.scrape.base import BiosUpdate, BoardInfo

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def test_strip_html_basic():
    assert _strip_html("<h2>PRIME A520M-R-CSM</h2>") == "PRIME A520M-R-CSM"


def test_strip_html_entities():
    assert _strip_html("Ryzen&trade; AM4") == "Ryzen™ AM4"


def test_strip_html_nested():
    assert _strip_html("<span><b>ROG STRIX</b></span>") == "ROG STRIX"


def test_strip_html_plain():
    assert _strip_html("PRIME B550-PLUS") == "PRIME B550-PLUS"


def test_strip_html_strips_whitespace():
    assert _strip_html("  <h2>  B550M Steel Legend  </h2>  ") == "B550M Steel Legend"


# ---------------------------------------------------------------------------
# Socket detection
# ---------------------------------------------------------------------------


def test_detect_socket_am5():
    assert _detect_socket("ROG CROSSHAIR X670E HERO") == "AM5"
    assert _detect_socket("PRIME B650-PLUS") == "AM5"
    assert _detect_socket("ProArt B850-CREATOR") == "AM5"
    assert _detect_socket("TUF GAMING X870-PLUS") == "AM5"
    assert _detect_socket("ROG STRIX A620-F GAMING") == "AM5"


def test_detect_socket_am4():
    assert _detect_socket("ROG CROSSHAIR VIII HERO X570") == "AM4"
    assert _detect_socket("PRIME B550-PLUS") == "AM4"
    assert _detect_socket("TUF GAMING B450-PRO GAMING") == "AM4"
    assert _detect_socket("ROG STRIX B350-F GAMING") == "AM4"
    assert _detect_socket("ROG STRIX X570-E GAMING") == "AM4"


def test_detect_socket_unknown():
    assert _detect_socket("ROG MAXIMUS XIII APEX") is None  # Z590 = Intel
    assert _detect_socket("WS C422 PRO/SE") is None


def test_extract_agesa_combopi():
    desc = "Update BIOS to support ComboAM5PI_1.3.0.0a AGESA."
    assert _extract_agesa(desc) == "ComboAM5PI_1.3.0.0a"


def test_extract_agesa_comboam4v2():
    desc = "1. Update ComboAM4v2PI_1.2.0.7 microcode"
    result = _extract_agesa(desc)
    assert result is not None
    assert "ComboAM4v2PI_1.2.0.7" in result


def test_extract_agesa_with_space():
    desc = "ComboAM5 PI_1.3.0.0 support"
    result = _extract_agesa(desc)
    assert result is not None


def test_extract_agesa_none():
    assert _extract_agesa(None) is None
    assert _extract_agesa("Bug fixes and stability improvements.") is None


# ---------------------------------------------------------------------------
# CAP header stripping (no network required)
# ---------------------------------------------------------------------------


def _make_bios_zip(cap_data: bytes, cap_name: str = "PRIME_X670-P_BIOS.CAP") -> bytes:
    """Create an in-memory ZIP containing a single .CAP file."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(cap_name, cap_data)
    return buf.getvalue()


def test_download_strips_cap_header(tmp_path: Path):
    """AsusScraper.download() must strip 0x800 bytes from the start of the .CAP."""
    rom_magic = b"BIOS_ROM_CONTENT_GOES_HERE" * 100
    cap_header = b"\x00" * ASUS_CAP_HEADER_SIZE
    cap_data = cap_header + rom_magic
    zip_bytes = _make_bios_zip(cap_data)

    transport = httpx.MockTransport(lambda _req: httpx.Response(200, content=zip_bytes))
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(
        vendor="ASUS",
        model="PRIME X670-P",
        socket="AM5",
        url="https://example.com",
    )
    update = BiosUpdate(
        board=board,
        bios_version="1234",
        download_url="https://dlcdnets.asus.com/pub/ASUS/mb/SocketAM5/PRIME_X670-P/PRIME_X670-P_BIOS.zip",
        release_date=None,
        agesa_version=None,
    )

    import asyncio

    async def run():
        async with AsusScraper(client=client) as scraper:
            out = await scraper.download(update, tmp_path)
        return out

    out = asyncio.run(run())
    assert out.exists()
    assert out.read_bytes() == rom_magic


def test_download_raises_when_no_cap(tmp_path: Path):
    """download() must raise ValueError when the ZIP has no .CAP file."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "nothing here")
    zip_bytes = buf.getvalue()

    transport = httpx.MockTransport(lambda _req: httpx.Response(200, content=zip_bytes))
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(vendor="ASUS", model="PRIME X670-P", socket="AM5", url="https://example.com")
    update = BiosUpdate(
        board=board,
        bios_version="0",
        download_url="https://dlcdnets.asus.com/pub/nocap.zip",
        release_date=None,
        agesa_version=None,
    )

    import asyncio

    async def run():
        async with AsusScraper(client=client) as scraper:
            await scraper.download(update, tmp_path)

    with pytest.raises(ValueError, match=r"No \.CAP file"):
        asyncio.run(run())


# ---------------------------------------------------------------------------
# list_bios_updates (mocked API)
# ---------------------------------------------------------------------------

_BIOS_API_RESPONSE = {
    "Status": "SUCCESS",
    "Result": {
        "Obj": [
            {
                "Name": "BIOS",
                "Files": [
                    {
                        "Version": "2001",
                        "ReleaseDate": "2024-01-15",
                        "Description": "1. Update ComboAM5PI_1.3.0.0a\n2. Fix BIOS boot issue",
                        "DownloadUrl": {"Global": "/pub/ASUS/mb/SocketAM5/PRIME_X670-P/PRIME_X670-P-ASUS-2001.zip"},
                    },
                    {
                        "Version": "1902",
                        "ReleaseDate": "2023-09-01",
                        "Description": "Update ComboAM4v2PI_1.2.0.7",
                        "DownloadUrl": {"Global": "/pub/ASUS/mb/SocketAM5/PRIME_X670-P/PRIME_X670-P-ASUS-1902.zip"},
                    },
                ],
            },
            {
                "Name": "Driver",  # should be ignored
                "Files": [{"Version": "99", "DownloadUrl": {"Global": "/driver.zip"}}],
            },
        ]
    },
}


def test_list_bios_updates_parses_response():
    import asyncio

    board = BoardInfo(
        vendor="ASUS",
        model="PRIME X670-P",
        socket="AM5",
        url="https://example.com",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_BIOS_API_RESPONSE)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    async def run():
        async with AsusScraper(client=client) as scraper:
            return await scraper.list_bios_updates(board)

    updates = asyncio.run(run())
    assert len(updates) == 2

    # First update
    u0 = updates[0]
    assert u0.bios_version == "2001"
    assert u0.release_date == "2024-01-15"
    assert u0.agesa_version is not None and "ComboAM5PI_1.3.0.0a" in u0.agesa_version
    assert u0.download_url.startswith("https://dlcdnets.asus.com")
    assert u0.download_url.endswith(".zip")

    # Second update
    u1 = updates[1]
    assert u1.bios_version == "1902"
    assert u1.release_date == "2023-09-01"


def test_list_bios_updates_failure_status():
    """Returns empty list when API status is not SUCCESS."""
    import asyncio

    board = BoardInfo(vendor="ASUS", model="ROG NONEXISTENT", socket="AM5", url="https://example.com")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"Status": "FAILURE", "Result": {}})

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    async def run():
        async with AsusScraper(client=client) as scraper:
            return await scraper.list_bios_updates(board)

    assert asyncio.run(run()) == []


# ---------------------------------------------------------------------------
# Context manager guard
# ---------------------------------------------------------------------------


def test_scraper_requires_context_manager():
    import asyncio

    scraper = AsusScraper()
    board = BoardInfo(vendor="ASUS", model="PRIME X670-P", socket="AM5", url="https://example.com")

    async def run():
        await scraper.list_bios_updates(board)

    with pytest.raises(RuntimeError, match="async context manager"):
        asyncio.run(run())


# ---------------------------------------------------------------------------
# list_boards – HTML stripping via mocked SeriesFilterResult API
# ---------------------------------------------------------------------------

_SERIES_FILTER_RESPONSE = {
    "Result": {
        "Total": 2,
        "ProductList": [
            {
                "Name": "<h2>PRIME A520M-R-CSM</h2>",
                "ProductURL": "https://www.asus.com/motherboards-components/motherboards/csm/prime-a520m-r-csm/",
            },
            {
                "Name": "<h2>ROG STRIX B550-F GAMING (WI-FI)</h2>",
                "ProductURL": "https://www.asus.com/motherboards-components/motherboards/rog/rog-strix-b550-f-gaming-wi-fi/",
            },
        ],
    }
}


def test_list_boards_strips_html_tags():
    """Board names returned by the ASUS API must have HTML tags removed."""
    import asyncio

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_SERIES_FILTER_RESPONSE)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    async def run():
        async with AsusScraper(client=client) as scraper:
            return await scraper.list_boards()

    boards = asyncio.run(run())
    names = [b.model for b in boards]
    assert "PRIME A520M-R-CSM" in names
    assert "ROG STRIX B550-F GAMING (WI-FI)" in names
    for name in names:
        assert "<" not in name, f"HTML tag found in board name: {name!r}"
        assert ">" not in name, f"HTML tag found in board name: {name!r}"


# ---------------------------------------------------------------------------
# AsusScraper is a VendorScraper subclass
# ---------------------------------------------------------------------------


def test_asus_scraper_is_vendor_scraper():
    from psp_etl.scrape.base import VendorScraper

    assert issubclass(AsusScraper, VendorScraper)
