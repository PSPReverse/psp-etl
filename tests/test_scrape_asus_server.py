"""Tests for ASUS server EPYC scraper."""

import asyncio
import zipfile
from io import BytesIO
from pathlib import Path

import httpx
import pytest

from psp_etl.scrape.asus import ASUS_CAP_HEADER_SIZE
from psp_etl.scrape.asus_server import (
    AsusServerScraper,
    _extract_server_agesa,
    _socket_for_model,
)
from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper

# ---------------------------------------------------------------------------
# Socket inference
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("KRPA-U16", "SP3"),
        ("KRPG-U8", "SP3"),
        ("KMPP-D32", "SP3"),
        ("K14PA-U12", "SP5"),
        ("K14PA-U24", "SP5"),
        ("K14PA-U12-Z", "SP5"),
        ("K14PG-U-Z", "SP6"),
        ("S14NA-U12", "SP6"),
        ("S14PA-U12", "SP6"),
        ("k14pa-u12", "SP5"),  # case-insensitive
    ],
)
def test_socket_for_model_known(model, expected):
    assert _socket_for_model(model) == expected


@pytest.mark.parametrize("model", ["P13R-I", "Z13PE-D16", "P12R-M", "ROG STRIX X670E"])
def test_socket_for_model_intel_or_consumer_returns_none(model):
    assert _socket_for_model(model) is None


# ---------------------------------------------------------------------------
# AGESA extraction (server-flavoured strings)
# ---------------------------------------------------------------------------


def test_extract_server_agesa_rome_pi():
    assert _extract_server_agesa("Update Agesa code to RomePI 1.0.0.E.") == "RomePI 1.0.0.E"


def test_extract_server_agesa_milan_crb():
    assert _extract_server_agesa("Update RC version to 5.22 MilanCrb 0AC0U025.") == "MilanCrb 0AC0U025"


def test_extract_server_agesa_genoa_code_to():
    assert _extract_server_agesa("Update Genoa Agesa code to 1.0.0.G.") == "Genoa 1.0.0.G"


def test_extract_server_agesa_milan_code_to():
    assert _extract_server_agesa("Update Milan Agesa code to 1.0.0.9") == "Milan 1.0.0.9"


def test_extract_server_agesa_none():
    assert _extract_server_agesa(None) is None
    assert _extract_server_agesa("Bug fixes only.") is None


# ---------------------------------------------------------------------------
# Catalog HTML scraping
# ---------------------------------------------------------------------------

_CATALOG_HTML = """\
<html><body>
<a href="/products/servers/server-motherboards/P13R-I"><h2>P13R-I</h2></a>
<a href="/products/servers/server-motherboards/K14PA-U12"><h2>K14PA-U12</h2></a>
<a href="/products/servers/server-motherboards/K14PA-U12"><h2>duplicate</h2></a>
<a href="/products/servers/server-motherboards/Z13PE-D16"><h2>Z13PE-D16</h2></a>
<a href="/products/servers/server-motherboards/S14NA-U12"><h2>S14NA-U12</h2></a>
<a href="/products/servers/server-motherboards/P12R-M"><h2>P12R-M</h2></a>
</body></html>
"""


def test_list_boards_filters_to_amd_epyc_and_adds_legacy():
    """list_boards keeps AMD EPYC catalog entries (de-dupes), filters Intel,
    and merges in the curated legacy KRPA-U16."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert "servers.asus.com" in str(request.url)
        return httpx.Response(200, text=_CATALOG_HTML)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    async def run():
        async with AsusServerScraper(client=client) as scraper:
            return await scraper.list_boards()

    boards = asyncio.run(run())
    by_model = {b.model: b for b in boards}

    # AMD EPYC current SKUs picked up
    assert "K14PA-U12" in by_model
    assert by_model["K14PA-U12"].socket == "SP5"
    assert "S14NA-U12" in by_model
    assert by_model["S14NA-U12"].socket == "SP6"

    # Legacy SP3 board merged in
    assert "KRPA-U16" in by_model
    assert by_model["KRPA-U16"].socket == "SP3"

    # Intel boards excluded
    assert "P13R-I" not in by_model
    assert "Z13PE-D16" not in by_model
    assert "P12R-M" not in by_model

    # No duplicate K14PA-U12
    assert sum(1 for b in boards if b.model == "K14PA-U12") == 1

    # Vendor + URL shape
    for b in boards:
        assert b.vendor == "ASUS"
        assert b.url.startswith("https://servers.asus.com/products/servers/server-motherboards/")


# ---------------------------------------------------------------------------
# list_bios_updates against mocked support API
# ---------------------------------------------------------------------------

_BIOS_API_RESPONSE = {
    "Status": "SUCCESS",
    "Result": {
        "Obj": [
            {
                "Name": "BIOS",
                "Files": [
                    {
                        "Version": "2305",
                        "ReleaseDate": "2026/04/29",
                        "Description": "1. Updated Genoa Agesa code to 1.0.0.G.",
                        "DownloadUrl": {
                            "Global": "/pub/ASUS/server/K14PA-U12/BIOS/K14PA-U12-ASUS-2305.zip",
                            "China": None,
                        },
                    },
                    {
                        "Version": "0601",
                        "ReleaseDate": "2024/07/26",
                        "Description": "1. Update Genoa Agesa code to 1.0.0.C",
                        "DownloadUrl": {
                            "Global": "/pub/ASUS/K14PA-U12-ASUS-0601.zip",
                            "China": None,
                        },
                    },
                ],
            },
            {  # BMC firmware - must be ignored
                "Name": "Firmware",
                "Files": [{"Version": "1.2.37", "DownloadUrl": {"Global": "/bmc.zip"}}],
            },
        ]
    },
}


def test_list_bios_updates_parses_server_response():
    board = BoardInfo(
        vendor="ASUS",
        model="K14PA-U12",
        socket="SP5",
        url="https://servers.asus.com/products/servers/server-motherboards/K14PA-U12",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        # Verify we hit the consumer support API with the server model name
        assert "support/webapi/ProductV2/GetPDBIOS" in str(request.url)
        assert "model=K14PA-U12" in str(request.url)
        return httpx.Response(200, json=_BIOS_API_RESPONSE)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    async def run():
        async with AsusServerScraper(client=client) as scraper:
            return await scraper.list_bios_updates(board)

    updates = asyncio.run(run())
    assert len(updates) == 2

    u0 = updates[0]
    assert u0.bios_version == "2305"
    assert u0.release_date == "2026/04/29"
    assert u0.agesa_version == "Genoa 1.0.0.G"
    assert u0.download_url == "https://dlcdnets.asus.com/pub/ASUS/server/K14PA-U12/BIOS/K14PA-U12-ASUS-2305.zip"

    u1 = updates[1]
    assert u1.bios_version == "0601"
    assert u1.agesa_version == "Genoa 1.0.0.C"


def test_list_bios_updates_failure_status_returns_empty():
    board = BoardInfo(vendor="ASUS", model="KRPG-U8", socket="SP3", url="https://example.com")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"Status": "FAIL", "Message": "Input string was not in a correct format.", "Result": None}
        )

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    async def run():
        async with AsusServerScraper(client=client) as scraper:
            return await scraper.list_bios_updates(board)

    assert asyncio.run(run()) == []


# ---------------------------------------------------------------------------
# CAP header stripping (server BIOSes use the same 0x800 capsule header)
# ---------------------------------------------------------------------------


def _make_cap_zip(rom: bytes, cap_name: str = "K14PA-U12-ASUS-2305.CAP") -> bytes:
    cap_data = b"\x00" * ASUS_CAP_HEADER_SIZE + rom
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(cap_name, cap_data)
    return buf.getvalue()


def test_download_strips_cap_header(tmp_path: Path):
    rom_payload = b"AMD_PSP_ROM_PAYLOAD" * 50
    zip_bytes = _make_cap_zip(rom_payload)

    transport = httpx.MockTransport(lambda _req: httpx.Response(200, content=zip_bytes))
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(vendor="ASUS", model="K14PA-U12", socket="SP5", url="https://example.com")
    update = BiosUpdate(
        board=board,
        bios_version="2305",
        download_url="https://dlcdnets.asus.com/pub/ASUS/server/K14PA-U12/BIOS/K14PA-U12-ASUS-2305.zip",
        release_date=None,
        agesa_version=None,
    )

    async def run():
        async with AsusServerScraper(client=client) as scraper:
            return await scraper.download(update, tmp_path)

    out = asyncio.run(run())
    assert out.exists()
    assert out.read_bytes() == rom_payload
    assert out.name.endswith(".rom")


def test_download_raises_when_no_cap(tmp_path: Path):
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "no rom here")
    transport = httpx.MockTransport(lambda _req: httpx.Response(200, content=buf.getvalue()))
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(vendor="ASUS", model="K14PA-U12", socket="SP5", url="https://example.com")
    update = BiosUpdate(
        board=board,
        bios_version="0",
        download_url="https://example.com/x.zip",
        release_date=None,
        agesa_version=None,
    )

    async def run():
        async with AsusServerScraper(client=client) as scraper:
            await scraper.download(update, tmp_path)

    with pytest.raises(ValueError, match=r"No \.CAP file"):
        asyncio.run(run())


# ---------------------------------------------------------------------------
# Misc guards
# ---------------------------------------------------------------------------


def test_scraper_requires_context_manager():
    scraper = AsusServerScraper()
    board = BoardInfo(vendor="ASUS", model="K14PA-U12", socket="SP5", url="https://example.com")

    async def run():
        await scraper.list_bios_updates(board)

    with pytest.raises(RuntimeError, match="async context manager"):
        asyncio.run(run())


def test_asus_server_scraper_is_vendor_scraper():
    assert issubclass(AsusServerScraper, VendorScraper)
