"""Tests for psp_etl.scrape.asrock_rack."""

import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest

from psp_etl.scrape.asrock_rack import AsRockRackScraper, classify_rack_socket

# ---------------------------------------------------------------------------
# classify_rack_socket — model -> socket mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model,expected_socket",
    [
        # SP3 (EPYC Naples / Rome / Milan)
        ("ROMED8-2T", "SP3"),
        ("ROMED8U-2T", "SP3"),
        ("ROMED4ID-2T", "SP3"),
        ("ROMED6U-2L2T", "SP3"),
        ("ROMED16QM3", "SP3"),
        ("ROME2D16-2T", "SP3"),
        ("EPYCD8", "SP3"),
        ("EPYCD8-2T", "SP3"),
        # SP5 (EPYC Genoa / Bergamo / Turin)
        ("GENOAD8UD-2T", "SP5"),
        ("GENOAD8UD-2T/X550", "SP5"),
        ("GENOAD24QM3", "SP5"),
        ("GENOAD16TX", "SP5"),
        ("GENOA2D16NQM3-2Q", "SP5"),
        ("TURIND8-2L2T", "SP5"),
        ("TURIN2D24G-2L", "SP5"),
        # SP6 (EPYC Siena)
        ("SIENAD8-2L2T", "SP6"),
        ("SIENAD10HM3", "SP6"),
        ("SIENAD8UD3", "SP6"),
        # Threadripper Pro
        ("WRX80D8-2T", "sWRX8"),
        ("WRX80-RUDI", "sWRX8"),
        ("WRX90", "sWRX9"),
        # Threadripper (non-Pro)
        ("TRX40D8-2N2T", "sTRX4"),
        # AM5 desktop EPYC 4004
        ("EPYC4000D4U", "AM5"),
        # Embedded EPYC 3000 (BGA)
        ("EPYC3101D4I-2T", "AM4-Embedded"),
        ("EPYC3251D4I-2T", "AM4-Embedded"),
        ("EPYC3451D4U-2L2T2O8R", "AM4-Embedded"),
        # AMD desktop chipsets on Rack workstation boards
        ("X470D4U", "AM4"),
        ("X470D4U2-2T", "AM4"),
        ("X570D4I-2T", "AM4"),
        ("X570D4U-2L2T", "AM4"),
        ("B550D4U", "AM4"),
        ("B650D4U-2L2T/BCM", "AM5"),
        ("B650D4U3", "AM5"),
        ("AM5D4ID-2T/BCM", "AM5"),
    ],
)
def test_classify_rack_socket_known_boards(model: str, expected_socket: str) -> None:
    assert classify_rack_socket("Server", model) == expected_socket


@pytest.mark.parametrize(
    "model",
    [
        # Intel boards in the same Server/ folder must NOT classify
        "C246 WS",
        "C2550D4I",
        "EPC612D8",
        "EPC621D8A",
        "E3C246D4U2-2T",
        # Random garbage
        "",
        "FooBar",
    ],
)
def test_classify_rack_socket_rejects_non_amd(model: str) -> None:
    assert classify_rack_socket("Server", model) is None


def test_classify_rack_socket_epyc4000_takes_precedence_over_epyc3xxx() -> None:
    """``EPYC4000`` (AM5) must not be mis-classified as ``EPYC3xxx`` embedded."""
    assert classify_rack_socket("Server", "EPYC4000D4U") == "AM5"
    assert classify_rack_socket("Server", "EPYC3101D4I-2T") == "AM4-Embedded"


# ---------------------------------------------------------------------------
# AsRockRackScraper — list_boards / list_bios_updates against mocked CDX
# ---------------------------------------------------------------------------


_CDX_SERVER = [
    ["original"],
    # AMD Rack boards on the unprotected CDN
    ["https://download.asrock.com/BIOS/Server/X470D4U(3.50)ROM.zip"],
    ["https://download.asrock.com/BIOS/Server/X470D4U2-2T(3.40)ROM.zip"],
    ["https://download.asrock.com/BIOS/Server/X570D4I-2T(L2.08a)ROM.zip"],
    ["https://download.asrock.com/BIOS/Server/TRX40D8-2N2T(01.30.00)BMC.zip"],
    # Intel boards in the same folder — should be filtered out
    ["https://download.asrock.com/BIOS/Server/C246%20WS(2.40)ROM.zip"],
    ["https://download.asrock.com/BIOS/Server/EPC621D8A(2.10)ROM.zip"],
    # Hypothetical EPYC entry — covered forward-compatibly
    ["https://download.asrock.com/BIOS/Server/ROMED8-2T(2.30)ROM.zip"],
]


def _response(status: int, *, json: list | None = None, content: bytes | None = None) -> httpx.Response:
    request = httpx.Request("GET", "https://example.com")
    if json is not None:
        return httpx.Response(status, json=json, request=request)
    return httpx.Response(status, content=content or b"", request=request)


def _mock_client(server_data: list | None = None) -> AsyncMock:
    rows = server_data if server_data is not None else _CDX_SERVER

    async def _get(url: str, **kwargs):
        params = kwargs.get("params", {})
        url_param = str(params.get("url", ""))
        if "Server" in url_param:
            return _response(200, json=rows)
        return _response(404)

    mock = AsyncMock()
    mock.get = _get
    return mock


def test_list_boards_returns_only_amd_models() -> None:
    async def _run():
        scraper = AsRockRackScraper(client=_mock_client())
        boards = await scraper.list_boards()
        models = {b.model for b in boards}
        assert "X470D4U" in models
        assert "X470D4U2-2T" in models
        assert "X570D4I-2T" in models
        assert "TRX40D8-2N2T" in models
        assert "ROMED8-2T" in models
        # Intel boards excluded
        assert "C246 WS" not in models
        assert "EPC621D8A" not in models

    asyncio.run(_run())


def test_list_boards_assigns_correct_socket() -> None:
    async def _run():
        scraper = AsRockRackScraper(client=_mock_client())
        boards = await scraper.list_boards()
        by_model = {b.model: b.socket for b in boards}
        assert by_model["X470D4U"] == "AM4"
        assert by_model["X570D4I-2T"] == "AM4"
        assert by_model["TRX40D8-2N2T"] == "sTRX4"
        assert by_model["ROMED8-2T"] == "SP3"

    asyncio.run(_run())


def test_list_boards_sets_vendor_to_asrock_rack() -> None:
    async def _run():
        scraper = AsRockRackScraper(client=_mock_client())
        boards = await scraper.list_boards()
        assert all(b.vendor == "ASRock Rack" for b in boards)

    asyncio.run(_run())


def test_list_boards_uses_asrockrack_support_url() -> None:
    async def _run():
        scraper = AsRockRackScraper(client=_mock_client())
        boards = await scraper.list_boards()
        for b in boards:
            assert b.url.startswith("https://www.asrockrack.com/general/productdetail.asp?Model=")
        urls = {b.model: b.url for b in boards}
        assert "ROMED8-2T" in urls["ROMED8-2T"]

    asyncio.run(_run())


def test_list_bios_updates_for_amd_board() -> None:
    async def _run():
        scraper = AsRockRackScraper(client=_mock_client())
        boards = {b.model: b for b in await scraper.list_boards()}
        updates = await scraper.list_bios_updates(boards["X470D4U"])
        assert len(updates) == 1
        assert updates[0].bios_version == "3.50"
        assert updates[0].download_url.endswith("X470D4U(3.50)ROM.zip")
        assert updates[0].board.socket == "AM4"

    asyncio.run(_run())


def test_list_bios_updates_unknown_board_returns_empty() -> None:
    async def _run():
        scraper = AsRockRackScraper(client=_mock_client())
        boards = {b.model: b for b in await scraper.list_boards()}
        # Mutate to a model that isn't in the CDX results
        from psp_etl.scrape.base import BoardInfo

        bogus = BoardInfo(
            vendor="ASRock Rack",
            model="DOES_NOT_EXIST",
            socket="SP3",
            url="https://example.com",
        )
        assert await scraper.list_bios_updates(bogus) == []
        # Sanity: real boards still resolve
        assert await scraper.list_bios_updates(boards["TRX40D8-2N2T"])

    asyncio.run(_run())


def test_cdx_cache_one_request_per_folder() -> None:
    http_calls: list[str] = []

    async def _run():
        async def counting_get(url: str, **kwargs):
            params = kwargs.get("params", {})
            http_calls.append(str(params.get("url", "")))
            return _response(200, json=_CDX_SERVER)

        mock = AsyncMock()
        mock.get = counting_get
        scraper = AsRockRackScraper(client=mock)

        await scraper.list_boards()
        first_count = len(http_calls)
        # list_bios_updates should reuse the cache
        boards = {b.model: b for b in await scraper.list_boards()}
        await scraper.list_bios_updates(boards["X470D4U"])
        assert len(http_calls) == first_count

    asyncio.run(_run())


def test_context_manager_creates_client() -> None:
    async def _run():
        async with AsRockRackScraper() as scraper:
            assert scraper._client is not None

    asyncio.run(_run())


def test_require_client_without_context_manager_raises() -> None:
    scraper = AsRockRackScraper()
    with pytest.raises(RuntimeError, match="async with"):
        scraper._require_client()
