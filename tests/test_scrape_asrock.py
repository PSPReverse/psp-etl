"""Tests for psp_etl.scrape.asrock."""

import asyncio
import io
import zipfile
from unittest.mock import AsyncMock

import httpx
import pytest

from psp_etl.scrape.asrock import (
    AsRockScraper,
    board_support_url,
    extract_rom,
    parse_bios_url,
)
from psp_etl.scrape.base import BiosUpdate, BoardInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_zip(*entries: tuple[str, bytes]) -> zipfile.ZipFile:
    """Create an in-memory ZipFile with the given (name, content) entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries:
            zf.writestr(name, content)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def _fake_board(model: str = "B650 LiveMixer", socket: str = "AM5") -> BoardInfo:
    return BoardInfo(
        vendor="ASRock",
        model=model,
        socket=socket,
        url="https://example.com",
    )


def _fake_update(
    model: str = "B650 LiveMixer",
    version: str = "1.14",
    socket: str = "AM5",
) -> BiosUpdate:
    return BiosUpdate(
        board=_fake_board(model, socket),
        bios_version=version,
        download_url=f"https://download.asrock.com/BIOS/{socket}/{model}({version})ROM.zip",
        release_date=None,
        agesa_version=None,
    )


# CDX-style responses (header row + data rows)
_CDX_AM5 = [
    ["original"],
    ["https://download.asrock.com/BIOS/AM5/B650%20LiveMixer(1.14.AS06)ROM.zip"],
    ["https://download.asrock.com/BIOS/AM5/B650%20LiveMixer(1.18.AS04)ROM.zip"],
    ["https://download.asrock.com/BIOS/AM5/X870E%20Taichi(1.20)ROM.zip"],
]
_CDX_AM4 = [
    ["original"],
    ["https://download.asrock.com/BIOS/AM4/A520M%20Pro4(1.00)ROM.zip"],
]


def _response(
    status: int, *, json: list | None = None, content: bytes | None = None, url: str = "https://example.com"
) -> httpx.Response:
    """Create an httpx.Response with a request attached (required for raise_for_status)."""
    request = httpx.Request("GET", url)
    if json is not None:
        return httpx.Response(status, json=json, request=request)
    return httpx.Response(status, content=content or b"", request=request)


def _mock_client(
    am5_data: list | None = None,
    am4_data: list | None = None,
    download_content: bytes | None = None,
) -> AsyncMock:
    """Return a mock httpx.AsyncClient whose .get() returns preset responses."""
    am5 = am5_data if am5_data is not None else _CDX_AM5
    am4 = am4_data if am4_data is not None else _CDX_AM4

    async def _get(url: str, **kwargs):
        params = kwargs.get("params", {})
        url_param = str(params.get("url", ""))
        if "AM5" in url_param:
            return _response(200, json=am5, url=url)
        if "AM4" in url_param:
            return _response(200, json=am4, url=url)
        if download_content is not None:
            return _response(200, content=download_content, url=url)
        return _response(404, url=url)

    mock = AsyncMock()
    mock.get = _get
    return mock


# ---------------------------------------------------------------------------
# parse_bios_url
# ---------------------------------------------------------------------------


def test_parse_bios_url_am5_with_suffix():
    result = parse_bios_url("https://download.asrock.com/BIOS/AM5/B650%20LiveMixer(1.14.AS06)ROM.zip")
    assert result == ("AM5", "B650 LiveMixer", "1.14.AS06")


def test_parse_bios_url_am4_basic():
    result = parse_bios_url("https://download.asrock.com/BIOS/AM4/A520M%20Pro4(1.00)ROM.zip")
    assert result == ("AM4", "A520M Pro4", "1.00")


def test_parse_bios_url_percent_encoded_parens():
    # Wayback CDX sometimes stores URLs with %28/%29 instead of ( )
    result = parse_bios_url("https://download.asrock.com/BIOS/AM5/B850%20Steel%20Legend%20WiFi%283.25%29ROM.zip")
    # %28 / %29 are not decoded by the regex (they don't match literal parens)
    # so the URL doesn't match — confirm graceful None
    assert result is None


def test_parse_bios_url_no_spaces_model():
    result = parse_bios_url("https://download.asrock.com/BIOS/AM5/B650M-HDVM.2(3.20)ROM.zip")
    assert result == ("AM5", "B650M-HDVM.2", "3.20")


def test_parse_bios_url_version_with_letters():
    result = parse_bios_url("https://download.asrock.com/BIOS/AM4/A300M-STX(3.60K)ROM.zip")
    assert result == ("AM4", "A300M-STX", "3.60K")


def test_parse_bios_url_returns_none_for_non_bios():
    assert parse_bios_url("https://download.asrock.com/Manual/foo.pdf") is None


def test_parse_bios_url_returns_none_for_wrong_host():
    assert parse_bios_url("https://example.com/BIOS/AM5/foo(1.0)ROM.zip") is None


def test_parse_bios_url_returns_none_for_garbage():
    assert parse_bios_url("not-a-url") is None


# ---------------------------------------------------------------------------
# board_support_url
# ---------------------------------------------------------------------------


def test_board_support_url_encodes_spaces():
    url = board_support_url("X870E Taichi")
    assert "X870E%20Taichi" in url
    assert url.startswith("https://www.asrock.com/mb/AMD/")
    assert url.endswith("/index.asp")


def test_board_support_url_no_spaces():
    url = board_support_url("B650M-HDVM.2")
    assert "B650M-HDVM.2" in url


# ---------------------------------------------------------------------------
# extract_rom
# ---------------------------------------------------------------------------


def test_extract_rom_prefers_rom_extension(tmp_path):
    zf = _make_zip(
        ("readme.txt", b"text"),
        ("firmware.ROM", b"A" * 1024),
        ("util.exe", b"B" * 512),
    )
    out = extract_rom(zf, tmp_path, _fake_update())
    assert out.suffix.lower() == ".rom"
    assert out.read_bytes() == b"A" * 1024


def test_extract_rom_prefers_bin_extension(tmp_path):
    zf = _make_zip(
        ("readme.txt", b"text"),
        ("firmware.BIN", b"C" * 2048),
    )
    out = extract_rom(zf, tmp_path, _fake_update())
    assert out.suffix.lower() == ".bin"
    assert out.read_bytes() == b"C" * 2048


def test_extract_rom_prefers_bios_extension(tmp_path):
    zf = _make_zip(("chip.BIOS", b"D" * 512))
    out = extract_rom(zf, tmp_path, _fake_update())
    assert out.suffix.lower() == ".bios"


def test_extract_rom_fallback_to_largest_file(tmp_path):
    zf = _make_zip(
        ("small.dat", b"tiny"),
        ("big.dat", b"E" * 4096),
    )
    out = extract_rom(zf, tmp_path, _fake_update())
    assert out.read_bytes() == b"E" * 4096


def test_extract_rom_skips_macosx_entries(tmp_path):
    zf = _make_zip(
        ("__MACOSX/._firmware.ROM", b"mac junk" * 100),
        ("firmware.ROM", b"F" * 1024),
    )
    out = extract_rom(zf, tmp_path, _fake_update())
    assert out.read_bytes() == b"F" * 1024


def test_extract_rom_skips_directory_entries(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.mkdir("subdir")
        zf.writestr("subdir/firmware.ROM", b"G" * 512)
    buf.seek(0)
    zf = zipfile.ZipFile(buf)
    out = extract_rom(zf, tmp_path, _fake_update())
    assert out.read_bytes() == b"G" * 512


def test_extract_rom_empty_zip_raises(tmp_path):
    zf = _make_zip()
    with pytest.raises(ValueError, match="Empty ZIP"):
        extract_rom(zf, tmp_path, _fake_update())


def test_extract_rom_output_path_contains_model_and_version(tmp_path):
    zf = _make_zip(("fw.ROM", b"H" * 128))
    out = extract_rom(zf, tmp_path, _fake_update(model="B650 LiveMixer", version="1.14"))
    assert "B650_LiveMixer" in out.name
    assert "1.14" in out.name


# ---------------------------------------------------------------------------
# AsRockScraper.list_boards
# ---------------------------------------------------------------------------


def test_list_boards_returns_unique_boards():
    async def _run():
        scraper = AsRockScraper(client=_mock_client())
        boards = await scraper.list_boards()
        models = {b.model for b in boards}
        assert "B650 LiveMixer" in models
        assert "X870E Taichi" in models
        assert "A520M Pro4" in models
        # No duplicates
        assert len(boards) == len({(b.socket, b.model) for b in boards})

    asyncio.run(_run())


def test_list_boards_sets_correct_socket():
    async def _run():
        scraper = AsRockScraper(client=_mock_client())
        boards = await scraper.list_boards()
        by_model = {b.model: b.socket for b in boards}
        assert by_model["B650 LiveMixer"] == "AM5"
        assert by_model["X870E Taichi"] == "AM5"
        assert by_model["A520M Pro4"] == "AM4"

    asyncio.run(_run())


def test_list_boards_sets_vendor():
    async def _run():
        scraper = AsRockScraper(client=_mock_client())
        boards = await scraper.list_boards()
        assert all(b.vendor == "ASRock" for b in boards)

    asyncio.run(_run())


def test_list_boards_constructs_support_url():
    async def _run():
        scraper = AsRockScraper(client=_mock_client())
        boards = await scraper.list_boards()
        for b in boards:
            assert b.url.startswith("https://www.asrock.com/mb/AMD/")

    asyncio.run(_run())


def test_list_boards_empty_cdx():
    async def _run():
        scraper = AsRockScraper(client=_mock_client(am5_data=[["original"]], am4_data=[["original"]]))
        boards = await scraper.list_boards()
        assert boards == []

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# AsRockScraper.list_bios_updates
# ---------------------------------------------------------------------------


def test_list_bios_updates_returns_all_versions():
    async def _run():
        scraper = AsRockScraper(client=_mock_client())
        board = _fake_board("B650 LiveMixer", "AM5")
        updates = await scraper.list_bios_updates(board)
        assert len(updates) == 2
        versions = {u.bios_version for u in updates}
        assert "1.14.AS06" in versions
        assert "1.18.AS04" in versions

    asyncio.run(_run())


def test_list_bios_updates_links_board():
    async def _run():
        scraper = AsRockScraper(client=_mock_client())
        board = _fake_board("B650 LiveMixer", "AM5")
        updates = await scraper.list_bios_updates(board)
        for u in updates:
            assert u.board is board

    asyncio.run(_run())


def test_list_bios_updates_download_url_points_to_cdn():
    async def _run():
        scraper = AsRockScraper(client=_mock_client())
        board = _fake_board("B650 LiveMixer", "AM5")
        updates = await scraper.list_bios_updates(board)
        for u in updates:
            assert u.download_url.startswith("https://download.asrock.com/")

    asyncio.run(_run())


def test_list_bios_updates_unknown_board_returns_empty():
    async def _run():
        scraper = AsRockScraper(client=_mock_client())
        board = _fake_board("Nonexistent Board", "AM5")
        updates = await scraper.list_bios_updates(board)
        assert updates == []

    asyncio.run(_run())


def test_list_bios_updates_uses_cdx_cache():
    """list_bios_updates should not make additional HTTP requests after list_boards."""
    http_calls: list[str] = []

    async def _run():
        am5 = _CDX_AM5
        am4 = _CDX_AM4

        async def counting_get(url: str, **kwargs):
            params = kwargs.get("params", {})
            url_param = str(params.get("url", ""))
            http_calls.append(url_param)
            if "AM5" in url_param:
                return _response(200, json=am5, url=url)
            if "AM4" in url_param:
                return _response(200, json=am4, url=url)
            return _response(404, url=url)

        mock = AsyncMock()
        mock.get = counting_get
        scraper = AsRockScraper(client=mock)

        await scraper.list_boards()
        http_calls_after_list_boards = len(http_calls)  # should be 2 (AM4 + AM5)

        board = _fake_board("B650 LiveMixer", "AM5")
        await scraper.list_bios_updates(board)
        # Cache hit — no additional HTTP requests
        assert len(http_calls) == http_calls_after_list_boards

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# AsRockScraper.download
# ---------------------------------------------------------------------------


def _make_bios_zip(filename: str = "firmware.ROM", content: bytes = b"ROM" * 100) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def test_download_extracts_rom(tmp_path):
    rom_data = b"FAKE_ROM_DATA" * 100
    zip_bytes = _make_bios_zip("firmware.ROM", rom_data)

    async def _run():
        scraper = AsRockScraper(client=_mock_client(download_content=zip_bytes))
        update = _fake_update()
        path = await scraper.download(update, tmp_path)
        assert path.exists()
        assert path.read_bytes() == rom_data

    asyncio.run(_run())


def test_download_creates_dest_dir(tmp_path):
    zip_bytes = _make_bios_zip()
    new_dir = tmp_path / "nested" / "output"

    async def _run():
        scraper = AsRockScraper(client=_mock_client(download_content=zip_bytes))
        path = await scraper.download(_fake_update(), new_dir)
        assert path.exists()

    asyncio.run(_run())


def test_download_http_error_raises(tmp_path):
    async def _get(url, **kwargs):
        return _response(404, url=url)

    mock = AsyncMock()
    mock.get = _get

    async def _run():
        scraper = AsRockScraper(client=mock)
        update = _fake_update()
        with pytest.raises(httpx.HTTPStatusError):
            await scraper.download(update, tmp_path)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# AsRockScraper context manager
# ---------------------------------------------------------------------------


def test_context_manager_creates_client():
    async def _run():
        async with AsRockScraper() as scraper:
            assert scraper._client is not None

    asyncio.run(_run())


def test_require_client_without_context_manager_raises():
    scraper = AsRockScraper()  # no client injected, no context manager
    with pytest.raises(RuntimeError, match="async with"):
        scraper._require_client()
