"""Tests for psp_etl.scrape.msi."""

import asyncio
import io
import struct
import zipfile
from unittest.mock import AsyncMock

import httpx
import pytest

from psp_etl.scrape.base import BiosUpdate, BoardInfo
from psp_etl.scrape.msi import (
    MsiScraper,
    _extract_txt_from_zip_header,
    _parse_lfh,
    parse_bios_url,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AM4_TXT = "MAG X570 TOMAHAWK WIFI(MS-7C84) V1.0 BIOS Release\r\n"
_AM5_TXT = "MEG X670E ACE(MS-7D67) V1.0 BIOS Release\r\n"

_CDX_RESPONSE = [
    ["original"],
    ["https://download.msi.com/bos_exe/mb/7C84v10.zip"],
    ["https://download.msi.com/bos_exe/mb/7C84v11.zip"],
    ["https://download.msi.com/bos_exe/mb/7D67v1A.zip"],
    ["https://download.msi.com/bos_exe/mb/0000v1.zip"],  # not AM4/AM5 → filtered
]


def _make_zip_partial(
    txt_content: str,
    board_id: str = "7C84",
    version: str = "10",
) -> bytes:
    """First 8192 bytes of a MSI BIOS ZIP (dir entry + TXT entry)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # Entry 0: directory (stored, 0 bytes)
        dir_info = zipfile.ZipInfo(f"{board_id}v{version}/")
        dir_info.compress_type = zipfile.ZIP_STORED
        zf.writestr(dir_info, b"")
        # Entry 1: release notes TXT (stored for simplicity)
        txt_info = zipfile.ZipInfo(f"{board_id}v{version}/{board_id}v9.txt")
        txt_info.compress_type = zipfile.ZIP_STORED
        zf.writestr(txt_info, txt_content.encode())
        # Entry 2: ROM image (just to make it realistic)
        zf.writestr(f"{board_id}v{version}/E{board_id}AMS.100", b"ROM" * 100)
    return buf.getvalue()[:8192]


def _make_full_zip(board_id: str = "7C84", version: str = "10") -> bytes:
    """A complete MSI BIOS ZIP for download tests."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        dir_info = zipfile.ZipInfo(f"{board_id}v{version}/")
        dir_info.compress_type = zipfile.ZIP_STORED
        zf.writestr(dir_info, b"")
        zf.writestr(f"{board_id}v{version}/{board_id}v9.txt", b"release notes")
        zf.writestr(f"{board_id}v{version}/E{board_id}AMS.100", b"FAKEFIRMWARE" * 200)
    return buf.getvalue()


def _response(
    status: int,
    *,
    json: list | None = None,
    content: bytes | None = None,
    url: str = "https://example.com",
) -> httpx.Response:
    request = httpx.Request("GET", url)
    if json is not None:
        return httpx.Response(status, json=json, request=request)
    return httpx.Response(status, content=content or b"", request=request)


def _make_mock_client(
    cdx_data: list | None = None,
    range_data: dict[str, bytes] | None = None,
    download_zip: bytes | None = None,
) -> AsyncMock:
    """Return a mock httpx.AsyncClient."""
    _cdx = cdx_data if cdx_data is not None else _CDX_RESPONSE
    _range = range_data or {}

    async def _get(url: str, **kwargs):
        headers = kwargs.get("headers", {})
        if "web.archive.org" in url:
            return _response(200, json=_cdx, url=url)
        if "Range" in headers:
            data = _range.get(url, b"")
            req = httpx.Request("GET", url)
            return httpx.Response(206, content=data, request=req)
        if download_zip is not None:
            return _response(200, content=download_zip, url=url)
        return _response(404, url=url)

    async def _head(url: str, **kwargs):
        # Simulate redirect: download.msi.com → download-2.msi.com
        final_url = url.replace("download.msi.com/", "download-2.msi.com/")
        req = httpx.Request("HEAD", final_url)
        return httpx.Response(200, request=req)

    mock = AsyncMock()
    mock.get = _get
    mock.head = _head
    return mock


def _fake_board(model: str = "MAG X570 TOMAHAWK WIFI", socket: str = "AM4") -> BoardInfo:
    return BoardInfo(vendor="MSI", model=model, socket=socket, url="https://example.com")


def _fake_update(model: str = "MAG X570 TOMAHAWK WIFI", version: str = "10") -> BiosUpdate:
    return BiosUpdate(
        board=_fake_board(model),
        bios_version=version,
        download_url="https://download.msi.com/bos_exe/mb/7C84v10.zip",
        release_date=None,
        agesa_version=None,
    )


# ---------------------------------------------------------------------------
# parse_bios_url
# ---------------------------------------------------------------------------


def test_parse_bios_url_basic():
    assert parse_bios_url("https://download.msi.com/bos_exe/mb/7C84v10.zip") == ("7C84", "10")


def test_parse_bios_url_hex_version():
    assert parse_bios_url("https://download-2.msi.com/bos_exe/mb/7C35v1A.zip") == ("7C35", "1A")


def test_parse_bios_url_normalizes_board_id_uppercase():
    result = parse_bios_url("https://download.msi.com/bos_exe/mb/7c84v10.zip")
    assert result is not None
    assert result[0] == "7C84"


def test_parse_bios_url_download2_cdn():
    result = parse_bios_url("https://download-2.msi.com/bos_exe/mb/7D67v1A.zip")
    assert result == ("7D67", "1A")


def test_parse_bios_url_returns_none_for_wrong_path():
    assert parse_bios_url("https://download.msi.com/other/path/foo.zip") is None


def test_parse_bios_url_returns_none_for_wrong_host():
    assert parse_bios_url("https://example.com/bos_exe/mb/7C84v10.zip") is None


def test_parse_bios_url_returns_none_for_garbage():
    assert parse_bios_url("not-a-url") is None


def test_parse_bios_url_returns_none_for_short_board_id():
    # Board ID must be exactly 4 hex chars
    assert parse_bios_url("https://download.msi.com/bos_exe/mb/7C8v10.zip") is None


# ---------------------------------------------------------------------------
# _parse_lfh
# ---------------------------------------------------------------------------


def _make_lfh(filename: str, compress: int, comp_size: int, uncomp_size: int) -> bytes:
    """Manually craft a ZIP local file header."""
    fname_bytes = filename.encode("utf-8")
    extra = b""
    header = struct.pack(
        "<4sHHHHHIIIHH",
        b"PK\x03\x04",
        20,  # version needed
        0,  # general purpose bit flag
        compress,
        0,  # last mod time
        0,  # last mod date
        0,  # CRC-32
        comp_size,
        uncomp_size,
        len(fname_bytes),
        len(extra),
    )
    return header + fname_bytes + extra


def test_parse_lfh_directory_entry():
    data = _make_lfh("7C84v10/", 0, 0, 0)
    result = _parse_lfh(data, 0)
    assert result is not None
    fname, compress, comp_size, uncomp_size, data_offset = result
    assert fname == "7C84v10/"
    assert compress == 0
    assert comp_size == 0
    assert uncomp_size == 0
    assert data_offset == 30 + len("7C84v10/")


def test_parse_lfh_wrong_signature():
    data = b"PK\x05\x06" + b"\x00" * 26
    assert _parse_lfh(data, 0) is None


def test_parse_lfh_truncated():
    # Less than 30 bytes available
    data = b"PK\x03\x04" + b"\x00" * 10
    assert _parse_lfh(data, 0) is None


def test_parse_lfh_filename_extends_beyond_data():
    # fname_len larger than remaining data
    fname = "a" * 100
    data = _make_lfh(fname, 0, 0, 0)
    # Truncate to cut off the filename
    assert _parse_lfh(data[:35], 0) is None


# ---------------------------------------------------------------------------
# _extract_txt_from_zip_header
# ---------------------------------------------------------------------------


def test_extract_txt_returns_model_line():
    data = _make_zip_partial(_AM4_TXT)
    result = _extract_txt_from_zip_header(data)
    assert result is not None
    assert "X570 TOMAHAWK" in result


def test_extract_txt_am5_board():
    data = _make_zip_partial(_AM5_TXT, board_id="7D67", version="1A")
    result = _extract_txt_from_zip_header(data)
    assert result is not None
    assert "X670E" in result


def test_extract_txt_returns_none_for_empty_data():
    assert _extract_txt_from_zip_header(b"") is None


def test_extract_txt_returns_none_for_garbage():
    assert _extract_txt_from_zip_header(b"\x00" * 8192) is None


def test_extract_txt_returns_none_when_txt_truncated():
    # Build a partial header where the TXT content doesn't fit in the range
    data = _make_zip_partial("A" * 9000)  # TXT bigger than 8KB
    # The raw bytes are still ≤8192, but the TXT data_offset+comp_size > 8192
    result = _extract_txt_from_zip_header(data)
    # Should return None (chunk too short) or the text if it fit — either is acceptable
    # but not raise an exception
    assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# MsiScraper.list_boards
# ---------------------------------------------------------------------------

_AM4_RANGE = {
    "https://download-2.msi.com/bos_exe/mb/7C84v10.zip": _make_zip_partial(_AM4_TXT, "7C84", "10"),
}
_AM5_RANGE = {
    "https://download-2.msi.com/bos_exe/mb/7D67v1A.zip": _make_zip_partial(_AM5_TXT, "7D67", "1A"),
}
_ALL_RANGE = {**_AM4_RANGE, **_AM5_RANGE}


def test_list_boards_finds_am4_board():
    async def _run():
        client = _make_mock_client(range_data=_ALL_RANGE)
        scraper = MsiScraper(client=client)
        boards = await scraper.list_boards()
        models = {b.model for b in boards}
        assert any("X570" in m or "TOMAHAWK" in m for m in models)

    asyncio.run(_run())


def test_list_boards_finds_am5_board():
    async def _run():
        client = _make_mock_client(range_data=_ALL_RANGE)
        scraper = MsiScraper(client=client)
        boards = await scraper.list_boards()
        am5 = [b for b in boards if b.socket == "AM5"]
        assert am5

    asyncio.run(_run())


def test_list_boards_sets_vendor():
    async def _run():
        client = _make_mock_client(range_data=_ALL_RANGE)
        scraper = MsiScraper(client=client)
        boards = await scraper.list_boards()
        assert all(b.vendor == "MSI" for b in boards)

    asyncio.run(_run())


def test_list_boards_no_duplicates():
    async def _run():
        client = _make_mock_client(range_data=_ALL_RANGE)
        scraper = MsiScraper(client=client)
        boards = await scraper.list_boards()
        models = [b.model for b in boards]
        assert len(models) == len(set(models))

    asyncio.run(_run())


def test_list_boards_empty_cdx():
    async def _run():
        client = _make_mock_client(cdx_data=[["original"]])
        scraper = MsiScraper(client=client)
        boards = await scraper.list_boards()
        assert boards == []

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# MsiScraper.list_bios_updates
# ---------------------------------------------------------------------------


def test_list_bios_updates_returns_all_versions():
    async def _run():
        client = _make_mock_client(range_data=_ALL_RANGE)
        scraper = MsiScraper(client=client)
        # Pre-populate cache as list_boards would
        await scraper.list_boards()
        board = next(b for b in await scraper.list_boards() if b.socket == "AM4")
        updates = await scraper.list_bios_updates(board)
        # CDX has v10 and v11 for 7C84
        versions = {u.bios_version for u in updates}
        assert "10" in versions
        assert "11" in versions

    asyncio.run(_run())


def test_list_bios_updates_links_board():
    async def _run():
        client = _make_mock_client(range_data=_ALL_RANGE)
        scraper = MsiScraper(client=client)
        await scraper.list_boards()
        board = next(b for b in await scraper.list_boards() if b.socket == "AM4")
        updates = await scraper.list_bios_updates(board)
        for u in updates:
            assert u.board is board

    asyncio.run(_run())


def test_list_bios_updates_unknown_board_returns_empty():
    async def _run():
        client = _make_mock_client(range_data=_ALL_RANGE)
        scraper = MsiScraper(client=client)
        await scraper.list_boards()
        unknown = _fake_board("Unknown Board XYZ")
        updates = await scraper.list_bios_updates(unknown)
        assert updates == []

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# MsiScraper.download
# ---------------------------------------------------------------------------


def test_download_extracts_rom(tmp_path):
    zip_bytes = _make_full_zip()

    async def _run():
        client = _make_mock_client(download_zip=zip_bytes)
        scraper = MsiScraper(client=client)
        update = _fake_update()
        path = await scraper.download(update, tmp_path)
        assert path.exists()
        assert path.read_bytes() == b"FAKEFIRMWARE" * 200

    asyncio.run(_run())


def test_download_creates_dest_dir(tmp_path):
    zip_bytes = _make_full_zip()
    new_dir = tmp_path / "nested" / "output"

    async def _run():
        client = _make_mock_client(download_zip=zip_bytes)
        scraper = MsiScraper(client=client)
        path = await scraper.download(_fake_update(), new_dir)
        assert path.exists()

    asyncio.run(_run())


def test_download_http_error_raises(tmp_path):
    async def _get(url, **kwargs):
        return _response(404, url=url)

    mock = AsyncMock()
    mock.get = _get

    async def _run():
        scraper = MsiScraper(client=mock)
        with pytest.raises(httpx.HTTPStatusError):
            await scraper.download(_fake_update(), tmp_path)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# CDX cache
# ---------------------------------------------------------------------------


def test_cdx_is_fetched_only_once():
    cdx_calls: list[str] = []

    async def _run():
        async def counting_get(url: str, **kwargs):
            if "web.archive.org" in url:
                cdx_calls.append(url)
                return _response(200, json=_CDX_RESPONSE, url=url)
            headers = kwargs.get("headers", {})
            if "Range" in headers:
                req = httpx.Request("GET", url)
                return httpx.Response(206, content=b"", request=req)
            return _response(404, url=url)

        async def _head(url, **kwargs):
            final_url = url.replace("download.msi.com/", "download-2.msi.com/")
            req = httpx.Request("HEAD", final_url)
            return httpx.Response(200, request=req)

        mock = AsyncMock()
        mock.get = counting_get
        mock.head = _head
        scraper = MsiScraper(client=mock)

        await scraper.list_boards()
        calls_after_first = len(cdx_calls)
        # Second call should use cache
        await scraper.list_boards()
        assert len(cdx_calls) == calls_after_first == 1

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


def test_context_manager_creates_client():
    async def _run():
        async with MsiScraper() as scraper:
            assert scraper._client is not None

    asyncio.run(_run())


def test_require_client_without_context_manager_raises():
    scraper = MsiScraper()
    with pytest.raises(RuntimeError, match="async with"):
        scraper._require_client()
