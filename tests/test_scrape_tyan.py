"""Tests for psp_etl.scrape.tyan."""

import asyncio
import io
import zipfile
from unittest.mock import AsyncMock

import httpx
import pytest

from psp_etl.scrape.base import BiosUpdate, BoardInfo
from psp_etl.scrape.tyan import (
    TyanScraper,
    extract_rom,
    parse_catalog,
    parse_downloads_page,
)

# ---------------------------------------------------------------------------
# HTML fixtures
# ---------------------------------------------------------------------------

# Minimal catalog page modelled on /en/products/amd_epyc_9004. Uses single
# quotes around href because that is what MiTAC's renderer emits.
_CATALOG_9004_HTML = """
<html><body>
<div class="product-grid">
    <div class="card">
        <h3><a href='/en/spec/Motherboards/S8050_S8050GM2NE'>S8050GM2NE<br>(S8050)</a></h3>
    </div>
    <div class="card">
        <h3><a href='/en/spec/Motherboards/S8050_S8050GM4NE-2T'>S8050GM4NE-2T<br>(S8050)</a></h3>
    </div>
    <div class="card">
        <h3><a href='/en/spec/Motherboards/S8056_S8056GM2NE-2T'>S8056GM2NE-2T<br>(S8056)</a></h3>
    </div>
    <!-- Duplicate link, e.g. once on the image and once on the title -->
    <div class="card">
        <a href='/en/spec/Motherboards/S8050_S8050GM2NE'><img src='/foo.jpg'></a>
    </div>
    <a href='/en/products/something_unrelated'>Other</a>
</div>
</body></html>
"""

_CATALOG_8004_HTML = """
<html><body>
<a href='/en/spec/Motherboards/S8040_S8040GM2NE'>S8040GM2NE</a>
<a href='/en/spec/Motherboards/S8040_S8040GM4NE-2T'>S8040GM4NE-2T</a>
</body></html>
"""

_CATALOG_EMPTY_HTML = "<html><body><p>No boards yet</p></body></html>"

# The downloads page renders a tbody#downloadTable with mixed BIOS/BMC/Drivers
# rows. We want only BIOS rows.
_DOWNLOADS_S8050_HTML = """
<html><body>
<table class='table table-striped'>
    <thead><tr><th>Type</th><th>Title</th><th>Date</th><th>Version</th><th></th></tr></thead>
    <tbody id="downloadTable">
        <tr>
            <td>BIOS</td>
            <td>S8050GM2NE_BIOS_V3.02</td>
            <td>2025-11-04</td>
            <td>V3.02 (0x10)</td>
            <td><a href='/en/downloads/details/MitacServer/S8050GM2NE_BIOS_4761'>Details</a></td>
        </tr>
        <tr>
            <td>BIOS</td>
            <td>S8050GM2NE_BIOS-v2.02</td>
            <td>2024-07-30</td>
            <td>V2.02 (0x02)</td>
            <td><a href='/x'>Details</a></td>
        </tr>
        <tr>
            <td>BMC</td>
            <td>8050_BMC_V5.01</td>
            <td>2025-11-13</td>
            <td>V5.01</td>
            <td><a href='/x'>Details</a></td>
        </tr>
        <tr>
            <td>Drivers</td>
            <td>NIC_DRV_v1</td>
            <td>2024-01-01</td>
            <td>v1</td>
            <td><a href='/x'>Details</a></td>
        </tr>
    </tbody>
</table>
</body></html>
"""

_DOWNLOADS_NO_TABLE_HTML = "<html><body><p>No downloads</p></body></html>"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _response(
    status: int,
    *,
    text: str | None = None,
    content: bytes | None = None,
    url: str = "https://example.com",
) -> httpx.Response:
    request = httpx.Request("GET", url)
    body = content if content is not None else (text or "").encode()
    return httpx.Response(status, content=body, request=request)


def _make_zip(*entries: tuple[str, bytes]) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries:
            zf.writestr(name, content)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def _make_bios_zip_bytes(rom_name: str = "BIOS8050020202.rom", rom_data: bytes = b"ROM" * 1024) -> bytes:
    """Realistic Tyan BIOS ZIP: capsule + HPM + raw ROM + flasher + notes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("8050_001.CAP", b"CAP_PAYLOAD" + b"\x00" * 8192)
        zf.writestr("BIOS8050020202.hpm", b"HPM_PAYLOAD" + b"\x00" * 8192)
        zf.writestr(rom_name, rom_data)
        zf.writestr("AfuEfix64.efi", b"FLASHER" * 50)
        zf.writestr("Flash.nsh", b"flash script")
        zf.writestr("ReleaseNoteBIOS8050020202.txt", b"release notes")
    return buf.getvalue()


def _fake_board(model: str = "S8050GM2NE", socket: str = "SP5") -> BoardInfo:
    return BoardInfo(
        vendor="Tyan",
        model=model,
        socket=socket,
        url=f"https://www.mitaccomputing.com/en/spec/Motherboards/S8050_{model}",
    )


def _fake_update(
    model: str = "S8050GM2NE",
    title: str = "S8050GM2NE_BIOS_V3.02",
    version: str = "V3.02",
) -> BiosUpdate:
    return BiosUpdate(
        board=_fake_board(model),
        bios_version=version,
        download_url=f"https://download1.mitaccomputing.com/pub/bios/{title}.zip",
        release_date=None,
        agesa_version=None,
    )


def _make_mock_client(
    catalog_pages: dict[str, str] | None = None,
    downloads_pages: dict[str, str] | None = None,
    download_zip: bytes | None = None,
) -> AsyncMock:
    """Mock httpx.AsyncClient that routes URLs to fixture HTML/bytes."""
    cat = catalog_pages or {}
    dls = downloads_pages or {}

    async def _get(url: str, **kwargs):
        for slug, html in cat.items():
            if f"/en/products/{slug}" in url:
                return _response(200, text=html, url=url)
        for slug, html in dls.items():
            if f"/en/downloads/Motherboards/{slug}" in url:
                return _response(200, text=html, url=url)
        if download_zip is not None and url.endswith(".zip"):
            return _response(200, content=download_zip, url=url)
        return _response(404, url=url)

    mock = AsyncMock()
    mock.get = _get
    return mock


# ---------------------------------------------------------------------------
# parse_catalog
# ---------------------------------------------------------------------------


def test_parse_catalog_extracts_unique_boards():
    result = parse_catalog(_CATALOG_9004_HTML)
    assert ("S8050_S8050GM2NE", "S8050GM2NE") in result
    assert ("S8050_S8050GM4NE-2T", "S8050GM4NE-2T") in result
    assert ("S8056_S8056GM2NE-2T", "S8056GM2NE-2T") in result


def test_parse_catalog_dedupes_repeat_anchors():
    # The fixture has two anchors pointing at the same spec page; expect one entry.
    result = parse_catalog(_CATALOG_9004_HTML)
    slugs = [s for s, _ in result]
    assert slugs.count("S8050_S8050GM2NE") == 1


def test_parse_catalog_ignores_unrelated_links():
    result = parse_catalog(_CATALOG_9004_HTML)
    slugs = {s for s, _ in result}
    assert all("spec/Motherboards" not in s or s in slugs for s in slugs)
    assert "something_unrelated" not in {s for s, _ in result}


def test_parse_catalog_empty_page_returns_empty():
    assert parse_catalog(_CATALOG_EMPTY_HTML) == []


def test_parse_catalog_model_drops_short_prefix():
    result = parse_catalog(_CATALOG_8004_HTML)
    by_model = dict((m, s) for s, m in result)
    assert "S8040GM2NE" in by_model
    assert "S8040GM4NE-2T" in by_model


# ---------------------------------------------------------------------------
# parse_downloads_page
# ---------------------------------------------------------------------------


def test_parse_downloads_page_returns_only_bios_rows():
    rows = parse_downloads_page(_DOWNLOADS_S8050_HTML)
    titles = [r["title"] for r in rows]
    assert "S8050GM2NE_BIOS_V3.02" in titles
    assert "S8050GM2NE_BIOS-v2.02" in titles
    assert "8050_BMC_V5.01" not in titles
    assert "NIC_DRV_v1" not in titles


def test_parse_downloads_page_captures_date_and_version():
    rows = parse_downloads_page(_DOWNLOADS_S8050_HTML)
    by_title = {r["title"]: r for r in rows}
    assert by_title["S8050GM2NE_BIOS_V3.02"]["date"] == "2025-11-04"
    assert by_title["S8050GM2NE_BIOS_V3.02"]["version"] == "V3.02 (0x10)"


def test_parse_downloads_page_no_table_returns_empty():
    assert parse_downloads_page(_DOWNLOADS_NO_TABLE_HTML) == []


# ---------------------------------------------------------------------------
# extract_rom
# ---------------------------------------------------------------------------


def test_extract_rom_prefers_rom_over_capsule(tmp_path):
    # Simulates a real Tyan ZIP — .CAP and .hpm are larger than .rom.
    zf = _make_zip(
        ("8050_001.CAP", b"\x00" * 100_000),
        ("BIOS.hpm", b"\x00" * 200_000),
        ("BIOS8050.rom", b"R" * 50_000),
        ("AfuEfix64.efi", b"\x00" * 5_000),
        ("notes.txt", b"text"),
    )
    out = extract_rom(zf, tmp_path, _fake_update())
    assert out.suffix == ".rom"
    assert out.read_bytes() == b"R" * 50_000


def test_extract_rom_prefers_bin_when_no_rom(tmp_path):
    zf = _make_zip(
        ("BIOS.bin", b"B" * 1024),
        ("AfuDos.exe", b"\x00" * 4096),
    )
    out = extract_rom(zf, tmp_path, _fake_update())
    assert out.suffix == ".bin"
    assert out.read_bytes() == b"B" * 1024


def test_extract_rom_filename_includes_model_and_version(tmp_path):
    zf = _make_zip(("BIOS.rom", b"X" * 64))
    out = extract_rom(zf, tmp_path, _fake_update(model="S8050GM2NE", version="V3.02"))
    assert "S8050GM2NE" in out.name
    assert "V3.02" in out.name


def test_extract_rom_skips_macosx_entries(tmp_path):
    zf = _make_zip(
        ("__MACOSX/._BIOS.rom", b"junk" * 10),
        ("BIOS.rom", b"R" * 1024),
    )
    out = extract_rom(zf, tmp_path, _fake_update())
    assert out.read_bytes() == b"R" * 1024


def test_extract_rom_skips_directory_entries(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf_w:
        zf_w.mkdir("subdir")
        zf_w.writestr("subdir/BIOS.rom", b"S" * 256)
    buf.seek(0)
    zf = zipfile.ZipFile(buf)
    out = extract_rom(zf, tmp_path, _fake_update())
    assert out.read_bytes() == b"S" * 256


def test_extract_rom_empty_zip_raises(tmp_path):
    zf = _make_zip()
    with pytest.raises(ValueError, match="Empty ZIP"):
        extract_rom(zf, tmp_path, _fake_update())


def test_extract_rom_only_wrappers_raises(tmp_path):
    # A pathological ZIP with only documentation, scripts and capsules.
    # No .rom, no .bin, and the only large files are CAP/HPM/EFI, which we
    # refuse to fall back to.
    zf = _make_zip(
        ("foo.CAP", b"C" * 1024),
        ("foo.hpm", b"H" * 2048),
        ("foo.efi", b"E" * 512),
        ("notes.txt", b"text"),
    )
    with pytest.raises(ValueError, match="No ROM-like file"):
        extract_rom(zf, tmp_path, _fake_update())


# ---------------------------------------------------------------------------
# TyanScraper.list_boards
# ---------------------------------------------------------------------------


def test_list_boards_walks_all_catalog_pages():
    catalogs = {
        "amd_epyc_9004": _CATALOG_9004_HTML,
        "amd_epyc_9005": _CATALOG_EMPTY_HTML,
        "amd_epyc_8004": _CATALOG_8004_HTML,
        "amd_epyc_4005": _CATALOG_EMPTY_HTML,
    }

    async def _run():
        scraper = TyanScraper(client=_make_mock_client(catalog_pages=catalogs), rate_limit=0)
        boards = await scraper.list_boards()
        models = {b.model for b in boards}
        assert "S8050GM2NE" in models
        assert "S8050GM4NE-2T" in models
        assert "S8056GM2NE-2T" in models
        assert "S8040GM2NE" in models
        assert "S8040GM4NE-2T" in models

    asyncio.run(_run())


def test_list_boards_assigns_correct_socket():
    catalogs = {
        "amd_epyc_9004": _CATALOG_9004_HTML,
        "amd_epyc_9005": _CATALOG_EMPTY_HTML,
        "amd_epyc_8004": _CATALOG_8004_HTML,
        "amd_epyc_4005": _CATALOG_EMPTY_HTML,
    }

    async def _run():
        scraper = TyanScraper(client=_make_mock_client(catalog_pages=catalogs), rate_limit=0)
        boards = await scraper.list_boards()
        by_model = {b.model: b.socket for b in boards}
        assert by_model["S8050GM2NE"] == "SP5"
        assert by_model["S8040GM2NE"] == "SP6"

    asyncio.run(_run())


def test_list_boards_socket_filter():
    catalogs = {
        "amd_epyc_9004": _CATALOG_9004_HTML,
        "amd_epyc_8004": _CATALOG_8004_HTML,
    }

    async def _run():
        scraper = TyanScraper(sockets=["SP6"], client=_make_mock_client(catalog_pages=catalogs), rate_limit=0)
        boards = await scraper.list_boards()
        sockets = {b.socket for b in boards}
        assert sockets == {"SP6"}

    asyncio.run(_run())


def test_list_boards_sets_vendor_and_url():
    catalogs = {"amd_epyc_9004": _CATALOG_9004_HTML}

    async def _run():
        scraper = TyanScraper(client=_make_mock_client(catalog_pages=catalogs), rate_limit=0)
        boards = await scraper.list_boards()
        assert boards
        for b in boards:
            assert b.vendor == "Tyan"
            assert "/en/spec/Motherboards/" in b.url
            assert b.url.startswith("https://www.mitaccomputing.com")

    asyncio.run(_run())


def test_list_boards_handles_404_catalog(caplog):
    # No pages registered → every catalog GET returns 404.
    async def _run():
        scraper = TyanScraper(client=_make_mock_client(), rate_limit=0)
        boards = await scraper.list_boards()
        assert boards == []

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# TyanScraper.list_bios_updates
# ---------------------------------------------------------------------------


def test_list_bios_updates_returns_all_bios_rows():
    async def _run():
        scraper = TyanScraper(
            client=_make_mock_client(downloads_pages={"S8050_S8050GM2NE": _DOWNLOADS_S8050_HTML}),
            rate_limit=0,
        )
        board = _fake_board("S8050GM2NE")
        updates = await scraper.list_bios_updates(board)
        assert len(updates) == 2
        urls = {u.download_url for u in updates}
        assert "https://download1.mitaccomputing.com/pub/bios/S8050GM2NE_BIOS_V3.02.zip" in urls
        assert "https://download1.mitaccomputing.com/pub/bios/S8050GM2NE_BIOS-v2.02.zip" in urls

    asyncio.run(_run())


def test_list_bios_updates_carries_release_date_and_version():
    async def _run():
        scraper = TyanScraper(
            client=_make_mock_client(downloads_pages={"S8050_S8050GM2NE": _DOWNLOADS_S8050_HTML}),
            rate_limit=0,
        )
        board = _fake_board("S8050GM2NE")
        updates = await scraper.list_bios_updates(board)
        by_version = {u.bios_version: u for u in updates}
        assert by_version["V3.02 (0x10)"].release_date == "2025-11-04"

    asyncio.run(_run())


def test_list_bios_updates_links_board():
    async def _run():
        scraper = TyanScraper(
            client=_make_mock_client(downloads_pages={"S8050_S8050GM2NE": _DOWNLOADS_S8050_HTML}),
            rate_limit=0,
        )
        board = _fake_board("S8050GM2NE")
        updates = await scraper.list_bios_updates(board)
        for u in updates:
            assert u.board is board

    asyncio.run(_run())


def test_list_bios_updates_404_returns_empty():
    async def _run():
        scraper = TyanScraper(client=_make_mock_client(), rate_limit=0)
        board = _fake_board("S8050GM2NE")
        updates = await scraper.list_bios_updates(board)
        assert updates == []

    asyncio.run(_run())


def test_list_bios_updates_caches_downloads_page():
    """Repeat calls for the same board should not re-issue the HTTP request."""
    http_calls: list[str] = []

    async def _run():
        async def counting_get(url: str, **kwargs):
            http_calls.append(url)
            if "/en/downloads/Motherboards/S8050_S8050GM2NE" in url:
                return _response(200, text=_DOWNLOADS_S8050_HTML, url=url)
            return _response(404, url=url)

        mock = AsyncMock()
        mock.get = counting_get
        scraper = TyanScraper(client=mock, rate_limit=0)
        board = _fake_board("S8050GM2NE")
        await scraper.list_bios_updates(board)
        n = len(http_calls)
        await scraper.list_bios_updates(board)
        assert len(http_calls) == n  # second call is a cache hit

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# TyanScraper.download
# ---------------------------------------------------------------------------


def test_download_extracts_rom(tmp_path):
    rom_data = b"FAKE_TYAN_ROM" * 256
    zip_bytes = _make_bios_zip_bytes(rom_data=rom_data)

    async def _run():
        scraper = TyanScraper(client=_make_mock_client(download_zip=zip_bytes), rate_limit=0)
        path = await scraper.download(_fake_update(), tmp_path)
        assert path.exists()
        assert path.read_bytes() == rom_data

    asyncio.run(_run())


def test_download_creates_dest_dir(tmp_path):
    zip_bytes = _make_bios_zip_bytes()
    new_dir = tmp_path / "nested" / "out"

    async def _run():
        scraper = TyanScraper(client=_make_mock_client(download_zip=zip_bytes), rate_limit=0)
        path = await scraper.download(_fake_update(), new_dir)
        assert path.exists()

    asyncio.run(_run())


def test_download_http_error_raises(tmp_path):
    async def _get(url, **kwargs):
        return _response(404, url=url)

    mock = AsyncMock()
    mock.get = _get

    async def _run():
        scraper = TyanScraper(client=mock, rate_limit=0)
        with pytest.raises(httpx.HTTPStatusError):
            await scraper.download(_fake_update(), tmp_path)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


def test_context_manager_creates_client():
    async def _run():
        async with TyanScraper(rate_limit=0) as scraper:
            assert scraper._client is not None

    asyncio.run(_run())


def test_require_client_without_context_manager_raises():
    scraper = TyanScraper(rate_limit=0)
    with pytest.raises(RuntimeError, match="async with"):
        scraper._require_client()
