"""Tests for psp_etl.scrape.hpe."""

from __future__ import annotations

import asyncio
import gzip
import io
import tarfile
import zipfile
from unittest.mock import AsyncMock

import httpx
import pytest

from psp_etl.scrape.base import BoardInfo
from psp_etl.scrape.hpe import (
    HpeScraper,
    ScexeUnwrapError,
    classify_proliant_model,
    parse_component_url,
    unwrap_scexe,
)

# ---------------------------------------------------------------------------
# classify_proliant_model
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        # Hyphen-separated tokens
        (
            "https://support.hpe.com/hpesc/public/swd/proliant-dl385-gen10-plus/cp048094.scexe",
            ("DL385 Gen10 Plus", "SP3"),
        ),
        # Underscore-separated tokens
        (
            "https://ftp.hp.com/pub/softpaq/sp123456/DL325_Gen10_Plus_v2/cp045810.scexe",
            ("DL325 Gen10 Plus v2", "SP3"),
        ),
        # %20-encoded spaces
        (
            "https://support.hpe.com/path/DL385%20Gen11/cp052222.scexe",
            ("DL385 Gen11", "SP5"),
        ),
        # Plus-encoded spaces
        (
            "https://support.hpe.com/path/DL765+Gen11/cp053333.scexe",
            ("DL765 Gen11", "SP5"),
        ),
        # Apollo XL chassis
        (
            "https://ftp.hp.com/pub/softpaq/sp1/XL345-Gen10-Plus/cp041111.scexe",
            ("XL345 Gen10 Plus", "SP3"),
        ),
        # DL725 Gen5 (Turin)
        (
            "https://support.hpe.com/path/DL725-Gen5/cp054321.scexe",
            ("DL725 Gen5", "SP5"),
        ),
        # XL225n Gen10
        (
            "https://h17007.www1.hpe.com/path/XL225n-Gen10/cp042000.scexe",
            ("XL225n Gen10", "SP3"),
        ),
    ],
)
def test_classify_proliant_model_known_boards(url: str, expected: tuple[str, str]) -> None:
    assert classify_proliant_model(url) == expected


def test_classify_proliant_model_picks_most_specific_match() -> None:
    """``DL385 Gen10 Plus v2`` must outrank the shorter ``DL385 Gen10 Plus``."""
    url = "https://support.hpe.com/path/DL385-Gen10-Plus-v2/cp048888.scexe"
    assert classify_proliant_model(url) == ("DL385 Gen10 Plus v2", "SP3")


def test_classify_proliant_model_gen10_distinct_from_gen10_plus() -> None:
    plain = classify_proliant_model("https://x/DL385-Gen10/cp1.scexe")
    plus = classify_proliant_model("https://x/DL385-Gen10-Plus/cp2.scexe")
    assert plain == ("DL385 Gen10", "SP3")
    assert plus == ("DL385 Gen10 Plus", "SP3")


@pytest.mark.parametrize(
    "url",
    [
        # Intel ProLiant - must NOT classify
        "https://support.hpe.com/path/DL360-Gen10/cp1.scexe",
        "https://support.hpe.com/path/DL380-Gen11/cp2.scexe",
        # No model token at all
        "https://support.hpe.com/path/cp123456.scexe",
        # Unknown model
        "https://support.hpe.com/path/DL999-Gen42/cp3.scexe",
        "",
    ],
)
def test_classify_proliant_model_rejects_non_amd(url: str) -> None:
    assert classify_proliant_model(url) is None


# ---------------------------------------------------------------------------
# parse_component_url
# ---------------------------------------------------------------------------


def test_parse_component_url_extracts_cp_id_and_classifies() -> None:
    result = parse_component_url(
        "https://support.hpe.com/swd/proliant-dl385-gen10-plus/cp048094.scexe",
    )
    assert result == ("cp048094", "DL385 Gen10 Plus", "SP3")


def test_parse_component_url_requires_cp_id() -> None:
    # Has a model but no CP ID - skip.
    assert parse_component_url("https://support.hpe.com/path/DL385-Gen11/bios.scexe") is None


def test_parse_component_url_requires_known_model() -> None:
    # Has a CP ID but no recognised model - skip.
    assert parse_component_url("https://support.hpe.com/path/cp012345.scexe") is None


def test_parse_component_url_case_insensitive_cp() -> None:
    result = parse_component_url("https://x/DL325-Gen11/CP012345.scexe")
    assert result is not None
    assert result[0] == "cp012345"


# ---------------------------------------------------------------------------
# unwrap_scexe
# ---------------------------------------------------------------------------


def _make_scexe_gzip_tar(rom_bytes: bytes, rom_name: str = "bios.bin") -> bytes:
    """Build a minimal HPE-style .scexe: shell header + gzip(tar(rom))."""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        info = tarfile.TarInfo(name=rom_name)
        info.size = len(rom_bytes)
        tf.addfile(info, io.BytesIO(rom_bytes))
    payload = gzip.compress(tar_buf.getvalue())
    header = b"#!/bin/sh\n# HPE Self-Extracting Component\n_skip=42\n" + b"\x00" * 16
    return header + payload


def _make_scexe_gzip_raw(rom_bytes: bytes) -> bytes:
    """Build a .scexe with a gzip-compressed *raw* (non-tar) payload."""
    payload = gzip.compress(rom_bytes)
    header = b"#!/bin/sh\nexit 0\n"
    return header + payload


def _make_scexe_zip(rom_name: str, rom_bytes: bytes, *extras: tuple[str, bytes]) -> bytes:
    """Build a .scexe whose payload is a ZIP archive."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr(rom_name, rom_bytes)
        for name, content in extras:
            zf.writestr(name, content)
    header = b"#!/bin/sh\nexit 0\n"
    return header + zip_buf.getvalue()


def test_unwrap_scexe_gzip_tar_returns_rom_bytes() -> None:
    rom = b"\xaa" * 4096
    blob = _make_scexe_gzip_tar(rom, rom_name="cp048094.bin")
    assert unwrap_scexe(blob) == rom


def test_unwrap_scexe_gzip_tar_picks_rom_extension() -> None:
    # Tar with a junk member and a .bin member - we want the .bin.
    tar_buf = io.BytesIO()
    rom = b"\xbb" * 2048
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        for name, content in (
            ("README.txt", b"docs"),
            ("flash.sh", b"#!/bin/sh"),
            ("bios.bin", rom),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    blob = b"#!/bin/sh\nexit 0\n" + gzip.compress(tar_buf.getvalue())
    assert unwrap_scexe(blob) == rom


def test_unwrap_scexe_gzip_raw_payload_returns_decompressed() -> None:
    rom = b"\xcc" * 8192
    blob = _make_scexe_gzip_raw(rom)
    assert unwrap_scexe(blob) == rom


def test_unwrap_scexe_zip_payload_picks_rom_member() -> None:
    rom = b"\xdd" * 4096
    blob = _make_scexe_zip("bios.bin", rom, ("README.txt", b"docs"), ("flash.exe", b"\x00" * 1024))
    assert unwrap_scexe(blob) == rom


def test_unwrap_scexe_zip_payload_largest_when_no_rom_extension() -> None:
    rom = b"\xee" * 6000
    blob = _make_scexe_zip("payload", rom, ("readme", b"x"))  # no recognised suffix
    assert unwrap_scexe(blob) == rom


def test_unwrap_scexe_no_archive_magic_raises() -> None:
    with pytest.raises(ScexeUnwrapError, match="No gzip or zip magic"):
        unwrap_scexe(b"#!/bin/sh\nexit 0\n" + b"plain text")


def test_unwrap_scexe_corrupt_gzip_raises() -> None:
    # Real gzip header followed by garbage so decompression fails mid-stream.
    blob = b"#!/bin/sh\n" + b"\x1f\x8b\x08" + b"\x00" * 2048
    with pytest.raises(ScexeUnwrapError, match="gzip decompression failed"):
        unwrap_scexe(blob)


def test_unwrap_scexe_corrupt_zip_raises() -> None:
    # Zip magic followed by garbage — zipfile will reject it.
    blob = b"#!/bin/sh\n" + b"PK\x03\x04" + b"\x00" * 1024
    with pytest.raises(ScexeUnwrapError, match="zip payload"):
        unwrap_scexe(blob)


# ---------------------------------------------------------------------------
# HpeScraper - CDX-driven enumeration
# ---------------------------------------------------------------------------

# Mock CDX rows: header row + a mix of HPE AMD ProLiant URLs and noise
# (Intel ProLiant, ambiguous CP-only URLs).
_CDX_SUPPORT_HPE = [
    ["original"],
    # AMD ProLiant — should classify
    ["https://support.hpe.com/hpesc/public/swd/proliant-dl385-gen10-plus/cp048094.scexe"],
    ["https://support.hpe.com/hpesc/public/swd/proliant-dl385-gen10-plus/cp048500.scexe"],
    ["https://support.hpe.com/hpesc/public/swd/proliant-dl325-gen11/cp052100.scexe"],
    ["https://support.hpe.com/hpesc/public/swd/proliant-dl385-gen11/cp052222.scexe"],
    # Intel — must NOT classify
    ["https://support.hpe.com/hpesc/public/swd/proliant-dl380-gen10/cp045000.scexe"],
    # No model in URL — must NOT classify
    ["https://support.hpe.com/hpesc/public/swd/cp046000.scexe"],
]

_CDX_FTP_HP = [
    ["original"],
    # AMD via legacy FTP mirror
    ["https://ftp.hp.com/pub/softpaq/sp123/DL345-Gen10-Plus/cp041000.scexe"],
    # Same CP ID seen via two prefixes — should still de-dupe per board
    ["https://ftp.hp.com/pub/softpaq/sp124/DL325-Gen11/cp052100.scexe"],
]


def _response(status: int, *, json: list | None = None, content: bytes | None = None) -> httpx.Response:
    request = httpx.Request("GET", "https://example.com")
    if json is not None:
        return httpx.Response(status, json=json, request=request)
    return httpx.Response(status, content=content or b"", request=request)


def _mock_cdx_client(
    *,
    support_hpe: list | None = None,
    ftp_hp: list | None = None,
    download_payload: bytes | None = None,
) -> AsyncMock:
    """Return a mock httpx client that routes by CDX url-prefix and serves a download payload."""
    support = support_hpe if support_hpe is not None else _CDX_SUPPORT_HPE
    ftp = ftp_hp if ftp_hp is not None else []

    async def _get(url: str, **kwargs):
        params = kwargs.get("params", {})
        url_param = str(params.get("url", ""))
        if "support.hpe.com" in url_param:
            return _response(200, json=support)
        if "ftp.hp.com" in url_param:
            return _response(200, json=ftp)
        if download_payload is not None and url.endswith(".scexe"):
            return _response(200, content=download_payload)
        # Other prefixes: return empty CDX
        if url_param:
            return _response(200, json=[["original"]])
        return _response(404)

    mock = AsyncMock()
    mock.get = _get
    return mock


def test_list_boards_returns_classified_models() -> None:
    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client())
        boards = await scraper.list_boards()
        models = {b.model for b in boards}
        assert "DL385 Gen10 Plus" in models
        assert "DL325 Gen11" in models
        assert "DL385 Gen11" in models
        # Intel and unclassified must be excluded
        assert "DL380 Gen10" not in models

    asyncio.run(_run())


def test_list_boards_assigns_correct_socket() -> None:
    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client())
        boards = await scraper.list_boards()
        by_model = {b.model: b.socket for b in boards}
        assert by_model["DL385 Gen10 Plus"] == "SP3"
        assert by_model["DL325 Gen11"] == "SP5"
        assert by_model["DL385 Gen11"] == "SP5"

    asyncio.run(_run())


def test_list_boards_dedupes_across_prefixes() -> None:
    """A model that appears in both support.hpe.com and ftp.hp.com shows up once."""

    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client(ftp_hp=_CDX_FTP_HP))
        boards = await scraper.list_boards()
        models = [b.model for b in boards]
        assert models.count("DL325 Gen11") == 1

    asyncio.run(_run())


def test_list_boards_aggregates_across_prefixes() -> None:
    """Boards only present under ftp.hp.com still surface."""

    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client(ftp_hp=_CDX_FTP_HP))
        boards = await scraper.list_boards()
        models = {b.model for b in boards}
        assert "DL345 Gen10 Plus" in models

    asyncio.run(_run())


def test_list_boards_sets_vendor_and_url() -> None:
    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client())
        boards = await scraper.list_boards()
        assert boards
        for b in boards:
            assert b.vendor == "HPE"
            assert b.url.startswith("https://www.hpe.com/")

    asyncio.run(_run())


def test_list_boards_empty_cdx_returns_empty() -> None:
    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client(support_hpe=[["original"]]))
        boards = await scraper.list_boards()
        assert boards == []

    asyncio.run(_run())


def test_list_boards_handles_cdx_http_error() -> None:
    """A 5xx from Wayback should not crash the scraper - just yield no boards."""

    async def _run():
        async def _get(url: str, **kwargs):
            return _response(503)

        mock = AsyncMock()
        mock.get = _get
        scraper = HpeScraper(client=mock)
        boards = await scraper.list_boards()
        assert boards == []

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# HpeScraper - list_bios_updates
# ---------------------------------------------------------------------------


def test_list_bios_updates_returns_distinct_cp_ids() -> None:
    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client())
        boards = {b.model: b for b in await scraper.list_boards()}
        updates = await scraper.list_bios_updates(boards["DL385 Gen10 Plus"])
        versions = {u.bios_version for u in updates}
        assert versions == {"cp048094", "cp048500"}

    asyncio.run(_run())


def test_list_bios_updates_dedupes_repeat_cp_across_prefixes() -> None:
    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client(ftp_hp=_CDX_FTP_HP))
        boards = {b.model: b for b in await scraper.list_boards()}
        updates = await scraper.list_bios_updates(boards["DL325 Gen11"])
        # cp052100 appears in both support.hpe.com and ftp.hp.com
        assert len(updates) == 1
        assert updates[0].bios_version == "cp052100"

    asyncio.run(_run())


def test_list_bios_updates_unknown_board_returns_empty() -> None:
    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client())
        bogus = BoardInfo(vendor="HPE", model="DL999 GenX", socket="SP5", url="https://x")
        assert await scraper.list_bios_updates(bogus) == []

    asyncio.run(_run())


def test_list_bios_updates_carries_download_url() -> None:
    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client())
        boards = {b.model: b for b in await scraper.list_boards()}
        updates = await scraper.list_bios_updates(boards["DL385 Gen10 Plus"])
        for u in updates:
            assert u.download_url.endswith(".scexe")
            assert u.board.model == "DL385 Gen10 Plus"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# HpeScraper - download
# ---------------------------------------------------------------------------


def test_download_extracts_rom_from_scexe(tmp_path) -> None:
    rom = b"FAKE_HPE_ROM" * 1024
    blob = _make_scexe_gzip_tar(rom, rom_name="cp048094.bin")

    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client(download_payload=blob))
        boards = {b.model: b for b in await scraper.list_boards()}
        updates = await scraper.list_bios_updates(boards["DL385 Gen10 Plus"])
        path = await scraper.download(updates[0], tmp_path)
        assert path.exists()
        assert path.read_bytes() == rom

    asyncio.run(_run())


def test_download_filename_includes_model_and_cp(tmp_path) -> None:
    rom = b"\x42" * 256
    blob = _make_scexe_gzip_raw(rom)

    async def _run():
        scraper = HpeScraper(client=_mock_cdx_client(download_payload=blob))
        boards = {b.model: b for b in await scraper.list_boards()}
        updates = await scraper.list_bios_updates(boards["DL385 Gen11"])
        path = await scraper.download(updates[0], tmp_path)
        # Spaces in model are replaced with underscores
        assert "DL385_Gen11" in path.name
        assert "cp052222" in path.name
        assert path.suffix == ".bin"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_context_manager_creates_and_closes_client() -> None:
    async def _run():
        async with HpeScraper() as scraper:
            assert scraper._client is not None
        assert scraper._client is None

    asyncio.run(_run())


def test_require_client_without_context_manager_raises() -> None:
    scraper = HpeScraper()
    with pytest.raises(RuntimeError, match="async with"):
        scraper._require_client()


def test_cdx_cache_one_query_per_prefix() -> None:
    http_calls: list[str] = []

    async def _run():
        async def counting_get(url: str, **kwargs):
            params = kwargs.get("params", {})
            http_calls.append(str(params.get("url", "")))
            return _response(200, json=[["original"]])

        mock = AsyncMock()
        mock.get = counting_get
        scraper = HpeScraper(client=mock)

        await scraper.list_boards()
        first = len(http_calls)
        # Second pass should hit only the cache.
        await scraper.list_boards()
        assert len(http_calls) == first

    asyncio.run(_run())
