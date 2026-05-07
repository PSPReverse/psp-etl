"""Tests for psp_etl.scrape.dell."""

from __future__ import annotations

import asyncio
import gzip

import httpx
import pytest

from psp_etl.scrape.base import BoardInfo
from psp_etl.scrape.dell import (
    CATALOG_PC_URL,
    CATALOG_URL,
    PFS_ENTRY_HEADER_SIZE,
    PFS_FOOTER_MAGIC,
    PFS_HEADER_MAGIC,
    DellScraper,
    classify_poweredge_socket,
    classify_precision_socket,
    parse_catalog,
    unwrap_dell_dup,
)

# ---------------------------------------------------------------------------
# Socket classifier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "socket"),
    [
        # Rome / Milan (SP3)
        ("R6515", "SP3"),
        ("R6525", "SP3"),
        ("R7515", "SP3"),
        ("R7525", "SP3"),
        ("R8515", "SP3"),
        ("C6525", "SP3"),
        # Genoa / Bergamo (SP5)
        ("R6615", "SP5"),
        ("R6625", "SP5"),
        ("R7615", "SP5"),
        ("R7625", "SP5"),
        ("R8615", "SP5"),
        ("R8625", "SP5"),
        ("C6615", "SP5"),
        ("XE9680", "SP5"),
        # Siena (SP6)
        ("R6715", "SP6"),
        ("R7715", "SP6"),
        ("R4715", "SP6"),
    ],
)
def test_classify_poweredge_socket_known_models(model: str, socket: str) -> None:
    assert classify_poweredge_socket(model) == socket


@pytest.mark.parametrize(
    "model",
    [
        "R740",  # 14G Intel
        "R750xs",  # 15G Intel
        "T550",  # Intel tower
        "MX740c",  # Intel modular
        "R6526",  # not a real model
        "",
    ],
)
def test_classify_poweredge_socket_skips_intel_and_unknown(model: str) -> None:
    assert classify_poweredge_socket(model) is None


@pytest.mark.parametrize(
    ("model", "socket"),
    [
        ("Precision-7875-Tower/Precision-7875-XL-Tower", "sWRX9"),
        ("Precision-7865-Tower", "sWRX8"),
    ],
)
def test_classify_precision_socket_threadripper_pro(model: str, socket: str) -> None:
    assert classify_precision_socket(model) == socket


@pytest.mark.parametrize(
    "model",
    [
        # 7960/7965 are Xeon despite being workstation-class Precisions.
        "Precision-7960-Tower/Precision-7960-XL-Tower",
        "Precision-7965-Rack",
        "Precision-7770",
        "Precision-3680-Tower",
        "Latitude-7320",
    ],
)
def test_classify_precision_socket_skips_intel_and_consumer(model: str) -> None:
    assert classify_precision_socket(model) is None


# ---------------------------------------------------------------------------
# Catalog XML parsing
# ---------------------------------------------------------------------------


_CATALOG_FIXTURE = """<?xml version="1.0" encoding="utf-8"?>
<Manifest version="26.05.04" baseLocation="downloads.dell.com">
  <SoftwareComponent dateTime="2026-04-27T03:46:08+05:30" packageID="RWK5K"
      packageType="LW64" path="FOLDER14403046M/1/BIOS_RWK5K_WN64_2.24.1.EXE"
      releaseDate="April 27, 2026" releaseID="RWK5K" vendorVersion="2.24.1">
    <Name><Display lang="en">PowerEdge BIOS R6525/R7525 2.24.1</Display></Name>
    <ComponentType value="BIOS"><Display lang="en">BIOS</Display></ComponentType>
    <Category value="BI"><Display lang="en">BIOS</Display></Category>
    <SupportedSystems>
      <Brand key="3" prefix="PE">
        <Display lang="en">PowerEdge</Display>
        <Model systemID="08FE" systemIDType="BIOS"><Display lang="en">R6525</Display></Model>
        <Model systemID="08FF" systemIDType="BIOS"><Display lang="en">R7525</Display></Model>
      </Brand>
    </SupportedSystems>
  </SoftwareComponent>
  <SoftwareComponent packageID="3P5N0" packageType="LW64"
      path="FOLDER12648511M/2/SAS-Drive_Firmware_3P5N0_WN64_LW0B_A00_01.EXE"
      releaseDate="March 03, 2025" releaseID="3P5N0" vendorVersion="LW0B">
    <Name><Display lang="en">SAS Drive Firmware</Display></Name>
    <ComponentType value="FRMW"><Display lang="en">Firmware</Display></ComponentType>
    <SupportedSystems>
      <Brand key="3" prefix="PE">
        <Display lang="en">PowerEdge</Display>
        <Model systemID="08FE" systemIDType="BIOS"><Display lang="en">R6525</Display></Model>
      </Brand>
    </SupportedSystems>
  </SoftwareComponent>
  <SoftwareComponent packageID="DD22Y" packageType="LW64"
      path="FOLDER13000000M/1/BIOS_DD22Y_WN64_3.0.1.EXE"
      releaseDate="May 02, 2026" releaseID="DD22Y" vendorVersion="3.0.1">
    <Name><Display lang="en">PowerEdge BIOS R750xs</Display></Name>
    <ComponentType value="BIOS"><Display lang="en">BIOS</Display></ComponentType>
    <SupportedSystems>
      <Brand key="3" prefix="PE">
        <Display lang="en">PowerEdge</Display>
        <Model systemID="0B9E" systemIDType="BIOS"><Display lang="en">R750xs</Display></Model>
      </Brand>
    </SupportedSystems>
  </SoftwareComponent>
</Manifest>
"""


def test_parse_catalog_returns_only_bios_components() -> None:
    entries = parse_catalog(_CATALOG_FIXTURE, brand_prefix="PE")
    # The SAS drive firmware row (ComponentType=FRMW) must be filtered out.
    assert {e.package_id for e in entries} == {"RWK5K", "DD22Y"}


def test_parse_catalog_groups_models_per_component() -> None:
    entries = parse_catalog(_CATALOG_FIXTURE, brand_prefix="PE")
    rwk5k = next(e for e in entries if e.package_id == "RWK5K")
    assert rwk5k.models == ("R6525", "R7525")
    assert rwk5k.version == "2.24.1"
    assert rwk5k.path == "FOLDER14403046M/1/BIOS_RWK5K_WN64_2.24.1.EXE"
    assert rwk5k.release_date == "April 27, 2026"


def test_parse_catalog_brand_filter_excludes_other_prefixes() -> None:
    # No PRE-branded entries in the fixture, so requesting Precision yields nothing.
    assert parse_catalog(_CATALOG_FIXTURE, brand_prefix="PRE") == []


# ---------------------------------------------------------------------------
# DUP / PFS unwrap
# ---------------------------------------------------------------------------


def _build_pfs_entry(payload: bytes) -> bytes:
    """Build a single PFS entry whose data area is *payload*."""
    header = bytearray(PFS_ENTRY_HEADER_SIZE)
    # DataSize at 0x28; signatures and metadata fields stay zero.
    header[0x28:0x2C] = len(payload).to_bytes(4, "little")
    return bytes(header) + payload


def _build_pfs_blob(entries: list[bytes]) -> bytes:
    """Wrap a list of PFS entries in PFS.HDR./PFS.FTR. markers."""
    body = b"".join(entries)
    # Header: magic(8) + version(4) + payload_size(4)
    header = PFS_HEADER_MAGIC + (1).to_bytes(4, "little") + len(body).to_bytes(4, "little")
    # Footer: magic(8) + payload_size(4) + checksum(4) — values are not validated.
    footer = PFS_FOOTER_MAGIC + len(body).to_bytes(4, "little") + (0).to_bytes(4, "little")
    return header + body + footer


def test_unwrap_dell_dup_returns_payload_with_psp_signature() -> None:
    rom = b"\x00" * 4096 + b"$PSP" + b"\xab" * 8192 + b"$BHD" + b"\xff" * 4096
    pfs = _build_pfs_blob([_build_pfs_entry(rom)])
    # Add some leading bytes so we exercise the PFS.HDR. search step.
    dup = b"\x4d\x5a" + b"\x00" * 1024 + pfs + b"trailing junk"
    assert unwrap_dell_dup(dup) == rom


def test_unwrap_dell_dup_picks_largest_amd_entry_among_decoys() -> None:
    config_blob = b"\x00" * 1024  # no PSP signature — must be skipped
    small_amd_blob = b"$PSP" + b"\x11" * 256
    large_amd_blob = b"\x00" * 1024 + b"$BHD" + b"\x22" * 16384
    pfs = _build_pfs_blob(
        [
            _build_pfs_entry(config_blob),
            _build_pfs_entry(small_amd_blob),
            _build_pfs_entry(large_amd_blob),
        ]
    )
    assert unwrap_dell_dup(pfs) == large_amd_blob


def test_unwrap_dell_dup_raises_when_no_pfs_header() -> None:
    with pytest.raises(ValueError, match=r"PFS\.HDR"):
        unwrap_dell_dup(b"MZ" + b"\x00" * 8192)


def test_unwrap_dell_dup_raises_when_no_amd_entry() -> None:
    pfs = _build_pfs_blob([_build_pfs_entry(b"intel-bios-payload" * 100)])
    with pytest.raises(ValueError, match="no PFS entry"):
        unwrap_dell_dup(pfs)


# ---------------------------------------------------------------------------
# Async API (mocked HTTP)
# ---------------------------------------------------------------------------


def _utf16_with_bom(text: str) -> bytes:
    return b"\xff\xfe" + text.encode("utf-16-le")


def _build_catalog_gzip(text: str) -> bytes:
    """Match Dell's wire format: gzip-wrapped UTF-16-LE XML with BOM."""
    return gzip.compress(_utf16_with_bom(text))


def _response(status: int, *, content: bytes = b"", url: str) -> httpx.Response:
    return httpx.Response(status, content=content, request=httpx.Request("GET", url))


def test_list_boards_yields_only_amd_poweredge_models() -> None:
    catalog_bytes = _build_catalog_gzip(_CATALOG_FIXTURE)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == CATALOG_URL:
            return _response(200, content=catalog_bytes, url=str(request.url))
        if str(request.url) == CATALOG_PC_URL:
            # Empty CAB → simulates the cabextract-missing path so the test is
            # hermetic. The scraper must still return the PowerEdge boards.
            return _response(200, content=b"\x00\x00\x00\x00", url=str(request.url))
        raise AssertionError(f"unexpected url: {request.url}")

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    async def run() -> list[BoardInfo]:
        async with DellScraper(client=client) as scraper:
            return await scraper.list_boards()

    boards = asyncio.run(run())

    # R750xs is Intel and must be filtered out; R6525 and R7525 are AMD.
    by_model = {b.model: b for b in boards}
    assert set(by_model) == {"R6525", "R7525"}
    assert by_model["R6525"].socket == "SP3"
    assert by_model["R6525"].vendor == "Dell"
    assert "poweredge-r6525" in by_model["R6525"].url


def test_list_bios_updates_returns_catalog_versions_for_board() -> None:
    catalog_bytes = _build_catalog_gzip(_CATALOG_FIXTURE)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == CATALOG_URL:
            return _response(200, content=catalog_bytes, url=str(request.url))
        return _response(200, content=b"", url=str(request.url))

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(vendor="Dell", model="R6525", socket="SP3", url="https://dell.example/r6525")

    async def run() -> list:
        async with DellScraper(client=client) as scraper:
            return await scraper.list_bios_updates(board)

    updates = asyncio.run(run())
    assert len(updates) == 1
    assert updates[0].bios_version == "2.24.1"
    assert updates[0].download_url == ("https://downloads.dell.com/FOLDER14403046M/1/BIOS_RWK5K_WN64_2.24.1.EXE")
    assert updates[0].release_date == "April 27, 2026"


def test_download_unwraps_dup_and_writes_rom(tmp_path) -> None:
    rom_payload = b"\x00" * 1024 + b"$PSP" + b"\xab" * 4096 + b"$BHD" + b"\x00" * 2048
    pfs = _build_pfs_blob([_build_pfs_entry(rom_payload)])
    dup_bytes = b"MZ" + b"\x00" * 256 + pfs

    def handler(request: httpx.Request) -> httpx.Response:
        return _response(200, content=dup_bytes, url=str(request.url))

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(vendor="Dell", model="R6525", socket="SP3", url="https://dell.example/r6525")
    update = type(
        "U",
        (),
        {
            "board": board,
            "bios_version": "2.24.1",
            "download_url": "https://downloads.dell.com/FOLDER1/1/BIOS.EXE",
            "release_date": None,
            "agesa_version": None,
        },
    )()

    async def run() -> object:
        async with DellScraper(client=client) as scraper:
            return await scraper.download(update, tmp_path)

    out_path = asyncio.run(run())
    assert out_path.exists()
    assert out_path.read_bytes() == rom_payload
    assert out_path.name == "R6525_2.24.1.rom"
