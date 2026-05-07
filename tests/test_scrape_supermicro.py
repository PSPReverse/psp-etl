"""Tests for psp_etl.scrape.supermicro."""

import asyncio
import io
import zipfile
from pathlib import Path

import httpx
import pytest

from psp_etl.scrape.base import BiosUpdate, BoardInfo
from psp_etl.scrape.supermicro import (
    SupermicroScraper,
    _detect_socket,
    _extract_version,
    build_download_url,
    extract_rom_bytes,
    parse_catalog,
)

# ---------------------------------------------------------------------------
# Socket detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("H11SSL-i", "SP3"),
        ("H11DSi-NT", "SP3"),
        ("H12SSL-i", "SP3"),
        ("H12SSW-AN6", "SP3"),
        ("H13SSL-N", "SP5"),
        ("H13DSG-O-CPU", "SP5"),
        ("H14SSL-N", "SP5"),
        ("H14SHM", "SP5"),
        ("M12SWA-TF", "sWRX8"),
        ("M13SWA-TF", "sWRX9"),
    ],
)
def test_detect_socket_known_prefixes(model: str, expected: str) -> None:
    assert _detect_socket(model) == expected


@pytest.mark.parametrize(
    "model",
    [
        "M11SDV-4C-LN4F",  # embedded EPYC 3000
        "BH12SSi-M25",  # blade
        "caram5-m",  # consumer AM5 reference
        "X12STH-F",  # Intel
        "",
    ],
)
def test_detect_socket_unknown_or_out_of_scope(model: str) -> None:
    assert _detect_socket(model) is None


# ---------------------------------------------------------------------------
# Version extraction
# ---------------------------------------------------------------------------


def test_extract_version_bundle() -> None:
    assert _extract_version("H12SS-(i)(C)(CT)(NT)_3.6_AS1.08.01_SAA1.5.0", "Bundle") == "3.6"
    assert _extract_version("H13SST-G(C)_3.7_AS1.09.02_SAA1.4.0-p10", "Bundle") == "3.7"
    assert _extract_version("H14SHM_2.0_AS01.06.00.03_SAA1.5.0-p2", "Bundle") == "2.0"


def test_extract_version_bios_only() -> None:
    assert _extract_version("3.4", "BIOS") == "3.4"
    assert _extract_version("2.4a", "BIOS") == "2.4a"
    assert _extract_version("1.3", "BIOS") == "1.3"


def test_extract_version_handles_empty_or_unparseable() -> None:
    assert _extract_version("", "Bundle") is None
    assert _extract_version("garbage_with_no_AS_marker", "Bundle") is None


# ---------------------------------------------------------------------------
# Download URL builder
# ---------------------------------------------------------------------------


def test_build_download_url() -> None:
    assert build_download_url("27899") == (
        "https://www.supermicro.com/support/resources/getfile.php?SoftwareItemID=27899"
    )


# ---------------------------------------------------------------------------
# Catalog parsing
# ---------------------------------------------------------------------------


_CATALOG_FIXTURE = """
<html><body><table>
<tr>
  <td align="left"></td><td></td><td></td><td></td><td>Header</td>
</tr>
<tr>
  <td align="left">
    <a href="/en/products/motherboard/H11SSL-C">H11SSL-C</a><br>
    <a href="/en/products/motherboard/H11SSL-i">H11SSL-i</a><br>
    <a href="/en/products/motherboard/H11SSL-i">H11SSL-i</a><br>
    <a href="/en/products/motherboard/H11SSL-NC">H11SSL-NC</a>
  </td>
  <td align="center" style="word-break: break-word;">3.4</td>
  <td align="left">
    <a href="/about/policies/disclaimer.php?SoftwareItemID=27899" target="_blank">BIOS_H11SSL_1A03_20250728_3.4_STDsp.zip</a>
  </td>
  <td align="left">
    <a href="/about/policies/disclaimer.php?SoftwareItemID=27899&type=releasenote" target="_blank">notes.pdf</a>
  </td>
  <td align="left">BIOS<br><font color='red'>caveat</font></td>
</tr>
<tr>
  <td align="left">
    <a href="/en/products/motherboard/H12SSL-i">H12SSL-i</a>
  </td>
  <td align="center" style="word-break: break-word;">H12SS-(i)(C)(CT)(NT)_3.6_AS1.08.01_SAA1.5.0</td>
  <td align="left">
    <a href="/about/policies/disclaimer.php?SoftwareItemID=30219" target="_blank">H12SS-(i)(C)(CT)(NT)_3.6_AS1.08.01_SAA1.5.0.zip</a>
  </td>
  <td align="left">
    <a href="/about/policies/disclaimer.php?SoftwareItemID=30219&type=biosreleasenote" target="_blank">notes.pdf</a>
  </td>
  <td align="left">Bundle</td>
</tr>
<tr>
  <td align="left">
    <a href="/en/products/motherboard/M12SWA-TF">M12SWA-TF</a>
  </td>
  <td align="center" style="word-break: break-word;">01.06.28</td>
  <td align="left">
    <a href="/about/policies/disclaimer.php?SoftwareItemID=28007" target="_blank">BMC_M12AST2600-B201MS_20251002_01.06.28_STDsp.zip</a>
  </td>
  <td align="left"></td>
  <td align="left">BMC</td>
</tr>
<tr>
  <td align="left">
    <a href="/en/products/motherboard/M12SWA-TF">M12SWA-TF</a>
  </td>
  <td align="center" style="word-break: break-word;">2.4a</td>
  <td align="left">
    <a href="/about/policies/disclaimer.php?SoftwareItemID=26540" target="_blank">BIOS_M12SWA-TF-1C1C_20250717_2.4a_STDsp.zip</a>
  </td>
  <td align="left"></td>
  <td align="left">BIOS</td>
</tr>
</table></body></html>
"""


def test_parse_catalog_extracts_rows() -> None:
    rows = parse_catalog(_CATALOG_FIXTURE)
    # Header row has no SoftwareItemID and is skipped.
    assert len(rows) == 4

    h11 = rows[0]
    assert h11.models == ["H11SSL-C", "H11SSL-i", "H11SSL-NC"]
    assert h11.software_id == "27899"
    assert h11.type_label == "BIOS"
    assert h11.title == "3.4"

    h12_bundle = rows[1]
    assert h12_bundle.models == ["H12SSL-i"]
    assert h12_bundle.software_id == "30219"
    assert h12_bundle.type_label == "Bundle"

    bmc_row = rows[2]
    assert bmc_row.type_label == "BMC"

    m12_bios = rows[3]
    assert m12_bios.models == ["M12SWA-TF"]
    assert m12_bios.title == "2.4a"
    assert m12_bios.type_label == "BIOS"


def test_parse_catalog_skips_release_note_links() -> None:
    """The download cell may contain a release-note link that shares the
    SoftwareItemID; the parser must pick the bare-URL bundle link."""
    html = """
    <table><tr>
      <td><a href="/en/products/motherboard/H13SSL-N">H13SSL-N</a></td>
      <td>3.0</td>
      <td>
        <a href="/about/policies/disclaimer.php?SoftwareItemID=99999&type=releasenote">notes.pdf</a>
        <a href="/about/policies/disclaimer.php?SoftwareItemID=99999">bundle.zip</a>
      </td>
      <td></td>
      <td>BIOS</td>
    </tr></table>
    """
    rows = parse_catalog(html)
    assert len(rows) == 1
    assert rows[0].software_id == "99999"
    assert rows[0].zip_filename == "bundle.zip"


# ---------------------------------------------------------------------------
# ZIP extraction
# ---------------------------------------------------------------------------


def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_extract_rom_bytes_bios_only_zip() -> None:
    """A BIOS-only archive holds the raw ROM next to flash utilities."""
    rom_bytes = b"$PSP" + b"\x00" * 1024 * 1024
    zip_bytes = _make_zip(
        {
            "H11SSL_1A03.B34": rom_bytes,
            "afudos.exe": b"flash utility binary" * 1000,
            "readme.txt": b"flash these bits, do not blame us if your board bricks",
        }
    )
    name, data = extract_rom_bytes(zip_bytes, "H11SSL-i")
    assert name == "H11SSL_1A03.B34"
    assert data == rom_bytes


def test_extract_rom_bytes_nested_bundle() -> None:
    """Bundle archives wrap a BIOS_*.zip inside the outer archive."""
    rom_bytes = b"$PSP" + b"\xab" * 4096
    inner_zip = _make_zip({"H12SSL-1B65.B36": rom_bytes, "afu.bat": b"echo flashing"})
    outer_zip = _make_zip(
        {
            "BIOS_H12SSL-1B65_20250901_3.6_STDsp.zip": inner_zip,
            "BMC_H12AST2500_01_08_01.zip": b"unrelated BMC blob" * 100,
            "release_notes.pdf": b"%PDF-1.4 fake",
        }
    )
    name, data = extract_rom_bytes(outer_zip, "H12SSL-i")
    assert name == "H12SSL-1B65.B36"
    assert data == rom_bytes


def test_extract_rom_bytes_prefers_model_prefix() -> None:
    """When multiple ROM-shaped files exist, prefer one matching the model."""
    target = b"\xff" * 8192
    decoy = b"\x00" * 16384
    zip_bytes = _make_zip(
        {
            "M12SWA-TF-1C1C.B24a": target,
            "STARTUP.NSH": decoy,
        }
    )
    name, data = extract_rom_bytes(zip_bytes, "M12SWA-TF")
    assert name == "M12SWA-TF-1C1C.B24a"
    assert data == target


def test_extract_rom_bytes_raises_when_only_docs() -> None:
    zip_bytes = _make_zip({"readme.pdf": b"%PDF", "notes.txt": b"hello"})
    with pytest.raises(FileNotFoundError):
        extract_rom_bytes(zip_bytes, "H11SSL-i")


# ---------------------------------------------------------------------------
# Async API (mocked HTTP)
# ---------------------------------------------------------------------------


def _response(status: int, *, content: bytes = b"", url: str = "https://example.com") -> httpx.Response:
    return httpx.Response(status, content=content, request=httpx.Request("GET", url))


def test_list_boards_filters_to_in_scope_sockets() -> None:
    """list_boards() returns only boards whose prefix maps to a known socket."""
    html = (
        _CATALOG_FIXTURE
        + """
    <table><tr>
      <td><a href="/en/products/motherboard/M11SDV-4C-LN4F">M11SDV-4C-LN4F</a></td>
      <td>2.0</td>
      <td><a href="/about/policies/disclaimer.php?SoftwareItemID=11111">x.zip</a></td>
      <td></td>
      <td>BIOS</td>
    </tr></table>
    """
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return _response(200, content=html.encode("utf-8"))

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    async def run() -> list[BoardInfo]:
        async with SupermicroScraper(client=client) as scraper:
            return await scraper.list_boards()

    boards = asyncio.run(run())
    models = {b.model: b.socket for b in boards}
    assert models == {
        "H11SSL-C": "SP3",
        "H11SSL-i": "SP3",
        "H11SSL-NC": "SP3",
        "H12SSL-i": "SP3",
        "M12SWA-TF": "sWRX8",
    }
    # M11SDV is filtered (no socket mapping); the BMC-only row shares
    # M12SWA-TF with the BIOS row, so it does not duplicate.
    for b in boards:
        assert b.vendor == "Supermicro"
        assert b.url.startswith("https://www.supermicro.com/en/products/motherboard/")


def test_list_bios_updates_returns_bios_and_bundle_skips_bmc() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response(200, content=_CATALOG_FIXTURE.encode("utf-8"))

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(
        vendor="Supermicro",
        model="M12SWA-TF",
        socket="sWRX8",
        url="https://www.supermicro.com/en/products/motherboard/M12SWA-TF",
    )

    async def run() -> list[BiosUpdate]:
        async with SupermicroScraper(client=client) as scraper:
            return await scraper.list_bios_updates(board)

    updates = asyncio.run(run())
    assert len(updates) == 1
    assert updates[0].bios_version == "2.4a"
    assert updates[0].download_url.endswith("SoftwareItemID=26540")
    assert updates[0].board.model == "M12SWA-TF"


def test_list_bios_updates_for_bundle_row() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response(200, content=_CATALOG_FIXTURE.encode("utf-8"))

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(
        vendor="Supermicro",
        model="H12SSL-i",
        socket="SP3",
        url="https://www.supermicro.com/en/products/motherboard/H12SSL-i",
    )

    async def run() -> list[BiosUpdate]:
        async with SupermicroScraper(client=client) as scraper:
            return await scraper.list_bios_updates(board)

    updates = asyncio.run(run())
    assert len(updates) == 1
    assert updates[0].bios_version == "3.6"


def test_download_writes_rom_to_disk(tmp_path: Path) -> None:
    rom_bytes = b"$PSP" + b"\x42" * 2048
    zip_bytes = _make_zip({"M12SWA-TF-1C1C.B24a": rom_bytes})

    def handler(request: httpx.Request) -> httpx.Response:
        if "getfile.php" in str(request.url):
            return _response(200, content=zip_bytes, url=str(request.url))
        return _response(404, url=str(request.url))

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(vendor="Supermicro", model="M12SWA-TF", socket="sWRX8", url="https://example.com")
    update = BiosUpdate(
        board=board,
        bios_version="2.4a",
        download_url=build_download_url("26540"),
        release_date=None,
        agesa_version=None,
    )

    async def run() -> Path:
        async with SupermicroScraper(client=client) as scraper:
            return await scraper.download(update, tmp_path)

    out = asyncio.run(run())
    assert out.exists()
    assert out.read_bytes() == rom_bytes
    # Filename is derived from model + version.
    assert "M12SWA-TF" in out.name
    assert "2.4a" in out.name
