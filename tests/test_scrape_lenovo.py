"""Tests for psp_etl.scrape.lenovo."""

from __future__ import annotations

import asyncio
import io
import zipfile
from pathlib import Path

import httpx
import pytest

from psp_etl.scrape.base import BiosUpdate, BoardInfo
from psp_etl.scrape.lenovo import (
    _BOARDS,
    DATACENTER_API,
    PCSUPPORT_API,
    LenovoScraper,
    _is_bios_item,
    _pick_file,
    _unix_to_iso,
    extract_thinkstation_rom,
)

# ---------------------------------------------------------------------------
# Static board table sanity
# ---------------------------------------------------------------------------


def test_board_table_covers_required_skus() -> None:
    """Issue #87 requires SR6x5, SR6x5 V3, and P620 at minimum."""
    models = {b.model for b in _BOARDS}
    required = {
        "ThinkSystem SR635",
        "ThinkSystem SR645",
        "ThinkSystem SR655",
        "ThinkSystem SR665",
        "ThinkSystem SR635 V3",
        "ThinkSystem SR645 V3",
        "ThinkSystem SR655 V3",
        "ThinkSystem SR665 V3",
        "ThinkStation P620",
    }
    assert required <= models


def test_board_table_uses_lowercase_4char_machine_types() -> None:
    for spec in _BOARDS:
        assert len(spec.machine_type) == 4, spec
        assert spec.machine_type == spec.machine_type.lower(), spec


def test_board_sockets_match_family() -> None:
    """ThinkSystem V3 -> SP5, ThinkSystem first-gen -> SP3, P620 -> sWRX8."""
    by_model = {b.model: b for b in _BOARDS}
    assert by_model["ThinkSystem SR665 V3"].socket == "SP5"
    assert by_model["ThinkSystem SR635 V3"].socket == "SP5"
    assert by_model["ThinkSystem SR665"].socket == "SP3"
    assert by_model["ThinkSystem SR635"].socket == "SP3"
    assert by_model["ThinkStation P620"].socket == "sWRX8"


# ---------------------------------------------------------------------------
# BIOS-item filter
# ---------------------------------------------------------------------------


def _bios_item(title: str, category: str, files: list[dict] | None = None) -> dict:
    return {
        "Title": title,
        "Category": {"Name": category},
        "Files": files or [],
        "SummaryInfo": {"Version": "1.0"},
    }


def test_is_bios_item_accepts_thinkstation_short_label() -> None:
    item = _bios_item("Flash BIOS Update for ThinkStation P620", "BIOS/UEFI")
    assert _is_bios_item(item)


def test_is_bios_item_accepts_thinksystem_long_label() -> None:
    item = _bios_item(
        "Lenovo System UEFI/BIOS Firmware",
        "Core System Firmware (UEFI (BIOS), LXCC(BMC) LXPM (Provisioning), FPGA)",
    )
    assert _is_bios_item(item)


@pytest.mark.parametrize(
    "title",
    [
        "ThinkSystem RAID 530-x Adapters update BIOS and Firmware (For Windows)",
        "Nvidia RTX 6000 Ada VBIOS for Windows 10 (64-bit), 11 - ThinkStation P620",
        "ThinkSystem 430-x SAS/SATA 12Gb HBA update BIOS and Firmware",
        "Lenovo Diagnostics UEFI Engineer Version (Bootable USB)",
        "Lenovo Drives Media Storage Firmware",
    ],
)
def test_is_bios_item_rejects_disqualifiers(title: str) -> None:
    item = _bios_item(title, "BIOS/UEFI")
    assert not _is_bios_item(item)


def test_is_bios_item_rejects_other_categories() -> None:
    item = _bios_item("Lenovo System UEFI/BIOS Firmware", "Software and Utilities")
    assert not _is_bios_item(item)


# ---------------------------------------------------------------------------
# File picker
# ---------------------------------------------------------------------------


def _file(type_str: str, name: str, version: str = "1.0", url: str = "https://x") -> dict:
    return {"TypeString": type_str, "Name": name, "Version": version, "URL": url}


def test_pick_file_thinkstation_prefers_efi_shell_zip() -> None:
    files = [
        _file("EXE", "Flash UEFI BIOS update (Operating System Version)", url="https://e.exe"),
        _file("ISO", "Flash UEFI BIOS Update (CD ISO image version)", url="https://e.iso"),
        _file("zip", "Flash UEFI BIOS Update – EFI Shell Utility", url="https://e.zip"),
        _file("zip", "Linux Capsule Update Package", url="https://l.zip"),
    ]
    chosen = _pick_file(files, family="ThinkStation")
    assert chosen is not None
    assert chosen["URL"] == "https://e.zip"


def test_pick_file_thinkstation_falls_back_when_no_efi_shell() -> None:
    files = [
        _file("EXE", "Flash UEFI BIOS update", url="https://e.exe"),
        _file("zip", "Bootable USB Package", url="https://b.zip"),
        _file("zip", "Linux Capsule Update Package", url="https://l.zip"),
    ]
    chosen = _pick_file(files, family="ThinkStation")
    assert chosen is not None
    assert chosen["URL"] == "https://b.zip"


def test_pick_file_thinksystem_prefers_uxz() -> None:
    files = [
        _file("HTML", "Release notes (HTML)", url="https://x.html"),
        _file("uxz", "Payload file", url="https://x.uxz"),
        _file("zip", "Payload (archive)", url="https://x.zip"),
    ]
    chosen = _pick_file(files, family="ThinkSystem")
    assert chosen is not None
    assert chosen["URL"] == "https://x.uxz"


def test_pick_file_thinksystem_v3_zip_payload_when_no_uxz() -> None:
    """SR665 V3 wraps the .uxz inside a zip whose Name starts with 'Payload'."""
    files = [
        _file("zip", "Payload (archive)", url="https://x.zip"),
        _file("HTML", "Release notes (HTML)", url="https://x.html"),
    ]
    chosen = _pick_file(files, family="ThinkSystem")
    assert chosen is not None
    assert chosen["URL"] == "https://x.zip"


def test_pick_file_returns_none_when_no_payload() -> None:
    files = [_file("HTML", "Release notes", url="https://x.html")]
    assert _pick_file(files, family="ThinkSystem") is None
    assert _pick_file(files, family="ThinkStation") is None


# ---------------------------------------------------------------------------
# Timestamp helper
# ---------------------------------------------------------------------------


def test_unix_to_iso() -> None:
    # 1772681404000 ms -> 2026-03-05 (UTC)
    assert _unix_to_iso({"Unix": 1772681404000}) == "2026-03-05"


def test_unix_to_iso_handles_missing() -> None:
    assert _unix_to_iso(None) is None
    assert _unix_to_iso({}) is None
    assert _unix_to_iso({"Unix": None}) is None


# ---------------------------------------------------------------------------
# ThinkStation ROM extraction
# ---------------------------------------------------------------------------


def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _fake_rom(size: int) -> bytes:
    """Synthetic ROM that passes validate_psp_rom (carries $PSP marker)."""
    body = bytearray(b"\x00" * size)
    # Place a $PSP signature at a plausible offset.
    marker = b"$PSP"
    body[0x1000 : 0x1000 + len(marker)] = marker
    return bytes(body)


def test_extract_thinkstation_rom_picks_largest_rom() -> None:
    rom = _fake_rom(0x2000)
    decoy = b"\x42" * 0x100
    zip_bytes = _make_zip(
        {
            "AfuEfix64.efi": b"flash util",
            "IMAGES07.ROM": rom,
            "ChgLogo.efi": decoy,
            "logo.nsh": b"",
        }
    )
    name, data = extract_thinkstation_rom(zip_bytes)
    assert name == "IMAGES07.ROM"
    assert data == rom


def test_extract_thinkstation_rom_rejects_unrecognised_image() -> None:
    """A .rom with no PSP signature should fail loud, not silently propagate."""
    bogus = b"\x00" * 0x2000
    zip_bytes = _make_zip({"IMAGES07.ROM": bogus})
    with pytest.raises(ValueError, match="PSP/BIOS directory signature"):
        extract_thinkstation_rom(zip_bytes)


def test_extract_thinkstation_rom_raises_when_no_rom_present() -> None:
    zip_bytes = _make_zip({"readme.txt": b"hello"})
    with pytest.raises(FileNotFoundError):
        extract_thinkstation_rom(zip_bytes)


# ---------------------------------------------------------------------------
# Async API (mocked HTTP)
# ---------------------------------------------------------------------------


def _response(
    status: int, *, json_body: dict | None = None, content: bytes = b"", url: str = "https://x"
) -> httpx.Response:
    if json_body is not None:
        return httpx.Response(status, json=json_body, request=httpx.Request("GET", url))
    return httpx.Response(status, content=content, request=httpx.Request("GET", url))


_SR665V3_FIXTURE = {
    "message": "succeed",
    "body": {
        "DownloadItems": [
            {
                "Title": "Lenovo System UEFI/BIOS Firmware",
                "Category": {"Name": "Core System Firmware (UEFI (BIOS), LXCC(BMC) LXPM (Provisioning), FPGA)"},
                "Date": {"Unix": 1772681404000},
                "Files": [
                    {
                        "TypeString": "HTML",
                        "Name": "Release notes (HTML)",
                        "Version": "5.81",
                        "URL": "https://download.lenovo.com/x/release.html",
                    },
                    {
                        "TypeString": "zip",
                        "Name": "Payload (archive)",
                        "Version": "5.81",
                        "URL": "https://download.lenovo.com/x/uefi.zip",
                    },
                ],
                "SummaryInfo": {"Version": "5.81"},
            },
            {
                "Title": "ThinkSystem RAID 940-x Adapters update BIOS and Firmware",
                "Category": {
                    "Name": "RAID/SAS HBA Controllers, Backplanes, Storage Expanders/Switches, Bootable Storage"
                },
                "Date": {"Unix": 1700000000000},
                "Files": [
                    {
                        "TypeString": "EXE",
                        "Name": "RAID firmware",
                        "Version": "52.20.0",
                        "URL": "https://download.lenovo.com/x/raid.exe",
                    },
                ],
            },
        ],
    },
}


_P620_FIXTURE = {
    "message": "succeed",
    "body": {
        "DownloadItems": [
            {
                "Title": "Flash BIOS Update for ThinkStation P620",
                "Category": {"Name": "BIOS/UEFI"},
                "Date": {"Unix": 1758000000000},
                "Files": [
                    {
                        "TypeString": "EXE",
                        "Name": "Flash UEFI BIOS update (Operating System Version)",
                        "Version": "S07KT6CA/1.108",
                        "URL": "https://download.lenovo.com/p/win.exe",
                    },
                    {
                        "TypeString": "zip",
                        "Name": "Flash UEFI BIOS Update – EFI Shell Utility",
                        "Version": "S07KT6CA/1.108",
                        "URL": "https://download.lenovo.com/p/efishell.zip",
                    },
                    {
                        "TypeString": "zip",
                        "Name": "Linux Capsule Update Package",
                        "Version": "S07KT6CA/1.108",
                        "URL": "https://download.lenovo.com/p/capsule.zip",
                    },
                ],
            },
            {
                "Title": "Nvidia RTX 6000 Ada VBIOS - ThinkStation P620",
                "Category": {"Name": "BIOS/UEFI"},
                "Date": {"Unix": 1700000000000},
                "Files": [
                    {
                        "TypeString": "zip",
                        "Name": "VBIOS",
                        "Version": "95.02",
                        "URL": "https://download.lenovo.com/p/vbios.zip",
                    },
                ],
            },
        ],
    },
}


def test_list_boards_emits_required_skus() -> None:
    async def run() -> list[BoardInfo]:
        async with LenovoScraper() as scraper:
            return await scraper.list_boards()

    boards = asyncio.run(run())
    by_model = {b.model: b for b in boards}
    assert "ThinkStation P620" in by_model
    assert by_model["ThinkStation P620"].socket == "sWRX8"
    assert by_model["ThinkStation P620"].vendor == "Lenovo"
    assert by_model["ThinkSystem SR665 V3"].socket == "SP5"
    assert by_model["ThinkSystem SR665"].socket == "SP3"


def test_list_bios_updates_thinksystem_filters_to_uefi_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith(DATACENTER_API)
        assert request.url.params.get("productId") == "7d9b"
        return _response(200, json_body=_SR665V3_FIXTURE)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(
        vendor="Lenovo",
        model="ThinkSystem SR665 V3",
        socket="SP5",
        url="https://x",
    )

    async def run() -> list[BiosUpdate]:
        async with LenovoScraper(client=client) as scraper:
            return await scraper.list_bios_updates(board)

    updates = asyncio.run(run())
    assert len(updates) == 1
    assert updates[0].bios_version == "5.81"
    assert updates[0].download_url == "https://download.lenovo.com/x/uefi.zip"
    assert updates[0].release_date == "2026-03-05"


def test_list_bios_updates_thinkstation_picks_efi_shell_zip() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith(PCSUPPORT_API)
        assert request.url.params.get("productId") == "30e0"
        return _response(200, json_body=_P620_FIXTURE)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(
        vendor="Lenovo",
        model="ThinkStation P620",
        socket="sWRX8",
        url="https://x",
    )

    async def run() -> list[BiosUpdate]:
        async with LenovoScraper(client=client) as scraper:
            return await scraper.list_bios_updates(board)

    updates = asyncio.run(run())
    assert len(updates) == 1
    assert updates[0].bios_version == "S07KT6CA/1.108"
    assert updates[0].download_url == "https://download.lenovo.com/p/efishell.zip"


def test_download_thinksystem_raises_not_implemented(tmp_path: Path) -> None:
    board = BoardInfo(
        vendor="Lenovo",
        model="ThinkSystem SR665 V3",
        socket="SP5",
        url="https://x",
    )
    update = BiosUpdate(
        board=board,
        bios_version="5.81",
        download_url="https://download.lenovo.com/x/uefi.zip",
        release_date=None,
        agesa_version=None,
    )

    async def run() -> Path:
        async with LenovoScraper() as scraper:
            return await scraper.download(update, tmp_path)

    with pytest.raises(NotImplementedError, match="UpdateXpress"):
        asyncio.run(run())


def test_download_thinkstation_writes_extracted_rom(tmp_path: Path) -> None:
    rom = _fake_rom(0x4000)
    payload_zip = _make_zip(
        {
            "AfuEfix64.efi": b"util" * 32,
            "IMAGES07.ROM": rom,
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://download.lenovo.com/p/efishell.zip":
            return _response(200, content=payload_zip, url=str(request.url))
        return _response(404, url=str(request.url))

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(
        vendor="Lenovo",
        model="ThinkStation P620",
        socket="sWRX8",
        url="https://x",
    )
    update = BiosUpdate(
        board=board,
        bios_version="S07KT6CA/1.108",
        download_url="https://download.lenovo.com/p/efishell.zip",
        release_date=None,
        agesa_version=None,
    )

    async def run() -> Path:
        async with LenovoScraper(client=client) as scraper:
            return await scraper.download(update, tmp_path)

    out = asyncio.run(run())
    assert out.exists()
    assert out.read_bytes() == rom
    # Filename carries the model and version stems for traceability.
    assert "ThinkStation_P620" in out.name
    # Slashes are scrubbed from the version segment.
    assert "S07KT6CA" in out.name


def test_list_bios_updates_caches_per_machine_type() -> None:
    """Two calls for the same board hit the API once."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _response(200, json_body=_SR665V3_FIXTURE)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    board = BoardInfo(
        vendor="Lenovo",
        model="ThinkSystem SR665 V3",
        socket="SP5",
        url="https://x",
    )

    async def run() -> int:
        async with LenovoScraper(client=client) as scraper:
            await scraper.list_bios_updates(board)
            await scraper.list_bios_updates(board)
        return calls

    assert asyncio.run(run()) == 1


def test_list_bios_updates_unknown_model_raises() -> None:
    board = BoardInfo(vendor="Lenovo", model="ThinkSystem SR999", socket="SP5", url="https://x")

    async def run() -> list[BiosUpdate]:
        async with LenovoScraper() as scraper:
            return await scraper.list_bios_updates(board)

    with pytest.raises(ValueError, match="Unknown Lenovo board model"):
        asyncio.run(run())


def test_scraper_requires_async_context_manager() -> None:
    """Calling list_bios_updates without entering the context fails loud."""
    scraper = LenovoScraper()
    board = BoardInfo(vendor="Lenovo", model="ThinkStation P620", socket="sWRX8", url="https://x")

    async def run() -> list[BiosUpdate]:
        return await scraper.list_bios_updates(board)

    with pytest.raises(RuntimeError, match="async context manager"):
        asyncio.run(run())
