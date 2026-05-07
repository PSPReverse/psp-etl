"""ASUS server EPYC motherboard BIOS scraper (SP3 / SP5 / SP6).

Distinct from :class:`psp_etl.scrape.asus.AsusScraper`, which targets consumer
AM4/AM5 boards. Server boards live on ``servers.asus.com``, but BIOS metadata
and downloads are still served by the consumer support API and CDN.

Discovery: HTML-scrape the public catalog page for current EPYC server models
(no JSON catalog endpoint exists for server boards), plus a small curated
fallback list of legacy SKUs that have been retired from the catalog but
remain accessible via the support API.

BIOS list + download: reuses the consumer
``www.asus.com/support/webapi/ProductV2/GetPDBIOS`` endpoint and the
``dlcdnets.asus.com`` CDN. Server BIOS ZIPs contain a single .CAP file with
the same 0x800-byte AMI capsule header as the consumer lineup.
"""

from __future__ import annotations

import re
import zipfile
from io import BytesIO
from pathlib import Path

import httpx

from psp_etl.scrape.asus import (
    ASUS_CAP_HEADER_SIZE,
    BIOS_API_URL,
    CDN_BASE,
    SUPPORT_API_HEADERS,
    WEBSITE,
)
from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper
from psp_etl.scrape.extract import safe_namelist

SERVER_CATALOG_URL = "https://servers.asus.com/products/Servers/Server-Motherboards"

# Anchor pattern for board tiles in the server catalog HTML, e.g.
#   <a href="/products/servers/server-motherboards/K14PA-U12">
_BOARD_ANCHOR_RE = re.compile(
    r'href="/products/servers/server-motherboards/([A-Za-z0-9][A-Za-z0-9_-]*)"',
)

# Legacy server boards that no longer appear on the live catalog page but
# remain queryable via the support BIOS API. Verified live during scraper
# implementation; KRPG-U8/KMPP-D32/K14PA-U24 returned errors and are
# omitted intentionally.
_LEGACY_BOARDS: tuple[str, ...] = ("KRPA-U16",)

# Maps a board model prefix to its EPYC socket family. Order matters:
# more specific prefixes (K14PG) must come before less specific (K14PA).
_SOCKET_BY_PREFIX: tuple[tuple[str, str], ...] = (
    ("K14PG", "SP6"),  # Siena
    ("S14NA", "SP6"),  # Siena
    ("S14PA", "SP6"),  # Siena
    ("K14PA", "SP5"),  # Genoa / Bergamo
    ("K14NA", "SP5"),
    ("K14SP", "SP5"),
    ("KRPA", "SP3"),  # Naples / Rome / Milan
    ("KRPG", "SP3"),
    ("KMPP", "SP3"),
)

# Server AGESA strings differ from consumer (no ComboAM* prefix). Examples
# observed in real BIOS descriptions:
#   "Update Agesa code to RomePI 1.0.0.E"
#   "Update RC version to 5.22 MilanCrb 0AC0U025"
#   "Update Genoa Agesa code to 1.0.0.G"
#   "Update Milan Agesa code to 1.0.0.9"
_AGESA_PI_RE = re.compile(
    r"\b((?:Naples|Rome|Milan|Genoa|Bergamo|Siena)(?:PI|Crb))\s*[_ ]?([\d.]+[A-Za-z0-9]*)",
    re.IGNORECASE,
)
_AGESA_CODE_RE = re.compile(
    r"\b(Naples|Rome|Milan|Genoa|Bergamo|Siena)\s+Agesa(?:\s+code)?(?:\s+to)?\s+([\d.]+[A-Za-z]?)",
    re.IGNORECASE,
)


def _socket_for_model(model: str) -> str | None:
    upper = model.upper()
    for prefix, socket in _SOCKET_BY_PREFIX:
        if upper.startswith(prefix):
            return socket
    return None


def _extract_server_agesa(description: str | None) -> str | None:
    if not description:
        return None
    if (m := _AGESA_PI_RE.search(description)) is not None:
        return f"{m.group(1)} {m.group(2)}".strip()
    if (m := _AGESA_CODE_RE.search(description)) is not None:
        return f"{m.group(1)} {m.group(2)}".strip()
    return None


class AsusServerScraper(VendorScraper):
    """VendorScraper for ASUS server (EPYC) motherboards on SP3/SP5/SP6."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> AsusServerScraper:
        if self._owns_client:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; psp-etl)"},
            )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("AsusServerScraper must be used as an async context manager")
        return self._client

    async def _fetch_catalog_models(self) -> list[str]:
        client = await self._get_client()
        resp = await client.get(SERVER_CATALOG_URL)
        resp.raise_for_status()
        models: list[str] = []
        seen: set[str] = set()
        for match in _BOARD_ANCHOR_RE.finditer(resp.text):
            model = match.group(1)
            if model in seen or _socket_for_model(model) is None:
                continue
            seen.add(model)
            models.append(model)
        return models

    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate AMD EPYC server motherboards (SP3/SP5/SP6)."""
        models = await self._fetch_catalog_models()
        seen = set(models)
        for legacy in _LEGACY_BOARDS:
            if legacy not in seen:
                models.append(legacy)
                seen.add(legacy)

        boards: list[BoardInfo] = []
        for model in models:
            socket = _socket_for_model(model)
            if socket is None:
                continue
            boards.append(
                BoardInfo(
                    vendor="ASUS",
                    model=model,
                    socket=socket,
                    url=f"https://servers.asus.com/products/servers/server-motherboards/{model}",
                )
            )
        return boards

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """List BIOS updates for the given server board via the support API."""
        client = await self._get_client()
        resp = await client.get(
            BIOS_API_URL,
            params={"website": WEBSITE, "model": board.model, "pdhashedid": ""},
            headers=SUPPORT_API_HEADERS,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("Status") != "SUCCESS":
            return []

        result = data.get("Result") or {}
        updates: list[BiosUpdate] = []
        for obj in result.get("Obj") or []:
            if obj.get("Name") != "BIOS":
                continue
            for file_info in obj.get("Files") or []:
                dl_obj = file_info.get("DownloadUrl") or {}
                cdn_path = dl_obj.get("Global") or dl_obj.get("China")
                if not cdn_path:
                    continue
                updates.append(
                    BiosUpdate(
                        board=board,
                        bios_version=file_info.get("Version", ""),
                        download_url=CDN_BASE + cdn_path,
                        release_date=file_info.get("ReleaseDate"),
                        agesa_version=_extract_server_agesa(file_info.get("Description")),
                    )
                )
        return updates

    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download a server BIOS ZIP, extract the .CAP, strip the 0x800 capsule header."""
        client = await self._get_client()
        resp = await client.get(update.download_url)
        resp.raise_for_status()

        dest_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(BytesIO(resp.content)) as zf:
            cap_names = [n for n in safe_namelist(zf) if n.upper().endswith(".CAP")]
            if not cap_names:
                raise ValueError(f"No .CAP file found in ZIP for {update.board.model} v{update.bios_version}")
            cap_name = cap_names[0]
            raw_cap = zf.read(cap_name)

        rom_data = raw_cap[ASUS_CAP_HEADER_SIZE:]
        out_path = dest_dir / f"{Path(cap_name).stem}.rom"
        out_path.write_bytes(rom_data)
        return out_path
