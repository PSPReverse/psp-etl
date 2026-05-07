"""Supermicro BIOS scraper for AMD-platform motherboards.

Covers EPYC SP3/SP5/SP6 (H11/H12/H13/H14 series) and Threadripper Pro
sWRX8/sWRX9 boards (M12SWA-TF, M13SWA-TF). Other AMD form factors
(M11SDV embedded, BH blade variants, caram5-m) appear in the catalog
but are not classified into a known socket and are skipped.

The catalog page (``bios_ipmi.php?vendor=2``) is the only public,
unauthenticated source: per-board download pages are gated behind a
contact-info form. Each ``<tr>`` row in the catalog provides:

* one or more model anchors (``/en/products/motherboard/{slug}``)
* a bundle title carrying the BIOS version
* a disclaimer URL containing ``SoftwareItemID=NNNN``
* a Type column: ``BIOS``, ``Bundle``, or ``BMC``

We extract the SoftwareItemID and download directly via
``/support/resources/getfile.php?SoftwareItemID=NNNN``; the
``disclaimer.php`` page is a JS click-through with no server-side
gating.

Note: ``www.supermicro.com`` is fronted by Akamai, which rejects
requests from datacenter IP ranges with HTTP 403 even when a
browser-like ``User-Agent`` is supplied. Run this scraper from a
residential or office network — the same restriction applies to the
existing Gigabyte scraper.
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from pathlib import Path

import httpx
from bs4 import BeautifulSoup, Tag

from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper
from psp_etl.scrape.extract import safe_namelist

logger = logging.getLogger(__name__)

CATALOG_URL = "https://www.supermicro.com/support/resources/bios_ipmi.php?vendor=2"
GETFILE_URL = "https://www.supermicro.com/support/resources/getfile.php"
PRODUCT_URL_TEMPLATE = "https://www.supermicro.com/en/products/motherboard/{slug}"

# Browser-like headers; the catalog endpoint is fronted by Akamai, which
# rejects bare User-Agent strings and tightened its filter to also reject
# UA-only requests that lack the Client Hints / Sec-Fetch-* family a real
# Chrome navigation sends. Mirrors the working set in gigabyte.py.
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Connection": "keep-alive",
}

# Map model prefix to AMD socket. Only EPYC and Threadripper Pro families
# are in scope for this scraper.
_PREFIX_TO_SOCKET: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^M12SWA\b", re.IGNORECASE), "sWRX8"),
    (re.compile(r"^M13SWA\b", re.IGNORECASE), "sWRX9"),
    # H11 = Naples / Rome, H12 = Rome / Milan — both single- or dual-socket SP3
    (re.compile(r"^H11", re.IGNORECASE), "SP3"),
    (re.compile(r"^H12", re.IGNORECASE), "SP3"),
    # H13 = Genoa / Bergamo / Siena, H14 = Turin — predominantly SP5
    (re.compile(r"^H13", re.IGNORECASE), "SP5"),
    (re.compile(r"^H14", re.IGNORECASE), "SP5"),
)

# Bundle titles look like ``H12SS-(i)(C)(CT)(NT)_3.6_AS1.08.01_SAA1.5.0``;
# we want the BIOS version that sits between an underscore and ``_AS``.
_BUNDLE_VERSION_RE = re.compile(r"_(\d+(?:\.\d+)?[a-z]?)_AS", re.IGNORECASE)

# SoftwareItemID lives in the disclaimer href: e.g.
# ``/about/policies/disclaimer.php?SoftwareItemID=27899``.
_SOFTWARE_ID_RE = re.compile(r"SoftwareItemID=(\d+)")

# Anchors for board model names: ``/en/products/motherboard/{slug}``.
_PRODUCT_HREF_RE = re.compile(r"/en/products/motherboard/([^/?#]+)", re.IGNORECASE)

# Types that carry a system BIOS image. ``BMC`` rows hold IPMI firmware
# only and are skipped.
_BIOS_TYPES = frozenset({"BIOS", "BUNDLE"})

# Names we never want to pick as the raw ROM.
_NON_ROM_SUFFIXES = frozenset(
    {
        ".exe",
        ".bat",
        ".sh",
        ".txt",
        ".pdf",
        ".doc",
        ".docx",
        ".jpg",
        ".png",
        ".gif",
        ".html",
        ".htm",
        ".md",
    }
)


def _detect_socket(model: str) -> str | None:
    """Return the AMD socket for *model* based on its series prefix.

    Returns ``None`` for non-EPYC/non-TRPro families (M11 embedded, BH
    blade variants, etc.) so the scraper can skip them cleanly.
    """
    for pattern, socket in _PREFIX_TO_SOCKET:
        if pattern.match(model):
            return socket
    return None


def _extract_version(title: str, type_label: str) -> str | None:
    """Parse the BIOS version from a catalog row title.

    For BIOS-only rows the title is the version itself (``3.4``, ``2.4a``);
    for Bundle rows the version is embedded between ``_`` and ``_AS``
    (``H12SS-(i)(C)(CT)(NT)_3.6_AS1.08.01_SAA1.5.0`` → ``3.6``).
    """
    title = title.strip()
    if not title:
        return None
    if type_label.upper() == "BUNDLE":
        m = _BUNDLE_VERSION_RE.search(title)
        return m.group(1) if m else None
    return title


class _CatalogRow:
    """Single parsed row from the AMD BIOS catalog page."""

    __slots__ = ("models", "software_id", "title", "type_label", "zip_filename")

    def __init__(
        self,
        models: list[str],
        title: str,
        software_id: str,
        zip_filename: str,
        type_label: str,
    ) -> None:
        self.models = models
        self.title = title
        self.software_id = software_id
        self.zip_filename = zip_filename
        self.type_label = type_label


def parse_catalog(html: str) -> list[_CatalogRow]:
    """Parse the catalog HTML into a list of rows.

    Each ``<tr>`` becomes one :class:`_CatalogRow`. Rows lacking a
    SoftwareItemID (header rows or non-download entries) are silently
    skipped.
    """
    soup = BeautifulSoup(html, "html.parser")
    rows: list[_CatalogRow] = []

    for tr in soup.find_all("tr"):
        if not isinstance(tr, Tag):
            continue
        cells = tr.find_all("td", recursive=False)
        if len(cells) < 5:
            continue

        models = _models_from_cell(cells[0])
        if not models:
            continue

        title = cells[1].get_text(separator=" ", strip=True)

        software_id, zip_filename = _download_from_cell(cells[2])
        if software_id is None:
            continue

        # The Type cell mixes plain text with red-text caveats; the first
        # word is the canonical type label.
        type_text = cells[4].get_text(separator=" ", strip=True)
        type_label = type_text.split()[0] if type_text else ""

        rows.append(
            _CatalogRow(
                models=models,
                title=title,
                software_id=software_id,
                zip_filename=zip_filename,
                type_label=type_label,
            )
        )

    return rows


def _models_from_cell(cell: Tag) -> list[str]:
    """Return unique board model names, preserving discovery order."""
    seen: dict[str, None] = {}
    for anchor in cell.find_all("a"):
        if not isinstance(anchor, Tag):
            continue
        href = anchor.get("href") or ""
        if not isinstance(href, str):
            continue
        if not _PRODUCT_HREF_RE.search(href):
            continue
        text = anchor.get_text(strip=True)
        if text:
            seen.setdefault(text, None)
    return list(seen)


def _download_from_cell(cell: Tag) -> tuple[str | None, str]:
    """Extract ``(software_id, zip_filename)`` from the download cell."""
    for anchor in cell.find_all("a"):
        if not isinstance(anchor, Tag):
            continue
        href = anchor.get("href") or ""
        if not isinstance(href, str):
            continue
        m = _SOFTWARE_ID_RE.search(href)
        if not m:
            continue
        # Skip release-note links (they share the SoftwareItemID but use
        # the ``&type=...releasenote`` suffix); the bundle ZIP is always
        # the no-type variant.
        if "type=" in href:
            continue
        return m.group(1), anchor.get_text(strip=True)
    return None, ""


def build_download_url(software_id: str) -> str:
    """Return the direct ZIP download URL for *software_id*."""
    return f"{GETFILE_URL}?SoftwareItemID={software_id}"


def _is_rom_member(name: str) -> bool:
    suffix = Path(name).suffix.lower()
    if suffix in _NON_ROM_SUFFIXES:
        return False
    if name.endswith("/"):
        return False
    return True


def _pick_bios_zip(zf: zipfile.ZipFile) -> str | None:
    """Locate a nested ``BIOS_*.zip`` inside a Bundle archive."""
    for name in safe_namelist(zf):
        base = Path(name).name
        if base.lower().endswith(".zip") and base.upper().startswith("BIOS_"):
            return name
    return None


def _pick_rom(zf: zipfile.ZipFile, model: str) -> str:
    """Pick the most plausible BIOS image inside *zf*.

    Heuristic: of the entries that aren't archives or doc files, prefer
    those that share the board model prefix; otherwise take the largest.
    """
    entries = [info for info in zf.infolist() if _is_rom_member(info.filename) and info.file_size > 0]
    if not entries:
        raise FileNotFoundError(f"No candidate ROM file found in ZIP (members: {zf.namelist()})")

    model_prefix = model.split("-")[0].upper()
    matching = [e for e in entries if Path(e.filename).name.upper().startswith(model_prefix)]
    pool = matching or entries
    return max(pool, key=lambda e: e.file_size).filename


def extract_rom_bytes(zip_data: bytes, model: str) -> tuple[str, bytes]:
    """Return ``(member_name, rom_bytes)`` from a Supermicro BIOS archive.

    Handles both BIOS-only ZIPs (raw ROM alongside flash utilities) and
    Bundle ZIPs (a nested ``BIOS_*.zip`` inside the outer archive).
    """
    with zipfile.ZipFile(io.BytesIO(zip_data)) as outer:
        nested = _pick_bios_zip(outer)
        if nested is not None:
            inner_bytes = outer.read(nested)
            with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner:
                target = _pick_rom(inner, model)
                return target, inner.read(target)
        target = _pick_rom(outer, model)
        return target, outer.read(target)


class SupermicroScraper(VendorScraper):
    """Scrape AMD Supermicro motherboards via the public BIOS catalog page."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._own_client = client is None
        self._catalog_rows: list[_CatalogRow] | None = None

    async def __aenter__(self) -> SupermicroScraper:
        if self._own_client:
            self._client = httpx.AsyncClient(
                timeout=60.0,
                follow_redirects=True,
                headers=_HEADERS,
            )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._own_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("SupermicroScraper must be used as an async context manager")
        return self._client

    async def _get_catalog(self) -> list[_CatalogRow]:
        if self._catalog_rows is None:
            client = self._require_client()
            resp = await client.get(CATALOG_URL)
            resp.raise_for_status()
            self._catalog_rows = parse_catalog(resp.text)
            logger.debug("Parsed %d catalog rows", len(self._catalog_rows))
        return self._catalog_rows

    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate Supermicro AMD motherboards with a known socket."""
        rows = await self._get_catalog()
        seen: dict[str, BoardInfo] = {}
        for row in rows:
            if row.type_label.upper() not in _BIOS_TYPES:
                continue
            for model in row.models:
                if model in seen:
                    continue
                socket = _detect_socket(model)
                if socket is None:
                    logger.debug("Skipping %s: socket not in scope", model)
                    continue
                seen[model] = BoardInfo(
                    vendor="Supermicro",
                    model=model,
                    socket=socket,
                    url=PRODUCT_URL_TEMPLATE.format(slug=model),
                )
        return list(seen.values())

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """Return every BIOS / Bundle entry the catalog has for *board*."""
        rows = await self._get_catalog()
        updates: list[BiosUpdate] = []
        for row in rows:
            if row.type_label.upper() not in _BIOS_TYPES:
                continue
            if board.model not in row.models:
                continue
            version = _extract_version(row.title, row.type_label)
            if not version:
                logger.debug(
                    "Skipping %s row with unparseable title %r",
                    board.model,
                    row.title,
                )
                continue
            updates.append(
                BiosUpdate(
                    board=board,
                    bios_version=version,
                    download_url=build_download_url(row.software_id),
                    release_date=None,
                    agesa_version=None,
                )
            )
        return updates

    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download a BIOS ZIP, unwrap any nested BIOS archive, write raw ROM."""
        client = self._require_client()
        dest_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Downloading Supermicro %s %s from %s",
            update.board.model,
            update.bios_version,
            update.download_url,
        )
        resp = await client.get(update.download_url)
        resp.raise_for_status()

        member, rom_bytes = extract_rom_bytes(resp.content, update.board.model)

        safe_model = re.sub(r"[^\w\-.]", "_", update.board.model)
        safe_version = re.sub(r"[^\w\-.]", "_", update.bios_version)
        suffix = Path(member).suffix.lower() or ".rom"
        out_path = dest_dir / f"{safe_model}_{safe_version}{suffix}"
        out_path.write_bytes(rom_bytes)
        return out_path
