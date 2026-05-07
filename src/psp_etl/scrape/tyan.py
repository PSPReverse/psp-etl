"""Tyan / MiTAC EPYC BIOS scraper.

Tyan was integrated into MiTAC Computing Technology Corp. on 2024-10-01;
``www.tyan.com`` was retired on 2026-03-31. BIOS distribution moved to
``www.mitaccomputing.com``. This scraper targets the new domain but keeps
the vendor name as ``Tyan`` for corpus continuity with historical data.

Discovery
---------

Catalog pages, one per EPYC processor family:

    /en/products/amd_epyc_9004    SP5 (Genoa)
    /en/products/amd_epyc_9005    SP5 (Turin)
    /en/products/amd_epyc_8004    SP6 (Siena)
    /en/products/amd_epyc_4005    AM5 (entry-level EPYC, AM5 package)

Each page lists boards with anchors of the form::

    /en/spec/Motherboards/{model_short}_{model_full}

The per-board downloads page lives at::

    /en/downloads/Motherboards/{model_short}_{model_full}

It contains a ``<tbody id="downloadTable">`` with rows of
``(type, title, date, version, detail-link)``. BIOS rows have
``type == "BIOS"``; the corresponding ZIP is reachable directly at::

    https://download1.mitaccomputing.com/pub/bios/{title}.zip

Per-detail page resolution is therefore unnecessary — every BIOS title
in the listing maps verbatim onto the CDN.

Extraction
----------

Tyan BIOS ZIPs typically contain a raw ``.rom`` (or ``.bin``) alongside
the AMI flash utility and several non-target wrappers (``.CAP`` capsule,
``.hpm`` HPM/IPMI image, release notes). We prefer ``.rom``/``.bin``
explicitly and refuse to fall back to the largest file, since the
Tyan-flavoured ``.CAP`` capsule is *not* the ASUS CAP format and the
``.hpm`` HPM image is even larger than the raw ROM.
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import time
import zipfile
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper
from psp_etl.scrape.extract import safe_namelist

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.mitaccomputing.com"
_BIOS_CDN = "https://download1.mitaccomputing.com/pub/bios"

# AMD EPYC catalog pages → socket. Order is stable so callers see boards
# in catalog order; SP5 (Genoa) before SP5 (Turin) before SP6 (Siena).
_CATALOG_SOCKETS: tuple[tuple[str, str], ...] = (
    ("amd_epyc_9004", "SP5"),
    ("amd_epyc_9005", "SP5"),
    ("amd_epyc_8004", "SP6"),
    ("amd_epyc_4005", "AM5"),
)

# Anchor href on a catalog page pointing at a board's spec page.
# Example: /en/spec/Motherboards/S8050_S8050GM2NE
_SPEC_HREF_RE = re.compile(r"/en/spec/Motherboards/([^/?#'\"]+)", re.IGNORECASE)

_HEADERS = {
    "User-Agent": "psp-etl",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


class TyanScraper(VendorScraper):
    """BIOS scraper for Tyan / MiTAC EPYC server motherboards."""

    def __init__(
        self,
        sockets: list[str] | None = None,
        rate_limit: float = 1.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Args:
        sockets: socket filter applied at catalog enumeration time. ``None``
            (default) walks every catalog page. Useful values are
            ``["SP5"]``, ``["SP6"]``, ``["AM5"]`` or any combination.
        rate_limit: minimum seconds between HTTP requests.
        client: optional pre-built ``httpx.AsyncClient``. If ``None`` one is
            created in ``__aenter__`` and closed in ``__aexit__``.
        """
        self.sockets = sockets
        self.rate_limit = rate_limit
        self._last_request: float = 0.0
        self._client: httpx.AsyncClient | None = client
        self._own_client = client is None
        # Per-board downloads-page HTML cache, keyed by spec slug
        # (e.g. ``"S8050_S8050GM2NE"``).
        self._downloads_cache: dict[str, str] = {}

    async def __aenter__(self) -> TyanScraper:
        if self._own_client:
            self._client = httpx.AsyncClient(
                timeout=60.0,
                follow_redirects=True,
                headers=_HEADERS,
            )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._own_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Use 'async with TyanScraper() as s:' to manage the client lifecycle")
        return self._client

    async def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.rate_limit:
            await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request = time.monotonic()

    # ------------------------------------------------------------------
    # Board enumeration
    # ------------------------------------------------------------------

    async def list_boards(self) -> list[BoardInfo]:
        """Walk all configured catalog pages and return discovered boards."""
        client = self._require_client()
        seen: dict[tuple[str, str], BoardInfo] = {}
        for slug, socket in _CATALOG_SOCKETS:
            if self.sockets is not None and socket not in self.sockets:
                continue
            await self._throttle()
            try:
                resp = await client.get(f"{_BASE_URL}/en/products/{slug}")
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                logger.warning("Tyan catalog %s returned HTTP %d", slug, exc.response.status_code)
                continue
            for spec_slug, model in parse_catalog(resp.text):
                key = (socket, model)
                if key in seen:
                    continue
                seen[key] = BoardInfo(
                    vendor="Tyan",
                    model=model,
                    socket=socket,
                    url=f"{_BASE_URL}/en/spec/Motherboards/{spec_slug}",
                )
        logger.info("Found %d Tyan boards across %d catalog pages", len(seen), len(_CATALOG_SOCKETS))
        return list(seen.values())

    # ------------------------------------------------------------------
    # BIOS update enumeration
    # ------------------------------------------------------------------

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """Fetch the board's downloads page and extract BIOS rows."""
        spec_slug = _spec_slug_from_url(board.url)
        if spec_slug is None:
            logger.warning("Cannot derive spec slug from %s", board.url)
            return []

        html = await self._fetch_downloads_page(spec_slug)
        if html is None:
            return []

        updates: list[BiosUpdate] = []
        for entry in parse_downloads_page(html):
            updates.append(
                BiosUpdate(
                    board=board,
                    bios_version=entry["version"],
                    download_url=f"{_BIOS_CDN}/{entry['title']}.zip",
                    release_date=entry["date"],
                    agesa_version=None,
                )
            )
        logger.info("Found %d BIOS updates for Tyan %s", len(updates), board.model)
        return updates

    async def _fetch_downloads_page(self, spec_slug: str) -> str | None:
        if spec_slug in self._downloads_cache:
            return self._downloads_cache[spec_slug]
        client = self._require_client()
        url = f"{_BASE_URL}/en/downloads/Motherboards/{spec_slug}"
        await self._throttle()
        try:
            resp = await client.get(url)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.warning("Tyan downloads page %s returned HTTP %d", spec_slug, exc.response.status_code)
            return None
        self._downloads_cache[spec_slug] = resp.text
        return resp.text

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download a Tyan BIOS ZIP and extract the raw ROM image."""
        client = self._require_client()
        dest_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Downloading Tyan %s %s from %s",
            update.board.model,
            update.bios_version,
            update.download_url,
        )
        await self._throttle()
        resp = await client.get(update.download_url)
        resp.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            path = extract_rom(zf, dest_dir, update)

        logger.info("Extracted ROM to %s", path)
        return path


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def parse_catalog(html: str) -> list[tuple[str, str]]:
    """Parse a catalog (``/en/products/amd_epyc_*``) page.

    Returns a list of ``(spec_slug, model)`` tuples in document order, with
    duplicates removed. ``spec_slug`` is the ``{short}_{full}`` segment used
    for both spec and downloads URLs; ``model`` is the human-readable full
    model name (the ``{full}`` half of the slug).

    Examples:
        >>> parse_catalog('<a href="/en/spec/Motherboards/S8050_S8050GM2NE">x</a>')
        [('S8050_S8050GM2NE', 'S8050GM2NE')]
    """
    soup = BeautifulSoup(html, "html.parser")
    seen: dict[str, str] = {}
    for anchor in soup.find_all("a", href=True):
        m = _SPEC_HREF_RE.search(anchor["href"])
        if not m:
            continue
        spec_slug = m.group(1)
        if spec_slug in seen:
            continue
        # Slug format is "{short}_{full}". Take the full half as the model.
        if "_" in spec_slug:
            model = spec_slug.split("_", 1)[1]
        else:
            model = spec_slug
        seen[spec_slug] = model
    return [(slug, model) for slug, model in seen.items()]


def parse_downloads_page(html: str) -> list[dict[str, str]]:
    """Parse the per-board downloads page and return BIOS rows.

    The page renders a ``<tbody id="downloadTable">`` whose rows have five
    cells: type, title, date, version, detail link. We pick out rows whose
    first cell text is ``"BIOS"``.

    Returns a list of dicts with keys ``title``, ``date``, ``version``.
    Rows missing any of those cells are skipped silently.
    """
    soup = BeautifulSoup(html, "html.parser")
    tbody = soup.find("tbody", id="downloadTable")
    if tbody is None:
        return []
    out: list[dict[str, str]] = []
    for row in tbody.find_all("tr"):
        cells = [c.get_text(strip=True) for c in row.find_all("td")]
        if len(cells) < 4:
            continue
        if cells[0].upper() != "BIOS":
            continue
        title, date, version = cells[1], cells[2], cells[3]
        if not title or not version:
            continue
        out.append({"title": title, "date": date, "version": version})
    return out


def _spec_slug_from_url(url: str) -> str | None:
    m = _SPEC_HREF_RE.search(url)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

# Preferred ROM extensions inside a Tyan ZIP. ``.CAP`` (Tyan capsule, *not*
# ASUS CAP) and ``.hpm`` (IPMI HPM) are deliberately excluded — they wrap the
# ROM in vendor formats we do not yet parse.
_ROM_EXTENSIONS = frozenset({".rom", ".bin"})

# Tyan ZIPs ship documentation, scripts, and flash utilities. Skip them when
# selecting the ROM payload.
_SKIP_EXTENSIONS = frozenset({".txt", ".pdf", ".doc", ".html", ".htm", ".nsh", ".bat", ".exe", ".efi", ".cap", ".hpm"})


def extract_rom(zf: zipfile.ZipFile, dest_dir: Path, update: BiosUpdate) -> Path:
    """Extract the raw ROM image from a Tyan BIOS ZIP archive.

    Selection order:
        1. The largest entry whose suffix is ``.rom`` or ``.bin``.
        2. Otherwise, the largest entry that is *not* obviously documentation,
           a flash utility, or a vendor wrapper format.

    Raises:
        ValueError: if the archive contains no usable file.
    """
    entries = [name for name in safe_namelist(zf) if not name.endswith("/") and not name.startswith("__MACOSX")]
    if not entries:
        raise ValueError(f"Empty ZIP for Tyan {update.board.model} {update.bios_version}")

    rom_entries = [name for name in entries if Path(name).suffix.lower() in _ROM_EXTENSIONS]
    if rom_entries:
        candidates = rom_entries
    else:
        candidates = [name for name in entries if Path(name).suffix.lower() not in _SKIP_EXTENSIONS]
        if not candidates:
            raise ValueError(
                f"No ROM-like file in Tyan {update.board.model} {update.bios_version} ZIP (contents: {entries})"
            )

    target = max(candidates, key=lambda n: zf.getinfo(n).file_size)
    suffix = Path(target).suffix.lower() or ".rom"

    safe_model = re.sub(r"[^\w\-.]", "_", update.board.model)
    safe_version = re.sub(r"[^\w\-.]", "_", update.bios_version)
    out_path = dest_dir / f"{safe_model}_{safe_version}{suffix}"
    out_path.write_bytes(zf.read(target))
    return out_path
