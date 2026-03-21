"""Gigabyte BIOS scraper.

Enumerates AM4/AM5 motherboards from Gigabyte product pages, finds BIOS download
links, downloads ZIPs, and extracts raw ROM images.

Note: www.gigabyte.com is protected by Akamai Bot Manager, which blocks requests
from datacenter IP ranges. This scraper is designed to work from residential or
office networks. 403 responses from the main site indicate bot detection; the CDN
(download.gigabyte.com) is accessible from all networks once download URLs are known.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import zipfile
from io import BytesIO
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper

logger = logging.getLogger(__name__)

# Gigabyte board listing page for each socket type.
# These pages list all motherboards with AM4/AM5 sockets.
_SOCKET_URLS: dict[str, str] = {
    "AM4": "https://www.gigabyte.com/Motherboard/All-Series/AM4",
    "AM5": "https://www.gigabyte.com/Motherboard/All-Series/AM5",
}

_BASE_URL = "https://www.gigabyte.com"
_CDN_URL = "https://download.gigabyte.com"

# Browser-like headers to avoid bot detection.
# www.gigabyte.com uses Akamai Bot Manager; these headers help from residential IPs.
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

_CDN_HEADERS = {
    "User-Agent": _HEADERS["User-Agent"],
    "Accept": "application/zip,application/octet-stream,*/*",
    "Referer": "https://www.gigabyte.com/",
}


class GigabyteScraper(VendorScraper):
    """Scrapes Gigabyte's website for AM4/AM5 BIOS updates."""

    def __init__(
        self,
        sockets: list[str] | None = None,
        rate_limit: float = 2.0,
        max_retries: int = 3,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """
        Args:
            sockets: List of socket types to scrape ("AM4", "AM5", or both).
                     Defaults to both AM4 and AM5.
            rate_limit: Seconds to wait between requests (default 2.0).
            max_retries: Number of retries on transient errors (default 3).
            client: Optional pre-existing AsyncClient. If None, one is created
                    in __aenter__ and closed in __aexit__.
        """
        self.sockets = sockets if sockets is not None else ["AM4", "AM5"]
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self._last_request: float = 0.0
        self._client: httpx.AsyncClient | None = client
        self._own_client = client is None

    async def __aenter__(self) -> GigabyteScraper:
        if self._own_client:
            self._client = httpx.AsyncClient(
                headers=_HEADERS,
                follow_redirects=True,
                timeout=30.0,
            )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._own_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Use 'async with GigabyteScraper() as s:' to manage the client lifecycle")
        return self._client

    async def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.rate_limit:
            await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request = time.monotonic()

    async def _get(self, client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
        """GET with throttling and retry on 5xx/network errors."""
        await self._throttle()
        for attempt in range(self.max_retries):
            try:
                resp = await client.get(url, **kwargs)
                if resp.status_code == 403:
                    logger.warning(
                        "403 Forbidden from %s — likely Akamai bot detection. Run from a residential or office IP.",
                        url,
                    )
                    resp.raise_for_status()
                if resp.status_code >= 500:
                    logger.warning("HTTP %d from %s, retrying...", resp.status_code, url)
                    await asyncio.sleep(2**attempt)
                    continue
                resp.raise_for_status()
                return resp
            except httpx.HTTPStatusError:
                raise
            except httpx.TransportError as exc:
                if attempt == self.max_retries - 1:
                    raise
                logger.warning("Transport error on %s: %s, retrying...", url, exc)
                await asyncio.sleep(2**attempt)
        raise RuntimeError(f"Failed to GET {url} after {self.max_retries} attempts")

    # ------------------------------------------------------------------
    # Board enumeration
    # ------------------------------------------------------------------

    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate all AM4/AM5 Gigabyte motherboard models."""
        client = self._require_client()
        boards: list[BoardInfo] = []
        for socket in self.sockets:
            if socket not in _SOCKET_URLS:
                logger.warning("Unknown socket type: %s", socket)
                continue
            try:
                socket_boards = await self._list_boards_for_socket(client, socket)
                boards.extend(socket_boards)
                logger.info("Found %d Gigabyte %s boards", len(socket_boards), socket)
            except httpx.HTTPStatusError as exc:
                logger.error(
                    "Failed to list %s boards: HTTP %d",
                    socket,
                    exc.response.status_code,
                )
        return boards

    async def _list_boards_for_socket(self, client: httpx.AsyncClient, socket: str) -> list[BoardInfo]:
        """Fetch and parse the Gigabyte board listing page for a given socket."""
        boards: list[BoardInfo] = []
        url = _SOCKET_URLS[socket]

        # Handle pagination — Gigabyte shows ~40 products per page.
        page = 1
        while True:
            page_url = url if page == 1 else f"{url}?page={page}"
            try:
                resp = await self._get(client, page_url)
            except httpx.HTTPStatusError:
                break

            soup = BeautifulSoup(resp.text, "html.parser")
            page_boards = self._parse_board_list(soup, socket)
            if not page_boards:
                break

            boards.extend(page_boards)

            # Check for a "next page" link to determine if more pages exist.
            if not self._has_next_page(soup):
                break
            page += 1

        return boards

    def _parse_board_list(self, soup: BeautifulSoup, socket: str) -> list[BoardInfo]:
        """Parse board list items from the product listing HTML.

        Gigabyte's product listing page uses a grid of product cards.
        Each card has an anchor pointing to the board's support page.
        The link pattern is: /Motherboard/{MODEL-SLUG}/support
        """
        boards: list[BoardInfo] = []

        # Primary selector: product list items with board support links.
        # Gigabyte uses various class names across page versions; try multiple.
        product_links: list = []

        # Pattern 1: Links directly to support pages
        for a in soup.find_all("a", href=re.compile(r"/Motherboard/[^/]+/support")):
            product_links.append(a)

        # Pattern 2: Product container divs with data attributes
        if not product_links:
            for item in soup.find_all(
                "div",
                class_=re.compile(r"product-item|item-select|prod-item"),
            ):
                a = item.find("a", href=re.compile(r"/Motherboard/"))
                if a:
                    product_links.append(a)

        # Deduplicate by href
        seen: set[str] = set()
        for a in product_links:
            href = a.get("href", "")
            if not href or href in seen:
                continue
            seen.add(href)

            # Extract model slug from URL: /Motherboard/{MODEL}/support
            # or /Motherboard/{MODEL} (without /support suffix)
            match = re.search(r"/Motherboard/([^/?#]+)", href)
            if not match:
                continue
            model_slug = match.group(1)
            # Strip revision suffix to get clean model name
            # e.g. "B550M-DS3H-rev-10" -> "B550M DS3H"
            model_name = _slug_to_name(model_slug)

            support_url = href if "/support" in href else f"{href}/support"
            if not support_url.startswith("http"):
                support_url = _BASE_URL + support_url

            boards.append(
                BoardInfo(
                    vendor="Gigabyte",
                    model=model_name,
                    socket=socket,
                    url=support_url,
                )
            )

        return boards

    def _has_next_page(self, soup: BeautifulSoup) -> bool:
        """Check if there is a next page in the product listing."""
        # Look for pagination "next" link
        next_link = soup.find("a", class_=re.compile(r"next|page-next"))
        if next_link:
            return True
        # Also look for next page indicator in pagination
        pagination = soup.find(class_=re.compile(r"pagination"))
        if pagination:
            active = pagination.find(class_="active")
            if active and active.find_next_sibling("li"):
                return True
        return False

    # ------------------------------------------------------------------
    # BIOS update listing
    # ------------------------------------------------------------------

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """List all available BIOS updates for a Gigabyte board.

        Fetches the board's support page and parses the BIOS download section.
        Download links point to download.gigabyte.com/FileList/BIOS/.
        """
        updates: list[BiosUpdate] = []
        client = self._require_client()
        try:
            resp = await self._get(client, board.url, headers={"Referer": _BASE_URL + "/"})
        except httpx.HTTPStatusError as exc:
            logger.error(
                "Failed to fetch support page for %s: HTTP %d",
                board.model,
                exc.response.status_code,
            )
            return updates

        soup = BeautifulSoup(resp.text, "html.parser")
        updates = self._parse_bios_downloads(soup, board)
        logger.info("Found %d BIOS updates for %s", len(updates), board.model)
        return updates

    def _parse_bios_downloads(self, soup: BeautifulSoup, board: BoardInfo) -> list[BiosUpdate]:
        """Parse BIOS download entries from the support page HTML.

        Gigabyte's support page has a BIOS section (anchor: #support-dl-bios)
        containing download rows. Each row has:
        - BIOS version string (e.g. "F36b", "F15")
        - Release date
        - Download link to download.gigabyte.com/FileList/BIOS/*.zip
        """
        updates: list[BiosUpdate] = []

        # Find all download links pointing to the Gigabyte CDN BIOS path
        bios_links = soup.find_all(
            "a",
            href=re.compile(r"download\.gigabyte\.com/FileList/BIOS/", re.I),
        )

        if not bios_links:
            # Fallback: look for links with data-href attribute (lazy-loaded)
            bios_links = soup.find_all(attrs={"data-href": re.compile(r"download\.gigabyte\.com/FileList/BIOS/", re.I)})
            # Use data-href as the actual download URL
            for tag in bios_links:
                tag["href"] = tag["data-href"]

        for link in bios_links:
            href = link.get("href", "")
            if not href:
                continue

            if not href.startswith("http"):
                href = "https:" + href if href.startswith("//") else _CDN_URL + href

            # Extract version from filename: mb_bios_{model}_{version}.zip
            version = _extract_version_from_url(href)
            if not version:
                # Fall back to link text or surrounding element text
                version = _extract_version_from_element(link)
            if not version:
                logger.debug("Could not extract version from %s, skipping", href)
                continue

            # Extract release date from surrounding HTML
            release_date = _extract_date_from_element(link)

            updates.append(
                BiosUpdate(
                    board=board,
                    bios_version=version,
                    download_url=href,
                    release_date=release_date,
                    agesa_version=None,
                )
            )

        return updates

    # ------------------------------------------------------------------
    # Download and extraction
    # ------------------------------------------------------------------

    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download a Gigabyte BIOS ZIP and extract the raw ROM image.

        Gigabyte distributes BIOS updates as ZIP archives containing a single
        ROM binary. The ROM file name varies but typically matches the BIOS
        version string or the board model. No vendor-specific header stripping
        is needed — the file is a raw ROM (unlike ASUS CAP format).

        Args:
            update: BIOS update metadata including the download URL.
            dest_dir: Directory to save the extracted ROM.

        Returns:
            Path to the extracted raw ROM file (named {sha256}.rom).
        """
        dest_dir.mkdir(parents=True, exist_ok=True)

        client = self._require_client()
        try:
            resp = await self._get(client, update.download_url, headers=_CDN_HEADERS)
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(f"Failed to download {update.download_url}: HTTP {exc.response.status_code}") from exc

        zip_data = resp.content
        rom_data = _extract_rom_from_zip(zip_data, update)

        rom_hash = hashlib.sha256(rom_data).hexdigest()
        rom_path = dest_dir / f"{rom_hash}.rom"

        if rom_path.exists():
            logger.debug("Skipping %s (already downloaded)", rom_hash[:12])
            return rom_path

        rom_path.write_bytes(rom_data)
        logger.info(
            "Downloaded %s BIOS %s → %s (%d bytes)",
            update.board.model,
            update.bios_version,
            rom_hash[:12],
            len(rom_data),
        )
        return rom_path


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _slug_to_name(slug: str) -> str:
    """Convert a Gigabyte URL slug to a human-readable board name.

    Examples:
        "B550M-DS3H-rev-10" -> "B550M DS3H"
        "X870E-AORUS-MASTER-rev-10" -> "X870E AORUS MASTER"
    """
    # Strip revision suffix: -rev-XX (e.g., -rev-10, -rev-11-12)
    name = re.sub(r"-rev-[\d-]+$", "", slug, flags=re.I)
    # Replace hyphens with spaces
    return name.replace("-", " ")


def _extract_version_from_url(url: str) -> str | None:
    """Extract the BIOS version string from a Gigabyte CDN URL.

    URL pattern: mb_bios_{model}_{version}.zip
    The version is the last underscore-separated component before .zip.

    Examples:
        "mb_bios_b550m-ds3h_f15.zip" -> "F15"
        "mb_bios_x870e-aorus-master_f6b.zip" -> "F6b"
    """
    # Match the last underscore-separated segment before .zip
    match = re.search(r"mb_bios_[^_]+_([^_.]+)\.zip", url, re.I)
    if match:
        return match.group(1).upper()
    # Fallback: last path component before .zip
    match = re.search(r"_([a-z0-9]+)\.zip$", url, re.I)
    if match:
        return match.group(1).upper()
    return None


def _extract_version_from_element(tag) -> str | None:
    """Extract BIOS version from the link text or surrounding table/list row."""
    # Try the link text first
    text = tag.get_text(strip=True)
    if text and re.match(r"^[Ff]\d+[a-zA-Z]*$", text):
        return text.upper()

    # Look in parent elements for a version string (e.g. "F15", "F36b")
    for parent in [tag.parent, tag.parent.parent if tag.parent else None]:
        if parent is None:
            continue
        parent_text = parent.get_text(" ", strip=True)
        match = re.search(r"\b([Ff]\d+[a-zA-Z]*)\b", parent_text)
        if match:
            return match.group(1).upper()

    return None


def _extract_date_from_element(tag) -> str | None:
    """Extract release date from the surrounding HTML element."""
    # Look for date patterns in parent elements
    for parent in [tag.parent, tag.parent.parent if tag.parent else None]:
        if parent is None:
            continue
        text = parent.get_text(" ", strip=True)
        # ISO date: 2024-03-15
        match = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", text)
        if match:
            return match.group(1)
        # US date: 03/15/2024 or 2024/03/15
        match = re.search(r"\b(\d{1,2}/\d{1,2}/\d{4})\b", text)
        if match:
            return match.group(1)

    return None


def _extract_rom_from_zip(zip_data: bytes, update: BiosUpdate) -> bytes:
    """Extract the raw ROM binary from a Gigabyte BIOS ZIP archive.

    Gigabyte BIOS ZIPs contain the raw ROM image without any vendor-specific
    header (unlike ASUS CAP format). The ROM file is identified by its extension
    (.rom, .bin, .F{xx}) or by being the largest binary file in the archive.

    Args:
        zip_data: Raw ZIP file bytes.
        update: BIOS update metadata (used for logging).

    Returns:
        Raw ROM bytes.

    Raises:
        ValueError: If no suitable ROM file is found in the archive.
    """
    # ROM file extensions in preference order
    rom_extensions = {".rom", ".bin", ".fd"}
    # Also match Gigabyte version-style extensions: .F15, .F36b, etc.
    version_ext_pattern = re.compile(r"\.[Ff]\d+[a-zA-Z]*$")

    with zipfile.ZipFile(BytesIO(zip_data)) as zf:
        names = zf.namelist()
        logger.debug("ZIP contents for %s: %s", update.bios_version, names)

        # Filter to top-level files only (ignore subdirectory contents that
        # are documentation, release notes, etc.)
        candidates: list[tuple[int, str]] = []
        for name in names:
            lower = name.lower()
            # Skip directories, text files, and executables
            if name.endswith("/"):
                continue
            if any(lower.endswith(ext) for ext in (".txt", ".pdf", ".exe", ".bat", ".inf", ".html", ".htm")):
                continue

            # Prefer known ROM extensions
            _, ext = _splitext(name)
            is_rom_ext = ext.lower() in rom_extensions or version_ext_pattern.search(name) is not None
            info = zf.getinfo(name)
            priority = 0 if is_rom_ext else 1
            candidates.append((priority, info.file_size, name))

        if not candidates:
            raise ValueError(
                f"No ROM file found in ZIP for {update.board.model} {update.bios_version}. ZIP contents: {names}"
            )

        # Sort: prefer ROM-extension files, then largest file
        candidates.sort(key=lambda x: (x[0], -x[1]))
        chosen_name = candidates[0][2]

        logger.debug(
            "Extracting %s from ZIP for %s %s",
            chosen_name,
            update.board.model,
            update.bios_version,
        )
        return zf.read(chosen_name)


def _splitext(path: str) -> tuple[str, str]:
    """Split a filename into (base, ext) handling Gigabyte version extensions like .F15."""
    # Try standard splitext first
    import os.path

    base, ext = os.path.splitext(path)
    if ext:
        return base, ext
    # Check for version-style extension: filename.F15, filename.F36b
    match = re.search(r"(\.[Ff]\d+[a-zA-Z]*)$", path)
    if match:
        ext = match.group(1)
        base = path[: -len(ext)]
        return base, ext
    return path, ""
