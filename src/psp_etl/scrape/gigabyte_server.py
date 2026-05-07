"""Gigabyte server (EPYC MZ-series) BIOS scraper.

Enumerates AMD EPYC server motherboards from Gigabyte's enterprise catalog
(https://www.gigabyte.com/Enterprise/Server-Motherboard?fid=2816), finds BIOS
download links on each board's support page, downloads the ZIP, and extracts
the raw ROM image.

Same Akamai Bot Manager protection as www.gigabyte.com — reuses the headers
and HTTP/throttle/retry plumbing from the consumer scraper. The CDN
(download.gigabyte.com) is unprotected once the URL is known.

Server URL patterns differ from consumer:
  - Catalog:     /Enterprise/Server-Motherboard?fid=2816
  - Per-board:   /Enterprise/Server-Motherboard/{MODEL}-rev-{rev}
  - Support:     /Enterprise/Server-Motherboard/{MODEL}-rev-{rev}/support
  - BIOS ZIP:    download.gigabyte.com/FileList/BIOS/mb_bios_{MODEL}_R{rev}_{ver}.zip

Socket coverage (by model prefix):
  - MZ01/MZ31/MZ32/MZ71/MZ72  → SP3 (Naples / Rome / Milan)
  - MZ33/MZ73                  → SP5 (Genoa / Bergamo / Turin)
  - MZ34                       → SP6 (Siena)
"""

from __future__ import annotations

import logging
import re

import httpx
from bs4 import BeautifulSoup

from psp_etl.scrape.base import BiosUpdate, BoardInfo
from psp_etl.scrape.gigabyte import (
    _BASE_URL,
    _CDN_URL,
    GigabyteScraper,
    _extract_date_from_element,
    _extract_version_from_element,
)

logger = logging.getLogger(__name__)

_CATALOG_URL = "https://www.gigabyte.com/Enterprise/Server-Motherboard?fid=2816"

# MZ-series model prefix → CPU socket family.
# Order matters only for documentation; prefixes do not overlap.
_SOCKET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^MZ01", re.I), "SP3"),
    (re.compile(r"^MZ31", re.I), "SP3"),
    (re.compile(r"^MZ32", re.I), "SP3"),
    (re.compile(r"^MZ71", re.I), "SP3"),
    (re.compile(r"^MZ72", re.I), "SP3"),
    (re.compile(r"^MZ33", re.I), "SP5"),
    (re.compile(r"^MZ73", re.I), "SP5"),
    (re.compile(r"^MZ34", re.I), "SP6"),
)

_ALL_SERVER_SOCKETS: tuple[str, ...] = ("SP3", "SP5", "SP6")


def _socket_for_model(model: str) -> str | None:
    name = model.strip().upper()
    for pattern, socket in _SOCKET_PATTERNS:
        if pattern.match(name):
            return socket
    return None


def _slug_to_model(slug: str) -> str:
    """Drop the ``-rev-XX`` suffix from a server URL slug.

    Examples:
        "MZ73-LM0-rev-3x" -> "MZ73-LM0"
        "MZ33-AR0-rev-1x-3x" -> "MZ33-AR0"
        "MZ72-HB0-rev-30" -> "MZ72-HB0"
    """
    name = re.sub(r"-rev-[\dxX-]+$", "", slug, flags=re.I)
    return name.upper()


def _extract_server_version_from_url(url: str) -> str | None:
    """Extract the BIOS version from a Gigabyte server CDN URL.

    Server filenames are ``mb_bios_{MODEL}_R{rev}_{ver}.zip[?v=hash]`` (e.g.
    ``mb_bios_MZ73-LM0_R07_F33.zip``). Returning the combined ``R{rev}_{ver}``
    distinguishes BIOSes built for different board revisions of the same SKU.
    """
    base = url.split("?", 1)[0]
    match = re.search(r"_R(\d+)_([A-Za-z0-9]+)\.zip$", base, re.I)
    if match:
        return f"R{match.group(1)}_{match.group(2).upper()}"
    match = re.search(r"_([A-Za-z0-9]+)\.zip$", base, re.I)
    if match:
        return match.group(1).upper()
    return None


class GigabyteServerScraper(GigabyteScraper):
    """Scrapes Gigabyte's enterprise site for AMD EPYC MZ-series BIOS updates."""

    def __init__(
        self,
        sockets: list[str] | None = None,
        rate_limit: float = 2.0,
        max_retries: int = 3,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """
        Args:
            sockets: Socket families to keep ("SP3", "SP5", "SP6"). Defaults to all.
            rate_limit: Seconds between requests.
            max_retries: Retries on transient errors.
            client: Optional pre-built ``httpx.AsyncClient``.
        """
        self.sockets = sockets if sockets is not None else list(_ALL_SERVER_SOCKETS)
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self._last_request: float = 0.0
        self._client = client
        self._own_client = client is None

    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate all AMD EPYC MZ-series Gigabyte server motherboards."""
        client = self._require_client()
        try:
            resp = await self._get(client, _CATALOG_URL)
        except httpx.HTTPStatusError as exc:
            logger.error(
                "Failed to list Gigabyte server boards: HTTP %d",
                exc.response.status_code,
            )
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        boards = self._parse_board_list(soup)

        socket_filter = {s.upper() for s in self.sockets}
        boards = [b for b in boards if b.socket in socket_filter]
        logger.info("Found %d Gigabyte server boards", len(boards))
        return boards

    def _parse_board_list(self, soup: BeautifulSoup, _socket: str | None = None) -> list[BoardInfo]:  # type: ignore[override]
        """Parse MZ-series server boards from the enterprise catalog HTML.

        Each board card carries an anchor pointing at
        ``/Enterprise/Server-Motherboard/{slug}``. The model is recovered by
        stripping the ``-rev-XX`` suffix; the socket is inferred from the
        model prefix.

        The ``_socket`` parameter is accepted for signature compatibility with
        the consumer scraper and ignored here — server boards span multiple
        sockets and are detected per-model.
        """
        boards: list[BoardInfo] = []
        seen: set[str] = set()

        for a in soup.find_all(
            "a",
            href=re.compile(r"/Enterprise/Server-Motherboard/MZ", re.I),
        ):
            href = a.get("href", "")
            if not href:
                continue

            match = re.search(
                r"/Enterprise/Server-Motherboard/([^/?#]+)",
                href,
                re.I,
            )
            if not match:
                continue
            slug = match.group(1)
            if not re.match(r"^MZ", slug, re.I):
                continue

            model = _slug_to_model(slug)
            socket = _socket_for_model(model)
            if socket is None:
                logger.debug("Unknown socket for %s; skipping", model)
                continue

            if slug in seen:
                continue
            seen.add(slug)

            support_url = href if "/support" in href else f"{href.rstrip('/')}/support"
            if not support_url.startswith("http"):
                support_url = _BASE_URL + support_url

            boards.append(
                BoardInfo(
                    vendor="Gigabyte",
                    model=model,
                    socket=socket,
                    url=support_url,
                )
            )

        return boards

    def _parse_bios_downloads(self, soup: BeautifulSoup, board: BoardInfo) -> list[BiosUpdate]:
        """Parse server BIOS download entries from a support page.

        Server filenames embed both a board-revision tag and the BIOS version
        (``mb_bios_{MODEL}_R{rev}_{ver}.zip``), so the version extraction is
        slightly different from the consumer scraper.
        """
        updates: list[BiosUpdate] = []

        bios_links = soup.find_all(
            "a",
            href=re.compile(r"download\.gigabyte\.com/FileList/BIOS/", re.I),
        )
        if not bios_links:
            bios_links = soup.find_all(attrs={"data-href": re.compile(r"download\.gigabyte\.com/FileList/BIOS/", re.I)})
            for tag in bios_links:
                tag["href"] = tag["data-href"]

        for link in bios_links:
            href = link.get("href", "")
            if not href:
                continue
            if not href.startswith("http"):
                href = "https:" + href if href.startswith("//") else _CDN_URL + href

            version = _extract_server_version_from_url(href)
            if not version:
                version = _extract_version_from_element(link)
            if not version:
                logger.debug("Could not extract version from %s, skipping", href)
                continue

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
