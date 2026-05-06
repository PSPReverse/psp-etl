"""ASRock BIOS scraper.

Board discovery uses the Wayback Machine CDX API to enumerate all known
BIOS ZIP URLs on download.asrock.com. The ASRock website (www.asrock.com)
is protected by a WAF that blocks automated requests; the CDX index serves
as a reliable alternative data source.

BIOS files are downloaded directly from the ASRock CDN.

URL format: https://download.asrock.com/BIOS/{socket}/{model}({version})ROM.zip
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from pathlib import Path
from urllib.parse import quote, unquote

import httpx

from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper
from psp_etl.scrape.extract import safe_namelist

logger = logging.getLogger(__name__)

_CDX_API = "https://web.archive.org/cdx/search/cdx"
_SOCKETS = ("AM4", "AM5")

# Matches: https://download.asrock.com/BIOS/{socket}/{model}({version})...
_BIOS_URL_RE = re.compile(
    r"https://download\.asrock\.com/BIOS/(AM[45])/([^(]+)\(([^)]+)\)",
    re.IGNORECASE,
)


class AsRockScraper(VendorScraper):
    """ASRock BIOS scraper using Wayback Machine CDX for board enumeration.

    Usage::

        async with AsRockScraper() as scraper:
            boards = await scraper.list_boards()
            for board in boards:
                updates = await scraper.list_bios_updates(board)
                for update in updates:
                    path = await scraper.download(update, dest_dir)
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._own_client = client is None
        # Cache: socket -> list of (model, version, url)
        self._cdx_cache: dict[str, list[tuple[str, str, str]]] = {}

    async def __aenter__(self) -> AsRockScraper:
        if self._own_client:
            self._client = httpx.AsyncClient(
                timeout=60.0,
                follow_redirects=True,
                headers={"User-Agent": "psp-etl"},
            )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._own_client and self._client:
            await self._client.aclose()

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Use 'async with AsRockScraper() as s:' to manage the client lifecycle")
        return self._client

    async def _fetch_cdx_for_socket(self, socket: str) -> list[tuple[str, str, str]]:
        """Return (model, version, url) tuples for all archived BIOS files.

        Results are cached after the first call per socket.
        """
        if socket in self._cdx_cache:
            return self._cdx_cache[socket]

        client = self._require_client()
        params = {
            "url": f"download.asrock.com/BIOS/{socket}/*",
            "output": "json",
            "fl": "original",
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "limit": "10000",
        }
        resp = await client.get(_CDX_API, params=params)
        resp.raise_for_status()

        rows: list[list[str]] = resp.json()
        # CDX returns a header row ["original"] when using fl= parameter
        if rows and rows[0] == ["original"]:
            rows = rows[1:]

        entries: list[tuple[str, str, str]] = []
        for row in rows:
            parsed = parse_bios_url(row[0])
            if parsed is not None:
                _, model, version = parsed
                entries.append((model, version, row[0]))

        self._cdx_cache[socket] = entries
        logger.debug("CDX returned %d BIOS entries for socket %s", len(entries), socket)
        return entries

    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate all ASRock AM4/AM5 motherboards via Wayback Machine CDX."""
        seen: dict[tuple[str, str], BoardInfo] = {}
        for socket in _SOCKETS:
            entries = await self._fetch_cdx_for_socket(socket)
            for model, _version, _url in entries:
                key = (socket, model)
                if key not in seen:
                    seen[key] = BoardInfo(
                        vendor="ASRock",
                        model=model,
                        socket=socket,
                        url=board_support_url(model),
                    )
        return list(seen.values())

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """List all available BIOS updates for a given board."""
        entries = await self._fetch_cdx_for_socket(board.socket)
        return [
            BiosUpdate(
                board=board,
                bios_version=version,
                download_url=url,
                release_date=None,
                agesa_version=None,
            )
            for model, version, url in entries
            if model == board.model
        ]

    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download a BIOS ZIP from ASRock CDN and extract the raw ROM/BIN."""
        client = self._require_client()
        dest_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Downloading ASRock %s %s from %s",
            update.board.model,
            update.bios_version,
            update.download_url,
        )
        resp = await client.get(update.download_url)
        resp.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            path = extract_rom(zf, dest_dir, update)

        logger.info("Extracted ROM to %s", path)
        return path


def parse_bios_url(url: str) -> tuple[str, str, str] | None:
    """Parse an ASRock BIOS CDN URL into ``(socket, model, version)``.

    Returns ``None`` if the URL does not match the expected pattern.

    Example::

        >>> parse_bios_url(
        ...     "https://download.asrock.com/BIOS/AM5/B650%20LiveMixer(1.14.AS06)ROM.zip"
        ... )
        ('AM5', 'B650 LiveMixer', '1.14.AS06')
    """
    m = _BIOS_URL_RE.match(url)
    if not m:
        return None
    socket = m.group(1).upper()
    model = unquote(m.group(2)).strip()
    version = m.group(3)
    return socket, model, version


def board_support_url(model: str) -> str:
    """Return the ASRock product support page URL for a board model."""
    return f"https://www.asrock.com/mb/AMD/{quote(model)}/index.asp"


def extract_rom(zf: zipfile.ZipFile, dest_dir: Path, update: BiosUpdate) -> Path:
    """Extract the firmware image from a BIOS ZIP archive.

    Prefers files with ``.ROM``, ``.BIN``, or ``.BIOS`` extensions.
    Falls back to the largest file when no recognised extension is found.
    Skips macOS resource-fork entries (``__MACOSX/``).
    """
    entries = [name for name in safe_namelist(zf) if not name.startswith("__MACOSX") and not name.endswith("/")]
    if not entries:
        raise ValueError(f"Empty ZIP for {update.board.model} {update.bios_version}")

    rom_entries = [name for name in entries if Path(name).suffix.upper() in {".ROM", ".BIN", ".BIOS"}]
    candidates = rom_entries if rom_entries else entries

    target = max(candidates, key=lambda n: zf.getinfo(n).file_size)
    suffix = Path(target).suffix.lower() or ".rom"

    safe_model = re.sub(r"[^\w\-.]", "_", update.board.model)
    out_path = dest_dir / f"{safe_model}_{update.bios_version}{suffix}"
    out_path.write_bytes(zf.read(target))
    return out_path
