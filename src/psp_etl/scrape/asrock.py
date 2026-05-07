"""ASRock BIOS scraper.

Board discovery uses the Wayback Machine CDX API to enumerate all known
BIOS ZIP URLs on download.asrock.com. The ASRock website (www.asrock.com)
is protected by a WAF that blocks automated requests; the CDX index serves
as a reliable alternative data source.

BIOS files are downloaded directly from the ASRock CDN.

URL format: https://download.asrock.com/BIOS/{folder}/{model}({version})...

The CDN organises BIOSes under top-level folders that usually name the
CPU socket (``AM4``, ``AM5``, ``sTRX4``, ``sTR5``, ``TR4``) but for
ASRock Rack boards they live under a generic ``Server`` folder and the
socket has to be inferred from the model name. ``AsRockScraper`` and the
Rack subclass share the same enumerate-and-extract logic and differ only
in the folder list and the (folder, model) -> socket mapping.
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote, unquote

import httpx

from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper
from psp_etl.scrape.extract import safe_namelist

logger = logging.getLogger(__name__)

_CDX_API = "https://web.archive.org/cdx/search/cdx"

# CDN folder names ASRock uses for each AMD socket. The strings are also the
# canonical socket values stored on ``BoardInfo.socket``; case matters because
# the Threadripper folders use a lowercase 's' prefix on the CDN
# (``sTRX4``/``sTR5``) while AM4/AM5/TR4 are upper-case. Threadripper Pro
# (``sWRX8``/``sWRX9``) lives only in the ASRock Rack catalogue and is handled
# by the rack scraper (see issue #84).
_SOCKETS = ("AM4", "AM5", "TR4", "sTRX4", "sTR5")

# Matches: https://download.asrock.com/BIOS/{folder}/{model}({version})...
# {folder} is captured loosely so subclasses can target Rack folders
# (e.g. "Server"); restrict via the ``folders`` constructor parameter.
_BIOS_URL_RE = re.compile(
    r"https://download\.asrock\.com/BIOS/([^/]+)/([^(]+)\(([^)]+)\)",
)


class AsRockScraper(VendorScraper):
    """ASRock BIOS scraper using Wayback Machine CDX for board enumeration.

    By default the scraper covers the consumer ``AM4`` / ``AM5`` folders.
    Subclasses pass alternative folder lists and a model-name-based
    classifier to cover server / workstation lines whose folders don't
    name the socket directly (see :class:`asrock_rack.AsRockRackScraper`).

    Usage::

        async with AsRockScraper() as scraper:
            boards = await scraper.list_boards()
            for board in boards:
                updates = await scraper.list_bios_updates(board)
                for update in updates:
                    path = await scraper.download(update, dest_dir)
    """

    vendor: str = "ASRock"

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        *,
        folders: tuple[str, ...] = _SOCKETS,
        classify: Callable[[str, str], str | None] | None = None,
    ) -> None:
        self._client = client
        self._own_client = client is None
        self._folders = folders
        # By default the folder name *is* the socket (AM4 / AM5).
        self._classify = classify if classify is not None else (lambda folder, _model: folder)
        # Cache: folder -> list of (socket, model, version, url)
        self._cdx_cache: dict[str, list[tuple[str, str, str, str]]] = {}

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
            raise RuntimeError(f"Use 'async with {type(self).__name__}() as s:' to manage the client lifecycle")
        return self._client

    def board_support_url(self, model: str) -> str:
        """Return the vendor product support page URL for a board model."""
        return board_support_url(model)

    async def _fetch_cdx_for_folder(self, folder: str) -> list[tuple[str, str, str, str]]:
        """Return ``(socket, model, version, url)`` tuples for archived BIOSes in ``folder``.

        The socket is derived from the configured classifier; entries
        whose model name does not classify (e.g. Intel boards under
        ``Server/``) are filtered out. Results are cached per folder.
        """
        if folder in self._cdx_cache:
            return self._cdx_cache[folder]

        client = self._require_client()
        params = {
            "url": f"download.asrock.com/BIOS/{folder}/*",
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

        entries: list[tuple[str, str, str, str]] = []
        for row in rows:
            parsed = parse_bios_url(row[0])
            if parsed is None:
                continue
            url_folder, model, version = parsed
            if url_folder.lower() != folder.lower():
                continue
            socket = self._classify(url_folder, model)
            if socket is None:
                continue
            entries.append((socket, model, version, row[0]))

        self._cdx_cache[folder] = entries
        logger.debug("CDX returned %d BIOS entries for folder %s", len(entries), folder)
        return entries

    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate motherboards via Wayback Machine CDX across configured folders."""
        seen: dict[tuple[str, str], BoardInfo] = {}
        for folder in self._folders:
            entries = await self._fetch_cdx_for_folder(folder)
            for socket, model, _version, _url in entries:
                key = (socket, model)
                if key not in seen:
                    seen[key] = BoardInfo(
                        vendor=self.vendor,
                        model=model,
                        socket=socket,
                        url=self.board_support_url(model),
                    )
        return list(seen.values())

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """List all available BIOS updates for a given board."""
        updates: list[BiosUpdate] = []
        for folder in self._folders:
            entries = await self._fetch_cdx_for_folder(folder)
            updates.extend(
                BiosUpdate(
                    board=board,
                    bios_version=version,
                    download_url=url,
                    release_date=None,
                    agesa_version=None,
                )
                for socket, model, version, url in entries
                if socket == board.socket and model == board.model
            )
        return updates

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
    """Parse an ASRock BIOS CDN URL into ``(folder, model, version)``.

    For consumer ASRock boards the folder is the socket (``AM4``,
    ``AM5``); for ASRock Rack boards it is a non-socket name like
    ``Server``. Callers map folder + model to a normalised socket via
    the scraper's classifier.

    Returns ``None`` if the URL does not match the expected pattern.

    Example::

        >>> parse_bios_url(
        ...     "https://download.asrock.com/BIOS/AM5/B650%20LiveMixer(1.14.AS06)ROM.zip"
        ... )
        ('AM5', 'B650 LiveMixer', '1.14.AS06')
        >>> parse_bios_url(
        ...     "https://download.asrock.com/BIOS/Server/X470D4U(3.50)ROM.zip"
        ... )
        ('Server', 'X470D4U', '3.50')
    """
    m = _BIOS_URL_RE.match(url)
    if not m:
        return None
    folder = m.group(1)
    model = unquote(m.group(2)).strip()
    version = m.group(3)
    return folder, model, version


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
