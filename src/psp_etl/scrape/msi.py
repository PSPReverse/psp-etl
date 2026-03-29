"""MSI BIOS scraper.

Board discovery uses the Wayback Machine CDX API to enumerate all known BIOS
ZIP URLs on download.msi.com.  The MSI website is protected by Akamai, but
the CDN (download.msi.com / download-2.msi.com) is publicly accessible.

CDN URL format:
    https://download.msi.com/bos_exe/mb/{BOARD_ID}v{VERSION}.zip

Each ZIP contains:
    {BOARD_ID}v{VERSION}/
    {BOARD_ID}v{VERSION}/{BOARD_ID}v{x}.txt   ← release notes with model name
    {BOARD_ID}v{VERSION}/E{BOARD_ID}IMS.{VER} ← raw BIOS image

The release-notes TXT is the *second* entry in the ZIP local-file stream
(after the directory entry) and fits within the first 8 KB.  We use an HTTP
Range request to read it without downloading the full 8–20 MB archive.
"""

from __future__ import annotations

import logging
import re
import struct
import zlib
import zipfile
import io
from pathlib import Path

import httpx

from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper

logger = logging.getLogger(__name__)

_CDX_API = "https://web.archive.org/cdx/search/cdx"
_CDN_BASE = "https://download.msi.com/bos_exe/mb/"

# Matches the CDN URL and extracts board_id + version
# e.g. https://download.msi.com/bos_exe/mb/7C84v10.zip → ("7C84", "10")
_URL_RE = re.compile(
    r"https?://download(?:-\d+)?\.msi\.com/bos_exe/mb/([0-9A-Fa-f]{4})v([0-9A-Za-z]+)\.zip",
    re.IGNORECASE,
)

# Chipset keywords for socket detection (in board model names)
_AM4_RE = re.compile(r"\b(X570|B550|B450|A520|X470|B350|X370|A320|B250|A300|B150)\b", re.IGNORECASE)
_AM5_RE = re.compile(r"\b(X670E?|B650E?|A620|X870E?|B850|B840)\b", re.IGNORECASE)

# Parses model name from release notes: "MAG X570 TOMAHAWK WIFI(MS-7C84) V1.0 BIOS Release"
_MODEL_RE = re.compile(
    r"^(.+?)\s*\(MS-[0-9A-Fa-f]+\)\s+V[\d.]+\s+BIOS\s+Release",
    re.MULTILINE | re.IGNORECASE,
)

# How many bytes to fetch for the range request to read the TXT header
_RANGE_BYTES = 8192


class MsiScraper(VendorScraper):
    """MSI BIOS scraper using Wayback Machine CDX for board enumeration.

    Uses HTTP Range requests to identify board model and socket from just the
    first 8 KB of each BIOS ZIP (avoids downloading the full 8–20 MB archive
    for board discovery).

    Usage::

        async with MsiScraper() as scraper:
            boards = await scraper.list_boards()
            for board in boards:
                updates = await scraper.list_bios_updates(board)
                for update in updates:
                    path = await scraper.download(update, dest_dir)
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._own_client = client is None
        # board_id → (model_name, socket)
        self._board_cache: dict[str, tuple[str, str]] = {}
        # board_id → list of (version, url)
        self._cdx_cache: dict[str, list[tuple[str, str]]] | None = None

    async def __aenter__(self) -> MsiScraper:
        if self._own_client:
            self._client = httpx.AsyncClient(
                timeout=60.0,
                follow_redirects=True,
                headers={"User-Agent": "psp-etl/0.1 (+https://github.com/vringar/psp-etl)"},
            )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._own_client and self._client:
            await self._client.aclose()

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Use 'async with MsiScraper() as s:' to manage the client lifecycle")
        return self._client

    # ------------------------------------------------------------------
    # CDX enumeration
    # ------------------------------------------------------------------

    async def _fetch_cdx(self) -> dict[str, list[tuple[str, str]]]:
        """Return {board_id: [(version, url), ...]} for all CDX-indexed ZIPs."""
        if self._cdx_cache is not None:
            return self._cdx_cache

        client = self._require_client()
        params = {
            "url": "download.msi.com/bos_exe/mb/*",
            "output": "json",
            "fl": "original",
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "limit": "10000",
        }
        resp = await client.get(_CDX_API, params=params)
        resp.raise_for_status()

        rows: list[list[str]] = resp.json()
        if rows and rows[0] == ["original"]:
            rows = rows[1:]

        result: dict[str, list[tuple[str, str]]] = {}
        for row in rows:
            parsed = parse_bios_url(row[0])
            if parsed is None:
                continue
            board_id, version = parsed
            result.setdefault(board_id.upper(), []).append((version, row[0]))

        self._cdx_cache = result
        logger.debug("CDX returned %d distinct MSI board IDs", len(result))
        return result

    # ------------------------------------------------------------------
    # Board identification via range request
    # ------------------------------------------------------------------

    async def _identify_board(self, board_id: str, first_url: str) -> tuple[str, str] | None:
        """Return (model_name, socket) by reading the TXT from the ZIP header.

        Uses a Range: bytes=0-8191 request so we only fetch the first 8 KB of
        the archive, which is sufficient to decompress the small release-notes
        TXT stored as the second local-file entry.

        Returns None if the board is not AM4 or AM5.
        """
        if board_id in self._board_cache:
            return self._board_cache[board_id]

        client = self._require_client()
        # The CDN redirects download.msi.com → download-2.msi.com.
        # Follow the redirect first, then do the range request on the final URL.
        head = await client.head(first_url)
        final_url = str(head.url)

        try:
            resp = await client.get(
                final_url,
                headers={"Range": f"bytes=0-{_RANGE_BYTES - 1}"},
            )
            # 206 Partial Content or 200 OK both acceptable
            if resp.status_code not in (200, 206):
                logger.debug("Range request failed (%d) for %s", resp.status_code, final_url)
                return None
            data = resp.content
        except httpx.HTTPError as exc:
            logger.debug("Range request error for %s: %s", final_url, exc)
            return None

        txt = _extract_txt_from_zip_header(data)
        if txt is None:
            logger.debug("Could not parse TXT from ZIP header for board %s", board_id)
            return None

        m = _MODEL_RE.search(txt)
        if not m:
            logger.debug("Could not parse model name from TXT for board %s:\n%s", board_id, txt[:200])
            return None

        model_name = m.group(1).strip()

        if _AM5_RE.search(model_name):
            socket = "AM5"
        elif _AM4_RE.search(model_name):
            socket = "AM4"
        else:
            logger.debug("Board %s (%s) is not AM4/AM5, skipping", board_id, model_name)
            return None

        logger.debug("Identified board %s → %s (%s)", board_id, model_name, socket)
        self._board_cache[board_id] = (model_name, socket)
        return model_name, socket

    # ------------------------------------------------------------------
    # VendorScraper interface
    # ------------------------------------------------------------------

    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate all AM4/AM5 MSI motherboards via Wayback Machine CDX."""
        cdx = await self._fetch_cdx()

        boards: list[BoardInfo] = []
        for board_id, versions in cdx.items():
            # Use the first (oldest) URL to identify the board
            first_url = versions[0][1]
            result = await self._identify_board(board_id, first_url)
            if result is None:
                continue
            model_name, socket = result
            boards.append(
                BoardInfo(
                    vendor="MSI",
                    model=model_name,
                    socket=socket,
                    url=f"https://www.msi.com/Motherboard/{model_name.replace(' ', '-')}/support",
                )
            )

        logger.info("Found %d MSI AM4/AM5 boards", len(boards))
        return boards

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """List all CDX-indexed BIOS updates for the given board."""
        cdx = await self._fetch_cdx()

        # Reverse-lookup: find board_id for this model
        board_id = _model_to_board_id(board.model, self._board_cache)
        if board_id is None:
            logger.warning("No board_id found for MSI %s", board.model)
            return []

        return [
            BiosUpdate(
                board=board,
                bios_version=version,
                download_url=url,
                release_date=None,
                agesa_version=None,
            )
            for version, url in cdx.get(board_id, [])
        ]

    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download a MSI BIOS ZIP and extract the raw ROM image."""
        client = self._require_client()
        dest_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Downloading MSI %s %s from %s",
            update.board.model,
            update.bios_version,
            update.download_url,
        )
        resp = await client.get(update.download_url)
        resp.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            path = _extract_rom(zf, dest_dir, update)

        logger.info("Extracted ROM to %s", path)
        return path


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def parse_bios_url(url: str) -> tuple[str, str] | None:
    """Parse a MSI CDN URL into ``(board_id, version)``.

    Returns ``None`` if the URL does not match the expected pattern.

    Examples::

        >>> parse_bios_url("https://download.msi.com/bos_exe/mb/7C84v10.zip")
        ('7C84', '10')
        >>> parse_bios_url("https://download-2.msi.com/bos_exe/mb/7C35v1A.zip")
        ('7C35', '1A')
    """
    m = _URL_RE.match(url)
    if not m:
        return None
    return m.group(1).upper(), m.group(2)


def _extract_txt_from_zip_header(data: bytes) -> str | None:
    """Parse the second local-file entry from a partial ZIP buffer.

    MSI BIOS ZIPs always start with:
      entry 0: directory  {BOARD_ID}v{VER}/         (0 bytes, stored)
      entry 1: text file  {BOARD_ID}v{VER}/...txt   (< 2 KB, deflated)

    We parse two local-file headers and decompress the TXT.
    Returns the decoded text, or None on any parse error.
    """
    offset = 0
    for _ in range(2):
        entry = _parse_lfh(data, offset)
        if entry is None:
            return None
        fname, compress, comp_size, uncomp_size, data_offset = entry
        if fname.lower().endswith(".txt"):
            chunk = data[data_offset : data_offset + comp_size]
            if len(chunk) < comp_size:
                return None  # TXT didn't fit in the range
            try:
                if compress == 8:
                    return zlib.decompress(chunk, -15).decode("utf-8", errors="replace")
                if compress == 0:
                    return chunk[:uncomp_size].decode("utf-8", errors="replace")
            except Exception:
                return None
        # Advance to next entry (comp_size == 0 for stored empty dirs)
        offset = data_offset + comp_size
    return None


def _parse_lfh(data: bytes, offset: int) -> tuple[str, int, int, int, int] | None:
    """Parse a ZIP local-file header at *offset*.

    Returns (filename, compression_method, comp_size, uncomp_size, data_offset)
    or None if there is not enough data or the signature is wrong.
    """
    if offset + 30 > len(data):
        return None
    if data[offset : offset + 4] != b"PK\x03\x04":
        return None
    try:
        (_, _, compress, _, _, _, comp_size, uncomp_size, fname_len, extra_len) = struct.unpack_from(
            "<HHHHHIIIHH", data, offset + 4
        )
    except struct.error:
        return None
    fname_start = offset + 30
    fname_end = fname_start + fname_len
    if fname_end > len(data):
        return None
    fname = data[fname_start:fname_end].decode("utf-8", errors="replace")
    data_start = fname_end + extra_len
    return fname, compress, comp_size, uncomp_size, data_start


def _model_to_board_id(model: str, cache: dict[str, tuple[str, str]]) -> str | None:
    """Reverse-lookup board_id from model name in the scraper cache."""
    for board_id, (cached_model, _) in cache.items():
        if cached_model == model:
            return board_id
    return None


def _extract_rom(zf: zipfile.ZipFile, dest_dir: Path, update: BiosUpdate) -> Path:
    """Extract the firmware image from a MSI BIOS ZIP archive.

    Skips release notes (.txt, .doc) and flash utilities (.exe).
    Falls back to the largest remaining file if no preferred extension found.
    """
    skip_exts = {".txt", ".doc", ".exe", ".bat", ".pdf", ".htm", ".html"}
    candidates = [
        name for name in zf.namelist() if not name.endswith("/") and Path(name).suffix.lower() not in skip_exts
    ]
    if not candidates:
        raise ValueError(
            f"No ROM file found in ZIP for MSI {update.board.model} {update.bios_version}. Contents: {zf.namelist()}"
        )

    target = max(candidates, key=lambda n: zf.getinfo(n).file_size)
    suffix = Path(target).suffix.lower() or ".bin"

    safe_model = re.sub(r"[^\w\-.]", "_", update.board.model)
    out_path = dest_dir / f"{safe_model}_{update.bios_version}{suffix}"
    out_path.write_bytes(zf.read(target))
    return out_path
