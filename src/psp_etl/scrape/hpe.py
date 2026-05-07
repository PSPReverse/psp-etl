"""HPE ProLiant AMD BIOS scraper.

HPE distributes ProLiant BIOS as **HP Self-Extracting Component**
(``.scexe``) files, either standalone on the HPE Support Center or
bundled inside the multi-gigabyte **Service Pack for ProLiant** (SPP)
ISO. Both routes are gated behind an HPE Passport login for current
firmware; only legacy components are reachable without authentication.

Discovery
---------

We use the Wayback Machine CDX index — the same approach as the
ASRock and MSI scrapers — to enumerate ``.scexe`` URLs that were
indexed before the login wall expanded. Wayback coverage of
``support.hpe.com`` is sparse for AMD ProLiant generations (all
post-2018) and CDX queries can legitimately return zero entries; the
class is built to remain correct (and hand off cleanly to manual
ingestion) when that happens.

URL patterns the scraper inspects on Wayback:

* ``support.hpe.com/.../*.scexe`` — current support center CDN
* ``ftp.hp.com/pub/softpaq/.../*.scexe`` — legacy FTP mirror
* ``h*.www*.hpe.com/.../*.scexe`` — legacy HPE marketing/support hosts

Component IDs (``cp{NNNNNN}.scexe``) are opaque on their own — without
the per-component XML manifest we cannot map a CP ID to a board. The
scraper therefore only emits a :class:`BoardInfo` when the URL or its
adjacent path segments embed a recognised ProLiant model token (e.g.
``DL385-Gen10-Plus``); CPs without identifying context are skipped.

ProLiant AMD lineup (model -> socket):

* Rome / Milan (SP3): DL325 Gen10 / Gen10 Plus / Gen10 Plus v2,
  DL345 Gen10 Plus, DL385 Gen10 / Gen10 Plus / Gen10 Plus v2,
  XL225n Gen10, XL345 Gen10 Plus
* Genoa / Bergamo / Turin (SP5): DL325 Gen11, DL345 Gen11,
  DL365 Gen11, DL385 Gen11, DL725 Gen5, DL765 Gen11, XL345 Gen11

Extraction
----------

``.scexe`` files are HP-flavoured self-extracting shell scripts: an
ASCII header followed by a binary payload (typically gzip-compressed
tar). :func:`unwrap_scexe` locates the first archive-magic byte
sequence after the script header, decompresses it if needed, and
returns the inner ROM image. Tar payloads are walked for the largest
``.bin`` / ``.rom`` / ``.fd`` member.

License-safe references: nothing relevant in surveyed prior art
(BIOSUtilities is MIT and provides a more general ``hp-scexe``
extractor we deliberately do not vendor here — the unwrap below is
intentionally narrow to what HPE BIOS ``.scexe`` files require).
"""

from __future__ import annotations

import gzip
import io
import logging
import re
import tarfile
import zipfile
import zlib
from pathlib import Path
from urllib.parse import unquote

import httpx

from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper
from psp_etl.scrape.extract import safe_namelist

logger = logging.getLogger(__name__)

_CDX_API = "https://web.archive.org/cdx/search/cdx"

# Wayback CDX query targets. Each entry is a URL prefix to query with
# the wildcard suffix ``/*.scexe``; the index is queried per-prefix
# because Wayback caps a single query at ``limit`` rows.
_HPE_CDX_PREFIXES: tuple[str, ...] = (
    "support.hpe.com/hpesc/public/swd",
    "ftp.hp.com/pub/softpaq",
    "downloads.linux.hpe.com",
    "h20566.www2.hpe.com",
    "h17007.www1.hpe.com",
)

# Model-name patterns (case-insensitive) found in HPE component URLs.
# The full token list is matched against the entire URL after
# normalising separators (``-``, ``_``, ``+``, ``%20``) to spaces, so
# both ``DL385-Gen10-Plus`` and ``DL385%20Gen10%20Plus`` resolve to the
# same model. Order matters: longer / more-specific tokens first so
# ``DL385 Gen10 Plus v2`` wins over ``DL385 Gen10 Plus`` and
# ``DL385 Gen10``.
_MODEL_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # SP3 (Rome / Milan)
    (re.compile(r"\bDL325\s+Gen10\s+Plus\s+v2\b", re.I), "DL325 Gen10 Plus v2", "SP3"),
    (re.compile(r"\bDL325\s+Gen10\s+Plus\b", re.I), "DL325 Gen10 Plus", "SP3"),
    (re.compile(r"\bDL325\s+Gen10\b", re.I), "DL325 Gen10", "SP3"),
    (re.compile(r"\bDL345\s+Gen10\s+Plus\b", re.I), "DL345 Gen10 Plus", "SP3"),
    (re.compile(r"\bDL385\s+Gen10\s+Plus\s+v2\b", re.I), "DL385 Gen10 Plus v2", "SP3"),
    (re.compile(r"\bDL385\s+Gen10\s+Plus\b", re.I), "DL385 Gen10 Plus", "SP3"),
    (re.compile(r"\bDL385\s+Gen10\b", re.I), "DL385 Gen10", "SP3"),
    (re.compile(r"\bXL225n\s+Gen10\b", re.I), "XL225n Gen10", "SP3"),
    (re.compile(r"\bXL345\s+Gen10\s+Plus\b", re.I), "XL345 Gen10 Plus", "SP3"),
    # SP5 (Genoa / Bergamo / Turin)
    (re.compile(r"\bDL325\s+Gen11\b", re.I), "DL325 Gen11", "SP5"),
    (re.compile(r"\bDL345\s+Gen11\b", re.I), "DL345 Gen11", "SP5"),
    (re.compile(r"\bDL365\s+Gen11\b", re.I), "DL365 Gen11", "SP5"),
    (re.compile(r"\bDL385\s+Gen11\b", re.I), "DL385 Gen11", "SP5"),
    (re.compile(r"\bDL725\s+Gen5\b", re.I), "DL725 Gen5", "SP5"),
    (re.compile(r"\bDL765\s+Gen11\b", re.I), "DL765 Gen11", "SP5"),
    (re.compile(r"\bXL345\s+Gen11\b", re.I), "XL345 Gen11", "SP5"),
)

# Match the CP component ID (always 6 zero-padded digits) anywhere in
# the URL. CP IDs are HPE's primary BIOS-component identifiers and are
# the only stable per-version handle the support center exposes.
_CP_ID_RE = re.compile(r"\bcp(\d{6})\b", re.I)

# Token separators that vary across HPE URL conventions; normalising
# them to spaces lets one set of model patterns match every form.
_URL_SEP_RE = re.compile(r"[-_+]+")


def _normalise_url_for_matching(url: str) -> str:
    """Return the URL with separators normalised so model regexes can match."""
    decoded = unquote(url)
    return _URL_SEP_RE.sub(" ", decoded)


def classify_proliant_model(url: str) -> tuple[str, str] | None:
    """Return ``(model, socket)`` for an HPE component URL or ``None``.

    Inspects the (decoded, separator-normalised) URL for the first
    matching ProLiant AMD model token. Returns ``None`` when no
    recognised model appears — these CPs are skipped because we cannot
    confidently attribute them without the per-component XML manifest.
    """
    haystack = _normalise_url_for_matching(url)
    for pattern, model, socket in _MODEL_PATTERNS:
        if pattern.search(haystack):
            return model, socket
    return None


def parse_component_url(url: str) -> tuple[str, str, str] | None:
    """Parse an HPE component URL into ``(cp_id, model, socket)``.

    Returns ``None`` when the URL contains no CP ID or no recognised
    ProLiant AMD model. The CP ID doubles as the BIOS version handle
    when the underlying SoftPaq is not parseable from the URL.
    """
    cp_match = _CP_ID_RE.search(url)
    if cp_match is None:
        return None
    cls = classify_proliant_model(url)
    if cls is None:
        return None
    model, socket = cls
    return f"cp{cp_match.group(1)}", model, socket


def board_support_url(model: str) -> str:
    """Return the public HPE QuickSpecs / product page URL for *model*."""
    slug = model.lower().replace(" ", "-")
    return f"https://www.hpe.com/psnow/doc/quickspecs?productNumber={slug}"


# ---------------------------------------------------------------------------
# .scexe unwrap
# ---------------------------------------------------------------------------

# Magic-byte signatures of archive payloads HPE ships inside .scexe.
# Order is significant: the first match in the byte stream wins.
_GZIP_MAGIC = b"\x1f\x8b\x08"  # gzip with deflate method
_ZIP_MAGIC = b"PK\x03\x04"

# Maximum bytes from the start of a .scexe to scan for archive magic.
# HPE shell-script headers are well under 100 KiB; a 1 MiB cap leaves
# plenty of margin without falling into the gzipped payload itself.
_HEADER_SCAN_LIMIT = 1 << 20  # 1 MiB

# ROM-payload extensions, in order of preference, found inside the
# decompressed tar.
_ROM_SUFFIXES: tuple[str, ...] = (".bin", ".rom", ".fd", ".cap")


class ScexeUnwrapError(ValueError):
    """Raised when a ``.scexe`` payload cannot be located or decompressed."""


def _find_archive_offset(data: bytes) -> tuple[int, bytes]:
    """Return ``(offset, magic)`` of the first archive payload in *data*.

    Scans only the leading ``_HEADER_SCAN_LIMIT`` bytes, which are
    guaranteed to contain the script header and the start of the
    payload for every HPE component .scexe in scope.
    """
    window = data[:_HEADER_SCAN_LIMIT]
    candidates: list[tuple[int, bytes]] = []
    for magic in (_GZIP_MAGIC, _ZIP_MAGIC):
        idx = window.find(magic)
        if idx >= 0:
            candidates.append((idx, magic))
    if not candidates:
        raise ScexeUnwrapError(
            f"No gzip or zip magic bytes in first {_HEADER_SCAN_LIMIT} bytes of .scexe payload",
        )
    return min(candidates, key=lambda c: c[0])


def _pick_rom_member(names: list[str]) -> str | None:
    """Pick the most plausible ROM file from a tar/zip member list.

    Prefers files whose extension is in :data:`_ROM_SUFFIXES`; ties are
    broken by descending name (so the largest version-suffixed file
    wins deterministically). Returns ``None`` when no member has a
    recognised ROM extension.
    """
    rom_members = [name for name in names if Path(name).suffix.lower() in _ROM_SUFFIXES]
    if not rom_members:
        return None
    return sorted(rom_members, reverse=True)[0]


def unwrap_scexe(data: bytes) -> bytes:
    """Return the BIOS ROM bytes embedded in an HPE ``.scexe`` blob.

    The function:

    1. Skips the shell-script header by scanning for the first gzip or
       zip magic byte sequence.
    2. Decompresses the payload (gzip stream or zip member).
    3. If the decompressed blob is a tar archive, extracts the largest
       member whose suffix is in :data:`_ROM_SUFFIXES`.
    4. Otherwise returns the decompressed bytes verbatim.

    Raises:
        ScexeUnwrapError: on missing / unsupported payload, or when
            the inner archive contains no ROM-like file.
    """
    offset, magic = _find_archive_offset(data)
    payload = data[offset:]

    if magic == _GZIP_MAGIC:
        try:
            inner = gzip.decompress(payload)
        except (OSError, EOFError, zlib.error) as exc:
            raise ScexeUnwrapError(f"gzip decompression failed: {exc}") from exc
        return _unwrap_tar_or_raw(inner)

    # ZIP — pick the first ROM-suffixed member, or the largest entry
    # if no recognised suffix is present.
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            entries = [name for name in safe_namelist(zf) if not name.endswith("/")]
            if not entries:
                raise ScexeUnwrapError("zip payload is empty")
            target = _pick_rom_member(entries)
            if target is None:
                target = max(entries, key=lambda n: zf.getinfo(n).file_size)
            return zf.read(target)
    except zipfile.BadZipFile as exc:
        raise ScexeUnwrapError(f"zip payload is malformed: {exc}") from exc


def _unwrap_tar_or_raw(data: bytes) -> bytes:
    """Return the BIOS ROM from a tar payload, or *data* itself if not a tar."""
    if not _looks_like_tar(data):
        return data
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            names = [m.name for m in tf.getmembers() if m.isfile()]
            target = _pick_rom_member(names)
            if target is None:
                # Fall through to the largest regular file. HPE BIOS
                # tarballs reliably contain a single .bin payload, so
                # this branch is defensive — never silently lose data.
                regular = [m for m in tf.getmembers() if m.isfile()]
                if not regular:
                    raise ScexeUnwrapError("tar payload contains no regular files")
                target = max(regular, key=lambda m: m.size).name
            handle = tf.extractfile(target)
            if handle is None:
                raise ScexeUnwrapError(f"could not open tar member {target!r}")
            return handle.read()
    except tarfile.TarError as exc:
        raise ScexeUnwrapError(f"tar payload is malformed: {exc}") from exc


def _looks_like_tar(data: bytes) -> bool:
    """Return ``True`` if *data* starts with a USTAR / GNU tar header."""
    # POSIX tar puts the magic ``ustar`` at offset 257 of the first
    # 512-byte block. ``v7`` (legacy) tars omit the magic; we treat
    # those as "not tar" and let the caller return raw bytes.
    if len(data) < 512:
        return False
    magic = data[257:265]
    return magic.startswith(b"ustar")


# ---------------------------------------------------------------------------
# Scraper
# ---------------------------------------------------------------------------


class HpeScraper(VendorScraper):
    """Scrape HPE ProLiant AMD BIOS components via the Wayback CDX index.

    The scraper enumerates ``.scexe`` URLs across the HPE support and
    legacy CDN domains listed in :data:`_HPE_CDX_PREFIXES`, classifies
    each URL into a (model, socket) by string-matching the ProLiant
    AMD lineup, and exposes them as :class:`BoardInfo` /
    :class:`BiosUpdate` objects.

    Wayback coverage of HPE AMD BIOSes is intentionally sparse — most
    components were never indexed before HPE Passport gating, and CDX
    queries can legitimately return zero matches. The scraper is
    structured so that any archive that *does* surface is parsed
    end-to-end (download + .scexe unwrap), which keeps the class
    useful for both incremental Wayback discovery and manual ingestion
    of out-of-band ``.scexe`` files (via :func:`unwrap_scexe`).
    """

    vendor: str = "HPE"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._own_client = client is None
        # Cache: prefix -> list of (cp_id, model, socket, url)
        self._cdx_cache: dict[str, list[tuple[str, str, str, str]]] = {}

    async def __aenter__(self) -> HpeScraper:
        if self._own_client:
            self._client = httpx.AsyncClient(
                timeout=60.0,
                follow_redirects=True,
                headers={"User-Agent": "psp-etl"},
            )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._own_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError(f"Use 'async with {type(self).__name__}() as s:' to manage the client lifecycle")
        return self._client

    async def _fetch_cdx_for_prefix(self, prefix: str) -> list[tuple[str, str, str, str]]:
        """Return ``(cp_id, model, socket, url)`` tuples for one Wayback prefix.

        Results are cached per prefix; failed Wayback queries return an
        empty list (and are cached) so a flaky CDX backend cannot
        amplify into per-call retries during a normal scrape.
        """
        if prefix in self._cdx_cache:
            return self._cdx_cache[prefix]

        client = self._require_client()
        params = {
            "url": f"{prefix}/*.scexe",
            "output": "json",
            "fl": "original",
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "limit": "10000",
        }
        try:
            resp = await client.get(_CDX_API, params=params)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("Wayback CDX query for %s failed: %s", prefix, exc)
            self._cdx_cache[prefix] = []
            return []

        rows: list[list[str]] = resp.json()
        if rows and rows[0] == ["original"]:
            rows = rows[1:]

        entries: list[tuple[str, str, str, str]] = []
        for row in rows:
            url = row[0]
            parsed = parse_component_url(url)
            if parsed is None:
                continue
            cp_id, model, socket = parsed
            entries.append((cp_id, model, socket, url))

        self._cdx_cache[prefix] = entries
        logger.debug("CDX returned %d HPE BIOS entries for %s", len(entries), prefix)
        return entries

    async def _all_entries(self) -> list[tuple[str, str, str, str]]:
        """Aggregate CDX entries across every configured prefix."""
        out: list[tuple[str, str, str, str]] = []
        for prefix in _HPE_CDX_PREFIXES:
            out.extend(await self._fetch_cdx_for_prefix(prefix))
        return out

    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate HPE ProLiant AMD boards reachable through Wayback CDX."""
        seen: dict[tuple[str, str], BoardInfo] = {}
        for _cp_id, model, socket, _url in await self._all_entries():
            key = (socket, model)
            if key in seen:
                continue
            seen[key] = BoardInfo(
                vendor=self.vendor,
                model=model,
                socket=socket,
                url=board_support_url(model),
            )
        logger.info("Found %d HPE ProLiant AMD boards via Wayback CDX", len(seen))
        return list(seen.values())

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """Return every distinct CP-ID BIOS component for *board*."""
        updates: list[BiosUpdate] = []
        seen_cps: set[str] = set()
        for cp_id, model, socket, url in await self._all_entries():
            if model != board.model or socket != board.socket:
                continue
            if cp_id in seen_cps:
                continue
            seen_cps.add(cp_id)
            updates.append(
                BiosUpdate(
                    board=board,
                    bios_version=cp_id,
                    download_url=url,
                    release_date=None,
                    agesa_version=None,
                ),
            )
        return updates

    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download a ``.scexe`` from the (Wayback) URL and write the raw ROM."""
        client = self._require_client()
        dest_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Downloading HPE %s %s from %s",
            update.board.model,
            update.bios_version,
            update.download_url,
        )
        resp = await client.get(update.download_url)
        resp.raise_for_status()

        rom_bytes = unwrap_scexe(resp.content)

        safe_model = re.sub(r"[^\w\-.]", "_", update.board.model)
        safe_version = re.sub(r"[^\w\-.]", "_", update.bios_version)
        out_path = dest_dir / f"{safe_model}_{safe_version}.bin"
        out_path.write_bytes(rom_bytes)
        logger.info("Extracted ROM to %s", out_path)
        return out_path
