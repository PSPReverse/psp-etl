"""Lenovo BIOS scraper for AMD-platform ThinkSystem servers and ThinkStation P620.

Two product lines, two domains, one shared JSON catalog endpoint:

* ThinkSystem (EPYC) servers live under ``datacentersupport.lenovo.com``
* ThinkStation P620 (Threadripper Pro WRX80) lives under ``pcsupport.lenovo.com``

Both expose ``api/v4/downloads/drivers?productId=<machineType>`` (4-character
machine type, lowercased), returning a JSON catalog whose ``DownloadItems``
array is filtered by category and title to isolate the system BIOS entry.

Because Lenovo identifies each board by its machine type rather than a model
name, the scraper carries an explicit (model, machine_type, socket, family)
table — there is no public model->MTM lookup endpoint we can crawl.

Download/unwrap status:

* ThinkStation P620: the catalog ships an "EFI Shell Utility" ZIP that
  contains a raw, uncompressed ``IMAGES07.ROM`` (32 MB) directly. We extract
  it as-is and verify a known PSP/firmware-volume signature.
* ThinkSystem (SR-series): the only payload offered is a ``.uxz`` archive
  whose inner ``.upd`` file is a Lenovo proprietary container starting with
  the magic word ``0xdeadc0de``. Without Lenovo's UpdateXpress decryption
  keys we cannot recover raw BIOS bytes; ``download()`` raises
  :class:`NotImplementedError` for ThinkSystem boards rather than writing a
  garbage file. ``list_boards`` and ``list_bios_updates`` still work, so the
  catalog inventory remains useful for tracking releases.
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper
from psp_etl.scrape.extract import safe_namelist, validate_psp_rom

logger = logging.getLogger(__name__)

# Lenovo's CDN routes the catalog API under a region prefix that matches the
# request's Accept-Language. The bare `/api/v4/...` path 302s to
# `/<region>/<lang>/pagenotfound`, which 500s. Fixing the prefix to `/us/en/`
# (matching our Accept-Language: en-US header) gives a stable JSON response.
DATACENTER_API = "https://datacentersupport.lenovo.com/us/en/api/v4/downloads/drivers"
PCSUPPORT_API = "https://pcsupport.lenovo.com/us/en/api/v4/downloads/drivers"
DATACENTER_REFERER = "https://datacentersupport.lenovo.com/"
PCSUPPORT_REFERER = "https://pcsupport.lenovo.com/"

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json,text/javascript,*/*;q=0.01",
    "Accept-Language": "en-US,en;q=0.9",
    "X-Requested-With": "XMLHttpRequest",
}

# Categories that may carry the system BIOS. ThinkStation uses the short
# label; ThinkSystem prefixes a long descriptive string we match by prefix.
_BIOS_CATEGORY_EXACT = "BIOS/UEFI"
_BIOS_CATEGORY_PREFIX = "Core System Firmware"

# Title fragments that disqualify an item even when it lives in a BIOS
# category — Lenovo cross-files RAID/HBA/GPU firmware under the same nodes.
_TITLE_DISQUALIFIERS = (
    "raid",
    "hba",
    "sas",
    "vbios",
    "rtx ",
    "nvidia",
    "gpu",
    "diagnostics",
    "drives media",
    "ethernet",
)


class _Family:
    THINKSYSTEM = "ThinkSystem"
    THINKSTATION = "ThinkStation"


@dataclass(frozen=True)
class _BoardSpec:
    """Static descriptor for a Lenovo AMD board."""

    model: str
    machine_type: str  # 4-character Lenovo MTM, lowercase
    socket: str
    family: str

    @property
    def support_url(self) -> str:
        if self.family == _Family.THINKSYSTEM:
            slug = self.model.lower().replace(" ", "/").replace("/v", "v")
            return f"https://datacentersupport.lenovo.com/products/servers/{slug}/{self.machine_type}"
        return f"https://pcsupport.lenovo.com/products/{self.machine_type}"


# Each Lenovo SKU often spans several machine types (different region or
# config codes). We pick the canonical per-region MTM that the support API
# answers; other MTMs return the same firmware payload, so one entry per
# board model is sufficient for ROM coverage.
_BOARDS: tuple[_BoardSpec, ...] = (
    # ThinkSystem V3 (Genoa, SP5). Machine types verified against the live
    # support API in 2026-05; all four V3 MTMs return the same combined
    # UEFI/BIOS firmware item with cross-listed Summary support.
    _BoardSpec("ThinkSystem SR635 V3", "7d9c", "SP5", _Family.THINKSYSTEM),
    _BoardSpec("ThinkSystem SR645 V3", "7d9d", "SP5", _Family.THINKSYSTEM),
    _BoardSpec("ThinkSystem SR655 V3", "7d9f", "SP5", _Family.THINKSYSTEM),
    _BoardSpec("ThinkSystem SR665 V3", "7d9b", "SP5", _Family.THINKSYSTEM),
    # ThinkSystem first-generation AMD (Rome/Milan, SP3).
    _BoardSpec("ThinkSystem SR635", "7y98", "SP3", _Family.THINKSYSTEM),
    _BoardSpec("ThinkSystem SR655", "7y00", "SP3", _Family.THINKSYSTEM),
    _BoardSpec("ThinkSystem SR645", "7d2x", "SP3", _Family.THINKSYSTEM),
    _BoardSpec("ThinkSystem SR665", "7d2w", "SP3", _Family.THINKSYSTEM),
    # ThinkStation Threadripper Pro workstation. The PX (sWRX9) is not yet
    # released as an AMD SKU at the time of writing.
    _BoardSpec("ThinkStation P620", "30e0", "sWRX8", _Family.THINKSTATION),
)

# Item-level matchers ------------------------------------------------------


def _is_bios_item(item: dict) -> bool:
    """Return True if *item* is a system BIOS/UEFI firmware download.

    The catalog mixes RAID/HBA/GPU firmware into the BIOS category for some
    boards, so we screen by category first, then reject obvious other-device
    titles.
    """
    category = (item.get("Category") or {}).get("Name") or ""
    if category != _BIOS_CATEGORY_EXACT and not category.startswith(_BIOS_CATEGORY_PREFIX):
        return False
    title = (item.get("Title") or "").lower()
    return all(token not in title for token in _TITLE_DISQUALIFIERS)


# File-level pickers ------------------------------------------------------


def _pick_file(files: list[dict], *, family: str) -> dict | None:
    """Return the catalog file we want to download for a given product family.

    ThinkStation favours the "EFI Shell Utility" ZIP (raw ROM inside);
    ThinkSystem only ever exposes a ``.uxz`` payload.
    """
    if family == _Family.THINKSTATION:
        # Prefer the EFI shell variant by Name, falling back to any ZIP that
        # is not the Linux capsule (which carries an encrypted update).
        candidates = [f for f in files if (f.get("TypeString") or "").lower() == "zip"]
        for f in candidates:
            name = (f.get("Name") or "").lower()
            if "efi shell" in name:
                return f
        # Last resort: first non-Linux-capsule zip.
        for f in candidates:
            name = (f.get("Name") or "").lower()
            if "linux" not in name and "capsule" not in name:
                return f
        return None

    # ThinkSystem: take the .uxz payload (or the wrapping zip when the
    # catalog ships the V3 generation as a zip-of-uxz).
    for f in files:
        ts = (f.get("TypeString") or "").lower()
        if ts == "uxz":
            return f
    for f in files:
        if (f.get("TypeString") or "").lower() == "zip":
            name = (f.get("Name") or "").lower()
            if name.startswith("payload"):
                return f
    return None


# ROM extraction ----------------------------------------------------------

_THINKSTATION_ROM_RE = re.compile(r".*\.rom$", re.IGNORECASE)


def extract_thinkstation_rom(zip_data: bytes) -> tuple[str, bytes]:
    """Return ``(member_name, rom_bytes)`` from a ThinkStation EFI-shell ZIP.

    The archive holds the raw flash image alongside flash utilities; we
    pick the largest ``*.rom`` entry, then sanity-check it carries a
    PSP/BIOS directory signature so silent vendor format changes fail loud.
    """
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        candidates = [
            info for info in zf.infolist() if _THINKSTATION_ROM_RE.match(info.filename) and info.file_size > 0
        ]
        if not candidates:
            raise FileNotFoundError(f"No .rom entry in ThinkStation EFI-shell ZIP (members: {safe_namelist(zf)})")
        # Refuse hostile zips before we read content.
        safe_namelist(zf)
        target = max(candidates, key=lambda info: info.file_size)
        rom_bytes = zf.read(target.filename)

    if not validate_psp_rom(rom_bytes):
        raise ValueError(
            f"ThinkStation ROM {target.filename!r} lacks any PSP/BIOS directory signature; "
            "Lenovo may have changed the package format."
        )
    return target.filename, rom_bytes


# Scraper -----------------------------------------------------------------


class LenovoScraper(VendorScraper):
    """Scrape Lenovo AMD ThinkSystem (EPYC) and ThinkStation P620 BIOSes.

    Catalog data is served by ``api/v4/downloads/drivers`` on either the
    PC-support or DataCenter-support host depending on product family. Both
    hosts are cached per board to avoid re-fetching for ``list_boards`` and
    ``list_bios_updates``.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._owns_client = client is None
        self._catalog_cache: dict[str, list[dict]] = {}

    async def __aenter__(self) -> LenovoScraper:
        if self._owns_client:
            self._client = httpx.AsyncClient(
                timeout=60.0,
                follow_redirects=True,
                headers=_HEADERS,
            )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("LenovoScraper must be used as an async context manager")
        return self._client

    async def list_boards(self) -> list[BoardInfo]:
        return [
            BoardInfo(
                vendor="Lenovo",
                model=spec.model,
                socket=spec.socket,
                url=spec.support_url,
            )
            for spec in _BOARDS
        ]

    async def _fetch_items(self, spec: _BoardSpec) -> list[dict]:
        if spec.machine_type in self._catalog_cache:
            return self._catalog_cache[spec.machine_type]

        client = self._require_client()
        if spec.family == _Family.THINKSYSTEM:
            api_url, referer = DATACENTER_API, DATACENTER_REFERER
        else:
            api_url, referer = PCSUPPORT_API, PCSUPPORT_REFERER

        try:
            resp = await client.get(
                api_url,
                params={"productId": spec.machine_type},
                headers={"Referer": referer},
            )
            resp.raise_for_status()
            payload = resp.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as exc:
            # Lenovo retires/rebrands MTMs without warning; if any one entry
            # in the table goes stale we want to skip it and continue with the
            # rest of the scrape rather than abort the whole run.
            logger.warning(
                "Lenovo API request failed for %s (%s): %s",
                spec.model,
                spec.machine_type,
                exc,
            )
            self._catalog_cache[spec.machine_type] = []
            return []

        if payload.get("message") != "succeed":
            logger.warning(
                "Lenovo API returned non-success for %s (%s): %r",
                spec.model,
                spec.machine_type,
                payload.get("message"),
            )
            self._catalog_cache[spec.machine_type] = []
            return []

        items = (payload.get("body") or {}).get("DownloadItems") or []
        self._catalog_cache[spec.machine_type] = items
        return items

    def _spec_for_board(self, board: BoardInfo) -> _BoardSpec:
        for spec in _BOARDS:
            if spec.model == board.model:
                return spec
        raise ValueError(f"Unknown Lenovo board model: {board.model!r}")

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        spec = self._spec_for_board(board)
        items = await self._fetch_items(spec)

        updates: list[BiosUpdate] = []
        for item in items:
            if not _is_bios_item(item):
                continue
            picked = _pick_file(item.get("Files") or [], family=spec.family)
            if picked is None:
                logger.debug("Lenovo %s item %r had no usable file", spec.model, item.get("Title"))
                continue
            version = picked.get("Version") or item.get("SummaryInfo", {}).get("Version")
            url = picked.get("URL")
            if not version or not url:
                continue
            updates.append(
                BiosUpdate(
                    board=board,
                    bios_version=str(version),
                    download_url=url,
                    release_date=_unix_to_iso(item.get("Date")),
                    agesa_version=None,
                )
            )
        return updates

    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        spec = self._spec_for_board(update.board)
        if spec.family != _Family.THINKSTATION:
            raise NotImplementedError(
                "Lenovo ThinkSystem firmware ships as an encrypted UpdateXpress "
                ".upd container (deadc0de magic); raw ROM extraction is not "
                "supported. Listing still works."
            )

        client = self._require_client()
        dest_dir.mkdir(parents=True, exist_ok=True)
        logger.info(
            "Downloading Lenovo %s %s from %s",
            update.board.model,
            update.bios_version,
            update.download_url,
        )
        resp = await client.get(update.download_url)
        resp.raise_for_status()
        member, rom_bytes = extract_thinkstation_rom(resp.content)

        safe_model = re.sub(r"[^\w\-.]", "_", update.board.model)
        safe_version = re.sub(r"[^\w\-.]", "_", update.bios_version)
        out_path = dest_dir / f"{safe_model}_{safe_version}_{Path(member).name}"
        out_path.write_bytes(rom_bytes)
        return out_path


def _unix_to_iso(stamp: dict | None) -> str | None:
    """Convert a Lenovo ``{"Unix": <ms>}`` timestamp to an ISO date string."""
    if not isinstance(stamp, dict):
        return None
    raw = stamp.get("Unix")
    if not isinstance(raw, int):
        return None
    # Lenovo expresses timestamps in milliseconds since the epoch.
    from datetime import UTC, datetime

    return datetime.fromtimestamp(raw / 1000, tz=UTC).date().isoformat()
