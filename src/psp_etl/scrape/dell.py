"""Dell BIOS scraper for AMD PowerEdge servers and Precision workstations.

Dell publishes a public, Akamai-fronted enterprise catalog and a separate
client (Precision/Latitude/OptiPlex) catalog from which all per-system
firmware can be enumerated without authentication:

* PowerEdge:  ``https://downloads.dell.com/catalog/Catalog.xml.gz``
  — gzip-wrapped UTF-16 XML, no WAF, no auth.
* Precision:  ``https://downloads.dell.com/catalog/CatalogPC.cab``
  — Microsoft Cabinet archive containing the same UTF-16 XML schema.

Each catalog lists ``<SoftwareComponent>`` entries. We pick the ones whose
``<ComponentType value="BIOS">`` and whose ``<SupportedSystems>`` contains a
PowerEdge ``Brand prefix="PE"`` model in the AMD product set, or the
Precision ``Brand prefix="PRE"`` Threadripper Pro model (only the 7875
Tower is TR-Pro on the current line-up; 7960/7965 are Xeon despite being
high-end Precisions, and are excluded).

Dell ships every BIOS as a self-extracting Windows DUP (``BIOS_*.EXE``) or
Linux DUP (``BIOS_*.BIN``). The catalog only references the ``WN64`` .EXE
variants; the BIOS ROM payload is embedded inside Dell's PFS (Platform
Firmware Storage) container. ``unwrap_dell_dup`` locates the PFS body in
the DUP and returns the entry payload that contains AMD ROM signatures.

The CAB Precision catalog requires a host-side ``cabextract`` binary;
when the binary is unavailable the scraper logs a warning and proceeds
with PowerEdge-only coverage.
"""

from __future__ import annotations

import gzip
import logging
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass
from pathlib import Path

import httpx

from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper
from psp_etl.scrape.extract import PSP_SIGNATURES

logger = logging.getLogger(__name__)

CATALOG_URL = "https://downloads.dell.com/catalog/Catalog.xml.gz"
CATALOG_PC_URL = "https://downloads.dell.com/catalog/CatalogPC.cab"
DOWNLOAD_BASE = "https://downloads.dell.com/"

# AMD PowerEdge model prefixes -> socket. The model number's third digit
# encodes the platform generation: ``5`` = Rome/Milan (SP3), ``6`` =
# Genoa/Bergamo/Turin (SP5), ``7`` = Siena (SP6). The fourth digit (``15``
# vs ``25``) is socket count and doesn't affect classification.
_POWEREDGE_MODEL_SOCKET: tuple[tuple[re.Pattern[str], str], ...] = (
    # Siena (SP6): R4715, R5715, R6715, R7715
    (re.compile(r"^R[4-7]715$", re.IGNORECASE), "SP6"),
    # Genoa / Bergamo / Turin (SP5): R6615/R6625/R7615/R7625/R8615/R8625,
    # plus C6615/C6620/C6625 compute nodes and the XE96xx HPC chassis.
    (re.compile(r"^R[6-8]6[12]5$", re.IGNORECASE), "SP5"),
    (re.compile(r"^C66[12]5$", re.IGNORECASE), "SP5"),
    (re.compile(r"^XE9[6-8]\d{2}$", re.IGNORECASE), "SP5"),
    # Rome / Milan (SP3): R6515/R7515/R8515 and R6525/R7525/R8525,
    # plus the C6525 compute node.
    (re.compile(r"^R[6-8]5[12]5$", re.IGNORECASE), "SP3"),
    (re.compile(r"^C6525$", re.IGNORECASE), "SP3"),
)

# Precision Threadripper Pro models. The 7875 Tower is sWRX9 (TR-Pro 7000WX);
# the 7865 Tower is sWRX8 (TR-Pro 5000WX). 7960/7965 are Xeon-based and not
# scoped here even though they share the Precision badge.
_PRECISION_MODEL_SOCKET: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^Precision-7875", re.IGNORECASE), "sWRX9"),
    (re.compile(r"^Precision-7865", re.IGNORECASE), "sWRX8"),
)

# PFS markers (Dell Platform Firmware Storage) used to locate the BIOS body
# inside a Windows or Linux DUP.
PFS_HEADER_MAGIC = b"PFS.HDR."
PFS_FOOTER_MAGIC = b"PFS.FTR."

# PFS entry header is a fixed 64-byte structure. Field offsets used here:
#   0x28 DataSize          (uint32 LE)
#   0x2C DataSignatureSize (uint32 LE)
#   0x30 MetadataSize      (uint32 LE)
#   0x34 MetadataSigSize   (uint32 LE)
PFS_ENTRY_HEADER_SIZE = 64
_PFS_DATA_SIZE_OFFSET = 0x28

# Current Dell DUPs (PE32+ self-extractors) embed the PFS volume as a
# zlib-compressed section preceded by a fixed 10-byte signature. Layout
# around each match (offsets relative to pattern start):
#   -1     section type (0xAA = Firmware, 0xBB = Utilities)
#    0..9  signature bytes EE AA 76 1B EC BB 20 F1 E6 51
#   10     header checksum byte (ignored)
#   11..   zlib stream (\x78\x9C deflate)
# Reference: platomav/BIOSUtilities Dell PFS Update Extractor (MIT).
_DELL_ZLIB_SECTION_RE = re.compile(
    b"\xee\xaa\x76\x1b\xec\xbb\x20\xf1\xe6\x51.\x78\x9c",
    re.DOTALL,
)
_DELL_FW_SECTION_TYPE = 0xAA
_DELL_ZLIB_STREAM_OFFSET = 0x0B


def classify_poweredge_socket(model: str) -> str | None:
    """Return the AMD socket for a PowerEdge *model* or ``None`` for non-AMD."""
    for pattern, socket in _POWEREDGE_MODEL_SOCKET:
        if pattern.match(model):
            return socket
    return None


def classify_precision_socket(model: str) -> str | None:
    """Return the AMD socket for a Precision *model* or ``None`` for non-AMD."""
    for pattern, socket in _PRECISION_MODEL_SOCKET:
        if pattern.match(model):
            return socket
    return None


@dataclass(frozen=True)
class _BiosComponent:
    """Single ``<SoftwareComponent>`` BIOS entry parsed from a Dell catalog."""

    package_id: str
    version: str
    release_date: str | None
    path: str
    models: tuple[str, ...]


def parse_catalog(xml_text: str, brand_prefix: str) -> list[_BiosComponent]:
    """Parse Dell catalog XML and return BIOS entries for *brand_prefix*.

    *brand_prefix* selects the system family within ``<SupportedSystems>``:
    ``"PE"`` for PowerEdge, ``"PRE"`` for Precision.

    Only entries with ``<ComponentType value="BIOS">`` are returned, with
    one component per matching ``<SupportedSystems>/<Brand>`` block. A
    component that targets multiple models still produces a single entry
    whose ``models`` tuple lists all of them.
    """
    # The published XML uses no namespaces at the root; ElementTree's default
    # parser handles UTF-16 byte input, but here we always feed decoded text.
    root = ET.fromstring(xml_text)
    entries: list[_BiosComponent] = []
    for sc in root.iter("SoftwareComponent"):
        ctype = sc.find("ComponentType")
        if ctype is None or ctype.get("value") != "BIOS":
            continue
        package_id = sc.get("packageID") or ""
        version = sc.get("vendorVersion") or ""
        release_date = sc.get("releaseDate")
        path = sc.get("path") or ""
        if not (package_id and path):
            continue

        models: list[str] = []
        supported = sc.find("SupportedSystems")
        if supported is None:
            continue
        for brand in supported.findall("Brand"):
            if brand.get("prefix") != brand_prefix:
                continue
            for model in brand.findall("Model"):
                display = model.find("Display")
                if display is None:
                    continue
                text = (display.text or "").strip()
                if text:
                    models.append(text)

        if not models:
            continue

        entries.append(
            _BiosComponent(
                package_id=package_id,
                version=version,
                release_date=release_date,
                path=path,
                models=tuple(models),
            )
        )
    return entries


def _extract_pfs_body(data: bytes) -> bytes | None:
    """Return the bytes between PFS.HDR. and PFS.FTR. markers, or ``None``."""
    hdr_idx = data.find(PFS_HEADER_MAGIC)
    if hdr_idx < 0:
        return None
    ftr_idx = data.find(PFS_FOOTER_MAGIC, hdr_idx + len(PFS_HEADER_MAGIC))
    if ftr_idx < 0:
        return None
    # 16-byte PFS header: 8-byte magic + uint32 version + uint32 payload size.
    # The footer offset is the authoritative end of the body; the size field
    # is ignored.
    body_start = hdr_idx + len(PFS_HEADER_MAGIC) + 8
    return data[body_start:ftr_idx]


def _largest_amd_pfs_payload(body: bytes) -> bytes | None:
    """Walk PFS entries in *body* and return the largest AMD-signed payload."""
    best: bytes | None = None
    pos = 0
    while pos + PFS_ENTRY_HEADER_SIZE <= len(body):
        header = body[pos : pos + PFS_ENTRY_HEADER_SIZE]
        data_size = int.from_bytes(header[_PFS_DATA_SIZE_OFFSET : _PFS_DATA_SIZE_OFFSET + 4], "little")
        data_sig_size = int.from_bytes(header[_PFS_DATA_SIZE_OFFSET + 4 : _PFS_DATA_SIZE_OFFSET + 8], "little")
        meta_size = int.from_bytes(header[_PFS_DATA_SIZE_OFFSET + 8 : _PFS_DATA_SIZE_OFFSET + 12], "little")
        meta_sig_size = int.from_bytes(header[_PFS_DATA_SIZE_OFFSET + 12 : _PFS_DATA_SIZE_OFFSET + 16], "little")

        entry_total = PFS_ENTRY_HEADER_SIZE + data_size + data_sig_size + meta_size + meta_sig_size
        if data_size == 0 or entry_total <= PFS_ENTRY_HEADER_SIZE or pos + entry_total > len(body):
            break

        payload_start = pos + PFS_ENTRY_HEADER_SIZE
        payload = body[payload_start : payload_start + data_size]

        if any(sig in payload for sig in PSP_SIGNATURES) and (best is None or len(payload) > len(best)):
            best = payload

        pos += entry_total
    return best


def _decompress_dell_firmware_sections(data: bytes) -> list[bytes]:
    """Return decompressed payloads for each Firmware-typed Dell zlib section."""
    sections: list[bytes] = []
    for match in _DELL_ZLIB_SECTION_RE.finditer(data):
        match_pos = match.start()
        if match_pos == 0:
            continue
        if data[match_pos - 1] != _DELL_FW_SECTION_TYPE:
            continue
        stream_start = match_pos + _DELL_ZLIB_STREAM_OFFSET
        try:
            decompressor = zlib.decompressobj()
            sections.append(decompressor.decompress(data[stream_start:]))
        except zlib.error as exc:
            logger.debug("Dell DUP: zlib decompression failed at offset %d: %s", stream_start, exc)
    return sections


def unwrap_dell_dup(data: bytes) -> bytes:
    """Extract the AMD BIOS ROM payload from a Dell DUP package.

    Two DUP variants are supported. Older DUPs embed the PFS (Platform
    Firmware Storage) volume as raw bytes, locatable directly via the
    ``PFS.HDR.``/``PFS.FTR.`` markers. Current PE32+ self-extractor DUPs
    instead split the PFS volume into one or more zlib-compressed sections
    (Firmware = 0xAA, Utilities = 0xBB) prefixed by a fixed signature; the
    Firmware sections decompress to a normal PFS volume.

    For each PFS volume found (raw or after zlib decompression), this
    function walks PFS entries and keeps the largest payload that contains
    a recognised AMD PSP/BIOS directory signature (``$PSP``, ``$PL2``,
    ``$BHD``, ``$BL2``).

    Raises:
        ValueError: if no PFS volume is found, or no PFS entry across all
            volumes holds an AMD-shaped payload (e.g. for an Intel
            Precision package mistakenly handed to this function).
    """
    candidates: list[bytes] = []

    raw_body = _extract_pfs_body(data)
    if raw_body is not None:
        payload = _largest_amd_pfs_payload(raw_body)
        if payload is not None:
            candidates.append(payload)

    zlib_sections = _decompress_dell_firmware_sections(data)
    for decompressed in zlib_sections:
        section_body = _extract_pfs_body(decompressed)
        if section_body is None:
            continue
        payload = _largest_amd_pfs_payload(section_body)
        if payload is not None:
            candidates.append(payload)

    if candidates:
        return max(candidates, key=len)

    if PFS_HEADER_MAGIC not in data and not zlib_sections:
        raise ValueError("Dell DUP: PFS.HDR. magic not found in any section")
    raise ValueError("Dell DUP: no PFS entry contains AMD BIOS signatures")


def _decode_catalog_bytes(raw: bytes) -> str:
    """Decode a Dell catalog payload to text, stripping the UTF-16 BOM."""
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16-le")[1:]  # drop the BOM character
    if raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16-be")[1:]
    return raw.decode("utf-8")


def _extract_cab(cab_bytes: bytes) -> bytes:
    """Extract the single XML member from a Dell CAB catalog.

    Requires a system ``cabextract`` binary. Returns ``b""`` (with a
    warning logged) when the binary is not on ``PATH`` so that callers
    can degrade gracefully to PowerEdge-only coverage.
    """
    cab_tool = shutil.which("cabextract")
    if cab_tool is None:
        logger.warning("cabextract binary not found; skipping Dell PC catalog (Precision boards)")
        return b""

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        cab_file = tmp_path / "CatalogPC.cab"
        cab_file.write_bytes(cab_bytes)
        result = subprocess.run(
            [cab_tool, "-d", str(tmp_path), "-q", str(cab_file)],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            logger.warning(
                "cabextract failed (rc=%d): %s",
                result.returncode,
                result.stderr.decode("utf-8", errors="replace").strip(),
            )
            return b""
        for path in tmp_path.iterdir():
            if path.suffix.lower() == ".xml":
                return path.read_bytes()
    return b""


class DellScraper(VendorScraper):
    """Dell PowerEdge (EPYC) and Precision (TR-Pro) BIOS scraper."""

    vendor: str = "Dell"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._own_client = client is None

    async def __aenter__(self) -> DellScraper:
        if self._own_client:
            self._client = httpx.AsyncClient(
                timeout=120.0,
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
            raise RuntimeError("Use 'async with DellScraper() as s:' to manage the client lifecycle")
        return self._client

    async def _fetch_poweredge_catalog(self) -> list[_BiosComponent]:
        client = self._require_client()
        resp = await client.get(CATALOG_URL)
        resp.raise_for_status()
        xml_text = _decode_catalog_bytes(gzip.decompress(resp.content))
        return parse_catalog(xml_text, brand_prefix="PE")

    async def _fetch_precision_catalog(self) -> list[_BiosComponent]:
        client = self._require_client()
        resp = await client.get(CATALOG_PC_URL)
        resp.raise_for_status()
        xml_bytes = _extract_cab(resp.content)
        if not xml_bytes:
            return []
        xml_text = _decode_catalog_bytes(xml_bytes)
        return parse_catalog(xml_text, brand_prefix="PRE")

    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate AMD PowerEdge servers and TR-Pro Precision workstations."""
        boards: dict[tuple[str, str], BoardInfo] = {}

        for component in await self._fetch_poweredge_catalog():
            for model in component.models:
                socket = classify_poweredge_socket(model)
                if socket is None:
                    continue
                key = (socket, model)
                if key in boards:
                    continue
                boards[key] = BoardInfo(
                    vendor=self.vendor,
                    model=model,
                    socket=socket,
                    url=f"https://www.dell.com/support/home/en-us/product-support/product/poweredge-{model.lower()}/drivers",
                )

        for component in await self._fetch_precision_catalog():
            for model in component.models:
                socket = classify_precision_socket(model)
                if socket is None:
                    continue
                slug = re.sub(r"[^A-Za-z0-9]+", "-", model).strip("-").lower()
                key = (socket, model)
                if key in boards:
                    continue
                boards[key] = BoardInfo(
                    vendor=self.vendor,
                    model=model,
                    socket=socket,
                    url=f"https://www.dell.com/support/home/en-us/product-support/product/{slug}/drivers",
                )

        return list(boards.values())

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """List every BIOS package the catalog has for *board*."""
        if classify_poweredge_socket(board.model) is not None:
            components = await self._fetch_poweredge_catalog()
        elif classify_precision_socket(board.model) is not None:
            components = await self._fetch_precision_catalog()
        else:
            return []

        updates: list[BiosUpdate] = []
        for component in components:
            if board.model not in component.models:
                continue
            updates.append(
                BiosUpdate(
                    board=board,
                    bios_version=component.version,
                    download_url=DOWNLOAD_BASE + component.path.lstrip("/"),
                    release_date=component.release_date,
                    agesa_version=None,
                )
            )
        return updates

    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download a Dell DUP package and unwrap the PSP-bearing BIOS ROM."""
        client = self._require_client()
        dest_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Downloading Dell %s %s from %s",
            update.board.model,
            update.bios_version,
            update.download_url,
        )
        resp = await client.get(update.download_url)
        resp.raise_for_status()

        rom_bytes = unwrap_dell_dup(resp.content)

        safe_model = re.sub(r"[^\w\-.]", "_", update.board.model)
        safe_version = re.sub(r"[^\w\-.]", "_", update.bios_version)
        out_path = dest_dir / f"{safe_model}_{safe_version}.rom"
        out_path.write_bytes(rom_bytes)
        return out_path
