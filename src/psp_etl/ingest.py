"""ROM ingestion: PSPTool-based extraction of PSP firmware entries."""

from __future__ import annotations

import hashlib
import logging
import re
import traceback
from pathlib import Path

from psptool import PSPTool

from .db import Database, Entry, ParseError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Zen generation helpers
# ---------------------------------------------------------------------------

# Maps PSPTool's 'Zen N' style strings to the canonical DB token 'zenN'.
# Also matches 'Zen 4/5' → ['zen4', 'zen5'] via the slash-separated variant.
_ZEN_NORM_RE = re.compile(r"zen\s*(\d)", re.IGNORECASE)
_ZEN_SLASH_RE = re.compile(r"zen\s*(\d(?:/\d)+)", re.IGNORECASE)


def _parse_zen_nums(gen: str) -> list[str]:
    """Extract all zen generation tokens, handling 'Zen 4/5' notation."""
    results: list[str] = []
    seen: set[str] = set()
    # First try slash-separated matches like 'Zen 4/5'
    for m in _ZEN_SLASH_RE.finditer(gen):
        for num in m.group(1).split("/"):
            tok = f"zen{num}"
            if tok not in seen:
                results.append(tok)
                seen.add(tok)
    # Then pick up any remaining 'Zen N' that weren't part of a slash group
    for m in _ZEN_NORM_RE.finditer(gen):
        tok = f"zen{m.group(1)}"
        if tok not in seen:
            results.append(tok)
            seen.add(tok)
    return results


def _normalize_zen_generation(gen: str | None) -> str | None:
    """Normalise PSPTool's 'Zen 1'/'Zen 4/5 (PSP ID …)' to 'zen1'/'zen4'.

    Returns only the *first* match.  Use :func:`_normalize_zen_generations`
    when a directory may span multiple generations.
    """
    if gen is None:
        return None
    tokens = _parse_zen_nums(gen)
    return tokens[0] if tokens else None


def _normalize_zen_generations(gen: str | None) -> list[str]:
    """Return all Zen generation tokens from a PSPTool zen_generation string.

    PSPTool sometimes returns newline-joined strings for directories shared
    across generations, e.g.::

        'Zen 1 (PSP ID 0xbc0a0000)\\nZen 2 (PSP ID 0xbc0a0100)'
        'Zen 4/5 (PSP ID 0xbc0d0300)'

    This function extracts every match and returns them as a list of canonical
    tokens (``['zen1', 'zen2']``).  Returns an empty list when *gen* is
    ``None`` or contains no recognisable generation marker.
    """
    if gen is None:
        return []
    return _parse_zen_nums(gen)


# Heuristic AGESA-version → Zen generation mapping.
# PSPTool detects generation from embedded PSP IDs (more reliable), so this
# is only used as a last-resort fallback when directory.zen_generation is None.
#
# Two flavours of AGESA strings exist in the corpus:
#  * Consumer / engineering tags (CBP-/CBS-) embedded in the ROM by AMD,
#    which PSPTool may surface as rom.agesa_version.
#  * Server-flavoured codenames (Naples/Rome/Milan/Genoa/...) that vendor
#    scrapers extract from BIOS release-notes pages and write to
#    images.agesa_version (e.g. "Genoa 1.0.0.G", "RomePI 1.0.0.E",
#    "MilanCrb 0AC0U025"). PSPTool never sees these.
_AGESA_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Family 17h: Naples (Zen 1), Summit Ridge (Zen 1), Raven Ridge (Zen+)
    (re.compile(r"CBP[- _]?(CZP|ZP|SHP|SSP|RVB|PHL)\b", re.IGNORECASE), "zen1"),
    (re.compile(r"\bNaples(?:PI|Crb)?\b", re.IGNORECASE), "zen1"),
    # Family 17h Mod 30h–3Fh/71h: Rome, Castle Peak, Renoir (Zen 2)
    (re.compile(r"CBP[- _]?(RN|MTS|CZN|SSP2|RVB2)\b", re.IGNORECASE), "zen2"),
    (re.compile(r"\bRome(?:PI|Crb)?\b", re.IGNORECASE), "zen2"),
    # Family 19h Mod 00h–0Fh: Milan (Zen 3)
    (re.compile(r"CBS[- _]?(GN|MIL|ARL|CHL|VAN)\b", re.IGNORECASE), "zen3"),
    (re.compile(r"\bMilan(?:PI|Crb|X)?\b", re.IGNORECASE), "zen3"),
    # Family 19h Mod 40h+ / Family 1Ah: Genoa, Bergamo, Siena, Raphael (Zen 4)
    (re.compile(r"CBS[- _]?(GNB|PHX|RPL|HWK)\b", re.IGNORECASE), "zen4"),
    (re.compile(r"\b(?:Genoa|Bergamo|Siena)(?:PI|Crb|X)?\b", re.IGNORECASE), "zen4"),
    # Family 1Ah Mod 20h+: Strix Point / Turin (Zen 5)
    (re.compile(r"CBS[- _]?(STX|TUR|KRK)\b", re.IGNORECASE), "zen5"),
    (re.compile(r"\bTurin(?:PI|Crb|X)?\b", re.IGNORECASE), "zen5"),
]


def classify_by_agesa(agesa_version: str | None) -> str | None:
    """Guess Zen generation from an AGESA version string.

    Returns a canonical string like 'zen1' … 'zen5', or *None* if unknown.
    """
    if not agesa_version:
        return None
    for pattern, gen in _AGESA_PATTERNS:
        if pattern.search(agesa_version):
            return gen
    return None


# Off-chip bootloader (type 0x1) version prefix -> generation. Only prefixes
# that map to exactly one generation among PSPTool-labelled corpus entries;
# '0.8' (zen1 and zen2) and the unlabelled '0.14'/'0.2A'/'0.3D' are left out.
_BL_VERSION_GEN = {
    "0.5": "zen1",
    "0.C": "zen2",
    "0.D": "zen2",
    "0.11": "zen3",
    "0.13": "zen3",
    "0.29": "zen4",
}


def classify_by_bl_version(version: str | None) -> str | None:
    """Guess Zen generation from an off-chip bootloader version like ``0.13.0.7A``."""
    if not version:
        return None
    return _BL_VERSION_GEN.get(".".join(version.split(".")[:2]).upper())


# ---------------------------------------------------------------------------
# Board-class classification
# ---------------------------------------------------------------------------

# Maps a CPU socket string to its canonical board_class label.
#
# Note: 'Embedded' is a valid value for images.board_class but no socket maps
# to it yet — it will be populated when an embedded scraper lands.
_SOCKET_TO_BOARD_CLASS: dict[str, str] = {
    "AM4": "Ryzen",
    "AM5": "Ryzen",
    "SP3": "EPYC",
    "SP5": "EPYC",
    "SP6": "EPYC",
    "sTRX4": "Threadripper",
    "sTR5": "Threadripper",
    "sWRX8": "ThreadripperPro",
}

BOARD_CLASSES: tuple[str, ...] = (
    "Ryzen",
    "EPYC",
    "Threadripper",
    "ThreadripperPro",
    "Embedded",
)


def classify_board_class(socket: str | None) -> str | None:
    """Map a CPU socket to a canonical board_class label.

    Returns one of ``BOARD_CLASSES`` or ``None`` when *socket* is unknown
    or ``None``.  Mirrors today's NULL-socket semantics: when the scraper
    failed to detect a socket, board_class is also NULL.
    """
    if socket is None:
        return None
    return _SOCKET_TO_BOARD_CLASS.get(socket)


# ---------------------------------------------------------------------------
# Core ingestion
# ---------------------------------------------------------------------------


def ingest_rom(
    rom_path: Path,
    image_id: int,
    db: Database,
    data_dir: Path = Path("data"),
) -> None:
    """Parse *rom_path* with PSPTool, write blobs to disk, and store entries.

    All PSPTool exceptions are caught and recorded in the ``parse_errors``
    table so that a single broken ROM does not abort the whole batch.

    Args:
        rom_path:  Path to the raw BIOS ROM image.
        image_id:  The ``images.id`` foreign-key for this ROM (must already
                   exist in the database).
        db:        Open :class:`~psp_etl.db.Database` instance.
        data_dir:  Root of the data directory tree.  Blobs are written to
                   ``data_dir/blobs/{sha256}.bin``.
    """
    blobs_dir = data_dir / "blobs"
    blobs_dir.mkdir(parents=True, exist_ok=True)

    # --- Parse the ROM with PSPTool ----------------------------------------
    try:
        psp = PSPTool.from_file(str(rom_path))
    except Exception as exc:  # noqa: BLE001 — PSPTool's exception surface is undocumented; record and continue
        db.insert_parse_error(
            ParseError(
                image_id=image_id,
                error_message=str(exc),
                traceback=traceback.format_exc(),
            )
        )
        return

    # Image-level AGESA from scrapers (BIOS release-notes / page metadata).
    # Used as a tertiary fallback when PSPTool doesn't annotate generation
    # and rom.agesa_version is also missing — common for server BIOSes where
    # PSPTool's combo_dir / tertiary-tag detection paths don't fire.
    image_row = db.get_image_by_id(image_id)
    image_agesa = image_row["agesa_version"] if image_row is not None else None

    # --- Walk ROM → directory → file tree ------------------------------------
    for rom_idx, rom in enumerate(psp.blob.roms):
        for dir_idx, directory in enumerate(rom.directories):
            bl_gen = next(
                (
                    classify_by_bl_version(f.get_readable_version())
                    for f in directory.files
                    if getattr(f, "type", None) == 1
                ),
                None,
            )
            for f in directory.files:
                _ingest_file(
                    f=f,
                    rom_idx=rom_idx,
                    dir_idx=dir_idx,
                    directory=directory,
                    rom=rom,
                    image_id=image_id,
                    image_agesa=image_agesa,
                    dir_bl_gen=bl_gen,
                    db=db,
                    blobs_dir=blobs_dir,
                )

    # --- Backfill zen_generation for BIOS-side directories ($BHD/$BL2) ------
    # PSPTool does not annotate BIOS directories with PSP IDs, so those entries
    # land with zen_generation=NULL.  Infer the generation from the dominant
    # non-NULL generation among other entries in the same ROM segment.
    db.backfill_zen_generation(image_id)


# ---------------------------------------------------------------------------
# Per-file helper
# ---------------------------------------------------------------------------


def _ingest_file(*, f, rom_idx, dir_idx, directory, rom, image_id, image_agesa, dir_bl_gen, db, blobs_dir):
    """Extract one PSP firmware file and persist it."""
    # PSPTool raises a wide and undocumented set of exceptions when a file is
    # malformed (struct unpack errors, key derivation errors, decompression
    # errors, …). We try the rich path first, then fall back to raw bytes,
    # and finally skip — but every fall-through is logged so a corrupted
    # entry never disappears silently.
    type_id = getattr(f, "type", "?")
    body: bytes | None = None
    if hasattr(f, "get_decrypted_decompressed_body"):
        try:
            body = f.get_decrypted_decompressed_body()
        except Exception as exc:  # noqa: BLE001 — PSPTool's exception surface is undocumented
            logger.warning(
                "image_id=%s rom=%d dir=%d type=%s: get_decrypted_decompressed_body failed (%s); "
                "falling back to raw bytes",
                image_id,
                rom_idx,
                dir_idx,
                type_id,
                exc,
            )
    if body is None:
        try:
            body = bytes(f.get_bytes())
        except Exception as exc:  # noqa: BLE001 — PSPTool's exception surface is undocumented
            logger.error(
                "image_id=%s rom=%d dir=%d type=%s: get_bytes also failed (%s); skipping entry",
                image_id,
                rom_idx,
                dir_idx,
                type_id,
                exc,
            )
            return

    if not body:
        logger.debug(
            "image_id=%s rom=%d dir=%d type=%s: empty body, skipping",
            image_id,
            rom_idx,
            dir_idx,
            type_id,
        )
        return

    # --- Content-address the blob --------------------------------------------
    blob_hash = hashlib.sha256(body).hexdigest()
    blob_path = blobs_dir / f"{blob_hash}.bin"
    if not blob_path.exists():
        blob_path.write_bytes(body)

    # --- Zen generation(s) ---------------------------------------------------
    # A PSP directory may serve multiple generations; PSPTool indicates this
    # with a newline-joined string like 'Zen 1 (...)\nZen 2 (...)'.
    # We fan out one entry row per generation so that queries filtering by
    # --gen find all relevant entries.
    raw_gen = getattr(directory, "zen_generation", None)
    zen_gens: list[str | None] = _normalize_zen_generations(raw_gen)
    if not zen_gens:
        # No PSP-ID annotation; fall back to ROM-embedded AGESA, then to the
        # scraper-supplied image.agesa_version. The latter unlocks server
        # BIOSes (EPYC etc.) where PSPTool returns no generation and the ROM
        # carries no consumer AGESA tag. Last resort: the directory's own
        # off-chip bootloader version.
        inferred = (
            classify_by_agesa(getattr(rom, "agesa_version", None)) or classify_by_agesa(image_agesa) or dir_bl_gen
        )
        zen_gens = [inferred]

    # --- Directory magic (bytes → str) ---------------------------------------
    raw_magic = getattr(directory, "magic", None)
    if isinstance(raw_magic, (bytes, bytearray)):
        dir_magic = raw_magic.decode(errors="replace")
    else:
        dir_magic = str(raw_magic) if raw_magic is not None else None

    # --- Shared entry attributes (safe getattr with defaults) ----------------
    common = dict(
        image_id=image_id,
        rom_index=rom_idx,
        directory_index=dir_idx,
        directory_magic=dir_magic,
        type_id=int(f.type),
        type_name=getattr(f, "get_readable_type", lambda: None)(),
        subprogram=getattr(getattr(f, "entry", None), "subprogram", 0) or 0,
        instance=getattr(getattr(f, "entry", None), "instance", 0) or 0,
        version=getattr(f, "get_readable_version", lambda: None)(),
        firmware_md5=getattr(f, "md5", lambda: None)(),
        blob_sha256=blob_hash,
        body_size=len(body),
        encrypted=bool(getattr(f, "encrypted", False)),
        compressed=bool(getattr(f, "compressed", False)),
        signed=bool(getattr(f, "is_signed", False)),
        load_address=getattr(f, "load_addr", None),
    )

    # Insert one row per generation (fan-out for multi-gen directories).
    for zen_gen in zen_gens:
        db.insert_entry(Entry(**common, zen_generation=zen_gen))
