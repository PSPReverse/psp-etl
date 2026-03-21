"""ROM ingestion: PSPTool-based extraction of PSP firmware entries."""

from __future__ import annotations

import hashlib
import re
import traceback
from pathlib import Path

from psptool import PSPTool

from .db import Database, Entry, ParseError


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
_AGESA_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Family 17h: Naples (Zen 1), Summit Ridge (Zen 1), Raven Ridge (Zen+)
    (re.compile(r"CBP[- _]?(CZP|ZP|SHP|SSP|RVB|PHL)\b", re.IGNORECASE), "zen1"),
    # Family 17h Mod 30h–3Fh/71h: Rome, Castle Peak, Renoir (Zen 2)
    (re.compile(r"CBP[- _]?(RN|MTS|CZN|SSP2|RVB2)\b", re.IGNORECASE), "zen2"),
    # Family 19h Mod 00h–0Fh: Milan (Zen 3)
    (re.compile(r"CBS[- _]?(GN|MIL|ARL|CHL|VAN)\b", re.IGNORECASE), "zen3"),
    # Family 19h Mod 40h+ / Family 1Ah: Genoa, Raphael (Zen 4)
    (re.compile(r"CBS[- _]?(GNB|PHX|RPL|HWK)\b", re.IGNORECASE), "zen4"),
    # Family 1Ah Mod 20h+: Strix Point / Turin (Zen 5)
    (re.compile(r"CBS[- _]?(STX|TUR|KRK)\b", re.IGNORECASE), "zen5"),
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
    except Exception as exc:
        db.insert_parse_error(
            ParseError(
                image_id=image_id,
                error_message=str(exc),
                traceback=traceback.format_exc(),
            )
        )
        return

    # --- Walk ROM → directory → file tree ------------------------------------
    for rom_idx, rom in enumerate(psp.blob.roms):
        for dir_idx, directory in enumerate(rom.directories):
            for f in directory.files:
                _ingest_file(
                    f=f,
                    rom_idx=rom_idx,
                    dir_idx=dir_idx,
                    directory=directory,
                    rom=rom,
                    image_id=image_id,
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


def _ingest_file(*, f, rom_idx, dir_idx, directory, rom, image_id, db, blobs_dir):
    """Extract one PSP firmware file and persist it."""
    # --- Extract body bytes --------------------------------------------------
    try:
        if hasattr(f, "get_decrypted_decompressed_body"):
            body = f.get_decrypted_decompressed_body()
        else:
            body = bytes(f.get_bytes())
    except Exception:
        try:
            body = bytes(f.get_bytes())
        except Exception:
            return  # Can't get any bytes; skip silently

    if not body:
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
        # No PSP-ID annotation; fall back to AGESA version heuristic.
        zen_gens = [classify_by_agesa(getattr(rom, "agesa_version", None))]

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
