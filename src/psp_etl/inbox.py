"""Ingest ROMs exported by PSP-DB (`pspdb export-roms`) with their provenance."""

from __future__ import annotations

import csv
import hashlib
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path

from psp_etl.db import Database, Image
from psp_etl.ingest import classify_board_class, ingest_rom

logger = logging.getLogger(__name__)

PROVENANCE_FILE = "provenance.tsv"
_PROVENANCE_COLUMNS = {"sha256", "vendor", "device", "socket", "chipset", "vendor_version", "link", "date"}


# Canonical vendor spelling, so exports using lower-case slugs match the scrapers' names.
CANONICAL_VENDORS = {
    "asus": "ASUS",
    "asrock": "ASRock",
    "asrock-rack": "ASRock Rack",
    "asrock rack": "ASRock Rack",
    "msi": "MSI",
    "gigabyte": "Gigabyte",
    "supermicro": "Supermicro",
    "tyan": "Tyan",
    "dell": "Dell",
    "hpe": "HPE",
    "lenovo": "Lenovo",
}


def canonical_vendor(name: str) -> str:
    return CANONICAL_VENDORS.get(name.strip().lower(), name.strip())


@dataclass
class InboxSummary:
    new: int = 0
    backfilled: int = 0
    unchanged: int = 0
    mismatched: int = 0
    missing: int = 0


def _image_from_row(row: dict[str, str], size: int) -> Image:
    def clean(key: str) -> str | None:
        value = (row.get(key) or "").strip()
        return value or None

    socket = clean("socket")
    return Image(
        sha256=row["sha256"],
        vendor=canonical_vendor(clean("vendor") or "manual"),
        model=clean("device"),
        socket=socket,
        board_class=clean("board_class") or classify_board_class(socket),
        bios_version=clean("vendor_version"),
        download_url=clean("link"),
        download_date=clean("date"),
        chipset=clean("chipset"),
        file_size=size,
    )


def ingest_inbox(inbox_dir: Path, db: Database, data_dir: Path, *, provenance_only: bool = False) -> InboxSummary:
    """Ingest every ROM listed in ``inbox_dir/provenance.tsv``.

    With ``provenance_only`` no ROM files are read: rows whose sha256 is already
    in the corpus only backfill provenance, and unknown shas count as missing.

    ROMs are verified against their sha256, stored content-addressed, parsed if
    new, and have provenance backfilled onto existing rows without duplicating
    them.  A sha256 listed several times (one row per source download) uses its
    first row.
    """
    tsv_path = inbox_dir / PROVENANCE_FILE
    with tsv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        required = _PROVENANCE_COLUMNS if provenance_only else _PROVENANCE_COLUMNS | {"path"}
        missing_columns = required - set(reader.fieldnames or [])
        if missing_columns:
            raise ValueError(f"{tsv_path} lacks columns: {', '.join(sorted(missing_columns))}")
        rows = list(reader)

    roms_dir = data_dir / "roms"
    roms_dir.mkdir(parents=True, exist_ok=True)
    summary = InboxSummary()
    seen: set[str] = set()

    for row in rows:
        sha256 = row["sha256"]
        if sha256 in seen:
            continue
        seen.add(sha256)

        if provenance_only:
            existing = db.get_image_by_sha256(sha256)
            if existing is None:
                summary.missing += 1
            elif db.backfill_image_provenance(sha256, _image_from_row(row, existing["file_size"] or 0)):
                summary.backfilled += 1
            else:
                summary.unchanged += 1
            continue

        source = inbox_dir / row["path"]
        if not source.is_file():
            logger.warning("missing ROM %s", source)
            summary.missing += 1
            continue
        rom_bytes = source.read_bytes()
        if hashlib.sha256(rom_bytes).hexdigest() != sha256:
            logger.warning("sha256 mismatch for %s", source)
            summary.mismatched += 1
            continue

        dest = roms_dir / f"{sha256}.rom"
        if not dest.exists():
            shutil.copy2(source, dest)

        image = _image_from_row(row, len(rom_bytes))
        existing = db.get_image_by_sha256(sha256)
        if existing is None:
            image_id = db.insert_image(image)
            ingest_rom(dest, image_id, db, data_dir)
            summary.new += 1
            continue

        if db.backfill_image_provenance(sha256, image):
            summary.backfilled += 1
        else:
            summary.unchanged += 1
        if not db.has_entries(existing["id"]):
            ingest_rom(dest, existing["id"], db, data_dir)

    return summary
