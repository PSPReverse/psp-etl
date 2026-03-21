"""Tests for ingest.py: ROM ingestion helpers and ingest_rom()."""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from psp_etl.db import Database, Image
from psp_etl.ingest import (
    _normalize_zen_generation,
    _normalize_zen_generations,
    classify_by_agesa,
    ingest_rom,
)


# ---------------------------------------------------------------------------
# _normalize_zen_generation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Zen 1", "zen1"),
        ("Zen 2", "zen2"),
        ("Zen 3", "zen3"),
        ("Zen 4", "zen4"),
        ("Zen 4/5", "zen4"),
        ("Zen 4/5 (PSP ID 0x0d030000)", "zen4"),
        ("zen 2", "zen2"),
        ("ZEN 3", "zen3"),
        (None, None),
        ("unknown", None),
        ("AGESA_UNKNOWN", None),
    ],
)
def test_normalize_zen_generation(raw, expected):
    assert _normalize_zen_generation(raw) == expected


# ---------------------------------------------------------------------------
# classify_by_agesa
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "agesa, expected",
    [
        (None, None),
        ("", None),
        ("AGESA!.. CBP-CZP-V0001", "zen1"),
        ("AGESA!.. CBP-RN-V1.0.0.8", "zen2"),
        ("AGESA!.. CBS-GN-V1.0.0.4", "zen3"),
        ("AGESA!.. CBS-GNB-V1.0.0.1", "zen4"),
        ("AGESA!.. CBS-STX-V1.0.0.0", "zen5"),
        ("AGESA_UNKNOWN", None),
    ],
)
def test_classify_by_agesa(agesa, expected):
    assert classify_by_agesa(agesa) == expected


# ---------------------------------------------------------------------------
# Fake PSPTool ROM factory
# ---------------------------------------------------------------------------


def _make_fake_file(
    type_id: int = 0x01,
    body: bytes = b"FAKE_BODY",
    subprogram: int = 0,
    instance: int = 0,
    encrypted: bool = False,
    compressed: bool = False,
    is_signed: bool = False,
    load_addr: int | None = None,
    readable_type: str = "PSP_FW_BOOT_LOADER~0x1",
    readable_version: str = "1.0.0",
    md5_hex: str | None = None,
    has_decrypted_method: bool = True,  # noqa: ARG001
):
    """Return a mock PSPTool File-like object."""
    f = MagicMock()
    f.type = type_id
    f.encrypted = encrypted
    f.compressed = compressed
    f.is_signed = is_signed
    f.load_addr = load_addr
    f.get_readable_type.return_value = readable_type
    f.get_readable_version.return_value = readable_version
    f.md5.return_value = md5_hex or hashlib.md5(body).hexdigest()
    f.get_bytes.return_value = body

    fake_entry = MagicMock()
    fake_entry.subprogram = subprogram
    fake_entry.instance = instance
    f.entry = fake_entry

    if has_decrypted_method:
        f.get_decrypted_decompressed_body.return_value = body
    else:
        del f.get_decrypted_decompressed_body  # make hasattr() return False

    return f


def _make_fake_directory(
    files: list,
    zen_generation: str | None = "Zen 2",
    magic: bytes = b"$PSP",
):
    d = MagicMock()
    d.files = files
    d.zen_generation = zen_generation
    d.magic = magic
    return d


def _make_fake_rom(directories: list, agesa_version: str = "AGESA!.. CBP-RN-V1"):
    r = MagicMock()
    r.directories = directories
    r.agesa_version = agesa_version
    return r


def _make_fake_psp(roms: list):
    psp = MagicMock()
    psp.blob.roms = roms
    return psp


# ---------------------------------------------------------------------------
# ingest_rom
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "test.db") as database:
        yield database


@pytest.fixture
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    return d


def _insert_image(db: Database) -> int:
    return db.insert_image(Image(sha256="deadbeef" * 8, vendor="ASUS"))


def test_ingest_rom_creates_entry_and_blob(db, data_dir, tmp_path):
    """Happy-path: one ROM, one directory, one file → one entry + blob."""
    body = b"PSP_FIRMWARE_DATA_HERE"
    f = _make_fake_file(body=body)
    directory = _make_fake_directory([f], zen_generation="Zen 2")
    rom = _make_fake_rom([directory])
    fake_psp = _make_fake_psp([rom])
    image_id = _insert_image(db)

    rom_path = tmp_path / "test.rom"
    rom_path.write_bytes(b"\xff" * 0x100)  # dummy content

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=fake_psp):
        ingest_rom(rom_path, image_id, db, data_dir)

    # Entry was inserted
    rows = db._conn.execute("SELECT * FROM entries").fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row["image_id"] == image_id
    assert row["zen_generation"] == "zen2"
    assert row["type_id"] == 0x01
    assert row["body_size"] == len(body)

    # Blob was written
    blob_hash = hashlib.sha256(body).hexdigest()
    blob_path = data_dir / "blobs" / f"{blob_hash}.bin"
    assert blob_path.exists()
    assert blob_path.read_bytes() == body


def test_ingest_rom_deduplicates_blob(db, data_dir, tmp_path):
    """Same blob content written twice should result in one blob file."""
    body = b"SAME_CONTENT"
    f1 = _make_fake_file(type_id=0x01, body=body, subprogram=0, instance=0)
    f2 = _make_fake_file(type_id=0x02, body=body, subprogram=0, instance=0)
    directory = _make_fake_directory([f1, f2])
    rom = _make_fake_rom([directory])
    fake_psp = _make_fake_psp([rom])
    image_id = _insert_image(db)

    rom_path = tmp_path / "test.rom"
    rom_path.write_bytes(b"\xff" * 0x100)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=fake_psp):
        ingest_rom(rom_path, image_id, db, data_dir)

    blobs = list((data_dir / "blobs").iterdir())
    assert len(blobs) == 1  # Same content → same sha256 → one file


def test_ingest_rom_parse_error_recorded(db, data_dir, tmp_path):
    """PSPTool.from_file() exception → parse_errors table populated."""
    image_id = _insert_image(db)
    rom_path = tmp_path / "broken.rom"
    rom_path.write_bytes(b"\x00" * 0x100)

    with patch("psp_etl.ingest.PSPTool.from_file", side_effect=ValueError("bad ROM")):
        ingest_rom(rom_path, image_id, db, data_dir)

    errors = db.get_parse_errors(image_id)
    assert len(errors) == 1
    assert "bad ROM" in errors[0]["error_message"]
    # No entries should have been created
    assert db._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0] == 0


def test_ingest_rom_fallback_to_get_bytes(db, data_dir, tmp_path):
    """get_decrypted_decompressed_body() failure → fallback to get_bytes()."""
    body = b"RAW_BYTES"
    f = _make_fake_file(body=body)
    f.get_decrypted_decompressed_body.side_effect = RuntimeError("decrypt failed")
    directory = _make_fake_directory([f])
    rom = _make_fake_rom([directory])
    fake_psp = _make_fake_psp([rom])
    image_id = _insert_image(db)

    rom_path = tmp_path / "test.rom"
    rom_path.write_bytes(b"\xff" * 0x100)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=fake_psp):
        ingest_rom(rom_path, image_id, db, data_dir)

    rows = db._conn.execute("SELECT * FROM entries").fetchall()
    assert len(rows) == 1
    assert rows[0]["body_size"] == len(body)


def test_ingest_rom_zen_generation_from_agesa_fallback(db, data_dir, tmp_path):
    """When directory.zen_generation is None, fall back to AGESA string."""
    body = b"ZEN2_FIRMWARE"
    f = _make_fake_file(body=body)
    directory = _make_fake_directory([f], zen_generation=None)
    rom = _make_fake_rom([directory], agesa_version="AGESA!.. CBP-RN-V1.0.0.8")
    fake_psp = _make_fake_psp([rom])
    image_id = _insert_image(db)

    rom_path = tmp_path / "test.rom"
    rom_path.write_bytes(b"\xff" * 0x100)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=fake_psp):
        ingest_rom(rom_path, image_id, db, data_dir)

    rows = db._conn.execute("SELECT zen_generation FROM entries").fetchall()
    assert rows[0]["zen_generation"] == "zen2"


def test_ingest_rom_multiple_roms_and_dirs(db, data_dir, tmp_path):
    """Multiple ROMs and directories all get indexed with correct rom_index/dir_index."""
    f00 = _make_fake_file(type_id=0x01, body=b"ROM0_DIR0")
    f10 = _make_fake_file(type_id=0x01, body=b"ROM1_DIR0")
    dir0 = _make_fake_directory([f00])
    dir1 = _make_fake_directory([f10])
    rom0 = _make_fake_rom([dir0])
    rom1 = _make_fake_rom([dir1])
    fake_psp = _make_fake_psp([rom0, rom1])
    image_id = _insert_image(db)

    rom_path = tmp_path / "test.rom"
    rom_path.write_bytes(b"\xff" * 0x100)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=fake_psp):
        ingest_rom(rom_path, image_id, db, data_dir)

    rows = db._conn.execute("SELECT rom_index, directory_index FROM entries ORDER BY rom_index").fetchall()
    assert len(rows) == 2
    assert rows[0]["rom_index"] == 0
    assert rows[1]["rom_index"] == 1


def test_ingest_rom_blobs_dir_created(db, tmp_path):
    """data_dir/blobs is created if it doesn't exist."""
    data_dir = tmp_path / "nonexistent_data"
    body = b"CONTENT"
    f = _make_fake_file(body=body)
    directory = _make_fake_directory([f])
    rom = _make_fake_rom([directory])
    fake_psp = _make_fake_psp([rom])
    image_id = _insert_image(db)

    rom_path = tmp_path / "test.rom"
    rom_path.write_bytes(b"\xff" * 0x100)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=fake_psp):
        ingest_rom(rom_path, image_id, db, data_dir)

    assert (data_dir / "blobs").is_dir()
    assert len(list((data_dir / "blobs").iterdir())) == 1


def test_normalize_zen_generations_single():
    assert _normalize_zen_generations("Zen 2 (PSP ID 0xbc0b0500)") == ["zen2"]


def test_normalize_zen_generations_multi():
    raw = "Zen 1 (PSP ID 0xbc0a0000)\nZen 2 (PSP ID 0xbc0a0100)"
    assert _normalize_zen_generations(raw) == ["zen1", "zen2"]


def test_normalize_zen_generations_none():
    assert _normalize_zen_generations(None) == []


def test_normalize_zen_generations_unknown():
    assert _normalize_zen_generations("AGESA_UNKNOWN") == []


def test_ingest_rom_multi_gen_directory_creates_two_entries(db, data_dir, tmp_path):
    """A directory with 'Zen 1\\nZen 2' zen_generation inserts one row per gen."""
    body = b"COMBO_FW"
    f = _make_fake_file(body=body, type_id=0x01)
    directory = _make_fake_directory([f], zen_generation="Zen 1 (PSP ID 0xbc0a0000)\nZen 2 (PSP ID 0xbc0a0100)")
    rom = _make_fake_rom([directory])
    fake_psp = _make_fake_psp([rom])
    image_id = _insert_image(db)

    rom_path = tmp_path / "test.rom"
    rom_path.write_bytes(b"\xff" * 0x100)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=fake_psp):
        ingest_rom(rom_path, image_id, db, data_dir)

    rows = db._conn.execute("SELECT zen_generation FROM entries ORDER BY zen_generation").fetchall()
    assert len(rows) == 2
    assert rows[0]["zen_generation"] == "zen1"
    assert rows[1]["zen_generation"] == "zen2"


def test_ingest_rom_backfills_null_gen_from_context(db, data_dir, tmp_path):
    """BHD entries (NULL gen) are backfilled with the dominant PSP gen."""
    body_psp = b"PSP_FW"
    body_bhd = b"BIOS_FW"

    f_psp = _make_fake_file(body=body_psp, type_id=0x01)
    f_bhd = _make_fake_file(body=body_bhd, type_id=0x62)

    psp_dir = _make_fake_directory([f_psp], zen_generation="Zen 3", magic=b"$PSP")
    bhd_dir = _make_fake_directory([f_bhd], zen_generation=None, magic=b"$BHD")

    rom = _make_fake_rom([psp_dir, bhd_dir], agesa_version="AGESA_UNKNOWN")
    fake_psp = _make_fake_psp([rom])
    image_id = _insert_image(db)

    rom_path = tmp_path / "test.rom"
    rom_path.write_bytes(b"\xff" * 0x100)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=fake_psp):
        ingest_rom(rom_path, image_id, db, data_dir)

    rows = db._conn.execute("SELECT type_id, zen_generation FROM entries ORDER BY type_id").fetchall()
    assert len(rows) == 2
    assert all(r["zen_generation"] == "zen3" for r in rows), rows


def test_ingest_rom_entry_dedup(db, data_dir, tmp_path):
    """Re-ingesting the same ROM does not create duplicate entries."""
    body = b"FIRMWARE"
    f = _make_fake_file(body=body, type_id=0x01, subprogram=0, instance=0)
    directory = _make_fake_directory([f])
    rom = _make_fake_rom([directory])
    fake_psp = _make_fake_psp([rom])
    image_id = _insert_image(db)

    rom_path = tmp_path / "test.rom"
    rom_path.write_bytes(b"\xff" * 0x100)

    with patch("psp_etl.ingest.PSPTool.from_file", return_value=fake_psp):
        ingest_rom(rom_path, image_id, db, data_dir)
        ingest_rom(rom_path, image_id, db, data_dir)

    count = db._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    assert count == 1
