"""Tests for inbox.py: ingesting PSP-DB `export-roms` output."""

import hashlib

import pytest
from click.testing import CliRunner

from psp_etl import inbox
from psp_etl.cli import cli
from psp_etl.db import Database, Image

HEADER = "sha256\tvendor\tdevice\tsocket\tboard_class\tchipset\tvendor_version\tlink\tdate\tmd5\tsize\tpath\n"


def _write_rom(directory, payload: bytes) -> str:
    sha = hashlib.sha256(payload).hexdigest()
    (directory / f"{sha}.rom").write_bytes(payload)
    return sha


def _row(sha, vendor="MSI", device="X670E", version="1.0", link="https://example.invalid/1.zip", path=None):
    return (
        f"{sha}\t{vendor}\t{device}\tAM5\tRyzen\tX670E\t{version}\t{link}\t2024-02-03\tmd5\t4\t{path or sha + '.rom'}\n"
    )


@pytest.fixture
def parsed(monkeypatch):
    """Replace ROM parsing with a recorder so tests need no real firmware."""
    calls = []
    monkeypatch.setattr(inbox, "ingest_rom", lambda rom, image_id, db, data_dir: calls.append((rom.name, image_id)))
    return calls


@pytest.fixture
def db(tmp_path):
    (tmp_path / "data").mkdir()
    with Database(tmp_path / "data" / "psp-etl.db") as database:
        yield database


def test_new_rom_is_stored_inserted_and_parsed(tmp_path, db, parsed):
    box = tmp_path / "box"
    box.mkdir()
    sha = _write_rom(box, b"rom-a")
    (box / "provenance.tsv").write_text(HEADER + _row(sha))

    summary = inbox.ingest_inbox(box, db, tmp_path / "data")

    assert (summary.new, summary.backfilled, summary.mismatched, summary.missing) == (1, 0, 0, 0)
    row = db.get_image_by_sha256(sha)
    assert (row["vendor"], row["model"], row["socket"], row["chipset"]) == ("MSI", "X670E", "AM5", "X670E")
    assert row["bios_version"] == "1.0"
    assert row["download_url"] == "https://example.invalid/1.zip"
    assert (tmp_path / "data" / "roms" / f"{sha}.rom").is_file()
    assert parsed == [(f"{sha}.rom", row["id"])]


def test_existing_manual_image_is_backfilled_not_duplicated(tmp_path, db, parsed):
    box = tmp_path / "box"
    box.mkdir()
    sha = _write_rom(box, b"rom-b")
    db.insert_image(Image(sha256=sha, vendor="manual"))
    (box / "provenance.tsv").write_text(HEADER + _row(sha, vendor="ASUS"))

    summary = inbox.ingest_inbox(box, db, tmp_path / "data")

    assert (summary.new, summary.backfilled) == (0, 1)
    assert db.get_image_by_sha256(sha)["vendor"] == "ASUS"
    assert db._conn.execute("SELECT COUNT(*) FROM images").fetchone()[0] == 1


def test_duplicate_rows_for_one_sha_use_the_first(tmp_path, db, parsed):
    box = tmp_path / "box"
    box.mkdir()
    sha = _write_rom(box, b"rom-c")
    (box / "provenance.tsv").write_text(HEADER + _row(sha, version="1.0") + _row(sha, version="2.0"))

    summary = inbox.ingest_inbox(box, db, tmp_path / "data")

    assert summary.new == 1
    assert db.get_image_by_sha256(sha)["bios_version"] == "1.0"


def test_hash_mismatch_and_missing_files_are_skipped(tmp_path, db, parsed):
    box = tmp_path / "box"
    box.mkdir()
    bad = "0" * 64
    (box / f"{bad}.rom").write_bytes(b"not that hash")
    ghost = "1" * 64
    (box / "provenance.tsv").write_text(HEADER + _row(bad) + _row(ghost))

    summary = inbox.ingest_inbox(box, db, tmp_path / "data")

    assert (summary.new, summary.mismatched, summary.missing) == (0, 1, 1)
    assert db.get_image_by_sha256(bad) is None
    assert parsed == []


def test_missing_columns_raise(tmp_path, db, parsed):
    box = tmp_path / "box"
    box.mkdir()
    (box / "provenance.tsv").write_text("sha256\tvendor\n")

    with pytest.raises(ValueError, match="lacks columns"):
        inbox.ingest_inbox(box, db, tmp_path / "data")


def test_cli_reports_summary_and_requires_tsv(tmp_path, parsed):
    runner = CliRunner(env={"COLUMNS": "200"})
    data = tmp_path / "data"
    box = tmp_path / "box"
    box.mkdir()

    missing = runner.invoke(cli, ["--data-dir", str(data), "ingest-inbox", str(box)])
    assert missing.exit_code != 0
    assert "provenance.tsv not found" in missing.output

    sha = _write_rom(box, b"rom-d")
    (box / "provenance.tsv").write_text(HEADER + _row(sha))
    ok = runner.invoke(cli, ["--data-dir", str(data), "ingest-inbox", str(box)])
    assert ok.exit_code == 0, ok.output
    assert "new=1" in ok.output


def test_provenance_only_backfills_without_rom_files(tmp_path, db, parsed):
    box = tmp_path / "box"
    box.mkdir()
    known = hashlib.sha256(b"rom-e").hexdigest()
    unknown = hashlib.sha256(b"rom-f").hexdigest()
    db.insert_image(Image(sha256=known, vendor="manual", file_size=5))
    (box / "provenance.tsv").write_text(
        "sha256\tvendor\tdevice\tsocket\tboard_class\tchipset\tvendor_version\tlink\tdate\n"
        f"{known}\tASUS\tB450\tAM4\tRyzen\tB450\t4403\thttps://example.invalid/b450.zip\t2023-01-01\n"
        f"{unknown}\tASUS\tB550\tAM4\tRyzen\tB550\t1\thttps://example.invalid/b550.zip\t2023-01-01\n"
    )

    summary = inbox.ingest_inbox(box, db, tmp_path / "data", provenance_only=True)

    assert (summary.backfilled, summary.missing, summary.new) == (1, 1, 0)
    row = db.get_image_by_sha256(known)
    assert (row["vendor"], row["bios_version"], row["download_url"]) == (
        "ASUS",
        "4403",
        "https://example.invalid/b450.zip",
    )
    assert db.get_image_by_sha256(unknown) is None
    assert parsed == []


def test_vendor_slugs_are_canonicalised(tmp_path, db, parsed):
    box = tmp_path / "box"
    box.mkdir()
    sha = _write_rom(box, b"rom-g")
    (box / "provenance.tsv").write_text(HEADER + _row(sha, vendor="asus"))

    inbox.ingest_inbox(box, db, tmp_path / "data")

    assert db.get_image_by_sha256(sha)["vendor"] == "ASUS"
    assert inbox.canonical_vendor("Some New Vendor") == "Some New Vendor"
