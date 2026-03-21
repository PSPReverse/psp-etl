"""Tests for vendor wrapper extraction utilities."""

import io
import zipfile

import pytest

from psp_etl.scrape.extract import (
    ASUS_CAP_HEADER_SIZE,
    PSP_SIGNATURES,
    extract_rom_from_zip,
    unwrap_asus_cap,
    validate_psp_rom,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_zip(files: dict[str, bytes]) -> bytes:
    """Return in-memory ZIP bytes containing *files* (name -> content)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# unwrap_asus_cap
# ---------------------------------------------------------------------------


class TestUnwrapAsusCap:
    def test_strips_header(self):
        header = b"\x00" * ASUS_CAP_HEADER_SIZE
        payload = b"\xaa\xbb\xcc\xdd" * 256
        result = unwrap_asus_cap(header + payload)
        assert result == payload

    def test_exact_boundary(self):
        """Data that is exactly ASUS_CAP_HEADER_SIZE + 1 byte long."""
        data = b"\xab" * ASUS_CAP_HEADER_SIZE + b"\xff"
        result = unwrap_asus_cap(data)
        assert result == b"\xff"

    def test_too_small_raises(self):
        with pytest.raises(ValueError, match="too small"):
            unwrap_asus_cap(b"\x00" * ASUS_CAP_HEADER_SIZE)

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="too small"):
            unwrap_asus_cap(b"")

    def test_one_byte_short_raises(self):
        with pytest.raises(ValueError):
            unwrap_asus_cap(b"\x00" * (ASUS_CAP_HEADER_SIZE - 1))

    def test_header_size_constant(self):
        assert ASUS_CAP_HEADER_SIZE == 0x800


# ---------------------------------------------------------------------------
# extract_rom_from_zip – ASUS
# ---------------------------------------------------------------------------


class TestExtractRomFromZipAsus:
    def test_extracts_cap_and_strips_header(self, tmp_path):
        header = b"\x00" * ASUS_CAP_HEADER_SIZE
        rom_payload = b"\xde\xad\xbe\xef" * 512
        zip_bytes = _make_zip({"ROG-CROSSHAIR.CAP": header + rom_payload})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        out = extract_rom_from_zip(zip_path, tmp_path / "out", vendor="ASUS")

        assert out.exists()
        assert out.read_bytes() == rom_payload

    def test_output_filename_has_rom_extension(self, tmp_path):
        header = b"\x00" * ASUS_CAP_HEADER_SIZE
        payload = b"\xff" * 100
        zip_bytes = _make_zip({"BIOS.cap": header + payload})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        out = extract_rom_from_zip(zip_path, tmp_path / "out", vendor="ASUS")
        assert out.suffix == ".rom"

    def test_case_insensitive_vendor(self, tmp_path):
        header = b"\x00" * ASUS_CAP_HEADER_SIZE
        payload = b"\xab" * 64
        zip_bytes = _make_zip({"fw.CAP": header + payload})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        out = extract_rom_from_zip(zip_path, tmp_path / "out", vendor="asus")
        assert out.read_bytes() == payload

    def test_no_cap_file_raises(self, tmp_path):
        zip_bytes = _make_zip({"readme.txt": b"hello"})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        with pytest.raises(FileNotFoundError):
            extract_rom_from_zip(zip_path, tmp_path / "out", vendor="ASUS")

    def test_creates_dest_dir(self, tmp_path):
        header = b"\x00" * ASUS_CAP_HEADER_SIZE
        payload = b"\xaa" * 32
        zip_bytes = _make_zip({"fw.CAP": header + payload})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        dest = tmp_path / "new" / "subdir"
        assert not dest.exists()
        extract_rom_from_zip(zip_path, dest, vendor="ASUS")
        assert dest.exists()


# ---------------------------------------------------------------------------
# extract_rom_from_zip – MSI / Gigabyte / ASRock (direct)
# ---------------------------------------------------------------------------


class TestExtractRomFromZipDirect:
    @pytest.mark.parametrize("vendor", ["MSI", "Gigabyte", "ASRock"])
    def test_extracts_rom_file(self, tmp_path, vendor):
        rom_data = b"\x55\xaa" * 256
        zip_bytes = _make_zip({"firmware.rom": rom_data})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        out = extract_rom_from_zip(zip_path, tmp_path / "out", vendor=vendor)

        assert out.exists()
        assert out.read_bytes() == rom_data

    @pytest.mark.parametrize("vendor", ["MSI", "Gigabyte", "ASRock"])
    def test_extracts_bin_file(self, tmp_path, vendor):
        rom_data = b"\xde\xad" * 128
        zip_bytes = _make_zip({"bios.bin": rom_data})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        out = extract_rom_from_zip(zip_path, tmp_path / "out", vendor=vendor)
        assert out.read_bytes() == rom_data

    @pytest.mark.parametrize("vendor", ["msi", "gigabyte", "asrock"])
    def test_case_insensitive_vendor(self, tmp_path, vendor):
        rom_data = b"\xff" * 64
        zip_bytes = _make_zip({"fw.rom": rom_data})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        out = extract_rom_from_zip(zip_path, tmp_path / "out", vendor=vendor)
        assert out.read_bytes() == rom_data

    def test_no_rom_file_raises(self, tmp_path):
        zip_bytes = _make_zip({"readme.txt": b"nothing here"})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        with pytest.raises(FileNotFoundError):
            extract_rom_from_zip(zip_path, tmp_path / "out", vendor="MSI")

    def test_preserves_original_filename(self, tmp_path):
        rom_data = b"\xab\xcd" * 32
        zip_bytes = _make_zip({"MEG-X570-UNIFY.ROM": rom_data})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        out = extract_rom_from_zip(zip_path, tmp_path / "out", vendor="MSI")
        assert out.name == "MEG-X570-UNIFY.ROM"

    def test_extension_case_insensitive(self, tmp_path):
        """Extension matching is case-insensitive (.ROM vs .rom)."""
        rom_data = b"\x11\x22" * 64
        zip_bytes = _make_zip({"bios.ROM": rom_data})
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        out = extract_rom_from_zip(zip_path, tmp_path / "out", vendor="ASRock")
        assert out.read_bytes() == rom_data

    def test_zip_with_multiple_files_picks_first_rom(self, tmp_path):
        """When a ZIP contains extra files, the first ROM/BIN is extracted."""
        rom_data = b"\xbe\xef" * 32
        zip_bytes = _make_zip(
            {
                "readme.txt": b"read me",
                "firmware.rom": rom_data,
                "changelog.txt": b"changes",
            }
        )
        zip_path = tmp_path / "bios.zip"
        zip_path.write_bytes(zip_bytes)

        out = extract_rom_from_zip(zip_path, tmp_path / "out", vendor="Gigabyte")
        assert out.read_bytes() == rom_data


# ---------------------------------------------------------------------------
# validate_psp_rom
# ---------------------------------------------------------------------------


class TestValidatePspRom:
    @pytest.mark.parametrize("sig", PSP_SIGNATURES)
    def test_returns_true_for_known_signature(self, sig):
        data = b"\x00" * 0x20000 + sig + b"\xff" * 0x100
        assert validate_psp_rom(data) is True

    def test_returns_false_for_random_data(self):
        data = b"\xaa\xbb\xcc\xdd" * 1024
        assert validate_psp_rom(data) is False

    def test_returns_false_for_empty(self):
        assert validate_psp_rom(b"") is False

    def test_signature_at_start(self):
        assert validate_psp_rom(b"$PSP" + b"\x00" * 100) is True

    def test_signature_at_end(self):
        assert validate_psp_rom(b"\x00" * 100 + b"$BHD") is True

    def test_partial_signature_not_matched(self):
        assert validate_psp_rom(b"$PS" + b"\x00" * 100) is False

    def test_psp_signatures_constant(self):
        assert b"$PSP" in PSP_SIGNATURES
        assert b"$PL2" in PSP_SIGNATURES
        assert b"$BHD" in PSP_SIGNATURES
        assert b"$BL2" in PSP_SIGNATURES
