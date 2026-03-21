"""Vendor wrapper extraction utilities for BIOS ROM images.

Handles ZIP extraction and vendor-specific unwrapping:
- ASUS: Strip 0x800-byte CAP capsule header
- MSI, Gigabyte, ASRock: Direct ROM inside ZIP (no unwrapping needed)
"""

import zipfile
from pathlib import Path

# ASUS CAP capsule header size (0x800 = 2048 bytes)
ASUS_CAP_HEADER_SIZE = 0x800

# File extensions considered ROM images inside ZIP archives, by vendor
_ASUS_EXTENSIONS = frozenset({".cap"})
_DIRECT_EXTENSIONS = frozenset({".rom", ".bin"})

# All recognised ROM extensions across all vendors
_ALL_ROM_EXTENSIONS = _ASUS_EXTENSIONS | _DIRECT_EXTENSIONS

# Known PSP/BIOS directory magic bytes that indicate a valid AMD BIOS ROM.
# These appear somewhere in the ROM image (not necessarily at offset 0).
# References:
#   - PSP Level-1 directory:  b"$PSP"
#   - PSP Level-2 directory:  b"$PL2"
#   - BIOS directory L1:      b"$BHD"
#   - BIOS directory L2:      b"$BL2"
PSP_SIGNATURES: tuple[bytes, ...] = (b"$PSP", b"$PL2", b"$BHD", b"$BL2")


def _find_rom_in_zip(zf: zipfile.ZipFile, extensions: frozenset[str]) -> str:
    """Return the name of the first entry in *zf* whose suffix matches *extensions*.

    Raises FileNotFoundError if no matching entry is found.
    """
    for name in zf.namelist():
        if Path(name).suffix.lower() in extensions:
            return name
    raise FileNotFoundError(f"No file with extension(s) {extensions} found in ZIP (contents: {zf.namelist()})")


def extract_rom_from_zip(zip_path: Path, dest_dir: Path, vendor: str) -> Path:
    """Extract the ROM image from a vendor ZIP archive.

    Picks the correct entry based on *vendor* and writes the raw bytes to
    *dest_dir*.  For ASUS images the CAP header is stripped before writing.

    Args:
        zip_path: Path to the downloaded ZIP file.
        dest_dir: Directory to write the extracted ROM to.
        vendor:   Vendor name, case-insensitive (e.g. "ASUS", "msi").

    Returns:
        Path to the extracted (and, for ASUS, unwrapped) ROM file.

    Raises:
        FileNotFoundError: If no recognisable ROM entry is found in the ZIP.
        ValueError: If the ASUS CAP file is too small to contain a header.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    vendor_upper = vendor.upper()

    with zipfile.ZipFile(zip_path, "r") as zf:
        if vendor_upper == "ASUS":
            entry_name = _find_rom_in_zip(zf, _ASUS_EXTENSIONS)
            raw = zf.read(entry_name)
            rom_bytes = unwrap_asus_cap(raw)
            out_name = Path(entry_name).stem + ".rom"
        else:
            # MSI, Gigabyte, ASRock — direct ROM inside ZIP
            entry_name = _find_rom_in_zip(zf, _DIRECT_EXTENSIONS)
            rom_bytes = zf.read(entry_name)
            out_name = Path(entry_name).name

    out_path = dest_dir / out_name
    out_path.write_bytes(rom_bytes)
    return out_path


def unwrap_asus_cap(data: bytes) -> bytes:
    """Strip the ASUS CAP capsule header from *data*.

    ASUS packages their BIOS ROM inside a .CAP file that prepends a
    0x800-byte (2048-byte) proprietary capsule header.  The raw ROM image
    starts immediately after this header.

    Args:
        data: Raw bytes of the .CAP file.

    Returns:
        ROM bytes with the header removed.

    Raises:
        ValueError: If *data* is shorter than the expected header size.
    """
    if len(data) <= ASUS_CAP_HEADER_SIZE:
        raise ValueError(
            f"ASUS CAP file is too small ({len(data)} bytes); expected more than {ASUS_CAP_HEADER_SIZE} bytes"
        )
    return data[ASUS_CAP_HEADER_SIZE:]


def validate_psp_rom(data: bytes) -> bool:
    """Return True if *data* looks like a valid AMD BIOS ROM.

    Checks for the presence of at least one known PSP or BIOS directory
    magic signature (``$PSP``, ``$PL2``, ``$BHD``, or ``$BL2``) anywhere
    in the image.  This is a lightweight sanity check; it does not guarantee
    full parseability by PSPTool (some Zen 4/5 images are known to trigger
    PSPTool bugs).

    Args:
        data: Raw bytes of the ROM image.

    Returns:
        True if a known signature is found, False otherwise.
    """
    return any(sig in data for sig in PSP_SIGNATURES)
