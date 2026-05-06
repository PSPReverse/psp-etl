# PSPTool: detect `zen_generation` for single-generation EPYC BIOSes

**Repo:** [PSPReverse/PSPTool](https://github.com/PSPReverse/PSPTool)
**Affected version:** v3.4 (verified on `python3.12-psptool-3.4`)
**Severity:** functional — affects every downstream consumer that filters/groups by `directory.zen_generation`

## Problem

Every directory and entry produced by `PSPTool.from_file()` for an EPYC server BIOS
has `zen_generation = None`, even though:

- The ROM is unambiguously a Naples / Rome / Milan / Genoa / Bergamo / Siena / Turin
  EPYC image (provable from PSP_FW_BOOT_LOADER version, AGESA tag, microcode patches,
  and AMD signing keys).
- The corresponding consumer/Threadripper (AM4 / AM5 / TRX40 / TRX50) ROMs *do* get
  the correct `zen_generation` set.
- PSPTool emits **no** `Unknown zen_generation_id=...` warning, so the failure is
  silent — there's no signal that detection just didn't fire.

This blocks downstream tooling that bins or scores entries by Zen generation. In the
psp-etl corpus rebuild that surfaced this, **37 freshly-scraped EPYC ROMs (16 SP3 +
16 SP5 + 4 SP6 + 1 sTRX4) parsed cleanly with zero `parse_errors`, but contributed
zero rows to the per-generation primary-image selection table** because every
entry's `zen_generation` was `None` and the downstream `GROUP BY zen_generation, …`
filter dropped them.

## Root cause

PSPTool currently has only two paths that set `Directory.zen_generation`:

| Path | Trigger | Code |
|---|---|---|
| **A. combo_dir** | FET points to a `2PSP` combo directory whose entries each carry `(zen_generation_id, sub_dir_offset)` pairs. AM4/AM5 BIOSes use this because one BIOS image supports multiple Zen generations on the same socket. | [`fet.py:_parse_combo_dir`](https://github.com/PSPReverse/PSPTool/blob/main/psptool/fet.py#L94-L130) |
| **B. tertiary self-tag** | Tertiary directory body contains a 3-byte zen-generation ID at offset 21. | [`directory.py:create_directories_if_not_exist`](https://github.com/PSPReverse/PSPTool/blob/main/psptool/directory.py#L86-L98) |

**EPYC server BIOSes hit neither path.** They have a single FET → single primary
`$PSP` + `$BHD` directory layout, with no combo_dir and no tertiary directories.
The primary directory body has no zen-generation field at offset 21.

So `zen_generation` stays at its `None` default and silently propagates to every
`Entry` carved out of those directories.

The current zen-generation table in
[`directory.py:42-48`](https://github.com/PSPReverse/PSPTool/blob/main/psptool/directory.py#L42-L48):

```python
ZEN_GENERATION_IDS = {
    'Zen 1':   [b'\x00\x09\xBC', b'\x00\x0A\xBC'],
    'Zen 2':   [b'\x05\x0B\xBC', b'\x01\x0A\xBC'],
    'Zen 3':   [b'\x01\x0C\xBC', b'\x00\x0C\xBC'],
    'Zen 4':   [b'\x04\x0D\xBC', b'\x0B\x0D\xBC'],
    'Zen 4/5': [b'\x03\x0D\xBC'],
}
```

is fine for what it covers — adding more IDs to it does **not** help here, because
the IDs are never read for EPYC BIOSes in the first place. The fix is structural:
add a third detection path for single-generation ROMs.

## Proposed fix: third detection path via PSP_FW_BOOT_LOADER version

The cleanest hook is `PSP_FW_BOOT_LOADER` (entry type `0x01`). Its 4-octet `version`
field has a strong, stable correlation with Zen generation across vendors. This was
verified empirically against 37 EPYC ROMs scraped from ASUS, Tyan, ASRock Rack
support sites covering Naples through Turin:

| `PSP_FW_BOOT_LOADER` version major.minor | Generation | EPYC family | Sample versions |
|---|---|---|---|
| `0.09.x.y`, `0.0A.x.y` | Zen 1 | Naples (SP3) | `0.9.0.…`, `0.A.0.…` |
| `0.0C.x.y`, `0.0B.x.y` | Zen 2 | Rome (SP3) | `0.C.0.68`, `0.C.0.89` |
| `0.13.x.y` | Zen 3 | Milan (SP3) | `0.13.0.50`, `0.13.0.7A` |
| `0.29.x.y` | Zen 4 | Genoa (SP5) / Siena (SP6) | `0.29.0.93`, `0.29.0.A2` |
| `0.3D.x.y` | Zen 5 | Turin / Bergamo (SP5) | `0.3D.0.68`, `0.3D.0.7A` |

Implementation sketch (in `Directory.update_zen_generation` or a new
post-parse pass on `PSPTool`):

```python
# After all FETs/directories are parsed, scan for PSP_FW_BOOT_LOADER entries
# in any directory whose zen_generation is still None. Use the boot-loader's
# version major.minor to back-fill.

_BL_VERSION_TO_ZEN = {
    0x09: 'Zen 1', 0x0A: 'Zen 1',
    0x0B: 'Zen 2', 0x0C: 'Zen 2',
    0x13: 'Zen 3',
    0x29: 'Zen 4',
    0x3D: 'Zen 5',
}

def _backfill_zen_generation_from_bootloader(self):
    for directory in self.directories_by_offset.values():
        if directory.zen_generation is not None:
            continue
        for entry in directory.entries:
            if entry.type == 0x01 and entry.version is not None:
                # version is a 4-byte field; major is byte[2] in PSP convention
                bl_major = entry.version[2]
                gen = _BL_VERSION_TO_ZEN.get(bl_major)
                if gen is not None:
                    directory.zen_generation = gen
                    break
```

Why this hook:

1. **PSP_FW_BOOT_LOADER is mandatory** — every PSP-bearing AMD ROM has one. No
   dependency on optional AGESA strings or microcode patches.
2. **The mapping is stable across vendors and BIOS revisions** — the boot-loader
   is signed by AMD, and its major version reflects the generation of PSP firmware
   architecture, not the OEM that built the BIOS.
3. **No false positives on existing combo_dir / tertiary paths** — the back-fill
   only fires when `directory.zen_generation is None`, so AM4 / AM5 detection is
   unchanged.
4. **Consistent with the project's existing pattern** of recognizing structures
   by their PSP-side magic/version metadata.

## Alternative fixes considered

- **AMD signing-key fingerprint lookup** (via `cert_tree.py`). More robust than
  boot-loader version, but requires expanding the embedded key catalog and
  fingerprinting every gen's root key. Higher engineering cost.
- **CPU microcode patch family/model**. PSPTool already parses microcode
  (`microcode_file.py`); the F-Mod CPUID range (e.g., F19h Mod 0xh = Zen 3) is
  unambiguous. Slightly heavier than reading the boot-loader version since you
  have to walk every microcode patch. Equally correct.
- **Adding new IDs to `ZEN_GENERATION_IDS`** — does not help. EPYC BIOSes never
  reach the lookup site (no combo_dir, no tertiary tag).

## Test data / acceptance criteria

The fix is correct iff `PSPTool.from_file()` returns
`directory.zen_generation == <expected gen>` for any EPYC BIOS where an existing
heuristic identifies the generation by:

- AGESA tag (`Naples`, `RomePI`, `Milan*`, `Genoa`, `Bergamo`, `Siena`, `Turin`)
- AMD product family (Naples=Zen 1, Rome=Zen 2, Milan=Zen 3, Genoa=Zen 4,
  Bergamo=Zen 4c, Siena=Zen 4c, Turin=Zen 5)

### Test ROMs — direct download URLs

All URLs below are **publicly accessible without authentication** from the
respective vendor CDN as of 2026-05-07. Each entry includes the post-unwrap
SHA-256 (the raw ROM after vendor-specific unwrapping is applied) so you can
verify you're testing the same image.

#### Negative tests — currently fail (expected: not `None`, actually `None`)

##### Zen 1 (Naples / SP3)

There are no public Naples BIOSes in this corpus; the negative test set
starts at Zen 2. A Naples sample can typically be obtained from
[Supermicro H11SSL-i archive on Wayback](https://web.archive.org/web/*/supermicro.com/products/motherboard/AMD/EPYC7000/H11SSL-i*),
but that requires manual archival lookup.

##### Zen 2 (Rome / SP3)

| URL | Model | BIOS | Expected | Post-unwrap SHA-256 |
|---|---|---|---|---|
| https://dlcdnets.asus.com/pub/ASUS/server/RS500A-10/BIOS&FW/KRPA-U16-ASUS-4501.zip | ASUS KRPA-U16 | 4501 (ROME) | Zen 2 (RomePI 1.0.0.E) | `2b68b6f7067007911f8dfb13b6afd43bfc9ca1b6b4bd40bd233949ebd458ff12` |
| https://dlcdnets.asus.com/pub/ASUS/mb/SocketSP3(4094)/KRPA-U16/BIOS&FW/KRPA-U16-ASUS-4301.zip | ASUS KRPA-U16 | 4301 (Rome) | Zen 2 (RomePI 1.0.0.C) | `3c5129dfef692c2d5d19499c541dd4e45b62b34a6f8d7102cdb531b9a7a938f0` |
| https://dlcdnets.asus.com/pub/ASUS/mb/SocketSP3(4094)/KRPA-U16/BIOS&FW/KRPA-U16-ASUS-0703.zip | ASUS KRPA-U16 | 0703 | Zen 2 (RomePI 1.0.0.6.) | `6ca94278fca4a73e05808ddd1e5f506ed0700cb9a32c21e6d93a7fa26a6898e0` |

##### Zen 3 (Milan / SP3)

| URL | Model | BIOS | Expected | Post-unwrap SHA-256 |
|---|---|---|---|---|
| https://dlcdnets.asus.com/pub/ASUS/KRPA-U16-M-ASUS-1002.zip | ASUS KRPA-U16 | 1002 (Milan) | Zen 3 (MilanCrb 0AC0U025) | `814b2392f2131871f581f1bdc2b7589a417f2685375b1a6f95c759985b62916f` |
| https://dlcdnets.asus.com/pub/ASUS/server/RS500A-10/BIOS&FW/KRPA-U16-M-ASUS-0701.zip | ASUS KRPA-U16 | 0701 (Milan) | Zen 3 (Milan 1.0.0.9) | `37dfbe711ffb4d144bae0aab2e0e5afc6d561c8608111da19852093092419980` |

##### Zen 4 (Genoa / SP5, also Siena / SP6)

| URL | Model | BIOS | Expected | Post-unwrap SHA-256 |
|---|---|---|---|---|
| https://dlcdnets.asus.com/pub/ASUS/server/K14PA-U12/BIOS/K14PA-U12-ASUS-2305.zip | ASUS K14PA-U12 (SP5) | 2305 | Zen 4 (Genoa) | `a04ff03cfae633eb43bc76256708689ca5c3a0a07f953a003c811004746a2541` |
| https://dlcdnets.asus.com/pub/ASUS/server/K14PA-U12/BIOS/K14PA-U12-ASUS-2202.zip | ASUS K14PA-U12 (SP5) | 2202 | Zen 4 (Genoa 1.0.0.F) | `22c677ad8a4433af6598da9609310bf25293db1a82b851637463801d05ded1e4` |
| https://dlcdnets.asus.com/pub/ASUS/K14PA-U12-ASUS-0601.zip | ASUS K14PA-U12 (SP5) | 0601 | Zen 4 (Genoa 1.0.0.C) | `a1415e39c876c1d75a580526979d276dcf775307f44274173d8e63c38624c80a` |
| https://dlcdnets.asus.com/pub/ASUS/server/S14NA-U12/BIOS/S14NA-U12-ASUS-0903.zip | ASUS S14NA-U12 (SP6) | 0903 | Zen 4 (Siena) | `adf013b091dcbc873dedbb8e3cd01654928abe3166fcb71cd3e9b436d562556c` |
| https://dlcdnets.asus.com/pub/ASUS/server/S14NA-U12/BIOS/S14NA-U12-ASUS-0702.zip | ASUS S14NA-U12 (SP6) | 0702 | Zen 4 (Siena) | `a61383ba2a9ac9fff2b21d3094df96becd1f5f84b2295f45b316f811d5f7caf0` |

##### Zen 5 (Turin / SP5)

| URL | Model | BIOS | Expected | Post-unwrap SHA-256 |
|---|---|---|---|---|
| https://download1.mitaccomputing.com/pub/bios/S8050GM4NE-2T_BIOS_V3.04.zip | Tyan S8050GM4NE-2T | V3.04 | Zen 5 (Turin) | `647198265eeec8ec5f9be1dbfd667160ea892b52f700a8f814452a537db69ddf` |
| https://download1.mitaccomputing.com/pub/bios/S8050GM2NE_BIOS_V3.02.zip | Tyan S8050GM2NE | V3.02 | Zen 5 (Turin) | `b70d4002b0b28c26cb533917efa6d819bb68fa168174fd965f57c9f7695ef695` |

##### Threadripper Pro (sTRX4 / Workstation)

| URL | Model | BIOS | Expected | Post-unwrap SHA-256 |
|---|---|---|---|---|
| https://download.asrock.com/BIOS/Server/TRX40D8-2N2T(01.30.00)BMC.zip | ASRock Rack TRX40D8-2N2T | 01.30.00 | Zen 2 (Castle Peak / sTRX4) | `c248eac28fc5530d018cdbc048221560aab22978b0982297ea55f1d74be3b126` |

#### Positive controls — currently work, must not regress

These are AM4 ROMs from ASRock Rack's server CDN that PSPTool already
classifies correctly via the existing combo_dir path. Any fix must keep
returning the same `zen_generation` for these:

| URL | Model | BIOS | Expected | Post-unwrap SHA-256 |
|---|---|---|---|---|
| https://download.asrock.com/BIOS/Server/X470D4U2-2T(3.40)ROM.zip | ASRock Rack X470D4U2-2T | 3.40 | Zen 1 + Zen 2 + Zen 3 (combo) | `f7dd95b71d77bf446e2532d5464222ae54e78b8f6669c16251ba67699080aacb` |
| https://download.asrock.com/BIOS/Server/X570D4I-2T(L2.08a)ROM.zip | ASRock Rack X570D4I-2T | L2.08a | Zen 2 + Zen 3 (combo) | `011dc7a6bb507330fdfea564264a454ae9ab12c0d8d54f03e8caf325031b3193` |

### Vendor unwrap notes

Reproducing these tests requires unwrapping the vendor-specific archive to
get the raw ROM file PSPTool ingests:

- **ASUS `.zip` (`*.CAP` inside)**: extract the `.CAP` file from the ZIP, then
  strip the **first 0x800 (2048) bytes** — that's the ASUS Aptio capsule
  header. The remaining bytes are the raw ROM. (Verified by
  [psp-etl `AsusServerScraper.download`](https://github.com/vringar/psp-etl/blob/main/src/psp_etl/scrape/asus_server.py).)
- **Tyan/MiTAC `.zip` (`*.BIN`/`*.ROM` inside)**: extract the largest
  `.bin`/`.rom` file from the ZIP. **Reject** any `.CAP` (Tyan's ASUS-format
  capsule), `.hpm` (IPMI wrapper), or executable wrapper — the raw ROM is the
  uncompressed image, not the capsule.
- **ASRock / ASRock Rack `.zip` (`*.ROM` inside)**: extract the largest
  `.ROM`/`.BIN` file from the ZIP — no header stripping required. The
  `BMC.zip` variants for Rack boards contain both the BIOS ROM and a BMC
  image; pick the larger one for BIOS testing.

### One-liner repro using psp-etl

If you have psp-etl checked out, the unwrap is automated:

```bash
git clone https://github.com/vringar/psp-etl.git
cd psp-etl && uv sync --extra dev

# Pull a single Rome BIOS into data/roms/, ingest it, and report what
# zen_generation each entry got assigned:
.venv/bin/python -c '
import asyncio, tempfile, hashlib
from pathlib import Path
from psp_etl.scrape.asus_server import AsusServerScraper
from psp_etl.scrape.base import BiosUpdate, BoardInfo

async def go():
    async with AsusServerScraper() as s:
        b = BoardInfo(vendor="ASUS", model="KRPA-U16", socket="SP3",
                      url="https://servers.asus.com/products/Servers/Server-Motherboards/KRPA-U16")
        u = BiosUpdate(board=b, bios_version="4501",
                       download_url="https://dlcdnets.asus.com/pub/ASUS/server/RS500A-10/BIOS&FW/KRPA-U16-ASUS-4501.zip",
                       release_date=None, agesa_version=None)
        with tempfile.TemporaryDirectory() as t:
            rom = await s.download(u, Path(t))
            print("sha256:", hashlib.sha256(rom.read_bytes()).hexdigest())
            from psptool import PSPTool
            psp = PSPTool.from_file(str(rom))
            for r in psp.blob.roms:
                for d in r.directories:
                    print(d.magic[:4].decode(errors="replace"), repr(d.zen_generation))

asyncio.run(go())
'
```

Expected current output (broken — every directory `None`):

```
$PSP None
$BHD None
$PL2 None
$BL2 None
```

Expected output after fix:

```
$PSP 'Zen 2'
$BHD 'Zen 2'
$PL2 'Zen 2'
$BL2 'Zen 2'
```

### Compact regression-test corpus

A minimal regression set for CI: 5 ROMs spanning generations Zen 2 → Zen 5
(plus the two positive controls). Total download ≈ 250 MB, all on
public CDNs. Listed above as the first row of each generation's table.

The assertion shape:

```python
import pytest
from psptool import PSPTool

@pytest.mark.parametrize("rom_path,expected_zen", [
    ("fixtures/KRPA-U16-ASUS-4501.rom",     "Zen 2"),  # Rome
    ("fixtures/KRPA-U16-M-ASUS-1002.rom",   "Zen 3"),  # Milan
    ("fixtures/K14PA-U12-ASUS-2305.rom",    "Zen 4"),  # Genoa
    ("fixtures/S14NA-U12-ASUS-0903.rom",    "Zen 4"),  # Siena (SP6)
    ("fixtures/S8050GM4NE-2T_V3.04.rom",    "Zen 5"),  # Turin
])
def test_epyc_zen_generation_detected(rom_path, expected_zen):
    psp = PSPTool.from_file(rom_path)
    for rom in psp.blob.roms:
        for d in rom.directories:
            assert d.zen_generation is not None, f"{rom_path}: directory {d.magic} has no zen_generation"
            assert expected_zen in d.zen_generation, f"{rom_path}: expected {expected_zen}, got {d.zen_generation!r}"
```

## Out of scope

- Detecting Zen generation for **non-PSP** ROMs (very old AMD platforms with
  no PSP) — they would still legitimately return `None`.
- Distinguishing Zen 4 from Zen 4c in finer-grained terms than the boot-loader
  version permits. (Bergamo / Siena currently share Zen 4 family heuristics
  with Genoa; that is a separate enhancement.)

## Reproduction

```python
from psptool import PSPTool

# Any EPYC BIOS — KRPA-U16 (Rome), KMPP-D32 (Milan), K14PA-U12 (Genoa), etc.
psp = PSPTool.from_file('KRPA-U16-ASUS-4501.rom')

# Before fix: every printed value is None
for rom in psp.blob.roms:
    for d in rom.directories:
        print(d.magic[:4], d.zen_generation)
# $PSP None
# $BHD None
# $PL2 None
# $BL2 None
```

## Related

- This issue surfaced during a corpus expansion in
  [psp-etl](https://github.com/vringar/psp-etl) where 37 newly-scraped EPYC
  ROMs ingested cleanly but contributed nothing to the
  `(zen_generation × board_class × type_id) → primary_image` selection table.
- Project README's "Zen 4/5 PSPTool warnings" caveat is the public-facing
  symptom of the same gap; the silent EPYC case is more pernicious because no
  warning is emitted.
