"""Ingest corpus ROMs into a scratch database and dump the resulting rows.

usage: compare_ingest.py OUT_DIR [--step N] [--start I --count C]

Run it once per PSP parser (put the parser under test first on PYTHONPATH)
and diff the two ``rows.txt`` files (``python -c`` sorting both) to check
that two parser builds produce identical entries. Also prints max RSS every
50 ROMs, which exposed a per-ROM memory leak in a binding once.
"""

import argparse
import hashlib
import resource
import sqlite3
import sys
from pathlib import Path

from psp_etl.db import Database, Image
from psp_etl.ingest import ingest_rom

ROW_QUERY = """
SELECT i.sha256, e.rom_index, e.directory_index, e.directory_magic, e.zen_generation,
       e.type_id, e.type_name, e.subprogram, e.instance, e.version, e.firmware_md5,
       e.blob_sha256, e.body_size, e.encrypted, e.compressed, e.signed, e.load_address
FROM entries e JOIN images i ON i.id = e.image_id
ORDER BY 1, 2, 3, 6, 8, 9, 12
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out")
    ap.add_argument("--roms", default="data/roms")
    ap.add_argument("--step", type=int, default=1)
    ap.add_argument("--start", type=int)
    ap.add_argument("--count", type=int)
    args = ap.parse_args()

    roms = sorted(Path(args.roms).glob("*.rom"))
    sample = roms[args.start : args.start + args.count] if args.start is not None and args.count else roms[:: args.step]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with Database(out / "t.db") as db:
        for n, rom in enumerate(sample):
            if n % 50 == 0:
                rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024
                print(n, rom.name[:16], rss, "MB", file=sys.stderr, flush=True)
            data = rom.read_bytes()
            image_id = db.insert_image(Image(sha256=hashlib.sha256(data).hexdigest(), vendor="x", file_size=len(data)))
            ingest_rom(rom, image_id, db, out / "data")
    conn = sqlite3.connect(out / "t.db")
    rows = conn.execute(ROW_QUERY).fetchall()
    errors = conn.execute("SELECT COUNT(*) FROM parse_errors").fetchone()[0]
    print(len(sample), "roms", len(rows), "entries", errors, "parse_errors")
    (out / "rows.txt").write_text("\n".join(map(repr, rows)))


if __name__ == "__main__":
    main()
