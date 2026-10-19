"""Extract vendor/board/BIOS-date hints from the ROMs of unprovenanced images.

usage: manual_image_hints.py OUT.tsv [--db data/psp-etl.db]

For every image still marked vendor=manual, scans the ROM for an ASUSTeK
string, up to two board-name strings and up to three MM/DD/YYYY dates (the
firmware build date, not the vendor release date). Output is a TSV that a
scraper can join against its release table to infer provenance. The board
strings are raw ROM text and are a filter, not a key.
"""

import argparse
import collections
import csv
import mmap
import re
import sqlite3
from pathlib import Path

BOARD = re.compile(
    rb"(?:PRIME|ROG STRIX|ROG CROSSHAIR|ROG ZENITH|TUF GAMING|TUF B|ProArt|Pro WS|EX-A|EX-B|M5A|M4A"
    rb"|MZ\d\d|H1[12]SS|H1[12]DS|ROMED|EPYCD|X[0-9]{3}D|B[0-9]{3}[A-Z]?[- ]|A[0-9]{3}M)[ -~]{2,24}"
)
DATE = re.compile(rb"\b(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/(20[12]\d)\b")
DATE16 = re.compile(rb"(?:[0-9]\x00){2}/\x00(?:[0-9]\x00){2}/\x00(?:2\x000\x00[12]\x00[0-9]\x00)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out")
    ap.add_argument("--db", default="data/psp-etl.db")
    ap.add_argument("--roms", default="data/roms")
    args = ap.parse_args()

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    shas = [r[0] for r in conn.execute("SELECT sha256 FROM images WHERE vendor = 'manual' ORDER BY sha256")]
    with open(args.out, "w", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(["sha256", "size", "asustek", "board_1", "board_2", "date_1", "date_2", "date_3"])
        for sha in shas:
            path = Path(args.roms) / f"{sha}.rom"
            with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                boards = collections.Counter(x.group().decode("latin1").strip() for x in BOARD.finditer(m))
                dates = collections.Counter(x.group().decode() for x in DATE.finditer(m))
                dates.update(x.group().decode("utf-16le") for x in DATE16.finditer(m))
                row = [sha, m.size(), int(m.find(b"ASUSTeK") >= 0)]
            top_boards = [b for b, _ in boards.most_common(2)]
            top_dates = [d for d, _ in dates.most_common(3)]
            writer.writerow(row + ([*top_boards, "", ""])[:2] + ([*top_dates, "", "", ""])[:3])


if __name__ == "__main__":
    main()
