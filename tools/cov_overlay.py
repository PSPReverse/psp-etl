"""Overlay a DrCov file on a re-reuse symbol map + firmware image.

usage: cov_overlay.py DRCOV SYMBOLS.json IMAGE [--bias N] [--module SUBSTR]

IMAGE is the file whose offsets equal addresses (the .hdr.bin for off-chip BL).
--bias is added to DrCov module offsets to get addresses (default 0).
Reports: coverage per function, reached->unreached call frontier, and
conditional branches in covered blocks with an uncovered successor.
"""

import argparse
import json
import re
import struct
import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

COND_BRANCH = re.compile(r"^(b(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(\.w|\.n)?|cbz|cbnz)$")


def parse_drcov(path, module_substr=None):
    data = open(path, "rb").read()
    pos = 0
    lines = []
    while True:
        end = data.index(b"\n", pos)
        line = data[pos:end].decode("latin1")
        pos = end + 1
        lines.append(line)
        if line.startswith("BB Table:"):
            break
    nbb = int(re.search(r"(\d+) bbs", lines[-1]).group(1))
    mods = {}
    cols = None
    for i, text in enumerate(lines):
        if text.startswith("Columns:"):
            cols = [c.strip() for c in text.split(":", 1)[1].split(",")]
            for row in lines[i + 1 :]:
                if row.startswith("BB Table"):
                    break
                f = [x.strip() for x in row.split(",")]
                mods[int(f[0])] = dict(zip(cols, f, strict=False))
            break
    want = None
    if module_substr:
        want = {m for m, d in mods.items() if module_substr in d.get("path", "")}
    bbs = []
    for _ in range(nbb):
        start, size, mod = struct.unpack_from("<IHH", data, pos)
        pos += 8
        if want is None or mod in want:
            bbs.append((start, size))
    return mods, bbs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("drcov")
    ap.add_argument("symbols")
    ap.add_argument("image")
    ap.add_argument("--bias", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--module")
    a = ap.parse_args()

    mods, bbs = parse_drcov(a.drcov, a.module)
    img = open(a.image, "rb").read()
    sym = json.load(open(a.symbols))
    funcs = sym["functions"]

    cov_starts = {s + a.bias for s, _ in bbs}
    cov_bytes = set()
    for s, n in bbs:
        cov_bytes.update(range(s + a.bias, s + a.bias + n))
    # Thumb BB addresses may carry bit0 in some DrCov producers; normalise both.
    cov_starts |= {s & ~1 for s in cov_starts}

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True

    def fn_cov(f):
        tot = hit = 0
        for lo, hi in f["ranges"]:
            tot += hi - lo
            hit += sum(1 for x in range(lo, hi) if x in cov_bytes)
        return hit, tot

    by_start = {f["start"]: f for f in funcs}
    rows = []
    calls = {}  # callee start -> set(caller start)
    for f in funcs:
        hit, tot = fn_cov(f)
        rows.append((f, hit, tot))
        for lo, hi in f["ranges"]:
            for i in md.disasm(img[lo:hi], lo):
                if i.mnemonic in ("bl", "blx", "b", "b.w") and i.op_str.startswith("#"):
                    t = int(i.op_str[1:], 0)
                    if t in by_start and t != f["start"] and i.mnemonic in ("bl", "blx"):
                        calls.setdefault(t, set()).add(f["start"])

    reached = {f["start"] for f, h, t in rows if h > 0}
    print(f"# modules: {[(m, d.get('path')) for m, d in mods.items()]}")
    print(f"# basic blocks: {len(bbs)} unique starts: {len(cov_starts)}")
    print(f"# functions: {len(funcs)} reached: {len(reached)} never: {len(funcs) - len(reached)}")

    print("\n## reached->unreached call frontier")
    for f, h, _t in rows:
        if h == 0 and calls.get(f["start"], set()) & reached:
            callers = sorted(calls[f["start"]] & reached)
            print(
                f"  {f['name']}@{f['start']:#x} <- " + ", ".join(f"{by_start[c]['name']}@{c:#x}" for c in callers[:4])
            )

    print("\n## covered conditional branches with an uncovered successor")
    n = 0
    for f, h, _t in rows:
        if h == 0:
            continue
        for lo, hi in f["ranges"]:
            insns = list(md.disasm(img[lo:hi], lo))
            for k, i in enumerate(insns):
                if COND_BRANCH.match(i.mnemonic) and i.address in cov_bytes:
                    tgt = None
                    m = re.search(r"#(0x[0-9a-fA-F]+)", i.op_str)
                    if m:
                        tgt = int(m.group(1), 16)
                    ft = i.address + i.size
                    miss = []
                    if tgt is not None and tgt not in cov_bytes:
                        miss.append(f"taken->{tgt:#x}")
                    if ft not in cov_bytes:
                        miss.append(f"fallthrough->{ft:#x}")
                    if miss and len(miss) == 1:
                        gate = f"{insns[k - 1].mnemonic} {insns[k - 1].op_str}" if k else ""
                        print(f"  {f['name']}: {i.address:#x} {i.mnemonic} {i.op_str}  [{gate}]  never: {miss[0]}")
                        n += 1
    print(f"# half-taken branches: {n}")

    print("\n## unreached functions (top by size)")
    for f, h, _t in sorted(rows, key=lambda r: -sum(hi - lo for lo, hi in r[0]["ranges"])):
        if h == 0:
            sz = sum(hi - lo for lo, hi in f["ranges"])
            print(f"  {f['name']}@{f['start']:#x} {sz}B")
            if sz < 200:
                break


if __name__ == "__main__":
    sys.exit(main())
