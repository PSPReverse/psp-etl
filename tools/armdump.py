"""Disassemble a range of a raw ARM binary and resolve pc-relative literal loads.

usage: armdump.py FILE START END {a|t} [--base ADDR]

FILE is a raw image (for example a blob from data/blobs). START/END are
addresses; --base is the address of the first byte (default 0). ``t`` is
Thumb, ``a`` is ARM. Requires capstone (``uv run --with capstone``).
"""

import argparse
import struct

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file")
    ap.add_argument("start", type=lambda x: int(x, 0))
    ap.add_argument("end", type=lambda x: int(x, 0))
    ap.add_argument("mode", choices=["a", "t"])
    ap.add_argument("--base", type=lambda x: int(x, 0), default=0)
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if args.mode == "t" else CS_MODE_ARM)
    lo, hi = args.start - args.base, args.end - args.base
    for ins in md.disasm(data[lo:hi], args.start):
        line = f"{ins.address:#x}: {ins.mnemonic} {ins.op_str}"
        if ins.mnemonic.startswith("ldr") and "pc" in ins.op_str and "#" in ins.op_str:
            try:
                off = int(ins.op_str.split("#")[-1].rstrip("]"), 0)
            except ValueError:
                off = None
            if off is not None:
                pc = (ins.address + 4) & ~3 if args.mode == "t" else ins.address + 8
                pos = pc + off - args.base
                if 0 <= pos + 4 <= len(data):
                    line += f"   ; =[{pc + off:#x}] {struct.unpack_from('<I', data, pos)[0]:#x}"
        print(line)


if __name__ == "__main__":
    main()
