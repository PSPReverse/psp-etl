"""List interrupt ids a userland blob attaches via ``movs r0, #id; svc #N``.

usage: irq_attach_scan.py BLOB [--svc 0x59] [--base ADDR]

In the Zen2 SecOS userland driver blobs ``svc #0x59`` is irq_attach(id);
the number comes from the kernel's SVC jump table, so check it per build.
Prints each attach site and the id. Requires capstone.
"""

import argparse
import re

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("blob")
    ap.add_argument("--svc", default="0x59")
    ap.add_argument("--base", type=lambda x: int(x, 0), default=0)
    args = ap.parse_args()

    data = open(args.blob, "rb").read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    seen = {}
    for a in range(0, len(data) - 4, 2):
        for ins in md.disasm(data[a : a + 4], a, 1):
            seen[a] = ins
    want = f"#{int(args.svc, 0):#x}"
    for a, ins in sorted(seen.items()):
        if ins.mnemonic != "svc" or ins.op_str != want:
            continue
        value = None
        for b in range(a - 14, a, 2):
            prev = seen.get(b)
            if prev and prev.mnemonic in ("movs", "mov", "mov.w"):
                m = re.match(r"r0, #(0x[0-9a-f]+|\d+)$", prev.op_str)
                if m:
                    value = int(m.group(1), 0)
        shown = hex(value) if value is not None else "computed"
        print(f"{args.base + a:#x}: svc {want} id={shown}")


if __name__ == "__main__":
    main()
