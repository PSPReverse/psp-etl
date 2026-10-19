"""Find key SecOS kernel landmarks by signature in one or more blobs.

usage: kernel_offsets.py SHA_PREFIX [SHA_PREFIX ...] [--blobs DIR]

Reports, per blob (body offsets): the FIQ dispatch function (reads the
interrupt-controller ID register at +0x2c4), the id 0x60 compare, WFI sites,
the irq_attach function (``cmp r0, #0x80``) and the pool addresses of the
mailbox / timer / interrupt-controller literals. Signature based, not
verified dynamically. Requires capstone.
"""

import argparse
import glob
import struct

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

LITERALS = {
    "mbox 0x03010570": 0x03010570,
    "IC 0x03010000": 0x03010000,
    "timer 0x0301040c": 0x0301040C,
    "0x0301070c": 0x0301070C,
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("prefixes", nargs="+")
    ap.add_argument("--blobs", default="data/blobs")
    args = ap.parse_args()

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    for prefix in args.prefixes:
        path = glob.glob(f"{args.blobs}/{prefix}*.bin")[0]
        data = open(path, "rb").read()
        seen = {}
        for a in range(0x100, min(len(data) - 4, 0x8000), 2):
            for ins in md.disasm(data[a : a + 4], a, 1):
                seen[a] = ins

        def fn_start(a: int, seen: dict = seen) -> int:
            s = a
            while s > a - 0x120 and not (s in seen and seen[s].mnemonic.startswith("push") and "lr" in seen[s].op_str):
                s -= 2
            return s

        def find(pred, seen: dict = seen) -> list[int]:
            return [a for a, i in sorted(seen.items()) if pred(i)]

        id_reads = find(lambda i: i.mnemonic.startswith("ldr") and i.op_str.endswith("#0x2c4]"))
        print(prefix, len(data))
        print("  FIQ fn candidates:", [hex(fn_start(a)) for a in id_reads])
        print("  cmp r0,#0x60:", [hex(a) for a in find(lambda i: i.mnemonic == "cmp" and i.op_str == "r0, #0x60")][:3])
        print("  wfi:", [hex(a) for a in find(lambda i: i.mnemonic == "wfi")])
        print(
            "  irq_attach:",
            [hex(fn_start(a)) for a in find(lambda i: i.mnemonic == "cmp" and i.op_str == "r0, #0x80")],
        )
        for name, value in LITERALS.items():
            pools = [hex(x) for x in range(0, len(data) - 3, 4) if struct.unpack_from("<I", data, x)[0] == value]
            print(f"  pool {name}: {pools[:4]}")


if __name__ == "__main__":
    main()
