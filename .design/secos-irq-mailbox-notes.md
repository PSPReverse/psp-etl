# SecOS interrupt controller and mailbox notes (static findings, Oct 2026)

Facts from static disassembly of corpus blobs and aspfuzz/qemu-psp dumps; dynamic
confirmation noted where it exists. Guesses are marked. Offsets are body offsets
unless a base is given. The PSP firmware here is Zen2/Zen3; Zen1 differs.

## Interrupt controller (IC)
- SecOS kernel base `0x03010000`: enable words `+0x200..`, ACK `+0x2b0+4*(id>>5)`,
  PEN `+0x2c0` (0 = nothing pending), ID `+0x2c4`. id = 32*group + bit.
- Off-chip BL (Zen2/3/4/5 builds) uses `0x030102b0` for ACK/PEN/ID (same layout, different base). Zen1 BL builds carry `0x030103b0`.
- Off-chip BL runs on IRQ (FIQ vector is `b .`); SecOS runs on FIQ (IRQ vector is `b .`).
- id `0x60` is the scheduler tick. id `0x15` is the CCP and requires CCP status bit 17 (`0x03006008`, write-1-to-clear).

## SecOS kernel landmarks (Zen2 18a38127 = 0.14.0.3B)
FIQ loop `0xf60`, id->event `0x2304` (idtab `0x6a7c`, byte `0x61` = unattached, else slot), tick `0x2358`,
irq_attach `0x3504`, idle `0x1d68` (WFI `0x1db2`). Other builds shift by up to ~0x100: use `tools/kernel_offsets.py`.
SVC numbers (Zen2 0.14.0.3E dispatcher): `0x59` irq_attach(id), `0x5a` wait, `0x5e/0x5f` lock/unlock.

## Mailbox (command register `0x03010570`, Linux C2PMSG_28)
- Pending command: word0 with bit31 clear, command in bits 23:16, args at `+4`/`+8`.
  Reply: `0x80000000 + status` (Zen2; Zen1 firmware replied `0xa0000000 + status`).
- Zen2 observed: cmd `0x1a` -> status 9, cmd `0x1c` -> status 4. Zen1 (2577cc07) handler table at `0x395f8`.
- SecOS app (VA `0x200000`) init at `0x202928`: attaches ids `0x10`, `0x3c` (mailbox), then `0x31`, `0x34` (TEE ring, C2PMSG_17 `0x03010544`).
  Dynamic result: the command path also runs without the doorbell in the fuzz harness (polled or tick-driven) - not shown to require it.

## Zen2 userland driver blob (type 0x28) addressing
Virtual address = body offset + `0xe00100` for the 0x15a4-group builds (0.14.0.39/3B/3D/3E/43).
Boot-args table `$RA2` (16 slots of 16 bytes: flags, A, B, ...) is validated at VA `0xe04f00`, called only from `0xe0c568` (requires `$ROM` magic at `0xe5532c`).

## Zen3 EPYC (Milan) notes
No EPYC Milan SecOS kernel is in the corpus (KRPA-U16 ROMs yield only BL/SMU/gasket/SEV). Off-chip BL f8d2fc01 (0.13.0.7A):
SPI window struct at `0x151d8`; the BHD directory read fails with status `0x145` when `[0x151d8+4]` is 0 (FET walk gated by a fuse-derived byte at `0x156fa`).

## Paused (do not continue without Stefan)
Callers/bounds analysis of the driver-blob flash-address lookup; Zen3 `0x107` boot-failure analysis.
