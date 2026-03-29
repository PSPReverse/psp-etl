// psp-etl: Mining AMD PSP Firmware at Scale
// Research presentation — polylux 0.4.0 + pdfpc notes
//
// Compile:  typst compile slides.typ slides.pdf
// Present:  pdfpc slides.pdf  (notes extracted automatically from PDF metadata)

#import "@preview/polylux:0.4.0": slide, toolbox

#set document(title: "psp-etl: Mining AMD PSP Firmware at Scale", author: "psp-etl")
#set page(
  paper: "presentation-16-9",
  margin: (x: 2cm, y: 1.5cm),
  fill: rgb("#0f1117"),
)
#set text(font: "Liberation Mono", fill: rgb("#e8e8e8"), size: 18pt)
#show heading.where(level: 1): it => text(size: 28pt, fill: rgb("#f0a500"), weight: "bold", it)
#show heading.where(level: 2): it => text(size: 20pt, fill: rgb("#7ec8e3"), weight: "bold", it)
#show heading.where(level: 3): it => text(size: 16pt, fill: rgb("#9ad18a"), weight: "bold", it)

// Emit a pdfpc speaker note for the current slide.
// (Works around the type-check bug in polylux 0.4.0's toolbox.pdfpc.speaker-note
//  when running under Typst 0.12+, where type() returns type objects not strings.)
#let note(text) = [ #metadata((t: "Note", v: text)) <pdfpc> ]

// Helper: slide footer with hardcoded numbers
#let footer(n, total) = place(
  bottom + right,
  dx: -0.5cm, dy: -0.3cm,
  text(size: 11pt, fill: rgb("#555555"))[#n / #total],
)

// Helper: left-accented block
#let box-accent(body) = block(
  fill: rgb("#1a1d27"),
  stroke: (left: 3pt + rgb("#f0a500")),
  inset: (left: 12pt, top: 8pt, bottom: 8pt, right: 8pt),
  radius: 2pt,
  body,
)

// Helper: code-coloured inline text
#let code(body) = text(font: "Liberation Mono", fill: rgb("#a8d8a8"), body)

// ---------------------------------------------------------------------------
// Slide 1 — Title
// ---------------------------------------------------------------------------
#slide[
  #v(3cm)
  #align(center)[
    #text(size: 40pt, fill: rgb("#f0a500"), weight: "bold")[psp-etl]
    #v(0.3cm)
    #text(size: 26pt)[Mining AMD PSP Firmware at Scale]
    #v(1.5cm)
    #line(length: 60%, stroke: 1pt + rgb("#333333"))
    #v(0.8cm)
    #text(size: 16pt, fill: rgb("#888888"))[
      Automated corpus collection · Pipeline extraction · Security analysis
    ]
  ]
  #footer[1][11]
  #note("Welcome slide. Set the tone: this is a tooling talk about building infrastructure for security research on a closed, privileged subsystem. Emphasize: everything shown is derived from publicly available BIOS updates. No NDA material, no hardware access required.")
]

// ---------------------------------------------------------------------------
// Slide 2 — What is the AMD PSP?
// ---------------------------------------------------------------------------
#slide[
  = What is the AMD PSP?

  #v(0.2cm)
  #box-accent[
    The *Platform Security Processor* (PSP) is an ARM Cortex-A5 core running
    AMD's TrustZone firmware, embedded in every Ryzen/EPYC SoC.
  ]

  #v(0.2cm)
  #set text(size: 16pt)
  == Key facts

  - *Boots before x86* — initializes DRAM, releases main CPU
  - *Secure boot chain* — validates each stage (ABL0--ABL8, PSP OS, SMU FW)
  - *Opaque blobs* — in BIOS flash under `$PSP` / `$BHD` directory structure
  - *ARM TrustZone* — separate security world, inaccessible to x86 after boot
  - *Closed source* — AMD has not published PSP firmware source

  #footer[2][11]
  #note("Audience may know TrustZone from mobile (Qualcomm, ARM). Frame the PSP as the same concept on desktop/server AMD. Key insight: it executes code at a higher privilege level than any OS or hypervisor can reach. The directory structure inside a BIOS image holds 20-30 distinct blob types.")
]

// ---------------------------------------------------------------------------
// Slide 3 — Why It Matters for Security Research
// ---------------------------------------------------------------------------
#slide[
  = Why It Matters

  #set text(size: 15pt)
  #grid(
    columns: (1fr, 1fr),
    gutter: 0.6cm,
    [
      == Attack Surface
      - *Privilege escalation* — PSP bugs reachable from kernel via mailbox
      - *Persistent implants* — survives OS reinstall & full-disk encryption
      - *Supply-chain risk* — same blobs across ASUS, ASRock, MSI, Gigabyte
      - *Secure boot bypass* — breaking PSP breaks the entire trust chain
    ],
    [
      == The Auditing Problem
      - Closed-source stripped ARM binaries
      - Spread across hundreds of vendor BIOS archives
      - No unified corpus — researchers reinvent extraction
      - ~20 firmware component types per image, updated monthly
      #v(0.2cm)
      #box-accent[*psp-etl solves the corpus problem.*]
    ],
  )
  #footer[3][11]
  #note("Ground the motivation concretely. Reference: Quarkslab (2020) found vulnerabilities in PSP that allowed arbitrary code execution in the secure world. The attack surface is real. Tooling is the bottleneck.")
]

// ---------------------------------------------------------------------------
// Slide 4 — The Corpus
// ---------------------------------------------------------------------------
#slide[
  = The Corpus

  #v(0.2cm)
  #grid(
    columns: (1fr, 1fr),
    gutter: 0.8cm,
    [
      == Scale
      - *~1,200* BIOS images collected
      - *4 vendors*: ASUS, ASRock, MSI, Gigabyte
      - *2 sockets*: AM4, AM5 · *4 gens*: Zen 1--4
      - *~320k* PSP directory entries extracted
      - *~15k* unique binary blobs analyzed
    ],
    [
      == Collection method
      - Vendor CDN URLs via *Wayback Machine CDX API*
      - No authentication required
      - BIOS zips downloaded, ROM extracted
      - Content-addressed storage (SHA-256 dedup)
      - Incremental: skip already-known images
    ],
  )

  #v(0.3cm)
  #box-accent[
    Breakdown: 1118 ASUS AM4 (48 boards) · 68 ASRock AM4 · MSI + Gigabyte supported
  ]

  #footer[4][11]
  #note("The Wayback Machine CDX API returns a JSON index of crawled URLs. We query for known vendor BIOS download patterns and get historical snapshots, giving us older BIOS versions that vendors may have taken down. Content-addressing means we never store the same firmware twice.")
]

// ---------------------------------------------------------------------------
// Slide 5 — The Pipeline
// ---------------------------------------------------------------------------
#slide[
  = The Pipeline

  #v(0.2cm)
  #align(center)[
    #box(fill: rgb("#1a1d27"), inset: 8pt, radius: 4pt)[
      #text(fill: rgb("#f0a500"), size: 20pt)[
        #code[scrape] #h(0.3cm) → #h(0.3cm) #code[ingest] #h(0.3cm) → #h(0.3cm) #code[analyze] #h(0.3cm) → #h(0.3cm) #code[select]
      ]
    ]
  ]

  #v(0.2cm)
  #set text(size: 14pt)
  #grid(
    columns: (1fr, 1fr, 1fr, 1fr),
    gutter: 0.4cm,
    [
      === scrape
      - Queries CDX API
      - Downloads BIOS ZIPs
      - Extracts .rom files
      - Records metadata in DB
    ],
    [
      === ingest
      - Parses PSP directory
      - Identifies blob types
      - Content-addresses blobs
      - Inserts entries into DB
    ],
    [
      === analyze
      - Extracts strings per blob
      - Classifies: format, error, postcodes
      - Computes richness score
      - Incremental (skips known)
    ],
    [
      === select
      - Groups by (gen, type)
      - Picks highest-score blob
      - Writes `primary_images`
      - PSP-only (excludes `$BHD`)
    ],
  )

  #footer[5][11]
  #note("Each stage is a separate CLI subcommand. This means you can run them independently: add new ROMs, then re-run ingest+analyze+select. The scrape step does NOT call ingest — explicit separation means you can inspect downloaded ROMs before committing them to the DB. Total pipeline time on 1200 ROMs: 10-15 min on a modern laptop.")
]

// ---------------------------------------------------------------------------
// Slide 6 — What We Extract
// ---------------------------------------------------------------------------
#slide[
  = What We Extract

  #set text(size: 15pt)
  #grid(
    columns: (1fr, 1fr),
    gutter: 0.6cm,
    [
      == PSP Directory Structure
      - Magic: `$PSP`, `$BHD`, `$BL2`, `$PL2`
      - Each entry: type ID + offset + size + flags
      - Nested L1/L2 directories in Zen 2+
      - Encrypted entries flagged (not extractable)
      - Gen inferred from AGESA/BIOS version
    ],
    [
      == Blob Types (selected)
      #table(
        columns: (auto, 1fr),
        stroke: none,
        fill: (_, row) => if calc.odd(row) { rgb("#1a1d27") } else { none },
        inset: 4pt,
        [*ID*], [*Name*],
        [0x00], [AMD Public Key],
        [0x01], [PSP FW Boot Loader],
        [0x02], [PSP FW Trusted OS],
        [0x08], [SMU Off-Chip FW],
        [0x0c], [PSP Boot Time Trustlets],
        [0x25], [MP2 Firmware],
        [0x30–0x37], [ABL0–ABL7 (AGESA Boot Loader)],
      )
    ],
  )

  #v(0.2cm)
  #box-accent[
    Strings extracted: format strings (`%s`, `%d`), error messages (`error`, `fail`, `assert`), postcodes.
  ]

  #footer[6][11]
  #note("The PSP directory is essentially a flat table-of-contents at a fixed offset in the BIOS flash image. Type IDs are AMD-internal; mapping them to names requires reverse engineering or AMD documentation leaks. ABL (AGESA Boot Loader) stages 0-8 are the richest targets: they contain extensive debug strings because they run during early POST.")
]

// ---------------------------------------------------------------------------
// Slide 7 — The Scoring Model
// ---------------------------------------------------------------------------
#slide[
  = The Scoring Model

  #v(0.1cm)
  #box-accent[
    Goal: given many copies of "ABL5 for Zen1", pick the *most analyzable* one.
  ]

  #v(0.2cm)
  #align(center)[
    #box(fill: rgb("#1a1d27"), inset: 10pt, radius: 4pt)[
      #text(size: 14pt)[
        score = #text(fill: rgb("#f0a500"))[format\_str] × 3.0
        + #text(fill: rgb("#7ec8e3"))[func\_name] × 2.0
        + #text(fill: rgb("#9ad18a"))[error\_msg] × 2.0
        + postcode × 1.0 + descriptive × 0.5 + other × 0.1
      ]
    ]
  ]

  #v(0.15cm)
  #set text(size: 14pt)
  #grid(
    columns: (1fr, 1fr),
    gutter: 0.6cm,
    [
      == String categories (min 6 chars)
      - *format\_string*: `%` specifiers (×3.0)
      - *function\_name*: `foo()` / `AMD_*:` (×2.0)
      - *error\_message*: `ERROR`, `FAIL`, `INVALID` (×2.0)
      - *postcode*: `PSPSTATUS_` / `ABLSTATUS_` (×1.0)
      - *descriptive*: printable seqs > 20 chars (×0.5)
    ],
    [
      == Why this works
      - Older BIOS versions ship debug builds
      - Same version can be stripped vs. unstripped
      - Format strings reveal API names & arg types
      - Higher score ≈ more useful for RE / fuzzing
    ],
  )

  #footer[7][11]
  #note("The scoring is intentionally simple — interpretable and adjustable. format_strings weight is highest (3x) because they carry structured information (function names, argument types) not just raw text. Six categories with decreasing weights let us rank blobs by reverse-engineering utility.")
]

// ---------------------------------------------------------------------------
// Slide 8 — Findings
// ---------------------------------------------------------------------------
#slide[
  = Key Findings

  #set text(size: 15pt)
  #grid(
    columns: (1fr, 1fr),
    gutter: 0.6cm,
    [
      == Score Distribution
      #table(
        columns: (auto, auto, auto),
        stroke: none,
        fill: (_, row) => if calc.odd(row) { rgb("#1a1d27") } else { none },
        inset: 4pt,
        [*Gen*], [*Best blob*], [*Max score*],
        [Zen 1], [ABL6], [1161],
        [Zen 2], [ABL5], [1026],
        [Zen 3], [PSP\_FW\_BOOT\_LOADER], [517],
        [Zen 4], [PSP\_FW\_BOOT\_LOADER], [310],
        [Zen 5], [PSP\_FW\_BOOT\_LOADER], [310],
      )
      #v(0.2cm)
      - Zen 3+ ABLs *significantly more stripped*
      - Zen 1 retains 300+ format strings per blob
      - Encryption increases with newer gens
    ],
    [
      == What format strings reveal
      #box-accent[
        `"[%s:%d] DDR4 training failed: ch=%d dimm=%d"`
      ]
      #v(0.1cm)
      - Internal module names (`MemPmu`, `SocV`)
      - DRAM training phases & failure modes
      - PCIe link state machines
      - SMU power management sequences
      - Cross-vendor: same AGESA, different flags → MD5 diff
    ],
  )

  #footer[8][11]
  #note("The score cliff between Zen1 and Zen3 is a concrete, quantified finding. Zen1 was likely compiled with debug flags in production; later generations AMD tightened this. This means Zen1 ABL5/ABL6 are the best entry points for RE and fuzzing seed generation. Cross-vendor MD5 differences mean ASUS and ASRock are shipping different compiled binaries for the 'same' AGESA version — supply chain signal.")
]

// ---------------------------------------------------------------------------
// Slide 9 — Use Cases
// ---------------------------------------------------------------------------
#slide[
  = Use Cases

  #v(0.1cm)
  #set text(size: 14pt)
  #grid(
    columns: (1fr, 1fr),
    gutter: 0.6cm,
    [
      === Cross-version diffing
      Track blob changes across BIOS versions. Score delta flags stripped debug info.

      #v(0.15cm)
      === Vendor comparison
      Same AGESA, different vendor: `best --format json` gives per-type MD5 fingerprints.

      #v(0.15cm)
      === Fuzzer seed corpus
      `best --folder --export-dir seeds/` exports richest blobs. Feed into AFL++/libFuzzer.
    ],
    [
      === Attack surface mapping
      Format strings → call sites. Error msgs → code paths. Combine with Ghidra xrefs.

      #v(0.15cm)
      === Emulator seeding
      Richest ABL blobs as QEMU/panda input -- more strings = more observable behavior.

      #v(0.15cm)
      === Regression detection
      Score drops sharply for new BIOS → AMD patched something interesting.
    ],
  )

  #footer[9][11]
  #note("These use cases should map directly to your audience's existing workflows. If they already use Ghidra or AFL++, psp-etl drops in as a corpus source. The regression detection angle is particularly interesting for tracking AMD's patch cadence without access to changelogs.")
]

// ---------------------------------------------------------------------------
// Slide 10 — Live Demo
// ---------------------------------------------------------------------------
#slide[
  #v(2cm)
  #align(center)[
    #text(size: 48pt, fill: rgb("#f0a500"), weight: "bold")[Live Demo]
    #v(1cm)
    #box(fill: rgb("#1a1d27"), inset: 20pt, radius: 6pt, width: 70%)[
      #align(left)[
        #text(size: 16pt)[
          #code[\$ python3 demo.py] \
          #v(0.5cm)
          #text(fill: rgb("#888888"))[
            scrape → ingest → analyze → select → stats → query
          ]
        ]
      ]
    ]
    #v(1cm)
    #text(size: 15pt, fill: rgb("#666666"))[
      ~4 ROM files · ASRock AM4 · live Wayback Machine download
    ]
  ]
  #footer[10][11]
  #note("Run: python3 demo.py from the repo root with a clean data/ directory. The script prompts before each step so you can narrate what is happening. Expected wall time: 3-5 min depending on network (scrape is the bottleneck). If network is flaky, you can pre-populate data/roms/ and skip step 1.")
]

// ---------------------------------------------------------------------------
// Slide 11 — Future Work
// ---------------------------------------------------------------------------
#slide[
  = Future Work

  #v(0.2cm)
  #set text(size: 14pt)
  #grid(
    columns: (1fr, 1fr, 1fr),
    gutter: 0.5cm,
    [
      === Ghidra Export #text(fill: rgb("#9ad18a"), size: 11pt)[ (in progress)]
      - Headless import of best blobs
      - Export functions, xrefs, CFG
      - Store in DB alongside strings
      - Cross-version diff at IR level
    ],
    [
      === Emulator Integration
      - QEMU-based PSP emulator
      - psp-etl as corpus provider
      - Automated execution traces
      - Coverage-guided fuzzing
    ],
    [
      === Function Name Recovery
      - Scorer finds ~10k entries today
      - Improve ARM symbol heuristics
      - Match format strings to SDK calls
      - Cross-ref open AGESA source
    ],
  )

  #v(0.3cm)
  #align(center)[
    #box-accent[
      #text(size: 15pt)[
        *Repository:* #text(fill: rgb("#7ec8e3"))[github.com/AMD-PSP/psp-etl] \
        *Pipeline:* scrape · ingest · analyze · select · query · best · stats
      ]
    ]
  ]

  #footer[11][11]
  #note("The Ghidra export design doc is already in the repo (see design/ directory) and implementation is in progress. Function name recovery currently finds ~10k entries via pattern matching (foo() and AMD_*: patterns), but ARM-specific heuristics can improve recall. Emulator integration depends on community psp-emu progress — psp-etl provides the corpus regardless of which emulator matures first.")
]
