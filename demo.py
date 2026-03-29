#!/usr/bin/env python3
"""
psp-etl interactive pipeline demo.

Run from the repo root with a clean data/ directory.
psp-etl must be installed and on PATH.

Each step prints a header, shows the exact command, waits for Enter,
streams the command output live, then prints a one-line summary.
Press 'q' + Enter at any prompt to quit.
"""

import os
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
DIM = "\033[2m"


def _print_header(step_num: int, total: int, title: str, description: str, cmd: list[str]) -> None:
    bar = "─" * 60
    print(f"\n{BOLD}{YELLOW}{bar}{RESET}")
    print(f"{BOLD}Step {step_num}/{total}: {title}{RESET}")
    print(f"{DIM}{description}{RESET}")
    print(f"\n  {CYAN}$ {' '.join(cmd)}{RESET}")
    print(f"{BOLD}{YELLOW}{bar}{RESET}")


def _prompt_continue() -> bool:
    """Return True to proceed, False to quit."""
    try:
        answer = input(f"\n{BOLD}Press Enter to run, or 'q' to quit: {RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer != "q"


def _run(cmd: list[str]) -> tuple[int, str]:
    """Stream command output live; return (returncode, combined stderr)."""
    stderr_lines: list[str] = []
    proc = subprocess.Popen(
        cmd,
        stdout=sys.stdout.fileno(),
        stderr=subprocess.PIPE,
        text=True,
    )
    # Stream stderr to terminal and capture it
    assert proc.stderr is not None
    for line in proc.stderr:
        sys.stderr.write(line)
        sys.stderr.flush()
        stderr_lines.append(line)
    proc.wait()
    return proc.returncode, "".join(stderr_lines)


def _run_captured(cmd: list[str]) -> tuple[int, str, str]:
    """Run command, capture both stdout and stderr, return (rc, stdout, stderr)."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def _ok(msg: str) -> None:
    print(f"\n{GREEN}{BOLD}✓ {msg}{RESET}")


def _warn(msg: str) -> None:
    print(f"\n{YELLOW}{BOLD}⚠ {msg}{RESET}")


def _error_ask(stderr: str) -> bool:
    """Print stderr excerpt and ask whether to continue. Returns True to continue."""
    print(f"\n{RED}{BOLD}Command exited non-zero.{RESET}")
    if stderr.strip():
        lines = stderr.strip().splitlines()
        print(f"{RED}--- stderr (last 10 lines) ---{RESET}")
        for line in lines[-10:]:
            print(f"  {RED}{line}{RESET}")
    try:
        answer = input(f"\n{BOLD}Continue anyway? [y/N]: {RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer == "y"


# ---------------------------------------------------------------------------
# Step definitions
# ---------------------------------------------------------------------------

DATA_DIR = "data"


STEPS: list[dict] = [
    {
        "title": "Scrape",
        "description": (
            "Download BIOS images from ASRock's CDN via the Wayback Machine CDX API.\n"
            "  Fetches ~2 boards, ~2–4 ROM files. No authentication required.\n"
            "  Creates data/ and data/roms/ automatically."
        ),
        "cmd": ["psp-etl", "--data-dir", DATA_DIR, "scrape", "asrock", "--socket", "am4", "--limit", "2"],
        "summary_fn": lambda rc, stderr: _summarize_scrape(rc),
    },
    {
        "title": "Ingest",
        "description": (
            "Parse all .rom files in data/roms/, extract PSP directory entries and blobs.\n"
            "  Already-ingested ROMs are skipped via INSERT OR IGNORE.\n"
            "  This is the slowest step (~5–8 min for 1200 ROMs; fast for 4)."
        ),
        "cmd": ["psp-etl", "--data-dir", DATA_DIR, "ingest", f"{DATA_DIR}/roms/"],
        "summary_fn": lambda rc, stderr: _summarize_ingest(rc),
    },
    {
        "title": "Analyze",
        "description": (
            "Run string analysis on all unanalyzed blobs.\n"
            "  Extracts: total strings, format strings (%s/%d), error messages, postcodes.\n"
            "  Computes a richness score per blob. Skips already-analyzed blobs."
        ),
        "cmd": ["psp-etl", "--data-dir", DATA_DIR, "analyze"],
        "summary_fn": lambda rc, stderr: _summarize_analyze(rc, stderr),
    },
    {
        "title": "Select",
        "description": (
            "Recompute primary image selections: best (highest-score) blob per (gen, type).\n"
            "  PSP-only: excludes $BHD/$BL2 BIOS-side entries.\n"
            "  Writes results to the primary_images table."
        ),
        "cmd": ["psp-etl", "--data-dir", DATA_DIR, "select"],
        "summary_fn": lambda rc, stderr: _summarize_select(rc),
    },
    {
        "title": "Stats",
        "description": (
            "Show a per-generation summary dashboard:\n  images per vendor, entries per generation, score distribution."
        ),
        "cmd": ["psp-etl", "--data-dir", DATA_DIR, "stats"],
        "summary_fn": lambda rc, stderr: _ok("Stats displayed.") if rc == 0 else _warn("Stats command failed."),
    },
    {
        "title": "Query",
        "description": (
            "Query the database for PSP-only entries (excludes $BHD/$BL2).\n"
            "  Shows type, version, generation, vendor, and score."
        ),
        "cmd": ["psp-etl", "--data-dir", DATA_DIR, "query", "--psp-only", "--has-strings"],
        "summary_fn": lambda rc, stderr: _ok("Query complete.") if rc == 0 else _warn("Query failed."),
    },
]


# ---------------------------------------------------------------------------
# Per-step summary helpers
# ---------------------------------------------------------------------------


def _summarize_scrape(rc: int) -> None:
    if rc != 0:
        _warn("Scrape exited non-zero — check output above.")
        return
    roms_dir = Path(DATA_DIR) / "roms"
    if roms_dir.exists():
        count = sum(1 for f in roms_dir.iterdir() if f.is_file())
        _ok(f"Scrape complete. {count} ROM file(s) in {roms_dir}/")
    else:
        _warn("Scrape finished but data/roms/ not created — may be a dry run or error.")


def _summarize_ingest(rc: int) -> None:
    if rc != 0:
        _warn("Ingest exited non-zero — check output above.")
        return
    _ok("Ingest complete. PSP entries and blobs written to database.")


def _summarize_analyze(rc: int, stderr: str) -> None:
    if rc != 0:
        _warn("Analyze exited non-zero — check output above.")
        return
    _ok("Analysis complete. String richness scores written to database.")


def _summarize_select(rc: int) -> None:
    if rc != 0:
        _warn("Select exited non-zero — check output above.")
        return
    _ok("Selection complete. primary_images table updated.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  psp-etl Interactive Pipeline Demo{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"""
{DIM}This script walks through the full psp-etl pipeline step by step.
Each step shows the exact command and waits for your confirmation.

Requirements:
  - psp-etl installed and on PATH
  - Clean data/ directory (or no data/ directory at all)
  - Internet access (step 1 uses Wayback Machine CDX API)

{YELLOW}NOTE: This will create/modify {DATA_DIR}/ in the current directory.{RESET}
{DIM}If data/ already contains existing ROMs, scrape will skip duplicates
and ingest will skip already-ingested ROMs.{RESET}
""")

    total = len(STEPS)
    for i, step in enumerate(STEPS, start=1):
        _print_header(i, total, step["title"], step["description"], step["cmd"])

        if not _prompt_continue():
            print(f"\n{YELLOW}Quit at step {i}/{total}.{RESET}")
            return 0

        print()
        rc, stderr = _run(step["cmd"])

        step["summary_fn"](rc, stderr)

        if rc != 0:
            if not _error_ask(stderr):
                print(f"\n{YELLOW}Aborted after step {i}/{total}.{RESET}")
                return rc

    print(f"\n{BOLD}{GREEN}{'═' * 60}{RESET}")
    print(f"{BOLD}{GREEN}  All steps complete!{RESET}")
    print(f"{BOLD}{GREEN}{'═' * 60}{RESET}")
    print(f"""
{DIM}Next steps:
  psp-etl --data-dir {DATA_DIR} best --gen zen1
  psp-etl --data-dir {DATA_DIR} best --folder --format json
  psp-etl --data-dir {DATA_DIR} best --export-dir seeds/
  psp-etl --data-dir {DATA_DIR} query --gen zen1 --has-strings --format csv{RESET}
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
