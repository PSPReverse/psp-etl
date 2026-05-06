# AGENTS.md — psp-etl

This file gives coding agents (and humans) the context they need to work
in this repository. It is intentionally short.

## What this repo is

This repo holds **two mostly independent codebases** under one git tree:

1. **`psp-etl`** — a Python 3.12 CLI tool for extracting, transforming, and
   loading AMD PSP firmware. It scrapes motherboard vendor websites for BIOS
   updates, parses ROMs with [PSPTool](https://github.com/PSPReverse/PSPTool),
   extracts PSP firmware blobs, runs string analysis, and ranks images by
   debug-symbol richness.
   - Source: `src/psp_etl/`
   - Tests: `tests/`
   - Entry point: `psp-etl` (defined in `pyproject.toml` → `cli:cli`)

2. **`ghidra_scripts/`** — a library of Ghidra/Java scripts for analysing the
   PSP blobs that `psp-etl` extracts. Intended to run inside Ghidra
   (interactively or via `analyzeHeadless`). It builds on the firmware corpus
   produced by `psp-etl` but is otherwise independent.
   - Source: `ghidra_scripts/`
   - See `ghidra_scripts/README.md` for the full pipeline.

The two halves share a corpus (`data/`) but no code. Changes to one rarely
require changes to the other.

## Quick reference: commands

```sh
# Enter the Nix dev shell (Python 3.12 + ruff + uv + actionlint + npins)
nix-shell -A shell

# Inside the shell:
uv venv .venv && uv sync --extra dev   # one-time setup
.venv/bin/pytest                       # run all tests (~5 s)
.venv/bin/ruff check .                 # lint
.venv/bin/ruff format --check .        # format check

# Build the package
nix-build -A psp-etl
./result/bin/psp-etl --help
```

## Conventions

### Python (psp-etl)

- **Python 3.12+ only.** Use modern syntax: `str | None`, `list[T]`,
  `from __future__ import annotations` is allowed but not required.
- **No bare `except:` or `except Exception:`.** Catch the specific exception.
  If you genuinely need a broad catch (e.g. wrapping a library call whose
  exception types are undocumented), log it and add `# noqa: BLE001` with a
  reason. Ruff `BLE` rules are enforced in CI.
- **Logging, not `print`, in library code.** `logging.getLogger(__name__)`
  at module top. CLI code (`cli.py`) uses `rich.console` for user-facing
  output and reserves logging for diagnostics.
- **Docstrings** on public functions and classes only — type hints carry
  most of the load. Don't restate types in prose.
- **No comments restating the code.** Only write comments where the *why*
  is non-obvious (a hidden constraint, a workaround for a specific upstream
  bug, an invariant that would surprise the reader).
- **Content-addressed storage.** ROM and blob files are stored under
  `data/{roms,blobs}/{sha256}.{rom,bin}`. Don't embed user-facing names —
  resolve to human-readable labels (vendor/model/version/type_name) at the
  presentation layer.

### SQL (psp-etl)

- All SQL lives in `src/psp_etl/db.py`. Other modules call `Database`
  methods, never raw SQL.
- **Parameterised queries only.** Never string-format user input into SQL.

### Ghidra scripts

- Each script extends `GhidraScript` and works under both the Ghidra
  Script Manager and `analyzeHeadless`.
- Use `//@category PSP.<Subcategory>` so scripts cluster under a single
  **PSP** node in the Script Manager tree.
- Layout under `ghidra_scripts/` is by purpose:
  `analysis/`, `transfer/`, `import_export/`, `setup/`, `project/`,
  `diagnostics/`. Pick the right home for new scripts.
- Read-only inspection scripts go in `diagnostics/`. Anything that mutates
  a program goes elsewhere.

## Where things live

| What | Where |
|------|-------|
| Python source | `src/psp_etl/` |
| Python tests | `tests/` |
| Ghidra scripts | `ghidra_scripts/` |
| Architecture decisions | `.design/*.md` |
| Issue tracker (local) | crosslink — `crosslink issue list` |
| Build (Python) | `default.nix`, `pyproject.toml` |
| CI | `.github/workflows/ci.yml` |
| Runtime data (gitignored) | `data/` — DB, ROMs, blobs, Ghidra projects |

## Notes for agents

- The data directory is **never** committed. It can grow into the GBs.
  Don't add files under `data/` to git.
- `*.gdt` (Ghidra Data Type archives) are gitignored — some are
  proprietary (SECT) and must not ship.
- This project lived inside a larger `AMD-PSP/` workspace during early
  development; any reference to a `research/` symlink is **legacy** and
  should be removed when encountered.
- Crosslink is the source of truth for open work. Use `crosslink issue
  list -s open` before starting; create new issues for non-trivial work.
