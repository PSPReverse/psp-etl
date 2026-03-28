# Feature: Ghidra Export

## Summary
Export complete PSP firmware images — all components from a single coherent image — to a Ghidra Server project via `analyzeHeadless`. Each component becomes a separate Ghidra program in a per-image project folder, with correct load addresses, known entry points, and extracted symbols applied automatically.

## Requirements

- REQ-1: A new `psp-etl images` command lists all images with a human-readable name (`{vendor}/{model}/{bios_version}`), aggregate string score, and sha256 prefix.
- REQ-2: A new `psp-etl show <path>` command displays full metadata for a specific firmware entry identified by `<image-name>/<directory_magic>/<type_id_hex>`, including load address, blob sha256, score, and whether a Ghidra program exists for it.
- REQ-3: `psp-etl export ghidra <image-name>` imports all non-encrypted components from the named image into the configured Ghidra Server project, one Ghidra program per component.
- REQ-4: Each Ghidra program is imported with `ARM:LE:32:v7` processor spec and the `load_address` from `entries.load_address` (PSPTool-provided). Components where `load_address IS NULL` are imported at `0x0` with a plate comment noting the address is unresolved (VMM-stage).
- REQ-5: When a firmware knowledge file (see `firmware-knowledge-toml.md`) matches the image, its entry points, memory map, and symbols are applied as a Ghidra post-analysis script.
- REQ-6: Strings from the `strings` table for each component's blob are pushed into the Ghidra program as pre-comments or labels at the matching addresses (where the string appears as a literal in the binary).
- REQ-7: Ghidra connection settings are read from a connections file (`~/.config/psp-etl/connections.toml`) supporting both a plain `password` field and a `password_command` field (shell-invoked to retrieve the password dynamically).
- REQ-8: A `--dry-run` flag prints the `analyzeHeadless` invocations that would be executed without running them.
- REQ-9: Image names are resolvable from both full `{vendor}/{model}/{bios_version}` form and sha256 prefix (minimum 6 hex chars).

## Acceptance Criteria

- [ ] AC-1 (REQ-1): `psp-etl images --gen zen2` produces a table with columns: name, sha256[:12], component count, aggregate score; rows are sorted by aggregate score descending.
- [ ] AC-2 (REQ-2): `psp-etl show asus/prime-x570-pro/3402/$PSP/0x08` prints load_address, blob_sha256, version, score, encrypted flag, and Ghidra program path (or "not exported" if absent).
- [ ] AC-3 (REQ-2): Sha prefix form `psp-etl show abc123/$PSP/0x08` resolves to the same entry as the full name form (when unambiguous).
- [ ] AC-4 (REQ-3): After `psp-etl export ghidra <image-name>`, the Ghidra Server project contains one program per non-encrypted entry from that image, named `<image-name>/<type_name>_<version>`.
- [ ] AC-5 (REQ-4): Components with `load_address IS NULL` produce a Ghidra program imported at base address `0x0` with a plate comment containing "VMM-stage: load address unknown".
- [ ] AC-6 (REQ-5): When a matching knowledge file exists, `analyzeHeadless` is invoked with a `-postScript` argument; the script applies the memory map regions and entry points from the file.
- [ ] AC-7 (REQ-7): If `password_command` is set in `connections.toml`, it is executed via `subprocess.run(shell=True)` and its stdout used as the password; plain `password` is used otherwise.
- [ ] AC-8 (REQ-8): `psp-etl export ghidra <image-name> --dry-run` prints `[DRY-RUN]`-prefixed `analyzeHeadless` command lines to stdout without executing any.
- [ ] AC-9 (REQ-9): Ambiguous sha prefix (matches more than one image) raises a `ClickException` naming the colliding images.

## Architecture

### New files

`src/psp_etl/export/` package (new):
- `__init__.py` — re-exports public surface
- `ghidra.py` — `analyzeHeadless` wrapper; builds invocation, calls subprocess, handles auth
- `connections.py` — parses `~/.config/psp-etl/connections.toml`; exposes `GhidraConnection` dataclass with `server: str`, `project: str`, `password: str` (resolved from either field)

`src/psp_etl/knowledge.py` (new, shared with emulator export) — loads and resolves firmware knowledge TOML files; see `firmware-knowledge-toml.md` for format spec.

### Modified files

`src/psp_etl/cli.py` — three new commands added to the existing `@click.group()`:
- `images` — queries `images` + `entries` + `string_analysis`; computes aggregate score as `AVG(sa.score)` across all entries for the image
- `show` — parses `<path>` argument, resolves image name or sha prefix via new `db.resolve_image()` helper, fetches entry by `(directory_magic, type_id)`
- `export` — new `@cli.group()` subgroup; `export ghidra` subcommand

`src/psp_etl/db.py` — new query methods:
- `list_images_with_scores(gen, socket)` — returns images joined with per-image aggregate score
- `resolve_image(name_or_sha)` — resolves `{vendor}/{model}/{bios_version}` or sha prefix to image row
- `get_entries_for_image(image_id)` — returns all entries for an image sorted by type_id

### Ghidra invocation

`analyzeHeadless` is invoked once per component (not once per image). A combined-image approach (one program with N memory blocks) is deferred because `analyzeHeadless` does not support multi-block import natively without a custom loader script.

```
analyzeHeadless \
  ghidra://{server}/{repo} \
  {project_path} \
  -connect {server} \
  -p {password} \
  -import {blob_path} \
  -processor ARM:LE:32:v7 \
  -loader BinaryLoader \
  -loader-baseAddress {load_address} \
  -analysisTimeoutPerFile 300 \
  [-postScript ApplyKnowledge.java {knowledge_json_path}]
```

The `GHIDRA_HEADLESS` env var (injected by Nix wrapper) provides the path to the `analyzeHeadless` binary; falls back to `analyzeHeadless` on PATH.

### Connections file

Location: `~/.config/psp-etl/connections.toml`

```toml
[ghidra]
server = "ghidra://raspi/PSPResearch"
project = "zen2-ryzen"

[ghidra.auth]
# Exactly one of password or password_command must be set
password = "hunter2"
# password_command = "pass psp-etl/ghidra"
```

`password_command` is run via `subprocess.run(cmd, shell=True, capture_output=True)` with its stripped stdout used as the password.

### Path syntax

`<image-name>/<directory_magic>/<type_id_hex>`

- `<image-name>`: `{vendor}/{model}/{bios_version}` or sha256 prefix (≥6 chars)
- `<directory_magic>`: `$PSP`, `$BHD`, `$BL2`, etc. (as stored in `entries.directory_magic`)
- `<type_id_hex>`: `0x08`, `0x01`, etc. (parsed with `int(..., 16)`)

## Open Questions

<!-- OPEN: Q1 -->
### Q1: Combined program vs per-component programs
Current design imports one Ghidra program per component. A single program with N memory blocks would allow true cross-component references (FP table pointer → next-stage code). This requires either a custom Ghidra loader script or pre-assembling a sparse memory image.

**To resolve**: After initial per-component export is working and you've validated load addresses from OCB reversing, decide whether to invest in a combined-image loader.
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: Ghidra program naming / deduplication
If the same component version exists in multiple images, `analyzeHeadless` will create duplicate programs with the same blob content. Should we check for an existing program by blob sha256 before importing?

**To resolve**: Decide whether to skip re-import of already-present blob sha256 (requires querying Ghidra project contents, which needs the REST API or a probe script) or always import and let Ghidra version them.
<!-- /OPEN -->

## Out of Scope

- MSI scraper integration
- Automatic FP table parsing to discover cross-stage load addresses (deferred; depends on OCB reversing completing)
- Combined multi-block Ghidra program import (deferred; see Q1)
- Ghidra REST API integration (use `analyzeHeadless` only)
- Address variance tracking across boards (belongs in emulator export design)
