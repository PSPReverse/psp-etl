# Feature: Ghidra MCP Server

## Summary

An HTTP-based MCP server that bridges Claude Code to a running Ghidra instance, enabling interactive reverse engineering of PSP firmware blobs. The server exposes Ghidra operations as MCP tools, allowing Claude Code to import blobs, trigger analysis, query functions/strings, and run scripts without manual GUI interaction.

## Requirements

- REQ-1: A new `psp-etl mcp-server` CLI subcommand starts an HTTP MCP server on a configurable port (default 8100).
- REQ-2: The MCP server exposes tools for importing blobs into Ghidra, listing programs, triggering analysis, querying functions/strings, and running post-analysis scripts.
- REQ-3: Ghidra connection settings are read from `~/.config/psp-etl/connections.toml` (same format as #16), supporting both `password` and `password_command`.
- REQ-4: Claude Code connects via `.mcp.json` pointing to `http://localhost:8100/mcp`.
- REQ-5: The server validates all blob paths against the `data/blobs/` directory (no arbitrary file access).
- REQ-6: The server provides a `ghidra_status` health-check tool that verifies the Ghidra connection is alive.

## Acceptance Criteria

- [ ] AC-1 (REQ-1): `psp-etl mcp-server --port 8100` starts a Streamable HTTP MCP server; `curl http://localhost:8100/mcp` returns an MCP-compatible response.
- [ ] AC-2 (REQ-2): Claude Code can call `ghidra_import` to import a blob by sha256 and receive confirmation with the Ghidra program path.
- [ ] AC-3 (REQ-2): Claude Code can call `ghidra_list_programs` and receive a JSON list of programs already in the Ghidra project.
- [ ] AC-4 (REQ-2): Claude Code can call `ghidra_get_functions` for a program and receive a list of function names, addresses, and sizes.
- [ ] AC-5 (REQ-3): If `password_command` is set, the server runs it at startup and uses the result for all `analyzeHeadless` invocations.
- [ ] AC-6 (REQ-5): `ghidra_import` with a blob_sha256 not present in `data/blobs/` returns an error, not a path traversal.
- [ ] AC-7 (REQ-6): `ghidra_status` returns `{"ok": true, "server": "...", "project": "..."}` when the connection is valid.

## Architecture

### Ghidra integration approach: `analyzeHeadless`

Three options were evaluated:

| Approach | Pros | Cons |
|---|---|---|
| `analyzeHeadless` (subprocess) | No runtime dependency on Ghidra GUI; works with Ghidra Server; battle-tested | Heavyweight per invocation (~5-10s JVM startup); batch-oriented |
| `ghidra_bridge` (RPC to running Ghidra) | Fine-grained API; low latency per call; interactive | Requires Ghidra GUI running; fragile Jython RPC proxy; security concerns |
| `pyhidra`/`pyghidra` (embedded via JPype) | Native CPython; full API access; no GUI needed | Embeds entire JVM; classpath/version coupling; not designed for server use |

**Recommendation: `analyzeHeadless`** for import and analysis operations (reuses #16 infrastructure), with a thin **post-analysis script** (`ExportMetadata.java`) that dumps functions/strings/xrefs to JSON for query tools. This avoids runtime coupling to a Ghidra GUI and keeps the MCP server stateless with respect to Ghidra.

Query tools (`ghidra_get_functions`, `ghidra_get_strings`) read from cached JSON metadata files produced by the analysis step, not from a live Ghidra connection. This makes queries fast and avoids per-query JVM startup.

<!-- OPEN: Q1 -->
### Q1: Live Ghidra queries vs cached metadata
The current design caches analysis output as JSON. An alternative is using `ghidra_bridge` for live queries against a running Ghidra instance, which would allow renaming functions, adding comments, etc. This would be more powerful but adds a hard dependency on a running Ghidra GUI with the bridge plugin loaded.

**To resolve**: Start with `analyzeHeadless` + cached metadata. If interactive rename/comment workflows prove valuable, add an optional `ghidra_bridge` backend behind the same MCP tool interface.
<!-- /OPEN -->

### MCP transport

Use **Streamable HTTP** (not SSE, which is deprecated). The server uses the `mcp` Python SDK's `FastMCP` with `transport="http"`.

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("psp-etl-ghidra", stateless_http=True)
```

Claude Code configuration (`.mcp.json` at project root):

```json
{
  "mcpServers": {
    "psp-etl-ghidra": {
      "type": "http",
      "url": "http://localhost:8100/mcp"
    }
  }
}
```

### MCP tools

| Tool | Description | Backend |
|---|---|---|
| `ghidra_status` | Health check: verify connection, return server/project info | No-op `analyzeHeadless` probe |
| `ghidra_import` | Import a blob by sha256 into the Ghidra project | `analyzeHeadless -import` + `ExportMetadata.java` postScript |
| `ghidra_analyze` | Re-run analysis on an already-imported program | `analyzeHeadless -process` + `ExportMetadata.java` postScript |
| `ghidra_list_programs` | List programs in the Ghidra project | `analyzeHeadless -process` with `ListPrograms.java` |
| `ghidra_get_functions` | Query functions (name, address, size) for a program | Read cached metadata JSON |
| `ghidra_get_strings` | Query defined strings for a program | Read cached metadata JSON |
| `ghidra_run_script` | Run a named script from `data/ghidra_scripts/` on a program | `analyzeHeadless -process -postScript` |

#### `ghidra_import` (primary tool, shown in detail)

Input: `blob_sha256` (required), `program_name`, `load_address`, `processor` (all optional, defaults from DB + `ARM:LE:32:v7` + `0x0`).

Output: `{ "program_path": str, "analysis_complete": bool, "error": str|null }`

Under the hood:
```sh
analyzeHeadless ghidra://{server}/{repo} {project} \
  -connect {server} -p {password} \
  -import data/blobs/{blob_sha256}.bin \
  -processor ARM:LE:32:v7 \
  -loader BinaryLoader -loader-baseAddress {load_address} \
  -analysisTimeoutPerFile 300 \
  -postScript ExportMetadata.java {metadata_output_dir}
```

#### `ghidra_get_functions` / `ghidra_get_strings` (query tools)

Input: `program_path` (required), plus optional filters (`min_size`, `name_filter`, `min_length`).

These read from cached JSON metadata (see below), not from a live Ghidra connection. Zero JVM startup cost.

#### `ghidra_run_script`

Input: `program_path`, `script_name` (validated: `^[a-zA-Z0-9_-]+\.(java|py)$`), `script_args[]`.

Output: `{ "stdout": str, "stderr": str, "exit_code": int }`

<!-- OPEN: Q2 -->
### Q2: Script allowlist
Should `ghidra_run_script` allow any `.java`/`.py` script in the scripts directory, or should it maintain an explicit allowlist of safe scripts? An allowlist prevents Claude from running arbitrary code through Ghidra, but limits flexibility.

**To resolve**: Start with directory-scoped (scripts must be in `data/ghidra_scripts/`). Add an allowlist if the threat model warrants it.
<!-- /OPEN -->

### Metadata cache

`ExportMetadata.java` is a Ghidra postScript run after import/analyze. It writes JSON to `data/ghidra_metadata/{program_path_hash}.json` containing: function list (name, address, size, calling convention), string list (address, value, length), and a timestamp. Query tools read these files directly.

### File layout

New files inside `src/psp_etl/`:

```
src/psp_etl/
  mcp_server.py          -- FastMCP server definition, tool handlers
  export/
    __init__.py
    ghidra.py             -- analyzeHeadless wrapper (shared with #16)
    connections.py        -- connections.toml parser (shared with #16)
data/
  ghidra_scripts/         -- Ghidra Java/Python scripts (ExportMetadata.java, etc.)
  ghidra_metadata/        -- cached JSON metadata per program
```

The MCP server lives inside `src/psp_etl/` (not a separate `tools/` directory) because it shares the database, blob paths, and export infrastructure. It is exposed as a CLI subcommand:

```python
@cli.command("mcp-server")
@click.option("--port", default=8100, show_default=True)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.pass_context
def mcp_server(ctx, port, host):
    """Start the Ghidra MCP server for Claude Code integration."""
    from psp_etl.mcp_server import create_server
    server = create_server(ctx.obj["data_dir"])
    server.run(transport="http", host=host, port=port)
```

Also runnable as `python -m psp_etl.mcp_server` for convenience.

### Dependencies

New packages added to `pyproject.toml` under an `mcp` optional dependency group:

```toml
[project.optional-dependencies]
mcp = ["mcp>=1.8"]
```

The `mcp` package pulls in `uvicorn`, `starlette`, and `httpx-sse`. No additional dependencies needed.

### Connections file

Reuses `~/.config/psp-etl/connections.toml` from #16 (same `[ghidra]` + `[ghidra.auth]` format with `password` or `password_command`). The MCP server resolves `password_command` once at startup and caches the result. `GHIDRA_HEADLESS` env var provides the `analyzeHeadless` path.

### Integration with #16 (`psp-etl export ghidra`)

The MCP server and `export ghidra` share the same `export/ghidra.py` wrapper and `export/connections.py` parser. They are independent entry points to the same underlying machinery:

- `export ghidra <image-name>` is the batch path: import all components from an image in one shot.
- MCP tools are the interactive path: import/query individual blobs on demand from Claude Code.

The `--dry-run` flag on `export ghidra` remains useful for scripting/CI; the MCP server does not replace it. The MCP server does not call `export ghidra` internally; both call `export.ghidra.run_headless()`.

<!-- OPEN: Q3 -->
### Q3: MCP server access to the psp-etl database
Should MCP tools like `ghidra_import` accept a `blob_sha256` and look up the entry's `load_address` from the database automatically? This would simplify the Claude Code workflow (just pass a sha256, the server fills in processor/load_address from the DB). But it couples the MCP server to the database schema.

**To resolve**: Implement DB lookup as the default behavior; allow explicit overrides via tool parameters. The DB is read-only from the MCP server's perspective, so coupling is acceptable.
<!-- /OPEN -->

## Security Considerations

- **Localhost only**: The server binds to `127.0.0.1` by default. Binding to `0.0.0.0` requires an explicit `--host` flag.
- **Blob path validation**: `ghidra_import` constructs blob paths as `data/blobs/{sha256}.bin` where `sha256` is validated as `^[a-f0-9]{64}$`. No user-supplied path components reach the filesystem.
- **Script directory scoping**: `ghidra_run_script` only runs scripts from `data/ghidra_scripts/`. The `script_name` parameter is validated against `^[a-zA-Z0-9_-]+\.(java|py)$` (no path separators).
- **`password_command` execution**: Runs via `subprocess.run(shell=True)` at startup only, not per-request. Same trust model as #16.
- **`analyzeHeadless` subprocess**: Invoked with controlled arguments; no user-supplied strings are interpolated into shell commands (use `subprocess.run(args_list)`, not `shell=True`).

## Out of Scope

- Live Ghidra GUI integration via `ghidra_bridge` (deferred; see Q1)
- MCP resources or prompts (tools only for now)
- Authentication on the MCP server itself (localhost-only; add if remote deployment is needed)
- Automated firmware knowledge application during MCP import (use `export ghidra` for that workflow)
- Multi-user/concurrent access to the Ghidra project
