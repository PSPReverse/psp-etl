"""Ingestion and storage of re-reuse Ghidra symbol maps (schema-1).

re-reuse publishes Ghidra symbol maps as JSON keyed by ``sha256_plain`` — the
decrypted+decompressed body hash, which equals psp-etl's ``entries.blob_sha256``
(the cross-repo join key).  These maps are *external* data, not derivable from
``data/roms``, so they are stored content-addressed on the filesystem under
``data_dir/symbol_maps/`` rather than in the rebuildable ``psp-etl.db``.

The schema is frozen: re-reuse only ADDS optional top-level keys, never renames
or removes existing ones, so unknown keys are tolerated.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_MAP_SUFFIX = ".symbols.json"


def _maps_dir(data_dir: Path) -> Path:
    return data_dir / "symbol_maps"


def _parse_and_validate(raw: bytes) -> dict:
    """Parse raw map bytes and enforce the schema-1 invariants.

    Raises ValueError on malformed JSON, wrong/absent schema, or a missing or
    malformed sha256_plain.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"expected a JSON object, got {type(data).__name__}")

    schema = data.get("schema")
    if schema != 1:
        raise ValueError(f"unsupported schema {schema!r} (expected 1)")

    sha256_plain = data.get("sha256_plain")
    if not isinstance(sha256_plain, str) or not _SHA256_RE.fullmatch(sha256_plain):
        raise ValueError(f"missing or malformed sha256_plain: {sha256_plain!r}")

    return data


def store_map(data_dir: Path, json_path_or_bytes: Path | str | bytes) -> str:
    """Validate and store a schema-1 symbol map content-addressed.

    ``json_path_or_bytes`` is either a path to a JSON file or its raw bytes.
    The raw bytes are stored verbatim at
    ``data_dir/symbol_maps/{sha256_plain}.symbols.json``.  Idempotent: re-storing
    the same map overwrites it identically.  Returns the ``sha256_plain`` key.

    Raises ValueError on malformed / missing-schema / missing-key input.
    """
    if isinstance(json_path_or_bytes, bytes):
        raw = json_path_or_bytes
    else:
        raw = Path(json_path_or_bytes).read_bytes()

    data = _parse_and_validate(raw)
    sha256_plain: str = data["sha256_plain"]

    maps_dir = _maps_dir(data_dir)
    maps_dir.mkdir(parents=True, exist_ok=True)
    dest = maps_dir / f"{sha256_plain}{_MAP_SUFFIX}"
    dest.write_bytes(raw)
    logger.info("stored symbol map %s (%d bytes)", sha256_plain, len(raw))
    return sha256_plain


def load_map(data_dir: Path, sha256_plain: str) -> dict | None:
    """Return the parsed stored map for ``sha256_plain``, or None if absent."""
    path = _maps_dir(data_dir) / f"{sha256_plain}{_MAP_SUFFIX}"
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    return json.loads(raw)


def iter_maps(data_dir: Path) -> Iterator[tuple[str, dict]]:
    """Yield ``(sha256_plain, parsed)`` for every stored map, sorted by key."""
    maps_dir = _maps_dir(data_dir)
    if not maps_dir.is_dir():
        return
    for path in sorted(maps_dir.glob(f"*{_MAP_SUFFIX}")):
        sha256_plain = path.name[: -len(_MAP_SUFFIX)]
        try:
            data = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("skipping unreadable symbol map %s: %s", path.name, exc)
            continue
        yield sha256_plain, data


def function_boundaries(map_dict: dict) -> list[tuple[int, int, str]]:
    """Flatten ``functions[].ranges`` into ``(start, end, name)`` tuples.

    A function may own several discontiguous address ranges; each becomes its own
    tuple carrying the function's name.  This is the accessor the DrCov
    coverage-overlay consumes.
    """
    boundaries: list[tuple[int, int, str]] = []
    for func in map_dict.get("functions", []):
        name = func.get("name", "")
        for rng in func.get("ranges", []):
            start, end = rng[0], rng[1]
            boundaries.append((start, end, name))
    return boundaries
