"""Tests for symbol-map ingestion (psp_etl.symbol_maps) and its CLI commands."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from psp_etl import symbol_maps
from psp_etl.cli import cli
from psp_etl.db import Database, Entry, Image

FIXTURES = Path(__file__).parent / "fixtures"
ZEN2_SHA = "6f94447d17591665750c58aabbac2580c9d640d5c7bd240e3f6911472c9b45f7"
ZEN3_SHA = "e4c4e05ad3f00f38b08dd4c6b3bf6c1c98c78c5a9b5e3245ed4d320d1d295dee"
ZEN2_MAP = FIXTURES / f"{ZEN2_SHA}.symbols.json"
ZEN3_MAP = FIXTURES / f"{ZEN3_SHA}.symbols.json"


@pytest.fixture
def runner():
    return CliRunner()


# ---------------------------------------------------------------------------
# store_map / load_map
# ---------------------------------------------------------------------------


def test_store_returns_sha256_plain(tmp_path):
    assert symbol_maps.store_map(tmp_path, ZEN2_MAP) == ZEN2_SHA


def test_store_content_addressed_path(tmp_path):
    symbol_maps.store_map(tmp_path, ZEN2_MAP)
    dest = tmp_path / "symbol_maps" / f"{ZEN2_SHA}.symbols.json"
    assert dest.is_file()


def test_store_bytes_verbatim(tmp_path):
    raw = ZEN2_MAP.read_bytes()
    symbol_maps.store_map(tmp_path, raw)
    dest = tmp_path / "symbol_maps" / f"{ZEN2_SHA}.symbols.json"
    assert dest.read_bytes() == raw


def test_store_load_round_trip(tmp_path):
    for fixture in (ZEN2_MAP, ZEN3_MAP):
        symbol_maps.store_map(tmp_path, fixture)
    loaded = symbol_maps.load_map(tmp_path, ZEN2_SHA)
    assert loaded["schema"] == 1
    assert loaded["sha256_plain"] == ZEN2_SHA
    assert len(loaded["functions"]) == 4


def test_store_is_idempotent(tmp_path):
    symbol_maps.store_map(tmp_path, ZEN2_MAP)
    symbol_maps.store_map(tmp_path, ZEN2_MAP)
    assert symbol_maps.load_map(tmp_path, ZEN2_SHA)["sha256_plain"] == ZEN2_SHA


def test_load_missing_returns_none(tmp_path):
    assert symbol_maps.load_map(tmp_path, "0" * 64) is None


def test_store_tolerates_optional_keys(tmp_path):
    """name_source / name_transfer are optional extras that must survive."""
    symbol_maps.store_map(tmp_path, ZEN2_MAP)
    loaded = symbol_maps.load_map(tmp_path, ZEN2_SHA)
    assert loaded["name_source"] == "synthetic-test-fixture"
    assert "name_transfer" in loaded


def test_store_tolerates_unknown_top_level_key(tmp_path):
    raw = json.dumps({"schema": 1, "sha256_plain": "a" * 64, "functions": [], "brand_new_field": 42}).encode()
    sha = symbol_maps.store_map(tmp_path, raw)
    assert symbol_maps.load_map(tmp_path, sha)["brand_new_field"] == 42


# ---------------------------------------------------------------------------
# rejection paths
# ---------------------------------------------------------------------------


def test_reject_wrong_schema(tmp_path):
    raw = json.dumps({"schema": 2, "sha256_plain": "a" * 64}).encode()
    with pytest.raises(ValueError, match="schema"):
        symbol_maps.store_map(tmp_path, raw)


def test_reject_missing_schema(tmp_path):
    raw = json.dumps({"sha256_plain": "a" * 64}).encode()
    with pytest.raises(ValueError, match="schema"):
        symbol_maps.store_map(tmp_path, raw)


def test_reject_missing_sha256_plain(tmp_path):
    raw = json.dumps({"schema": 1}).encode()
    with pytest.raises(ValueError, match="sha256_plain"):
        symbol_maps.store_map(tmp_path, raw)


def test_reject_malformed_sha256_plain(tmp_path):
    raw = json.dumps({"schema": 1, "sha256_plain": "NOThex"}).encode()
    with pytest.raises(ValueError, match="sha256_plain"):
        symbol_maps.store_map(tmp_path, raw)


def test_reject_uppercase_sha256_plain(tmp_path):
    raw = json.dumps({"schema": 1, "sha256_plain": "A" * 64}).encode()
    with pytest.raises(ValueError, match="sha256_plain"):
        symbol_maps.store_map(tmp_path, raw)


def test_reject_invalid_json(tmp_path):
    with pytest.raises(ValueError, match="JSON"):
        symbol_maps.store_map(tmp_path, b"{not json")


# ---------------------------------------------------------------------------
# iter_maps / function_boundaries
# ---------------------------------------------------------------------------


def test_iter_maps_empty(tmp_path):
    assert list(symbol_maps.iter_maps(tmp_path)) == []


def test_iter_maps_yields_all(tmp_path):
    symbol_maps.store_map(tmp_path, ZEN2_MAP)
    symbol_maps.store_map(tmp_path, ZEN3_MAP)
    got = dict(symbol_maps.iter_maps(tmp_path))
    assert set(got) == {ZEN2_SHA, ZEN3_SHA}
    assert got[ZEN2_SHA]["schema"] == 1


def test_function_boundaries_flattening():
    map_dict = {
        "functions": [
            {"name": "f1", "ranges": [[0, 4]]},
            {"name": "f2", "ranges": [[8, 12], [16, 20]]},
            {"name": "f3", "ranges": []},
        ]
    }
    # f3 has no ranges → contributes nothing; f2 contributes two tuples.
    assert symbol_maps.function_boundaries(map_dict) == [
        (0, 4, "f1"),
        (8, 12, "f2"),
        (16, 20, "f2"),
    ]


def test_function_boundaries_on_fixture(tmp_path):
    symbol_maps.store_map(tmp_path, ZEN2_MAP)
    loaded = symbol_maps.load_map(tmp_path, ZEN2_SHA)
    bounds = symbol_maps.function_boundaries(loaded)
    # Every function contributes at least one range → at least one tuple each.
    assert len(bounds) >= 4
    # The first function in the fixture is _start at [256, 260].
    assert (256, 260, "_start") in bounds
    assert all(isinstance(t, tuple) and len(t) == 3 for t in bounds)


# ---------------------------------------------------------------------------
# CLI: import-map / maps
# ---------------------------------------------------------------------------


def _make_corpus(data_dir: Path) -> None:
    with Database(data_dir / "psp-etl.db") as db:
        img = db.insert_image(Image(sha256="rom1", vendor="ASUS", model="PRIME X570-P"))
        db.insert_entry(
            Entry(
                image_id=img,
                type_id=0x01,
                type_name="PSP_FW_BOOT_LOADER~0x1",
                zen_generation="zen2",
                version="0.14.0.3B",
                blob_sha256=ZEN2_SHA,
            )
        )


def test_cli_import_map_and_maps_table(runner, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    _make_corpus(data_dir)

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "import-map", str(ZEN2_MAP), str(ZEN3_MAP)])
    assert result.exit_code == 0, result.output
    assert "Stored 2 map(s)" in result.output

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "maps"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    assert "PSP_FW_BOOT_LOADER~0x1" in result.output
    assert "zen2" in result.output
    assert "4" in result.output
    # ZEN3 blob is not in the corpus → marked as no corpus blob.
    assert "no corpus blob" in result.output


def test_cli_maps_json(runner, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    _make_corpus(data_dir)
    runner.invoke(cli, ["--data-dir", str(data_dir), "import-map", str(ZEN2_MAP), str(ZEN3_MAP)])

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "maps", "--format", "json"])
    assert result.exit_code == 0
    records = {r["sha256_plain"]: r for r in json.loads(result.output)}
    assert records[ZEN2_SHA]["function_count"] == 4
    assert records[ZEN2_SHA]["zen_generation"] == "zen2"
    assert records[ZEN2_SHA]["has_corpus_blob"] is True
    assert records[ZEN3_SHA]["has_corpus_blob"] is False
    assert records[ZEN3_SHA]["type_name"] is None


def test_cli_import_map_rejects_bad_file(runner, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    bad = tmp_path / "bad.symbols.json"
    bad.write_text(json.dumps({"schema": 2, "sha256_plain": "a" * 64}))

    result = runner.invoke(cli, ["--data-dir", str(data_dir), "import-map", str(bad)])
    assert result.exit_code != 0
    assert "REJECT" in result.output


def test_cli_maps_no_db(runner, tmp_path):
    result = runner.invoke(cli, ["--data-dir", str(tmp_path / "noexist"), "maps"])
    assert result.exit_code != 0


def test_cli_maps_empty(runner, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    with Database(data_dir / "psp-etl.db"):
        pass
    result = runner.invoke(cli, ["--data-dir", str(data_dir), "maps"])
    assert result.exit_code == 0
    assert "No symbol maps stored" in result.output
