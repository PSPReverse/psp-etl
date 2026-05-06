"""CLI entry point for psp-etl."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import logging
import shutil
import sqlite3
import statistics
import tempfile
from datetime import UTC, datetime
from itertools import groupby
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from psp_etl.db import Database, Image, PrimaryImage, StringAnalysis
from psp_etl.scrape.asrock import AsRockScraper
from psp_etl.scrape.asus import AsusScraper
from psp_etl.scrape.base import VendorScraper
from psp_etl.scrape.gigabyte import GigabyteScraper
from psp_etl.scrape.msi import MsiScraper

logger = logging.getLogger(__name__)

_VENDOR_SCRAPERS: dict[str, type[VendorScraper]] = {
    "asrock": AsRockScraper,
    "asus": AsusScraper,
    "gigabyte": GigabyteScraper,
    "msi": MsiScraper,
}

_DEFAULT_DATA_DIR = Path("data")


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(version="0.1.0")
@click.option(
    "--data-dir",
    type=click.Path(path_type=Path),
    default=_DEFAULT_DATA_DIR,
    show_default=True,
    envvar="PSP_ETL_DATA_DIR",
    help="Data directory for database, ROMs, and blobs.",
)
@click.pass_context
def cli(ctx: click.Context, data_dir: Path) -> None:
    """PSP-ETL: AMD PSP Firmware Extraction, Transformation & Loading Pipeline."""
    ctx.ensure_object(dict)
    ctx.obj["data_dir"] = data_dir


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("roms", nargs=-1, type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--vendor", default="manual", show_default=True, help="Vendor name to record for manually ingested ROMs.")
@click.option("--model", default=None, help="Board model to record for manually ingested ROMs.")
@click.pass_context
def ingest(ctx: click.Context, roms: tuple[Path, ...], vendor: str, model: str | None) -> None:
    """Parse ROM file(s) or directory, extract PSP entries and blobs."""
    from psp_etl.ingest import ingest_rom

    data_dir: Path = ctx.obj["data_dir"]
    db_path = data_dir / "psp-etl.db"
    roms_dir = data_dir / "roms"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    roms_dir.mkdir(parents=True, exist_ok=True)

    # Expand directories
    rom_paths: list[Path] = []
    for path in roms:
        if path.is_dir():
            rom_paths.extend(sorted(path.glob("*.rom")))
        else:
            rom_paths.append(path)

    if not rom_paths:
        click.echo("No ROM files found.")
        return

    console = Console()
    with Database(db_path) as db:
        for rom_path in rom_paths:
            rom_bytes = rom_path.read_bytes()
            sha256 = hashlib.sha256(rom_bytes).hexdigest()

            # Copy to content-addressed location
            dest = roms_dir / f"{sha256}.rom"
            if not dest.exists():
                shutil.copy2(rom_path, dest)

            existing = db.get_image_by_sha256(sha256)
            if existing is not None:
                image_id = existing["id"]
                if db.has_entries(image_id):
                    console.print(f"[dim]EXISTS[/dim] {rom_path.name} ({sha256[:12]}…)")
                    continue
                console.print(f"[yellow]REPARSE[/yellow] {rom_path.name} ({sha256[:12]}…)")
            else:
                image_id = db.insert_image(
                    Image(
                        sha256=sha256,
                        vendor=vendor,
                        model=model,
                        file_size=len(rom_bytes),
                        download_date=datetime.now(UTC).isoformat(timespec="seconds"),
                    )
                )
                console.print(f"[green]NEW[/green]    {rom_path.name} ({sha256[:12]}…)")

            ingest_rom(dest, image_id, db, data_dir)

    console.print(f"\n[bold]Ingested {len(rom_paths)} ROM(s).[/bold]")


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--reanalyze", is_flag=True, help="Re-analyze already-analyzed blobs.")
@click.pass_context
def analyze(ctx: click.Context, reanalyze: bool) -> None:
    """Run string analysis on all unanalyzed blobs."""
    from psp_etl import strings as strings_mod

    data_dir: Path = ctx.obj["data_dir"]
    db_path = data_dir / "psp-etl.db"
    blobs_dir = data_dir / "blobs"

    if not db_path.exists():
        raise click.ClickException(f"Database not found: {db_path}")

    with Database(db_path) as db:
        if reanalyze:
            entries = [e for e in db.query_entries() if e["blob_sha256"]]
        else:
            entries = list(db.get_unanalyzed_entries())

        # Group by blob_sha256 to analyze each unique blob once
        blobs_to_entries: dict[str, list] = {}
        for entry in entries:
            bsha = entry["blob_sha256"]
            if bsha:
                blobs_to_entries.setdefault(bsha, []).append(entry)

        if not blobs_to_entries:
            click.echo("Nothing to analyze.")
            return

        analyzed = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        ) as progress:
            task = progress.add_task("Analyzing blobs…", total=len(blobs_to_entries))
            for blob_sha256, blob_entries in blobs_to_entries.items():
                blob_path = blobs_dir / f"{blob_sha256}.bin"
                if not blob_path.exists():
                    progress.advance(task)
                    continue

                result = strings_mod.analyze_blob(blob_path)
                db.insert_strings(blob_sha256, result.strings)

                for entry in blob_entries:
                    db.insert_string_analysis(
                        StringAnalysis(
                            entry_id=entry["id"],
                            total_strings=result.total_strings,
                            unique_strings=result.unique_strings,
                            format_strings=result.format_strings,
                            function_names=result.function_names,
                            error_messages=result.error_messages,
                            postcode_strings=result.postcode_strings,
                            descriptive_strings=result.descriptive_strings,
                            score=result.score,
                        )
                    )
                analyzed += 1
                progress.advance(task)

    click.echo(f"Analyzed {analyzed} unique blob(s).")


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--gen", type=click.Choice(["zen1", "zen2", "zen3", "zen4", "zen5"]), help="Filter by Zen generation.")
@click.option("--type", "type_id", type=str, default=None, help="Filter by hex type_id (e.g. 0x08).")
@click.option("--vendor", type=str, default=None, help="Filter by vendor name.")
@click.option("--min-score", type=float, default=None, help="Minimum string analysis score.")
@click.option("--has-strings", is_flag=True, default=False, help="Only entries with score > 0.")
@click.option("--string", "string_pattern", type=str, default=None, help="Filter by strings contained in blob.")
@click.option("--psp-only", is_flag=True, default=False, help="Exclude BIOS-side ($BHD/$BL2) entries.")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default="table", help="Output format.")
@click.pass_context
def query(
    ctx: click.Context,
    gen: str | None,
    type_id: str | None,
    vendor: str | None,
    min_score: float | None,
    has_strings: bool,
    string_pattern: str | None,
    psp_only: bool,
    fmt: str,
) -> None:
    """Query the PSP entry database."""
    data_dir: Path = ctx.obj["data_dir"]
    db_path = data_dir / "psp-etl.db"

    if not db_path.exists():
        raise click.ClickException(f"Database not found: {db_path}")

    parsed_type_id: int | None = None
    if type_id is not None:
        try:
            parsed_type_id = int(type_id, 16)
        except ValueError as exc:
            raise click.BadParameter(
                f"expected a hex integer (e.g. 0x08), got {type_id!r}",
                param_hint="'--type'",
            ) from exc

    with Database(db_path) as db:
        rows = db.query_entries(
            zen_generation=gen,
            type_id=parsed_type_id,
            vendor=vendor,
            min_score=min_score,
            has_strings=has_strings,
            string_pattern=string_pattern,
            psp_only=psp_only,
        )

    if not rows:
        click.echo("No entries found.")
        return

    _QUERY_FORMATTERS[fmt](rows)


_QUERY_COLUMNS = ["type_name", "version", "zen_generation", "vendor", "model", "score"]


def _query_format_table(rows: list) -> None:
    console = Console()
    table = Table(title="PSP Entries")
    table.add_column("Type", style="cyan")
    table.add_column("Version")
    table.add_column("Gen", style="green")
    table.add_column("Vendor", style="magenta")
    table.add_column("Model")
    table.add_column("Score", justify="right", style="yellow")
    for row in rows:
        score = row["score"]
        table.add_row(
            row["type_name"] or f"0x{row['type_id']:02x}",
            row["version"] or "",
            row["zen_generation"] or "",
            row["vendor"] or "",
            row["model"] or "",
            f"{score:.1f}" if score is not None else "—",
        )
    console.print(table)


def _query_format_json(rows: list) -> None:
    records = [{col: row[col] for col in _QUERY_COLUMNS} for row in rows]
    click.echo(json.dumps(records, indent=2))


def _query_format_csv(rows: list) -> None:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_QUERY_COLUMNS)
    writer.writeheader()
    for row in rows:
        writer.writerow({col: row[col] for col in _QUERY_COLUMNS})
    click.echo(buf.getvalue(), nl=False)


_QUERY_FORMATTERS = {
    "table": _query_format_table,
    "json": _query_format_json,
    "csv": _query_format_csv,
}


# ---------------------------------------------------------------------------
# best
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--gen",
    type=click.Choice(["zen1", "zen2", "zen3", "zen4", "zen5"]),
    help="Filter by Zen generation.",
)
@click.option(
    "--type",
    "type_id",
    type=str,
    default=None,
    help="Filter by hex type_id (e.g. 0x01). Ignored with --folder.",
)
@click.option(
    "--folder",
    is_flag=True,
    default=False,
    help="Show best folder (image+directory) per generation instead of per type.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format.",
)
@click.option(
    "--export-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Copy best blobs here.",
)
@click.pass_context
def best(
    ctx: click.Context,
    gen: str | None,
    type_id: str | None,
    folder: bool,
    fmt: str,
    export_dir: Path | None,
) -> None:
    """Show best (highest-scoring) PSP firmware blobs."""
    data_dir: Path = ctx.obj["data_dir"]
    db_path = data_dir / "psp-etl.db"

    if not db_path.exists():
        raise click.ClickException(f"Database not found: {db_path}")

    console = Console()

    if folder:
        with Database(db_path) as db:
            rows = db.get_best_folders(zen_generation=gen)
            if not rows:
                click.echo("No primary images found.")
                return
            # Attach per-component detail for JSON; reuse db inside context
            if fmt == "json":
                records = []
                for row in rows:
                    entries = db.get_entries_for_folder(row["image_id"], row["zen_generation"], row["directory_magic"])
                    records.append(
                        {
                            "zen_generation": row["zen_generation"],
                            "vendor": row["vendor"],
                            "model": row["model"],
                            "bios_version": row["bios_version"],
                            "sha256": row["sha256"],
                            "directory_magic": row["directory_magic"],
                            "total_score": row["total_score"],
                            "component_count": row["component_count"],
                            "components": [
                                {
                                    "type_id": f"0x{e['type_id']:02x}",
                                    "type_name": e["type_name"],
                                    "score": e["score"],
                                    "blob_sha256": e["blob_sha256"],
                                    "encrypted": bool(e["encrypted"]),
                                }
                                for e in entries
                            ],
                        }
                    )
                click.echo(json.dumps(records, indent=2))
                return

        table = Table(title="Best PSP Folder per Generation")
        table.add_column("Gen", style="cyan")
        table.add_column("Vendor", style="magenta")
        table.add_column("Model")
        table.add_column("BIOS", style="dim")
        table.add_column("Dir")
        table.add_column("Score", style="green", justify="right")
        table.add_column("Components", justify="right")
        for row in rows:
            table.add_row(
                row["zen_generation"] or "—",
                row["vendor"] or "—",
                row["model"] or "—",
                row["bios_version"] or "—",
                row["directory_magic"] or "—",
                f"{row['total_score']:.1f}",
                str(row["component_count"]),
            )
        console.print(table)

        if export_dir is not None:
            blobs_dir = data_dir / "blobs"
            export_dir.mkdir(parents=True, exist_ok=True)
            exported = skipped = 0
            with Database(db_path) as db:
                for row in rows:
                    entries = db.get_entries_for_folder(row["image_id"], row["zen_generation"], row["directory_magic"])
                    for entry in entries:
                        blob_sha256 = entry["blob_sha256"]
                        if not blob_sha256:
                            skipped += 1
                            continue
                        src = blobs_dir / f"{blob_sha256}.bin"
                        if not src.exists():
                            skipped += 1
                            continue
                        raw_name = entry["type_name"] or f"type_{entry['type_id']:02x}"
                        type_name = raw_name.replace("/", "_").replace(" ", "_")
                        dest = export_dir / f"{row['zen_generation']}_{type_name}.bin"
                        shutil.copy2(src, dest)
                        console.print(f"  [dim]{dest.name}[/dim]")
                        exported += 1
            console.print(f"\n[green]Exported {exported} blob(s) to {export_dir}[/green]")
            if skipped:
                console.print(f"[yellow]Skipped {skipped} (no blob available)[/yellow]")
        return

    parsed_type_id: int | None = None
    if type_id is not None:
        try:
            parsed_type_id = int(type_id, 16)
        except ValueError as exc:
            raise click.BadParameter(
                f"expected a hex integer (e.g. 0x01), got {type_id!r}",
                param_hint="'--type'",
            ) from exc

    with Database(db_path) as db:
        rows = db.get_best_entries(zen_generation=gen, type_id=parsed_type_id)

    if not rows:
        click.echo("No primary images found.")
        return

    if fmt == "json":
        click.echo(
            json.dumps(
                [
                    {
                        "zen_generation": row["zen_generation"],
                        "type_id": f"0x{row['type_id']:02x}",
                        "type_name": row["type_name"],
                        "score": row["score"],
                        "vendor": row["vendor"],
                        "model": row["model"],
                    }
                    for row in rows
                ],
                indent=2,
            )
        )
        return

    table = Table(title="Best PSP Firmware Images")
    table.add_column("Gen", style="cyan")
    table.add_column("Type ID", style="yellow")
    table.add_column("Type Name")
    table.add_column("Version")
    table.add_column("Score", style="green", justify="right")
    table.add_column("Vendor")
    table.add_column("Model")
    for row in rows:
        table.add_row(
            row["zen_generation"] or "—",
            f"0x{row['type_id']:02x}",
            row["type_name"] or "(unknown)",
            row["version"] or "(unknown)",
            f"{row['score']:.1f}" if row["score"] is not None else "—",
            row["vendor"] or "—",
            row["model"] or "—",
        )
    console.print(table)

    if export_dir is not None:
        blobs_dir = data_dir / "blobs"
        export_dir.mkdir(parents=True, exist_ok=True)
        exported = skipped = 0
        for row in rows:
            blob_sha256 = row["blob_sha256"]
            if not blob_sha256:
                skipped += 1
                continue
            src = blobs_dir / f"{blob_sha256}.bin"
            if not src.exists():
                console.print(f"[yellow]Warning:[/yellow] blob not found: {src.name}")
                skipped += 1
                continue
            type_name = (row["type_name"] or f"type_{row['type_id']:02x}").replace("/", "_").replace(" ", "_")
            version = (row["version"] or "unknown").replace("/", "_").replace(" ", "_")
            dest = export_dir / f"{type_name}_{version}.bin"
            shutil.copy2(src, dest)
            console.print(f"  [dim]{dest.name}[/dim]")
            exported += 1
        console.print(f"\n[green]Exported {exported} blob(s) to {export_dir}[/green]")
        if skipped:
            console.print(f"[yellow]Skipped {skipped} (no blob available)[/yellow]")


# ---------------------------------------------------------------------------
# scrape
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("vendor", type=click.Choice(["asrock", "gigabyte", "asus", "msi", "all"]))
@click.option("--socket", type=click.Choice(["am4", "am5", "all"]), default="all", help="Filter by CPU socket.")
@click.option("--limit", type=int, default=None, help="Max boards to process per vendor.")
@click.option("--dry-run", is_flag=True, help="List download URLs without downloading.")
@click.pass_context
def scrape(ctx: click.Context, vendor: str, socket: str, limit: int | None, dry_run: bool) -> None:
    """Scrape and download BIOS updates from vendor websites."""
    vendors_to_run = list(_VENDOR_SCRAPERS.keys()) if vendor == "all" else [vendor]

    data_dir: Path = ctx.obj["data_dir"]
    db_path = data_dir / "psp-etl.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with Database(db_path) as db:
        asyncio.run(_scrape_async(vendors_to_run, socket, limit, dry_run, data_dir, db))

    console = Console()
    if dry_run:
        console.print("\n[bold]Dry run complete.[/bold] No files downloaded.")
    else:
        console.print("\n[bold]Scrape complete.[/bold]")


async def _scrape_async(
    vendor_names: list[str],
    socket: str,
    limit: int | None,
    dry_run: bool,
    data_dir: Path,
    db: Database,
) -> None:
    roms_dir = data_dir / "roms"
    roms_dir.mkdir(parents=True, exist_ok=True)
    console = Console()

    for vendor_name in vendor_names:
        console.rule(f"[bold]{vendor_name}")

        async with _VENDOR_SCRAPERS[vendor_name]() as scraper:
            boards = await scraper.list_boards()
            if socket != "all":
                boards = [b for b in boards if b.socket.lower() == socket.lower()]
            if limit is not None:
                boards = boards[:limit]

            console.print(f"  Found [bold]{len(boards)}[/bold] boards")
            if not boards:
                continue

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                board_task = progress.add_task("Processing boards", total=len(boards))
                for board in boards:
                    progress.update(board_task, description=f"[cyan]{board.model}[/cyan]")
                    updates = await scraper.list_bios_updates(board)
                    for update in updates:
                        if dry_run:
                            console.print(
                                f"  [dim]DRY-RUN[/dim] {board.model} v{update.bios_version} → {update.download_url}"
                            )
                            continue
                        with tempfile.TemporaryDirectory() as tmp:
                            rom_path = await scraper.download(update, Path(tmp))
                            rom_bytes = rom_path.read_bytes()
                            sha256 = hashlib.sha256(rom_bytes).hexdigest()
                            if db.get_image_by_sha256(sha256) is not None:
                                console.print(f"  [dim]SKIP[/dim] {board.model} v{update.bios_version} (exists)")
                                continue
                            dest = roms_dir / f"{sha256}.rom"
                            if not dest.exists():
                                shutil.copy2(rom_path, dest)
                            db.insert_image(
                                Image(
                                    sha256=sha256,
                                    vendor=board.vendor,
                                    model=board.model,
                                    socket=board.socket,
                                    bios_version=update.bios_version,
                                    agesa_version=update.agesa_version,
                                    download_url=update.download_url,
                                    file_size=len(rom_bytes),
                                    download_date=datetime.now(UTC).isoformat(timespec="seconds"),
                                )
                            )
                            console.print(
                                f"  [green]NEW[/green] {board.model} v{update.bios_version} → {sha256[:12]}….rom"
                            )
                    progress.advance(board_task)


# ---------------------------------------------------------------------------
# select
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def select(ctx: click.Context) -> None:
    """Recompute primary image selections (best blob per gen/type/version)."""
    data_dir: Path = ctx.obj["data_dir"]
    db_path = data_dir / "psp-etl.db"

    if not db_path.exists():
        raise click.ClickException(f"Database not found: {db_path}")

    console = Console()
    with Database(db_path) as db:
        candidates = db.get_selection_candidates(psp_only=True)

        if not candidates:
            click.echo("No entries with zen_generation and version found.")
            return

        selections: list[dict] = []
        cross_vendor_cases: list[dict] = []

        def _group_key(row: sqlite3.Row) -> tuple:
            return (row["zen_generation"], row["type_id"])

        for key, group_iter in groupby(candidates, key=_group_key):
            zen_gen, type_id = key
            entries = list(group_iter)
            best_entry = entries[0]  # ordered by score DESC

            db.upsert_primary_image(
                PrimaryImage(
                    zen_generation=zen_gen,
                    type_id=type_id,
                    version=best_entry["version"],
                    best_entry_id=best_entry["entry_id"],
                    best_image_id=best_entry["image_id"],
                    score=best_entry["score"],
                )
            )

            selections.append(
                {
                    "zen_generation": zen_gen,
                    "type_id": type_id,
                    "type_name": best_entry["type_name"] or "",
                    "version": best_entry["version"],
                    "vendor": best_entry["vendor"],
                    "score": best_entry["score"],
                    "candidates": len(entries),
                }
            )

            # Detect cross-vendor md5 differences
            md5_vendors: dict[str | None, set[str]] = {}
            for entry in entries:
                md5_vendors.setdefault(entry["firmware_md5"], set()).add(entry["vendor"])
            distinct_md5s = {m for m in md5_vendors if m is not None}
            if len(distinct_md5s) > 1:
                vendors_by_md5 = {md5: sorted(vs) for md5, vs in md5_vendors.items() if md5 is not None}
                logger.info(
                    "Cross-vendor md5 difference: gen=%s type=%d — %s",
                    zen_gen,
                    type_id,
                    vendors_by_md5,
                )
                cross_vendor_cases.append(
                    {
                        "zen_generation": zen_gen,
                        "type_id": type_id,
                        "md5_vendors": vendors_by_md5,
                    }
                )

        table = Table(title="Primary Image Selections")
        table.add_column("Generation", style="cyan")
        table.add_column("Type ID", justify="right")
        table.add_column("Type Name")
        table.add_column("Version")
        table.add_column("Vendor", style="green")
        table.add_column("Score", justify="right", style="bold")
        table.add_column("Candidates", justify="right")
        for sel in selections:
            table.add_row(
                sel["zen_generation"],
                str(sel["type_id"]),
                sel["type_name"],
                sel["version"],
                sel["vendor"],
                f"{sel['score']:.1f}",
                str(sel["candidates"]),
            )
        console.print(table)
        console.print(f"\n[bold]{len(selections)}[/bold] primary images selected.")

        if cross_vendor_cases:
            console.print(
                f"\n[yellow]{len(cross_vendor_cases)} cross-vendor compilation difference(s) detected:[/yellow]"
            )
            for case in cross_vendor_cases:
                console.print(f"  gen={case['zen_generation']} type={case['type_id']}")
                for md5, vendors in case["md5_vendors"].items():
                    console.print(f"    md5={md5[:12]}… → {', '.join(vendors)}")


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--gen",
    type=click.Choice(["zen1", "zen2", "zen3", "zen4", "zen5"]),
    default=None,
    help="Filter to a specific Zen generation.",
)
@click.pass_context
def stats(ctx: click.Context, gen: str | None) -> None:
    """Show a per-generation summary dashboard."""
    data_dir: Path = ctx.obj["data_dir"]
    db_path = data_dir / "psp-etl.db"

    if not db_path.exists():
        raise click.ClickException(f"Database not found: {db_path}")

    console = Console()
    title_suffix = f" (gen={gen})" if gen else ""

    with Database(db_path) as db:
        vendor_table = Table(title=f"Images per Vendor{title_suffix}", box=box.SIMPLE_HEAD)
        vendor_table.add_column("Vendor", style="cyan")
        vendor_table.add_column("Images", justify="right")
        rows = db.stats_images_by_vendor(gen)
        for row in rows:
            vendor_table.add_row(row["vendor"] or "unknown", str(row["cnt"]))
        if not rows:
            vendor_table.add_row("[dim]no data[/dim]", "")
        console.print(vendor_table)

        gen_table = Table(title=f"Entries per Generation{title_suffix}", box=box.SIMPLE_HEAD)
        gen_table.add_column("Generation", style="cyan")
        gen_table.add_column("Entries", justify="right")
        gen_table.add_column("Encrypted", justify="right")
        gen_table.add_column("Enc%", justify="right")
        rows = db.stats_entries_by_generation(gen)
        for row in rows:
            total = row["total"]
            enc = row["encrypted_count"] or 0
            pct = f"{100.0 * enc / total:.1f}%" if total else "—"
            gen_table.add_row(row["zen_generation"] or "unknown", str(total), str(enc), pct)
        if not rows:
            gen_table.add_row("[dim]no data[/dim]", "", "", "")
        console.print(gen_table)

        score_table = Table(title=f"String Score Distribution{title_suffix}", box=box.SIMPLE_HEAD)
        score_table.add_column("Generation", style="cyan")
        score_table.add_column("Analyzed", justify="right")
        score_table.add_column("Min", justify="right")
        score_table.add_column("Mean", justify="right")
        score_table.add_column("P90", justify="right")
        score_table.add_column("Max", justify="right")
        scores_by_gen = db.stats_scores_by_generation(gen)
        for gen_key in sorted(scores_by_gen):
            scores = sorted(scores_by_gen[gen_key])
            n = len(scores)
            p90 = scores[min(int(n * 0.9), n - 1)]
            score_table.add_row(
                gen_key,
                str(n),
                f"{min(scores):.1f}",
                f"{statistics.mean(scores):.1f}",
                f"{p90:.1f}",
                f"{max(scores):.1f}",
            )
        if not scores_by_gen:
            score_table.add_row("[dim]no data[/dim]", "", "", "", "", "")
        console.print(score_table)

        with_strings, without_strings = db.stats_score_nonzero(gen)
        summary_table = Table(title=f"Score Summary{title_suffix}", box=box.SIMPLE_HEAD)
        summary_table.add_column("Category", style="cyan")
        summary_table.add_column("Count", justify="right")
        summary_table.add_row("Entries with score > 0", str(with_strings))
        summary_table.add_row("Entries with score = 0 or unanalyzed", str(without_strings))
        console.print(summary_table)


if __name__ == "__main__":
    cli()
