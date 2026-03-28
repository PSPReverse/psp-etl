#!/usr/bin/env python3
"""Compare the best folder for a generation against the global per-type best.

Shows which components you sacrifice by picking one coherent image instead
of cherrypicking the best blob per type.

Usage: python scripts/folder-vs-best.py [gen] [--data-dir DIR]
"""

import json
import subprocess
import sys


def run(args: list[str]) -> list:
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def main() -> None:
    from rich.console import Console
    from rich.table import Table
    from rich import box

    gen = "zen2"
    data_dir_args: list[str] = []
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--data-dir" and i + 1 < len(args):
            data_dir_args = ["--data-dir", args[i + 1]]
            i += 2
        else:
            gen = args[i]
            i += 1

    base = ["psp-etl"] + data_dir_args

    folder_data = run(base + ["best", "--folder", "--gen", gen, "--format", "json"])
    global_data = run(base + ["best", "--gen", gen, "--format", "json"])

    if not folder_data:
        print(f"No folder data for {gen}")
        sys.exit(1)

    global_best: dict[str, float] = {row["type_id"]: (row["score"] or 0.0) for row in global_data}

    folder = folder_data[0]
    components = sorted(folder["components"], key=lambda c: -(c["score"] or 0))

    console = Console()
    table = Table(
        title=f"[bold]{gen}[/bold]: {folder['vendor']} {folder['model']} ({folder['bios_version']}) vs global best",
        box=box.SIMPLE_HEAD,
    )
    table.add_column("Type ID", style="dim")
    table.add_column("Type Name")
    table.add_column("Folder", justify="right")
    table.add_column("Global Best", justify="right")
    table.add_column("Delta", justify="right")
    table.add_column("Delta %", justify="right")

    for comp in components:
        type_id = comp["type_id"]
        folder_score = comp["score"] or 0.0
        best_score = global_best.get(type_id, 0.0)
        delta = folder_score - best_score
        delta_pct = (delta / best_score * 100) if best_score > 0 else 0.0

        if delta_pct == 0:
            style = "green"
        elif delta_pct >= -20:
            style = "yellow"
        else:
            style = "red"

        table.add_row(
            type_id,
            comp["type_name"] or "",
            f"{folder_score:.0f}",
            f"{best_score:.0f}",
            f"[{style}]{delta:+.0f}[/{style}]",
            f"[{style}]{delta_pct:.1f}%[/{style}]",
        )

    # Sum only over the types present in both views so the totals are comparable.
    total_folder = sum(c["score"] or 0.0 for c in components)
    total_global = sum(global_best.get(c["type_id"], c["score"] or 0.0) for c in components)

    console.print(table)
    console.print(f"Folder total: [green]{total_folder:.0f}[/green]  Global sum: [cyan]{total_global:.0f}[/cyan]")


if __name__ == "__main__":
    main()
