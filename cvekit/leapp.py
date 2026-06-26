"""LEAPP upgrade inhibitor detection."""
import csv
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()
DATA_DIR = Path(__file__).parent.parent / "data"


def run(from_ver: str, to_ver: str):
    path = DATA_DIR / "leapp_inhibitors.csv"
    if not path.exists():
        console.print(f"[red]No inhibitor data at {path}[/]")
        return

    inhibitors = []
    with open(path) as f:
        for row in csv.DictReader(f):
            if row.get("from_ver") == from_ver and row.get("to_ver") == to_ver:
                inhibitors.append(row)

    if not inhibitors:
        console.print(f"[green]No known LEAPP inhibitors for RHEL {from_ver} → {to_ver}.[/]")
        return

    t = Table(title=f"LEAPP Inhibitors — RHEL {from_ver} → {to_ver}", show_lines=True)
    t.add_column("Package", style="cyan")
    t.add_column("Reason", style="bold red")
    t.add_column("Fix")

    for row in inhibitors:
        t.add_row(row.get("package_name", ""), row.get("reason", ""), row.get("fix", ""))

    console.print(t)
    console.print(f"[yellow]{len(inhibitors)} inhibitor(s) will block upgrade.[/]")
    console.print("[dim]Run `leapp preupgrade` on the target host for a live check.[/]")
