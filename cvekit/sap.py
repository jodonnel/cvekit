"""SAP Note cross-reference for CVEs."""
import csv
from pathlib import Path
from rich.console import Console
from rich.table import Table
from cvekit.db import connect

console = Console()
DATA_DIR = Path(__file__).parent.parent / "data"


def run(cve: str = None):
    path = DATA_DIR / "sap_note_xref.csv"
    if not path.exists():
        console.print(f"[red]No SAP Note data at {path}[/]")
        return

    rows = []
    with open(path) as f:
        for row in csv.DictReader(f):
            if cve and row.get("cve_id") != cve:
                continue
            rows.append(row)

    if not rows:
        msg = f"No SAP Notes found for {cve}." if cve else "No SAP Note cross-references loaded."
        console.print(f"[yellow]{msg}[/]")
        return

    t = Table(title=f"SAP Note Cross-Reference{' — ' + cve if cve else ''}", show_lines=True)
    t.add_column("CVE", style="cyan", no_wrap=True)
    t.add_column("SAP Note")
    t.add_column("Component")
    t.add_column("Title")

    for row in rows:
        t.add_row(
            row.get("cve_id", ""),
            row.get("sap_note", ""),
            row.get("component", ""),
            row.get("title", ""),
        )
    console.print(t)
    console.print("[dim]SAP Notes require S-user login: https://launchpad.support.sap.com/[/]")
