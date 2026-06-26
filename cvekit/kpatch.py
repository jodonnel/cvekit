"""kpatch live-patch coverage check."""
import csv
from pathlib import Path
from rich.console import Console
from rich.table import Table
from cvekit.db import connect

console = Console()

DATA_DIR = Path(__file__).parent.parent / "data"


def _load_coverage_csv() -> dict[str, dict]:
    path = DATA_DIR / "kpatch_coverage.csv"
    coverage = {}
    if path.exists():
        with open(path) as f:
            for row in csv.DictReader(f):
                coverage[row["cve_id"]] = row
    return coverage


def run(rhel: str):
    conn = connect()
    cves = conn.execute(
        "SELECT cve_id, severity, cvss_score, summary FROM cves WHERE rhel_version=? ORDER BY cvss_score DESC",
        (rhel,)
    ).fetchall()

    if not cves:
        console.print(f"[yellow]No CVEs in local DB for RHEL {rhel}. Run `cvekit scan` first.[/]")
        return

    coverage = _load_coverage_csv()

    t = Table(title=f"kpatch Coverage — RHEL {rhel}", show_lines=True)
    t.add_column("CVE", style="cyan", no_wrap=True)
    t.add_column("Severity")
    t.add_column("CVSS3", justify="right")
    t.add_column("kpatch", justify="center")
    t.add_column("Patch ID")

    patched = unpatched = 0
    for row in cves:
        cid = row["cve_id"]
        c = coverage.get(cid, {})
        available = c.get("available", "0") == "1"
        patch_id = c.get("patch_id", "")
        if available:
            kpatch_col = "[green]✓[/]"
            patched += 1
        else:
            kpatch_col = "[red]✗[/]"
            unpatched += 1
        t.add_row(cid, row["severity"] or "", str(row["cvss_score"] or ""), kpatch_col, patch_id)

    console.print(t)
    total = patched + unpatched
    pct = round(patched / total * 100) if total else 0
    console.print(f"kpatch coverage: [green]{patched}[/] / {total} CVEs ({pct}%)")
    if unpatched:
        console.print(f"[yellow]{unpatched} CVEs require a reboot or manual patch.[/]")
