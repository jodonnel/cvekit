"""RHSDA + NVD CVE fetch for cvekit."""
import httpx
import json
from datetime import datetime, timedelta, timezone
from rich.console import Console
from rich.table import Table
from cvekit.db import connect

console = Console()

RHSDA_BASE = "https://access.redhat.com/labs/securitydataapi/cve.json"
NVD_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _rhsda_fetch(rhel: str, severity: list[str], days: int) -> list[dict]:
    after = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    params = {
        "after": after,
        "severity": ",".join(severity),
        "package": f"rhel{rhel}",
    }
    with httpx.Client(timeout=30) as client:
        resp = client.get(RHSDA_BASE, params=params)
        resp.raise_for_status()
        return resp.json()


def run(rhel: str, severity: list[str], days: int):
    console.print(f"[bold yellow]cvekit scan[/] — RHEL {rhel} | severity: {', '.join(severity)} | last {days} days")
    cves = _rhsda_fetch(rhel=rhel, severity=severity, days=days)

    if not cves:
        console.print("[dim]No CVEs found.[/]")
        return

    conn = connect()
    inserted = 0
    for c in cves:
        conn.execute(
            """INSERT OR REPLACE INTO cves
               (cve_id, rhel_version, severity, cvss_score, summary, published, modified)
               VALUES (?,?,?,?,?,?,?)""",
            (c.get("CVE"), rhel, c.get("severity"), c.get("cvss3_score"),
             c.get("bugzilla_description"), c.get("public_date"), c.get("resource_url"))
        )
        inserted += 1
    conn.commit()

    t = Table(title=f"CVEs — RHEL {rhel} (last {days}d)", show_lines=True)
    t.add_column("CVE", style="cyan", no_wrap=True)
    t.add_column("Severity", style="bold red")
    t.add_column("CVSS3", justify="right")
    t.add_column("Summary")
    for c in cves[:20]:
        t.add_row(
            c.get("CVE", ""),
            c.get("severity", ""),
            str(c.get("cvss3_score", "")),
            (c.get("bugzilla_description", "") or "")[:80],
        )
    console.print(t)
    if len(cves) > 20:
        console.print(f"[dim]... and {len(cves) - 20} more. Run `cvekit report` for full dashboard.[/]")
    console.print(f"[green]Stored {inserted} CVEs in local DB.[/]")


def sync_feeds():
    """Pull all severities for RHEL 7/8/9/10, store in DB."""
    conn = connect()
    for rhel in ["7", "8", "9", "10"]:
        for sev in ["Critical", "Important"]:
            console.print(f"  Syncing RHEL {rhel} {sev}...")
            try:
                cves = _rhsda_fetch(rhel=rhel, severity=[sev], days=365)
                for c in cves:
                    conn.execute(
                        """INSERT OR REPLACE INTO cves
                           (cve_id, rhel_version, severity, cvss_score, summary, published, modified)
                           VALUES (?,?,?,?,?,?,?)""",
                        (c.get("CVE"), rhel, sev, c.get("cvss3_score"),
                         c.get("bugzilla_description"), c.get("public_date"), c.get("resource_url"))
                    )
                conn.execute(
                    "INSERT INTO sync_log (source, records, status) VALUES (?,?,?)",
                    (f"rhsda/rhel{rhel}/{sev}", len(cves), "ok")
                )
            except Exception as e:
                conn.execute(
                    "INSERT INTO sync_log (source, records, status) VALUES (?,?,?)",
                    (f"rhsda/rhel{rhel}/{sev}", 0, f"error: {e}")
                )
    conn.commit()
