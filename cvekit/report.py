"""HTML CVE dashboard generator."""
import json
from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console
from cvekit.db import connect

console = Console()


def run(rhel: str, out: str, customer: str):
    conn = connect()
    cves = [dict(r) for r in conn.execute(
        "SELECT * FROM cves WHERE rhel_version=? ORDER BY cvss_score DESC",
        (rhel,)
    ).fetchall()]
    kpatch = {r["cve_id"]: dict(r) for r in conn.execute(
        "SELECT * FROM kpatch_coverage WHERE rhel_version=?", (rhel,)
    ).fetchall()}
    sap = {}
    for r in conn.execute("SELECT * FROM sap_note_xref").fetchall():
        sap.setdefault(r["cve_id"], []).append(dict(r))

    critical = [c for c in cves if (c.get("severity") or "").lower() == "critical"]
    important = [c for c in cves if (c.get("severity") or "").lower() == "important"]
    kpatch_covered = sum(1 for c in cves if kpatch.get(c["cve_id"], {}).get("available") == 1)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def cve_rows(cve_list):
        rows = ""
        for c in cve_list:
            cid = c["cve_id"]
            kp = kpatch.get(cid, {})
            kp_badge = '<span class="badge kpatch">kpatch ✓</span>' if kp.get("available") == 1 else ""
            sap_badge = '<span class="badge sap">SAP Note</span>' if cid in sap else ""
            score = c.get("cvss_score") or "—"
            rows += f"""
            <tr>
              <td><code>{cid}</code></td>
              <td>{c.get("severity","")}</td>
              <td class="score">{score}</td>
              <td>{(c.get("summary") or "")[:90]}</td>
              <td>{kp_badge}{sap_badge}</td>
            </tr>"""
        return rows

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>cvekit — {customer} RHEL {rhel} CVE Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #151515; color: #d0d4da; font-family: system-ui, sans-serif; padding: 32px; }}
  h1 {{ color: #ee0000; font-size: 28px; margin-bottom: 4px; }}
  .meta {{ color: #6b7280; font-size: 13px; margin-bottom: 32px; }}
  .stats {{ display: flex; gap: 24px; margin-bottom: 32px; }}
  .stat {{ background: #1f1f1f; border: 1px solid #333; border-radius: 8px; padding: 20px 28px; }}
  .stat .num {{ font-size: 36px; font-weight: 700; color: #f0ab00; }}
  .stat .label {{ color: #9ca3af; font-size: 13px; margin-top: 4px; }}
  .stat.red .num {{ color: #ee0000; }}
  .stat.green .num {{ color: #3e8635; }}
  h2 {{ color: #f0ab00; font-size: 18px; margin: 28px 0 12px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #1f1f1f; color: #9ca3af; text-align: left; padding: 10px 12px; border-bottom: 1px solid #333; }}
  td {{ padding: 9px 12px; border-bottom: 1px solid #222; vertical-align: top; }}
  tr:hover td {{ background: #1f1f1f; }}
  code {{ color: #79c0ff; font-size: 12px; }}
  .score {{ color: #f0ab00; font-weight: 600; }}
  .badge {{ display: inline-block; font-size: 11px; padding: 2px 7px; border-radius: 4px; margin-right: 4px; }}
  .badge.kpatch {{ background: #1a3a1a; color: #3e8635; border: 1px solid #3e8635; }}
  .badge.sap {{ background: #1a2a3a; color: #79c0ff; border: 1px solid #79c0ff; }}
  footer {{ margin-top: 40px; color: #4b5563; font-size: 12px; }}
</style>
</head>
<body>
<h1>cvekit — {customer}</h1>
<div class="meta">Red Hat Enterprise Linux {rhel} &nbsp;·&nbsp; Generated: {generated} &nbsp;·&nbsp; <a href="https://github.com/JimDemosLinux/cvekit" style="color:#f0ab00">JimDemosLinux/cvekit</a></div>

<div class="stats">
  <div class="stat red"><div class="num">{len(critical)}</div><div class="label">Critical CVEs</div></div>
  <div class="stat"><div class="num">{len(important)}</div><div class="label">Important CVEs</div></div>
  <div class="stat green"><div class="num">{kpatch_covered}</div><div class="label">kpatch covered (no reboot)</div></div>
  <div class="stat"><div class="num">{len(cves)}</div><div class="label">Total CVEs tracked</div></div>
</div>

<h2>Critical</h2>
<table>
  <thead><tr><th>CVE</th><th>Severity</th><th>CVSS3</th><th>Summary</th><th>Coverage</th></tr></thead>
  <tbody>{cve_rows(critical) or '<tr><td colspan="5" style="color:#6b7280">None.</td></tr>'}</tbody>
</table>

<h2>Important</h2>
<table>
  <thead><tr><th>CVE</th><th>Severity</th><th>CVSS3</th><th>Summary</th><th>Coverage</th></tr></thead>
  <tbody>{cve_rows(important) or '<tr><td colspan="5" style="color:#6b7280">None.</td></tr>'}</tbody>
</table>

<footer>
  Built with <a href="https://github.com/JimDemosLinux/cvekit" style="color:#f0ab00">cvekit</a> — open source, Apache 2.0.
  Data: Red Hat Security Data API + NVD. kpatch and SAP Note cross-references are seeded CSVs.
</footer>
</body>
</html>"""

    Path(out).write_text(html)
    console.print(f"[green]Report written to {out}[/]")
