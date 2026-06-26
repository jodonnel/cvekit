# cvekit — CVE Swiss Army Knife

Open-source CVE tracking, kpatch coverage, LEAPP inhibitor detection, and SAP Note cross-reference for Red Hat Enterprise Linux.

**Home:** [JimDemosLinux](https://github.com/JimDemosLinux) | Built with ❤️ and open tooling.

## What it does

| Subcommand | Purpose |
|------------|---------|
| `cvekit scan` | Pull CVEs for a RHEL version from RHSDA + NVD |
| `cvekit kpatch` | Check kpatch live-patch coverage for active CVEs |
| `cvekit leapp` | Flag LEAPP inhibitors (SHA-1 RPMs, unsigned agents) |
| `cvekit sap` | Cross-reference SAP Notes for CVE impact |
| `cvekit report` | Generate HTML dashboard for a customer |
| `cvekit sync` | Refresh all feeds (runs daily via GitHub Actions) |

## Install

```bash
pipx install cvekit   # coming soon
# or
git clone https://github.com/JimDemosLinux/cvekit
cd cvekit && pip install -e .
```

## Data sources

- [Red Hat Security Data API](https://access.redhat.com/labs/securitydataapi/)
- [NVD JSON Feed](https://nvd.nist.gov/vuln/data-feeds)
- kpatch coverage: seeded CSV (RH Security Data API kpatch filter is undocumented)
- SAP Notes: seeded cross-reference CSV (SAP Portal requires S-user OAuth — cannot be public)
- LEAPP inhibitors: seeded CSV of known problematic packages (Avamar, NessusAgent, etc.)

## Architecture

```
cvekit/
├── cvekit/
│   ├── __init__.py
│   ├── cli.py          # Click entrypoint
│   ├── scan.py         # RHSDA + NVD fetch
│   ├── kpatch.py       # kpatch coverage check
│   ├── leapp.py        # LEAPP inhibitor detection
│   ├── sap.py          # SAP Note cross-reference
│   ├── report.py       # HTML dashboard generator
│   └── db.py           # SQLite schema + queries
├── data/
│   ├── kpatch_coverage.csv
│   ├── leapp_inhibitors.csv
│   └── sap_note_xref.csv
├── .github/
│   └── workflows/
│       └── daily-sync.yml
├── pyproject.toml
└── README.md
```

## Daily sync

GitHub Actions runs `cvekit sync` every day at 06:00 UTC. Updated feeds are committed back to `main`. No infrastructure required.

## License

Apache 2.0 — free to use, fork, and redistribute.
