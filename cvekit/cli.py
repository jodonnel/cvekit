"""cvekit CLI — entry point for all subcommands."""
import click
from cvekit import __version__


@click.group()
@click.version_option(__version__)
def cli():
    """cvekit: CVE Swiss Army Knife for RHEL."""
    pass


@cli.command()
@click.option("--rhel", default="9", show_default=True, help="RHEL major version (7, 8, 9, 10)")
@click.option("--severity", default="Critical,Important", show_default=True, help="Comma-separated severity filter")
@click.option("--days", default=30, show_default=True, help="CVEs modified in last N days")
def scan(rhel, severity, days):
    """Pull CVEs for a RHEL version from RHSDA + NVD."""
    from cvekit.scan import run
    run(rhel=rhel, severity=severity.split(","), days=days)


@cli.command()
@click.option("--rhel", default="9", show_default=True)
def kpatch(rhel):
    """Check kpatch live-patch coverage for active CVEs."""
    from cvekit.kpatch import run
    run(rhel=rhel)


@cli.command()
@click.option("--from-ver", default="8", show_default=True, help="Source RHEL version")
@click.option("--to-ver", default="9", show_default=True, help="Target RHEL version")
def leapp(from_ver, to_ver):
    """Flag LEAPP inhibitors — SHA-1 RPMs, unsigned agents, known blockers."""
    from cvekit.leapp import run
    run(from_ver=from_ver, to_ver=to_ver)


@cli.command()
@click.option("--cve", default=None, help="Specific CVE ID to look up (e.g. CVE-2024-1234)")
def sap(cve):
    """Cross-reference SAP Notes for CVE impact."""
    from cvekit.sap import run
    run(cve=cve)


@cli.command()
@click.option("--rhel", default="9", show_default=True)
@click.option("--out", default="cve-report.html", show_default=True, help="Output HTML file")
@click.option("--customer", default="Customer", help="Customer name for the report header")
def report(rhel, out, customer):
    """Generate HTML CVE dashboard for a customer."""
    from cvekit.report import run
    run(rhel=rhel, out=out, customer=customer)


@cli.command()
def sync():
    """Refresh all CVE feeds. Runs daily via GitHub Actions."""
    from cvekit.scan import sync_feeds
    sync_feeds()
    click.echo("Sync complete.")
