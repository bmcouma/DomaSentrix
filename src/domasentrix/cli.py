"""DomaSentrix command-line interface."""

import typer

from domasentrix import __version__
from domasentrix.checks.dns import DNSAuditResult, audit_dns
from domasentrix.core.target import TargetValidationError, normalize_domain

app = typer.Typer(
    name="domasentrix",
    help="Domain security configuration auditing toolkit.",
    no_args_is_help=True,
)


@app.command()
def validate(
    domain: str = typer.Argument(..., help="Domain name to validate."),
) -> None:
    """Validate and normalize a domain name."""
    try:
        normalized = normalize_domain(domain)
    except TargetValidationError as exc:
        typer.secho(f"Invalid target: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Valid domain: {normalized}")


@app.command()
def dns(
    domain: str = typer.Argument(..., help="Domain name to assess."),
) -> None:
    """Assess DNS records and email authentication policies."""
    try:
        result = audit_dns(domain)
    except TargetValidationError as exc:
        typer.secho(f"Invalid target: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    _display_dns_result(result)
    if result.errors:
        raise typer.Exit(code=1)


def _display_dns_result(result: DNSAuditResult) -> None:
    typer.echo(f"DNS assessment for: {result.domain}")

    typer.echo("Records:")
    for record_type in ("A", "AAAA", "MX", "TXT", "DMARC"):
        records = result.records.get(record_type, [])
        typer.echo(f"  {record_type}:")
        if records:
            for record in records:
                typer.echo(f"    {record}")
        else:
            typer.echo("    (none)")

    typer.echo("Findings:")
    if result.findings:
        for finding in result.findings:
            typer.echo(
                f"  [{finding.severity.upper()}] {finding.code}: {finding.message}"
            )
    else:
        typer.echo("  None")

    typer.echo("DNS lookup errors:")
    if result.errors:
        for record_type, error in result.errors.items():
            typer.echo(f"  {record_type}: {error}")
    else:
        typer.echo("  None")


@app.command()
def version() -> None:
    """Display the DomaSentrix version."""
    typer.echo(f"DomaSentrix v{__version__}")
