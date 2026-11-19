"""DomaSentrix command-line interface."""

import typer

from domasentrix import __version__
from domasentrix.checks.dns import DNSAuditResult, audit_dns
from domasentrix.checks.tls import TLSAuditResult, audit_tls
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


@app.command()
def tls(
    domain: str = typer.Argument(..., help="Domain name to assess."),
    port: int = typer.Option(443, min=1, max=65535, help="TLS port."),
    timeout: float = typer.Option(
        5.0,
        min=0.000001,
        help="Timeout in seconds for each connection attempt.",
    ),
) -> None:
    """Assess a domain's TLS connection and verified certificate."""
    try:
        result = audit_tls(domain, port=port, timeout=timeout)
    except TargetValidationError as exc:
        typer.secho(f"Invalid target: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        typer.secho(f"Invalid TLS options: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    _display_tls_result(result)
    if result.errors:
        raise typer.Exit(code=1)


def _display_tls_result(result: TLSAuditResult) -> None:
    typer.echo(f"TLS assessment for: {result.domain}:{result.port}")

    typer.echo("Connection:")
    typer.echo(f"  Protocol: {result.protocol or '(not established)'}")
    typer.echo(f"  Cipher: {result.cipher or '(not established)'}")

    typer.echo("Protocol assessments:")
    if result.protocol_assessments:
        for assessment in result.protocol_assessments:
            typer.echo(f"  {assessment.version}: {assessment.status.upper()}")
            if assessment.cipher:
                typer.echo(f"    Cipher: {assessment.cipher}")
            if assessment.error:
                typer.echo(f"    Error: {assessment.error}")
    else:
        typer.echo("  (not performed)")

    typer.echo("Certificate:")
    if result.certificate is not None:
        certificate = result.certificate
        typer.echo(f"  Subject: {certificate.subject}")
        typer.echo(f"  Issuer: {certificate.issuer}")
        typer.echo(f"  Serial number: {certificate.serial_number}")
        typer.echo(f"  Version: {certificate.version}")
        typer.echo(f"  Not before: {certificate.not_before.isoformat()}")
        typer.echo(f"  Not after: {certificate.not_after.isoformat()}")
        typer.echo(f"  Days until expiry: {certificate.days_until_expiry}")
        if certificate.subject_alt_names:
            typer.echo(
                "  DNS subject alternative names: "
                + ", ".join(certificate.subject_alt_names)
            )
        else:
            typer.echo("  DNS subject alternative names: (none)")
    else:
        typer.echo("  (not available)")

    typer.echo("Findings:")
    if result.findings:
        for finding in result.findings:
            typer.echo(
                f"  [{finding.severity.upper()}] {finding.code}: {finding.message}"
            )
    else:
        typer.echo("  None")

    typer.echo("TLS/connection errors:")
    if result.errors:
        for error_type, error in result.errors.items():
            typer.echo(f"  {error_type}: {error}")
    else:
        typer.echo("  None")


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
