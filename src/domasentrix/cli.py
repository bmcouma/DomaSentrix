"""DomaSentrix command-line interface."""

import os
import ssl
from pathlib import Path
from typing import Annotated, Literal

import httpx
import typer
from dns.exception import DNSException

from domasentrix import __version__
from domasentrix.checks.dns import DNSAuditResult, audit_dns
from domasentrix.checks.http import HTTPAuditResult, audit_http
from domasentrix.checks.tls import TLSAuditResult, audit_tls
from domasentrix.core.target import TargetValidationError, normalize_domain
from domasentrix.reporting import (
    build_assessment_report,
    render_html_report,
    serialize_assessment_report,
)
from domasentrix.scoring.engine import (
    CATEGORY_CAPS,
    SEVERITY_ORDER,
    SOURCE_ORDER,
    score_assessment,
)
from domasentrix.scoring.models import SecurityAssessment, SourceCategory

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


@app.command()
def http(
    domain: str = typer.Argument(..., help="Domain name to assess."),
    http_port: int = typer.Option(80, min=1, max=65535, help="HTTP port."),
    https_port: int = typer.Option(443, min=1, max=65535, help="HTTPS port."),
    timeout: float = typer.Option(
        5.0,
        min=0.000001,
        help="Timeout in seconds for each connection.",
    ),
    max_redirects: int = typer.Option(
        5,
        min=0,
        max=10,
        help="Maximum same-domain redirects to follow per request.",
    ),
) -> None:
    """Assess HTTP-to-HTTPS behavior and security headers."""
    try:
        result = audit_http(
            domain,
            http_port=http_port,
            https_port=https_port,
            timeout=timeout,
            max_redirects=max_redirects,
        )
    except TargetValidationError as exc:
        typer.secho(f"Invalid target: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        typer.secho(f"Invalid HTTP options: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    _display_http_result(result)
    if result.errors:
        raise typer.Exit(code=1)


@app.command()
def assess(
    domain: str = typer.Argument(..., help="Domain name to assess across all modules."),
    output_format: Annotated[
        Literal["text", "json", "html"],
        typer.Option("--format", help="Assessment report format."),
    ] = "text",
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write a JSON or HTML report to a new file."),
    ] = None,
) -> None:
    """Run DNS, TLS, and HTTP assessments and calculate a combined score."""
    if output is not None and output_format == "text":
        typer.secho(
            "--output can only be used with --format json or html.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    if output_format == "html" and output is None:
        typer.secho(
            "HTML reports require --output FILE.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        normalized_domain = normalize_domain(domain)
    except TargetValidationError as exc:
        typer.secho(
            f"Invalid target: {exc}",
            fg=typer.colors.RED,
            err=output_format != "text",
        )
        raise typer.Exit(code=1) from exc

    unavailable_errors: dict[SourceCategory, str] = {}
    dns_result: DNSAuditResult | None = None
    tls_result: TLSAuditResult | None = None
    http_result: HTTPAuditResult | None = None

    try:
        dns_result = audit_dns(normalized_domain)
    except (DNSException, OSError) as exc:
        unavailable_errors["dns"] = f"{type(exc).__name__}: {exc}"

    try:
        tls_result = audit_tls(normalized_domain)
    except (ssl.SSLError, OSError, OverflowError, TimeoutError) as exc:
        unavailable_errors["tls"] = f"{type(exc).__name__}: {exc}"

    try:
        http_result = audit_http(normalized_domain)
    except (httpx.HTTPError, ssl.SSLError, OSError, ValueError) as exc:
        unavailable_errors["http"] = f"{type(exc).__name__}: {exc}"

    assessment = score_assessment(dns_result, tls_result, http_result)
    if output_format == "json":
        try:
            serialized_report = serialize_assessment_report(
                normalized_domain,
                assessment,
                unavailable_errors,
            )
        except (TypeError, ValueError) as exc:
            typer.secho(
                f"Could not serialize JSON report: {exc}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1) from exc

        if output is None:
            typer.echo(serialized_report)
        else:
            _write_report_file(output, serialized_report)
    elif output_format == "html":
        try:
            report_data = build_assessment_report(
                normalized_domain,
                assessment,
                unavailable_errors,
            )
            rendered_report = render_html_report(report_data)
        except (TypeError, ValueError) as exc:
            typer.secho(
                f"Could not render HTML report: {exc}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1) from exc
        if output is None:
            typer.secho(
                "HTML reports require --output FILE.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        _write_report_file(output, rendered_report)
    else:
        _display_security_assessment(normalized_domain, assessment, unavailable_errors)

    has_result_errors = any(assessment.operational_errors.values())
    if not assessment.is_complete or unavailable_errors or has_result_errors:
        raise typer.Exit(code=1)


def _write_report_file(path: Path, report_content: str) -> None:
    created_file = False
    file_identity: tuple[int, int] | None = None
    try:
        with path.open("x", encoding="utf-8", newline="\n") as report_file:
            created_file = True
            file_stat = os.fstat(report_file.fileno())
            file_identity = (file_stat.st_dev, file_stat.st_ino)
            report_file.write(report_content)
            report_file.write("\n")
    except FileExistsError as exc:
        typer.secho(
            f"Report file already exists; refusing to overwrite: {path}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1) from exc
    except (OSError, ValueError) as exc:
        cleanup_note = (
            _remove_partial_report(path, file_identity) if created_file else None
        )
        message = f"Could not write report file {path}: {exc}"
        if cleanup_note is not None:
            message = f"{message} {cleanup_note}"
        typer.secho(
            message,
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1) from exc


def _remove_partial_report(
    path: Path,
    file_identity: tuple[int, int] | None,
) -> str | None:
    if file_identity is None:
        return f"Could not verify whether a partial report remains at {path}."

    try:
        current_stat = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"Could not inspect a possible partial report at {path}: {exc}"

    if file_identity != (current_stat.st_dev, current_stat.st_ino):
        return None

    try:
        path.unlink()
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"Could not remove partial report file {path}: {exc}"
    return None


def _display_security_assessment(
    domain: str,
    assessment: SecurityAssessment,
    unavailable_errors: dict[SourceCategory, str],
) -> None:
    typer.echo(f"Combined security assessment for: {domain}")
    completeness = (
        "Complete"
        if assessment.is_complete
        else "Partial (missing modules or operational errors)"
    )
    typer.echo(f"Assessment completeness: {completeness}")
    if assessment.is_complete:
        typer.echo(f"Overall score: {assessment.overall_score}/100")
        typer.echo(f"Risk classification: {assessment.risk_level}")
    else:
        typer.echo("Overall score: Not available (assessment is partial).")
        typer.echo("Risk classification: Not available (assessment is partial).")

    typer.echo(
        "Available modules: "
        + (
            ", ".join(source.upper() for source in assessment.available_sources)
            or "None"
        )
    )
    typer.echo(
        "Missing modules: "
        + (", ".join(source.upper() for source in assessment.missing_sources) or "None")
    )

    typer.echo("Category summary:")
    for source in SOURCE_ORDER:
        deduction = assessment.category_deductions[source]
        typer.echo(
            f"  {source.upper()}: {deduction} deduction "
            f"(maximum {CATEGORY_CAPS[source]})"
        )
    if assessment.total_deduction is None:
        typer.echo("  Total deduction: Not available (assessment is partial).")
    else:
        typer.echo(f"  Total deduction: {assessment.total_deduction}")

    typer.echo("Findings:")
    if assessment.findings:
        for source in SOURCE_ORDER:
            source_findings = [
                finding for finding in assessment.findings if finding.source == source
            ]
            if not source_findings:
                continue
            typer.echo(f"  {source.upper()}:")
            for finding in source_findings:
                typer.echo(
                    f"    [{finding.severity.upper()}] {finding.code}: "
                    f"{finding.message} (deduction: {finding.deduction})"
                )
                if finding.evidence is not None:
                    typer.echo(f"      Evidence: {finding.evidence}")
                if finding.remediation is not None:
                    typer.echo(f"      Remediation: {finding.remediation}")
    else:
        typer.echo("  No findings observed in the available assessment results.")

    typer.echo("Finding statistics:")
    for severity in SEVERITY_ORDER:
        label = "informational" if severity == "info" else severity
        typer.echo(
            f"  {label.capitalize()}: {assessment.finding_counts_by_severity[severity]}"
        )

    typer.echo("Operational errors:")
    has_errors = bool(unavailable_errors) or any(assessment.operational_errors.values())
    if has_errors:
        typer.secho(
            "  WARNING: Operational errors limit assessment coverage; affected "
            "checks are not treated as secure.",
            fg=typer.colors.YELLOW,
            bold=True,
        )
    for source in SOURCE_ORDER:
        source_errors = dict(assessment.operational_errors[source])
        if source in unavailable_errors:
            source_errors["assessment"] = unavailable_errors[source]
        if source_errors:
            typer.echo(f"  {source.upper()}:")
            for error_type, error in source_errors.items():
                typer.echo(f"    {error_type}: {error}")
    if not has_errors:
        typer.echo("  None")


def _display_http_result(result: HTTPAuditResult) -> None:
    typer.echo(f"HTTP assessment for: {result.domain}")
    typer.echo(
        "HTTPS available: " + ("Yes" if result.https_available else "Not established")
    )
    redirect_status = (
        "Yes"
        if result.http_to_https_redirect is True
        else "No"
        if result.http_to_https_redirect is False
        else "Not determined"
    )
    typer.echo(f"HTTP-to-HTTPS redirect: {redirect_status}")

    for label, response in (
        ("HTTP response", result.http_response),
        ("HTTPS response", result.https_response),
    ):
        typer.echo(f"{label}:")
        if response is None:
            typer.echo("  Not established")
            continue
        typer.echo(f"  Status: {response.status_code}")
        typer.echo(f"  Final URL: {response.url}")
        typer.echo(f"  HTTP version: {response.http_version}")
        typer.echo(f"  Redirects followed: {response.redirect_count}")
        for header_name, values in response.headers.items():
            typer.echo(f"  {header_name}: {', '.join(values)}")

    typer.echo("Findings:")
    if result.findings:
        for finding in result.findings:
            typer.echo(
                f"  [{finding.severity.upper()}] {finding.code}: {finding.message}"
            )
            typer.echo(f"    Evidence: {finding.evidence}")
            typer.echo(f"    Remediation: {finding.remediation}")
    else:
        typer.echo("  None")

    typer.echo("HTTP errors:")
    if result.errors:
        for error_type, error in result.errors.items():
            typer.echo(f"  {error_type}: {error}")
    else:
        typer.echo("  None")


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
