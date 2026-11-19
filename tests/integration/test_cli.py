"""CLI integration tests."""

from typer.testing import CliRunner

from domasentrix.checks.dns import DNSAuditResult, DNSFinding
from domasentrix.cli import app

runner = CliRunner()


def test_dns_command_displays_records_findings_and_no_errors(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: DNSAuditResult(
            domain="example.com",
            records={
                "A": ["93.184.216.34"],
                "AAAA": [],
                "MX": ["10 mail.example.com"],
                "TXT": ["v=spf1 -all"],
                "DMARC": [],
            },
            findings=[
                DNSFinding(
                    code="DMARC_MISSING",
                    severity="medium",
                    message="No DMARC policy was found.",
                )
            ],
        ),
    )

    result = runner.invoke(app, ["dns", "EXAMPLE.COM"])

    assert result.exit_code == 0
    assert "DNS assessment for: example.com" in result.output
    assert "93.184.216.34" in result.output
    assert "10 mail.example.com" in result.output
    assert "[MEDIUM] DMARC_MISSING" in result.output
    assert "DNS lookup errors:\n  None" in result.output


def test_dns_command_displays_errors_and_returns_nonzero(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: DNSAuditResult(
            domain="example.com",
            records={"A": [], "AAAA": [], "MX": [], "TXT": [], "DMARC": []},
            errors={"A": "The DNS query timed out."},
        ),
    )

    result = runner.invoke(app, ["dns", "example.com"])

    assert result.exit_code == 1
    assert "A: The DNS query timed out." in result.output


def test_dns_command_rejects_invalid_domain() -> None:
    result = runner.invoke(app, ["dns", "127.0.0.1"])

    assert result.exit_code == 1
    assert "IP addresses are not accepted" in result.output
