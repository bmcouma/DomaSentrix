"""CLI integration tests."""

from datetime import UTC, datetime

from typer.testing import CliRunner

from domasentrix.checks.dns import DNSAuditResult, DNSFinding
from domasentrix.checks.tls import (
    TLSAuditResult,
    TLSCertificateInfo,
    TLSFinding,
    TLSProtocolAssessment,
)
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


def test_tls_command_displays_verified_certificate(monkeypatch) -> None:
    now = datetime.now(UTC)
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain, port=443, timeout=5.0: TLSAuditResult(
            domain="example.com",
            port=port,
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            certificate=TLSCertificateInfo(
                subject="commonName=example.com",
                issuer="organizationName=Example CA",
                serial_number="123456789ABC",
                version=3,
                not_before=now,
                not_after=now,
                days_until_expiry=60,
                subject_alt_names=("example.com",),
            ),
            protocol_assessments=[
                TLSProtocolAssessment(
                    version="TLSv1.3",
                    status="supported",
                    cipher="TLS_AES_256_GCM_SHA384",
                ),
                TLSProtocolAssessment(
                    version="TLSv1.2",
                    status="supported",
                    cipher="ECDHE-RSA-AES256-GCM-SHA384",
                ),
            ],
            findings=[
                TLSFinding(
                    code="TLS_CERTIFICATE_EXPIRING_SOON",
                    severity="medium",
                    message="The TLS certificate expires within 30 days.",
                )
            ],
        ),
    )

    result = runner.invoke(
        app,
        ["tls", "EXAMPLE.COM", "--port", "8443", "--timeout", "3"],
    )

    assert result.exit_code == 0
    assert "TLS assessment for: example.com:8443" in result.output
    assert "Protocol: TLSv1.3" in result.output
    assert "Cipher: TLS_AES_256_GCM_SHA384" in result.output
    assert "Protocol assessments:" in result.output
    assert "TLSv1.3: SUPPORTED" in result.output
    assert "TLSv1.2: SUPPORTED" in result.output
    assert "Subject: commonName=example.com" in result.output
    assert "Issuer: organizationName=Example CA" in result.output
    assert "Days until expiry: 60" in result.output
    assert "[MEDIUM] TLS_CERTIFICATE_EXPIRING_SOON" in result.output
    assert "TLS/connection errors:\n  None" in result.output


def test_tls_command_displays_verification_error_and_returns_nonzero(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain, port=443, timeout=5.0: TLSAuditResult(
            domain="example.com",
            port=port,
            errors={
                "connection": ("Certificate verification failed: hostname mismatch")
            },
            findings=[
                TLSFinding(
                    code="TLS_CERTIFICATE_VERIFICATION_FAILED",
                    severity="high",
                    message="The TLS certificate could not be verified.",
                )
            ],
        ),
    )

    result = runner.invoke(app, ["tls", "example.com"])

    assert result.exit_code == 1
    assert "(not established)" in result.output
    assert "Certificate:\n  (not available)" in result.output
    assert "[HIGH] TLS_CERTIFICATE_VERIFICATION_FAILED" in result.output
    assert "hostname mismatch" in result.output


def test_tls_command_rejects_invalid_domain() -> None:
    result = runner.invoke(app, ["tls", "127.0.0.1"])

    assert result.exit_code == 1
    assert "IP addresses are not accepted" in result.output
