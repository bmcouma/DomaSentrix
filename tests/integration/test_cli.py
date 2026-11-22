"""CLI integration tests."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Self, TextIO

import pytest
from typer.testing import CliRunner

from domasentrix.checks.dns import DNSAuditResult, DNSFinding
from domasentrix.checks.http import HTTPAuditResult, HTTPFinding, HTTPResponseInfo
from domasentrix.checks.tls import (
    TLSAuditResult,
    TLSCertificateInfo,
    TLSFinding,
    TLSProtocolAssessment,
)
from domasentrix.cli import app

runner = CliRunner()


def _mock_successful_assessments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: DNSAuditResult(domain=domain),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain: TLSAuditResult(domain=domain, port=443),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain: HTTPAuditResult(domain=domain, http_port=80, https_port=443),
    )


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


def test_http_command_displays_assessment_and_options(monkeypatch) -> None:
    response = HTTPResponseInfo(
        url="https://example.com/",
        status_code=200,
        http_version="HTTP/1.1",
        redirect_count=1,
        headers={"strict-transport-security": ("max-age=31536000",)},
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain, **kwargs: HTTPAuditResult(
            domain="example.com",
            http_port=kwargs["http_port"],
            https_port=kwargs["https_port"],
            http_response=response,
            https_response=response,
            http_to_https_redirect=True,
            https_available=True,
            findings=[
                HTTPFinding(
                    code="HTTP_SERVER_DISCLOSURE",
                    severity="low",
                    message="Server identifies an implementation.",
                    evidence="HTTPS: example-server/1.2",
                    remediation="Remove unnecessary server identification.",
                )
            ],
        ),
    )

    result = runner.invoke(
        app,
        [
            "http",
            "example.com",
            "--http-port",
            "8080",
            "--https-port",
            "8443",
            "--timeout",
            "3",
            "--max-redirects",
            "4",
        ],
    )

    assert result.exit_code == 0
    assert "HTTP assessment for: example.com" in result.output
    assert "HTTPS available: Yes" in result.output
    assert "HTTP-to-HTTPS redirect: Yes" in result.output
    assert "Final URL: https://example.com/" in result.output
    assert "strict-transport-security: max-age=31536000" in result.output
    assert "[LOW] HTTP_SERVER_DISCLOSURE" in result.output
    assert "HTTP errors:\n  None" in result.output


def test_http_command_displays_errors_and_returns_nonzero(monkeypatch) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain, **kwargs: HTTPAuditResult(
            domain="example.com",
            http_port=80,
            https_port=443,
            errors={"https_request": "timeout: timed out"},
        ),
    )

    result = runner.invoke(app, ["http", "example.com"])

    assert result.exit_code == 1
    assert "HTTPS available: Not established" in result.output
    assert "https_request: timeout: timed out" in result.output


def test_http_command_rejects_invalid_domain() -> None:
    result = runner.invoke(app, ["http", "127.0.0.1"])

    assert result.exit_code == 1
    assert "IP addresses are not accepted" in result.output


def test_assess_command_runs_complete_assessment_with_normalized_domain(
    monkeypatch,
) -> None:
    calls: list[tuple[str, str]] = []

    def fake_dns(domain: str) -> DNSAuditResult:
        calls.append(("dns", domain))
        return DNSAuditResult(domain=domain)

    def fake_tls(domain: str) -> TLSAuditResult:
        calls.append(("tls", domain))
        return TLSAuditResult(domain=domain, port=443)

    def fake_http(domain: str) -> HTTPAuditResult:
        calls.append(("http", domain))
        return HTTPAuditResult(domain=domain, http_port=80, https_port=443)

    monkeypatch.setattr("domasentrix.cli.audit_dns", fake_dns)
    monkeypatch.setattr("domasentrix.cli.audit_tls", fake_tls)
    monkeypatch.setattr("domasentrix.cli.audit_http", fake_http)

    result = runner.invoke(app, ["assess", " EXAMPLE.COM. "])

    assert result.exit_code == 0
    assert calls == [
        ("dns", "example.com"),
        ("tls", "example.com"),
        ("http", "example.com"),
    ]
    assert "Combined security assessment for: example.com" in result.output
    assert "Assessment completeness: Complete" in result.output
    assert "Overall score: 100/100" in result.output
    assert "Risk classification: low" in result.output
    assert "Available modules: DNS, TLS, HTTP" in result.output
    assert "Missing modules: None" in result.output
    assert "DNS: 0 deduction (maximum 25)" in result.output
    assert "TLS: 0 deduction (maximum 35)" in result.output
    assert "HTTP: 0 deduction (maximum 40)" in result.output
    assert "Total deduction: 0" in result.output
    assert "Critical: 0" in result.output
    assert "Informational: 0" in result.output
    assert "Operational errors:\n  None" in result.output


def test_assess_command_displays_findings_from_all_modules(monkeypatch) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: DNSAuditResult(
            domain=domain,
            findings=[
                DNSFinding(
                    code="SPF_MISSING",
                    severity="medium",
                    message="No SPF policy was found.",
                )
            ],
        ),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain: TLSAuditResult(
            domain=domain,
            port=443,
            findings=[
                TLSFinding(
                    code="TLS_CERTIFICATE_VERIFICATION_FAILED",
                    severity="high",
                    message="The certificate could not be verified.",
                )
            ],
        ),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain: HTTPAuditResult(
            domain=domain,
            http_port=80,
            https_port=443,
            findings=[
                HTTPFinding(
                    code="HTTP_SERVER_DISCLOSURE",
                    severity="low",
                    message="The Server header discloses implementation information.",
                    evidence="HTTPS: example-server/1.2",
                    remediation="Remove unnecessary server identification.",
                )
            ],
        ),
    )

    result = runner.invoke(app, ["assess", "example.com"])

    assert result.exit_code == 0
    assert "DNS:" in result.output
    assert "[MEDIUM] SPF_MISSING" in result.output
    assert "TLS:" in result.output
    assert "[HIGH] TLS_CERTIFICATE_VERIFICATION_FAILED" in result.output
    assert "HTTP:" in result.output
    assert "[LOW] HTTP_SERVER_DISCLOSURE" in result.output
    assert "Evidence: HTTPS: example-server/1.2" in result.output
    assert "Remediation: Remove unnecessary server identification." in result.output
    assert "Overall score: 80/100" in result.output
    assert "Risk classification: moderate" in result.output
    assert "DNS: 6 deduction (maximum 25)" in result.output
    assert "TLS: 12 deduction (maximum 35)" in result.output
    assert "HTTP: 2 deduction (maximum 40)" in result.output
    assert "Total deduction: 20" in result.output
    assert "Medium: 1" in result.output
    assert "High: 1" in result.output
    assert "Low: 1" in result.output


def test_assess_command_preserves_spaces_in_http_finding_text(monkeypatch) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: DNSAuditResult(domain=domain),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain: TLSAuditResult(domain=domain, port=443),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain: HTTPAuditResult(
            domain=domain,
            http_port=80,
            https_port=443,
            findings=[
                HTTPFinding(
                    code="HTTP_FRAME_PROTECTION_MISSING",
                    severity="medium",
                    message=(
                        "Neither X-Frame-Options nor a restrictive CSP "
                        "frame-ancestors directive provides framing protection."
                    ),
                    evidence="Both protections are absent or ineffective.",
                    remediation=(
                        "Set X-Frame-Options or a restrictive CSP "
                        "frame-ancestors directive."
                    ),
                ),
                HTTPFinding(
                    code="HTTP_CSP_MISSING",
                    severity="medium",
                    message="The HTTPS response does not set Content-Security-Policy.",
                    evidence="Content-Security-Policy header is absent.",
                    remediation=(
                        "Define a policy appropriate to the site's resources and "
                        "inline code."
                    ),
                ),
                HTTPFinding(
                    code="HTTP_PERMISSIONS_POLICY_MISSING",
                    severity="low",
                    message="Permissions-Policy is absent.",
                    evidence="Permissions-Policy header is absent.",
                    remediation=(
                        "Consider explicitly restricting browser features the site "
                        "does not use."
                    ),
                ),
            ],
        ),
    )

    result = runner.invoke(app, ["assess", "example.com"])

    assert result.exit_code == 0
    assert (
        "Neither X-Frame-Options nor a restrictive CSP frame-ancestors "
        "directive provides framing protection."
    ) in result.output
    assert "The HTTPS response does not set Content-Security-Policy." in result.output
    assert (
        "Consider explicitly restricting browser features the site does not use."
    ) in result.output


def test_assess_command_rejects_invalid_domain_before_running_checks(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: pytest.fail("DNS assessment must not run."),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain: pytest.fail("TLS assessment must not run."),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain: pytest.fail("HTTP assessment must not run."),
    )

    result = runner.invoke(app, ["assess", "127.0.0.1"])

    assert result.exit_code == 1
    assert "Invalid target:" in result.output
    assert "IP addresses are not accepted" in result.output


@pytest.mark.parametrize("unavailable_source", ["dns", "tls", "http"])
def test_assess_command_continues_and_reports_partial_results(
    monkeypatch,
    unavailable_source: str,
) -> None:
    calls: list[str] = []

    def successful_dns(domain: str) -> DNSAuditResult:
        calls.append("dns")
        return DNSAuditResult(domain=domain)

    def successful_tls(domain: str) -> TLSAuditResult:
        calls.append("tls")
        return TLSAuditResult(domain=domain, port=443)

    def successful_http(domain: str) -> HTTPAuditResult:
        calls.append("http")
        return HTTPAuditResult(domain=domain, http_port=80, https_port=443)

    def failed_assessment(domain: str) -> None:
        calls.append(unavailable_source)
        raise OSError("simulated network failure")

    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        failed_assessment if unavailable_source == "dns" else successful_dns,
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        failed_assessment if unavailable_source == "tls" else successful_tls,
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        failed_assessment if unavailable_source == "http" else successful_http,
    )

    result = runner.invoke(app, ["assess", "example.com"])

    assert result.exit_code == 1
    assert len(calls) == 3
    assert "Assessment completeness: Partial" in result.output
    assert f"Missing modules: {unavailable_source.upper()}" in result.output
    assert "Overall score: Not available (assessment is partial)." in result.output
    assert (
        "Risk classification: Not available (assessment is partial)." in result.output
    )
    assert "WARNING: Operational errors limit assessment coverage" in result.output
    assert f"{unavailable_source.upper()}:" in result.output
    assert "OSError: simulated network failure" in result.output
    assert "assessment passed" not in result.output.casefold()


def test_assess_command_displays_result_errors_separately(monkeypatch) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: DNSAuditResult(
            domain=domain,
            errors={"A": "The DNS query timed out."},
        ),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain: TLSAuditResult(domain=domain, port=443),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain: HTTPAuditResult(domain=domain, http_port=80, https_port=443),
    )

    result = runner.invoke(app, ["assess", "example.com"])

    assert result.exit_code == 1
    assert (
        "Assessment completeness: Partial (missing modules or operational errors)"
        in result.output
    )
    assert "Overall score: Not available (assessment is partial)." in result.output
    assert (
        "Risk classification: Not available (assessment is partial)." in result.output
    )
    assert "Operational errors:" in result.output
    assert "WARNING: Operational errors limit assessment coverage" in result.output
    assert "DNS:" in result.output
    assert "A: The DNS query timed out." in result.output
    findings_section = result.output.split("Findings:\n", maxsplit=1)[1].split(
        "Finding statistics:",
        maxsplit=1,
    )[0]
    assert "The DNS query timed out." not in findings_section


def test_validate_and_version_commands_remain_available() -> None:
    validate_result = runner.invoke(app, ["validate", "EXAMPLE.COM"])
    version_result = runner.invoke(app, ["version"])

    assert validate_result.exit_code == 0
    assert "Valid domain: example.com" in validate_result.output
    assert version_result.exit_code == 0
    assert "DomaSentrix v" in version_result.output


def test_assess_json_writes_only_json_to_stdout(monkeypatch) -> None:
    _mock_successful_assessments(monkeypatch)
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: DNSAuditResult(
            domain=domain,
            findings=[
                DNSFinding(
                    "SPF_MISSING",
                    "medium",
                    "No SPF policy was found.",
                )
            ],
        ),
    )

    result = runner.invoke(app, ["assess", "EXAMPLE.COM", "--format", "json"])

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["target"]["domain"] == "example.com"
    assert report["assessment"]["completeness"] == "complete"
    assert report["findings"][0]["code"] == "SPF_MISSING"
    assert result.stderr == ""


def test_assess_json_writes_new_utf8_file_without_stdout(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _mock_successful_assessments(monkeypatch)
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "assess",
            "example.com",
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    assert result.stdout == ""
    saved_report = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved_report["target"]["domain"] == "example.com"
    assert saved_report["schema_version"] == "1.0"


def test_assess_json_partial_report_is_valid_and_keeps_errors_separate(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: DNSAuditResult(
            domain=domain,
            errors={"A": "The DNS query timed out."},
        ),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain: TLSAuditResult(domain=domain, port=443),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain: HTTPAuditResult(domain=domain, http_port=80, https_port=443),
    )

    result = runner.invoke(app, ["assess", "example.com", "--format", "json"])

    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["assessment"]["completeness"] == "partial"
    assert report["assessment"]["score"] is None
    assert report["assessment"]["risk"] is None
    assert report["assessment"]["total_deduction"] is None
    assert report["operational_errors"] == [
        {
            "source": "dns",
            "category": "A",
            "message": "The DNS query timed out.",
        }
    ]
    assert result.stderr == ""


def test_assess_json_includes_check_exception_as_operational_error(monkeypatch) -> None:
    def failed_dns(domain: str) -> DNSAuditResult:
        raise OSError("resolver unavailable")

    monkeypatch.setattr("domasentrix.cli.audit_dns", failed_dns)
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain: TLSAuditResult(domain=domain, port=443),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain: HTTPAuditResult(domain=domain, http_port=80, https_port=443),
    )

    result = runner.invoke(app, ["assess", "example.com", "--format", "json"])

    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["assessment"]["completeness"] == "partial"
    assert report["assessment"]["score"] is None
    assert report["assessment"]["missing_sources"] == ["dns"]
    assert report["operational_errors"] == [
        {
            "source": "dns",
            "category": "assessment",
            "message": "OSError: resolver unavailable",
        }
    ]
    assert result.stderr == ""


def test_assess_json_refuses_to_overwrite_existing_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _mock_successful_assessments(monkeypatch)
    report_path = tmp_path / "report.json"
    report_path.write_text("keep this report", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "assess",
            "example.com",
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert report_path.read_text(encoding="utf-8") == "keep this report"
    assert result.stdout == ""
    assert "refusing to overwrite" in result.stderr


def test_assess_rejects_output_option_with_text_format(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "assess",
            "example.com",
            "--format",
            "text",
            "--output",
            str(tmp_path / "report.json"),
        ],
    )

    assert result.exit_code == 1
    assert "only be used with --format json" in result.stderr
    assert not (tmp_path / "report.json").exists()


def test_assess_json_sends_invalid_domain_diagnostic_to_stderr() -> None:
    result = runner.invoke(app, ["assess", "127.0.0.1", "--format", "json"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Invalid target:" in result.stderr


def test_assess_json_reports_file_write_errors_on_stderr(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _mock_successful_assessments(monkeypatch)
    report_path = tmp_path / "missing-directory" / "report.json"

    result = runner.invoke(
        app,
        [
            "assess",
            "example.com",
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Could not write report file" in result.stderr


def test_assess_json_removes_partial_file_after_write_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _mock_successful_assessments(monkeypatch)
    report_path = tmp_path / "partial-report.json"
    original_open = Path.open

    class FailingWriter:
        def __init__(self, file: TextIO) -> None:
            self.file = file

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_: object) -> None:
            self.file.close()

        def fileno(self) -> int:
            return self.file.fileno()

        def write(self, content: str) -> int:
            self.file.write(content[:8])
            raise OSError("simulated disk-full error")

    def failing_open(
        path: Path,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> TextIO | FailingWriter:
        file = original_open(
            path,
            mode,
            buffering=buffering,
            encoding=encoding,
            errors=errors,
            newline=newline,
        )
        return FailingWriter(file) if path == report_path else file

    monkeypatch.setattr(Path, "open", failing_open)

    result = runner.invoke(
        app,
        [
            "assess",
            "example.com",
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert "simulated disk-full error" in result.stderr
    assert not report_path.exists()


def test_assess_json_reports_serialization_errors_on_stderr(monkeypatch) -> None:
    _mock_successful_assessments(monkeypatch)

    def fail_serialization(*args: object) -> str:
        raise ValueError("invalid report data")

    monkeypatch.setattr(
        "domasentrix.cli.serialize_assessment_report",
        fail_serialization,
    )

    result = runner.invoke(app, ["assess", "example.com", "--format", "json"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Could not serialize JSON report: invalid report data" in (result.stderr)


def test_assess_html_requires_output_before_running_checks(monkeypatch) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: pytest.fail("DNS assessment must not run."),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain: pytest.fail("TLS assessment must not run."),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain: pytest.fail("HTTP assessment must not run."),
    )

    result = runner.invoke(app, ["assess", "example.com", "--format", "html"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "HTML reports require --output FILE." in result.stderr


def test_assess_html_sends_invalid_domain_diagnostic_to_stderr(
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "assess",
            "127.0.0.1",
            "--format",
            "html",
            "--output",
            str(tmp_path / "report.html"),
        ],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Invalid target:" in result.stderr


def test_assess_html_writes_self_contained_report_to_new_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    calls = {"dns": 0, "tls": 0, "http": 0}

    def fake_dns(domain: str) -> DNSAuditResult:
        calls["dns"] += 1
        return DNSAuditResult(domain=domain)

    def fake_tls(domain: str) -> TLSAuditResult:
        calls["tls"] += 1
        return TLSAuditResult(domain=domain, port=443)

    def fake_http(domain: str) -> HTTPAuditResult:
        calls["http"] += 1
        return HTTPAuditResult(domain=domain, http_port=80, https_port=443)

    monkeypatch.setattr("domasentrix.cli.audit_dns", fake_dns)
    monkeypatch.setattr("domasentrix.cli.audit_tls", fake_tls)
    monkeypatch.setattr("domasentrix.cli.audit_http", fake_http)
    report_path = tmp_path / "report.html"

    result = runner.invoke(
        app,
        [
            "assess",
            "EXAMPLE.COM.",
            "--format",
            "html",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    assert calls == {"dns": 1, "tls": 1, "http": 1}
    assert result.stdout == ""
    report = report_path.read_text(encoding="utf-8")
    assert "<!doctype html>" in report
    assert "<title>DomaSentrix Security Assessment: example.com</title>" in report
    assert "Executive summary" in report
    assert "Assessment coverage" in report
    assert "Operational errors</h2>" in report
    assert "default-src 'none'" in report
    assert "<script" not in report.casefold()
    assert "<link " not in report.casefold()


def test_assess_html_refuses_to_overwrite_existing_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _mock_successful_assessments(monkeypatch)
    report_path = tmp_path / "report.html"
    report_path.write_text("keep this report", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "assess",
            "example.com",
            "--format",
            "html",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert report_path.read_text(encoding="utf-8") == "keep this report"
    assert result.stdout == ""
    assert "refusing to overwrite" in result.stderr


def test_assess_html_preserves_partial_status_and_errors(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "domasentrix.cli.audit_dns",
        lambda domain: DNSAuditResult(
            domain=domain,
            errors={"A": "The DNS query timed out."},
        ),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_tls",
        lambda domain: TLSAuditResult(domain=domain, port=443),
    )
    monkeypatch.setattr(
        "domasentrix.cli.audit_http",
        lambda domain: HTTPAuditResult(domain=domain, http_port=80, https_port=443),
    )
    report_path = tmp_path / "partial.html"

    result = runner.invoke(
        app,
        [
            "assess",
            "example.com",
            "--format",
            "html",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    report = report_path.read_text(encoding="utf-8")
    assert 'class="status status-partial">Partial</span>' in report
    assert 'Overall score</strong><br><span class="score">Not available' in report
    assert "The DNS query timed out." in report
    assert "Operational errors limited assessment coverage." in report
