"""Unit tests for TLS certificate and connection assessment."""

import ssl
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from domasentrix.checks import tls as tls_module
from domasentrix.checks.tls import audit_tls
from domasentrix.core.target import TargetValidationError


def _certificate(days_until_expiry: int = 60) -> dict[str, Any]:
    """Build a certificate dictionary for deterministic tests."""
    now = datetime.now(UTC)

    not_before = now - timedelta(days=1)
    not_after = now + timedelta(days=days_until_expiry)

    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Example CA"),),),
        "serialNumber": "123456789ABC",
        "version": 3,
        "notBefore": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "example.com"),),
    }


class FakeRawSocket:
    """Mock TCP socket supporting context management."""

    def __enter__(self) -> "FakeRawSocket":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class FakeTLSSocket:
    """Mock TLS socket returning controlled connection information."""

    def __init__(
        self,
        certificate: dict[str, Any] | None = None,
        protocol: str = "TLSv1.3",
    ) -> None:
        self.certificate = _certificate() if certificate is None else certificate
        self.protocol = protocol

    def __enter__(self) -> "FakeTLSSocket":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def version(self) -> str:
        return self.protocol

    def cipher(self) -> tuple[str, str, int]:
        return ("TLS_AES_256_GCM_SHA384", self.protocol, 256)

    def getpeercert(self) -> dict[str, Any]:
        return self.certificate


class FakeSSLContext:
    """Mock SSL context for controlled TLS connections."""

    def __init__(self, tls_socket: FakeTLSSocket) -> None:
        self.tls_socket = tls_socket
        self.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

    def wrap_socket(
        self,
        raw_socket: object,
        server_hostname: str,
    ) -> FakeTLSSocket:
        return self.tls_socket


def _mock_successful_connection(
    monkeypatch: pytest.MonkeyPatch,
    certificate: dict[str, Any] | None = None,
    protocol: str = "TLSv1.3",
) -> None:
    """Mock a successful TCP and TLS connection."""
    fake_tls_socket = FakeTLSSocket(
        certificate=certificate,
        protocol=protocol,
    )
    fake_context = FakeSSLContext(fake_tls_socket)

    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda address, timeout: FakeRawSocket(),
    )
    monkeypatch.setattr(
        tls_module.ssl,
        "create_default_context",
        lambda: fake_context,
    )


def test_audit_tls_returns_verified_certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful connection should return certificate information."""
    _mock_successful_connection(monkeypatch)

    result = audit_tls("EXAMPLE.COM.")

    assert result.domain == "example.com"
    assert result.port == 443
    assert result.protocol == "TLSv1.3"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"

    assert result.certificate is not None
    assert result.certificate.subject == "commonName=example.com"
    assert result.certificate.issuer == "organizationName=Example CA"
    assert result.certificate.serial_number == "123456789ABC"
    assert result.certificate.version == 3
    assert "example.com" in result.certificate.subject_alt_names
    assert result.certificate.days_until_expiry > 30

    assert result.errors == {}


def test_audit_tls_reports_certificate_expiring_soon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A certificate expiring within 30 days should produce a finding."""
    _mock_successful_connection(
        monkeypatch,
        certificate=_certificate(days_until_expiry=20),
    )

    result = audit_tls("example.com")

    assert any(
        finding.code == "TLS_CERTIFICATE_EXPIRING_SOON" for finding in result.findings
    )


def test_audit_tls_reports_critical_expiry_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A certificate expiring within seven days should produce a high finding."""
    _mock_successful_connection(
        monkeypatch,
        certificate=_certificate(days_until_expiry=5),
    )

    result = audit_tls("example.com")

    assert any(
        finding.code == "TLS_CERTIFICATE_EXPIRING_CRITICAL"
        and finding.severity == "high"
        for finding in result.findings
    )


def test_certificate_expiry_warning_uses_exact_time_thresholds() -> None:
    """Expiry findings should not round up almost a full extra day."""
    now = datetime.now(UTC)
    certificate = tls_module.TLSCertificateInfo(
        subject="commonName=example.com",
        issuer="organizationName=Example CA",
        serial_number="123456789ABC",
        version=3,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=7, hours=1),
        days_until_expiry=7,
        subject_alt_names=("example.com",),
    )
    result = tls_module.TLSAuditResult(
        domain="example.com",
        port=443,
        certificate=certificate,
    )

    tls_module._assess_certificate_findings(result)

    assert not any(
        finding.code == "TLS_CERTIFICATE_EXPIRING_CRITICAL"
        for finding in result.findings
    )


def test_audit_tls_reports_tls_1_2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TLS 1.2 should be identified as negotiated protocol information."""
    _mock_successful_connection(
        monkeypatch,
        protocol="TLSv1.2",
    )

    result = audit_tls("example.com")

    assert any(finding.code == "TLS_1_2_NEGOTIATED" for finding in result.findings)


def test_audit_tls_includes_legacy_protocol_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The complete assessment should include confirmed legacy protocol findings."""
    _mock_successful_connection(monkeypatch)

    monkeypatch.setattr(
        tls_module,
        "_assess_protocols",
        lambda domain, port, timeout: [
            tls_module.TLSProtocolAssessment(
                version="TLSv1",
                status="supported",
                cipher="AES128-SHA",
            ),
            tls_module.TLSProtocolAssessment(
                version="TLSv1.1",
                status="inconclusive",
                error="No compatible cipher suites",
            ),
        ],
    )

    result = audit_tls("example.com")

    assert any(finding.code == "TLS_1_0_SUPPORTED" for finding in result.findings)
    assert not any(finding.code == "TLS_1_1_SUPPORTED" for finding in result.findings)


def test_audit_tls_rejects_invalid_domain() -> None:
    """Invalid targets should be rejected before network access."""
    with pytest.raises(TargetValidationError):
        audit_tls("https://example.com")


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_audit_tls_rejects_invalid_port(port: int) -> None:
    """Ports outside the valid TCP range should be rejected."""
    with pytest.raises(ValueError, match="Port must be"):
        audit_tls("example.com", port=port)


@pytest.mark.parametrize("timeout", [0, -1, -5.0, float("nan"), float("inf")])
def test_audit_tls_rejects_invalid_timeout(timeout: float) -> None:
    """Non-positive connection timeouts should be rejected."""
    with pytest.raises(ValueError, match="Timeout must be"):
        audit_tls("example.com", timeout=timeout)


def test_audit_tls_reports_timeout_outside_socket_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Socket timeout overflow should be reported rather than escaping."""

    def raise_timeout_overflow(address: object, timeout: float) -> None:
        raise OverflowError("timestamp out of range")

    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        raise_timeout_overflow,
    )

    result = audit_tls("example.com", timeout=1e300)

    assert "connection" in result.errors
    assert "outside the supported range" in result.errors["connection"]
    assert all(
        assessment.status == "inconclusive"
        for assessment in result.protocol_assessments
    )


def test_audit_tls_reports_certificate_verification_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid certificate should produce a security finding."""

    class VerificationFailureContext:
        minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

        def wrap_socket(
            self,
            raw_socket: object,
            server_hostname: str,
        ) -> None:
            raise ssl.SSLCertVerificationError("hostname mismatch")

    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda address, timeout: FakeRawSocket(),
    )
    monkeypatch.setattr(
        tls_module.ssl,
        "create_default_context",
        lambda: VerificationFailureContext(),
    )

    result = audit_tls("example.com")

    assert "connection" in result.errors
    assert any(
        finding.code == "TLS_CERTIFICATE_VERIFICATION_FAILED"
        for finding in result.findings
    )
    assert result.certificate is None


def test_audit_tls_reports_expired_certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An expired certificate should produce a specific security finding."""

    class ExpiredCertificateContext:
        minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

        def wrap_socket(
            self,
            raw_socket: object,
            server_hostname: str,
        ) -> None:
            raise ssl.SSLCertVerificationError(
                10,
                "certificate has expired",
            )

    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda address, timeout: FakeRawSocket(),
    )
    monkeypatch.setattr(
        tls_module.ssl,
        "create_default_context",
        lambda: ExpiredCertificateContext(),
    )

    result = audit_tls("example.com")

    assert result.certificate is None
    assert "connection" in result.errors
    assert any(finding.code == "TLS_CERTIFICATE_EXPIRED" for finding in result.findings)
    assert any(
        finding.code == "TLS_CERTIFICATE_VERIFICATION_FAILED"
        for finding in result.findings
    )


def test_audit_tls_reports_connection_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A connection timeout should be recorded separately from findings."""

    def raise_timeout(address: object, timeout: float) -> None:
        raise TimeoutError("connection timed out")

    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        raise_timeout,
    )

    result = audit_tls("example.com")

    assert "connection" in result.errors
    assert "timed out" in result.errors["connection"].lower()
    assert result.findings == []


def test_audit_tls_reports_tls_context_setup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Trust-store or TLS context setup failures should be recorded."""

    def raise_ssl_error() -> None:
        raise ssl.SSLError("system trust store unavailable")

    monkeypatch.setattr(
        tls_module.ssl,
        "create_default_context",
        raise_ssl_error,
    )

    result = audit_tls("example.com")

    assert "connection" in result.errors
    assert "system trust store unavailable" in result.errors["connection"]
    assert len(result.protocol_assessments) == 4
    assert all(
        assessment.status == "inconclusive"
        for assessment in result.protocol_assessments
    )


def test_audit_tls_reports_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Network failures should be captured without crashing the assessment."""

    def raise_network_error(address: object, timeout: float) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        raise_network_error,
    )

    result = audit_tls("example.com")

    assert "connection" in result.errors
    assert "connection refused" in result.errors["connection"]


def test_audit_tls_handles_missing_certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A connection without a readable certificate should return an error."""
    _mock_successful_connection(
        monkeypatch,
        certificate={},
    )

    result = audit_tls("example.com")

    assert result.certificate is None
    assert "certificate" in result.errors
