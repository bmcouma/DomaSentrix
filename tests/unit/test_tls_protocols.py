"""Tests for independent TLS protocol assessment."""

import ssl

import pytest

from domasentrix.checks import tls as tls_module


class FakeRawSocket:
    """Mock TCP socket supporting context management."""

    def __enter__(self) -> "FakeRawSocket":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class FakeTLSSocket:
    """Mock TLS socket with a configurable negotiated protocol."""

    def __init__(self, protocol: str = "TLSv1.3") -> None:
        self.protocol = protocol

    def __enter__(self) -> "FakeTLSSocket":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def version(self) -> str:
        return self.protocol

    def cipher(self) -> tuple[str, str, int]:
        return ("TLS_AES_256_GCM_SHA384", self.protocol, 256)

    def getpeercert(self) -> dict[str, object]:
        return {}


class FakeSSLContext:
    """Mock SSL context preserving certificate verification settings."""

    def __init__(
        self,
        tls_socket: FakeTLSSocket | None = None,
        error: Exception | None = None,
    ) -> None:
        self.tls_socket = tls_socket or FakeTLSSocket()
        self.error = error
        self.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        self.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        self.verify_mode = ssl.CERT_REQUIRED
        self.check_hostname = True

    def wrap_socket(
        self,
        raw_socket: object,
        server_hostname: str,
    ) -> FakeTLSSocket:
        if self.error is not None:
            raise self.error

        return self.tls_socket


@pytest.mark.parametrize(
    ("version_name", "version"),
    tls_module._PROTOCOL_VERSIONS,
)
def test_probe_protocol_reports_supported_version(
    monkeypatch: pytest.MonkeyPatch,
    version_name: str,
    version: ssl.TLSVersion,
) -> None:
    """A verified handshake using the requested version means supported."""
    context = FakeSSLContext(tls_socket=FakeTLSSocket(protocol=version_name))

    monkeypatch.setattr(
        tls_module.ssl,
        "create_default_context",
        lambda: context,
    )
    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda address, timeout: FakeRawSocket(),
    )

    result = tls_module._probe_protocol(
        "example.com",
        443,
        5.0,
        version_name,
        version,
    )

    assert result.version == version_name
    assert result.status == "supported"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"
    assert result.error is None

    assert context.minimum_version == version
    assert context.maximum_version == version
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_probe_protocol_marks_handshake_failure_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed handshake must not automatically mean unsupported."""
    context = FakeSSLContext(error=ssl.SSLError("no protocols available"))

    monkeypatch.setattr(
        tls_module.ssl,
        "create_default_context",
        lambda: context,
    )
    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda address, timeout: FakeRawSocket(),
    )

    version_name, version = tls_module._PROTOCOL_VERSIONS[-1]

    result = tls_module._probe_protocol(
        "example.com",
        443,
        5.0,
        version_name,
        version,
    )

    assert result.status == "inconclusive"
    assert result.error is not None
    assert "no protocols available" in result.error


def test_probe_protocol_marks_certificate_failure_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Certificate verification failure prevents confirming protocol support."""
    context = FakeSSLContext(
        error=ssl.SSLCertVerificationError("certificate verify failed")
    )

    monkeypatch.setattr(
        tls_module.ssl,
        "create_default_context",
        lambda: context,
    )
    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda address, timeout: FakeRawSocket(),
    )

    version_name, version = tls_module._PROTOCOL_VERSIONS[-1]

    result = tls_module._probe_protocol(
        "example.com",
        443,
        5.0,
        version_name,
        version,
    )

    assert result.status == "inconclusive"
    assert "SSLCertVerificationError" in (result.error or "")


def test_probe_protocol_rejects_unexpected_negotiated_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unexpected negotiated protocol must not be reported as supported."""
    context = FakeSSLContext(tls_socket=FakeTLSSocket(protocol="TLSv1.2"))

    monkeypatch.setattr(
        tls_module.ssl,
        "create_default_context",
        lambda: context,
    )
    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda address, timeout: FakeRawSocket(),
    )

    version_name, version = tls_module._PROTOCOL_VERSIONS[-1]

    result = tls_module._probe_protocol(
        "example.com",
        443,
        5.0,
        version_name,
        version,
    )

    assert result.status == "inconclusive"
    assert "unexpected protocol" in (result.error or "").lower()


def test_assess_protocols_probes_all_four_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The assessment must independently probe all four TLS versions."""
    calls: list[str] = []

    def fake_probe(
        domain: str,
        port: int,
        timeout: float,
        version_name: str,
        version: ssl.TLSVersion,
    ) -> tls_module.TLSProtocolAssessment:
        calls.append(version_name)

        return tls_module.TLSProtocolAssessment(
            version=version_name,
            status="inconclusive",
            error="Controlled test result",
        )

    monkeypatch.setattr(
        tls_module,
        "_probe_protocol",
        fake_probe,
    )

    results = tls_module._assess_protocols(
        "example.com",
        443,
        5.0,
    )

    assert calls == ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    assert len(results) == 4
    assert all(result.status == "inconclusive" for result in results)


def test_audit_tls_returns_legacy_findings_after_protocol_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """audit_tls should apply findings to protocol probe results."""
    context = FakeSSLContext(tls_socket=FakeTLSSocket())
    monkeypatch.setattr(
        tls_module.ssl,
        "create_default_context",
        lambda: context,
    )
    monkeypatch.setattr(
        tls_module.socket,
        "create_connection",
        lambda address, timeout: FakeRawSocket(),
    )

    calls: list[str] = []

    def fake_probe(
        domain: str,
        port: int,
        timeout: float,
        version_name: str,
        version: ssl.TLSVersion,
    ) -> tls_module.TLSProtocolAssessment:
        calls.append(version_name)
        status = "supported" if version_name in {"TLSv1", "TLSv1.1"} else "inconclusive"
        return tls_module.TLSProtocolAssessment(
            version=version_name,
            status=status,
        )

    monkeypatch.setattr(tls_module, "_probe_protocol", fake_probe)

    result = tls_module.audit_tls("example.com")

    assert calls == ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    assert [assessment.status for assessment in result.protocol_assessments] == [
        "supported",
        "supported",
        "inconclusive",
        "inconclusive",
    ]
    assert {finding.code for finding in result.findings} >= {
        "TLS_1_0_SUPPORTED",
        "TLS_1_1_SUPPORTED",
    }


@pytest.mark.parametrize(
    ("version", "expected_code"),
    [
        ("TLSv1", "TLS_1_0_SUPPORTED"),
        ("TLSv1.1", "TLS_1_1_SUPPORTED"),
    ],
)
def test_audit_tls_reports_legacy_protocol_support(
    version: str,
    expected_code: str,
) -> None:
    """Confirmed support for deprecated TLS versions must produce findings."""
    from domasentrix.checks.tls import (
        TLSAuditResult,
        TLSProtocolAssessment,
        _assess_legacy_protocol_findings,
    )

    result = TLSAuditResult(
        domain="example.com",
        port=443,
        protocol_assessments=[
            TLSProtocolAssessment(
                version=version,
                status="supported",
            )
        ],
    )

    _assess_legacy_protocol_findings(result)

    assert any(
        finding.code == expected_code and finding.severity == "high"
        for finding in result.findings
    )


@pytest.mark.parametrize("version", ["TLSv1", "TLSv1.1"])
def test_inconclusive_legacy_protocol_does_not_produce_finding(
    version: str,
) -> None:
    """Inconclusive protocol probes must not produce legacy support findings."""
    from domasentrix.checks.tls import (
        TLSAuditResult,
        TLSProtocolAssessment,
        _assess_legacy_protocol_findings,
    )

    result = TLSAuditResult(
        domain="example.com",
        port=443,
        protocol_assessments=[
            TLSProtocolAssessment(
                version=version,
                status="inconclusive",
                error="No compatible cipher suites",
            )
        ],
    )

    _assess_legacy_protocol_findings(result)

    assert result.findings == []
