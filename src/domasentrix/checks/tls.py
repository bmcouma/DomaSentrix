"""TLS certificate and connection security assessment."""

import socket
import ssl
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from math import isfinite
from typing import Literal, cast

from domasentrix.core.target import normalize_domain

Severity = Literal["critical", "high", "medium", "low", "info"]
ProtocolStatus = Literal["supported", "unsupported", "inconclusive"]


@dataclass(frozen=True)
class TLSFinding:
    """A security observation from a TLS assessment."""

    code: str
    severity: Severity
    message: str


@dataclass(frozen=True)
class TLSCertificateInfo:
    """Information retrieved from a verified TLS certificate."""

    subject: str
    issuer: str
    serial_number: str
    version: int
    not_before: datetime
    not_after: datetime
    days_until_expiry: int
    subject_alt_names: tuple[str, ...]


@dataclass(frozen=True)
class TLSProtocolAssessment:
    """Result of testing one specific TLS protocol version."""

    version: str
    status: ProtocolStatus
    cipher: str | None = None
    error: str | None = None


@dataclass
class TLSAuditResult:
    """Structured results from a TLS assessment."""

    domain: str
    port: int
    protocol: str | None = None
    cipher: str | None = None
    certificate: TLSCertificateInfo | None = None
    protocol_assessments: list[TLSProtocolAssessment] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    findings: list[TLSFinding] = field(default_factory=list)


_TLS_1_0 = ssl.TLSVersion(0x0301)
_TLS_1_1 = ssl.TLSVersion(0x0302)

_PROTOCOL_VERSIONS = (
    ("TLSv1", _TLS_1_0),
    ("TLSv1.1", _TLS_1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)


def _format_name(name: tuple[tuple[tuple[str, str], ...], ...]) -> str:
    """Convert a certificate distinguished name into readable text."""
    attributes = [f"{key}={value}" for group in name for key, value in group]
    return ", ".join(attributes)


def _extract_certificate(
    certificate: Mapping[str, object],
) -> TLSCertificateInfo:
    """Extract information from a certificate returned by a verified socket."""
    subject = cast(
        tuple[tuple[tuple[str, str], ...], ...],
        certificate["subject"],
    )
    issuer = cast(
        tuple[tuple[tuple[str, str], ...], ...],
        certificate["issuer"],
    )

    not_before_raw = cast(str, certificate["notBefore"])
    not_after_raw = cast(str, certificate["notAfter"])

    not_before = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(not_before_raw),
        tz=UTC,
    )
    not_after = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(not_after_raw),
        tz=UTC,
    )

    now = datetime.now(UTC)
    days_until_expiry = (not_after - now).days

    san_entries = cast(
        tuple[tuple[str, str], ...],
        certificate.get("subjectAltName", ()),
    )
    subject_alt_names = tuple(
        value for name_type, value in san_entries if name_type == "DNS"
    )

    return TLSCertificateInfo(
        subject=_format_name(subject),
        issuer=_format_name(issuer),
        serial_number=cast(str, certificate.get("serialNumber", "")),
        version=cast(int, certificate.get("version", 0)),
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=days_until_expiry,
        subject_alt_names=subject_alt_names,
    )


def _probe_protocol(
    domain: str,
    port: int,
    timeout: float,
    version_name: str,
    version: ssl.TLSVersion,
) -> TLSProtocolAssessment:
    """Test one TLS version while preserving certificate verification."""
    try:
        context = ssl.create_default_context()
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=r"ssl\.TLSVersion\.TLSv1(_1)? is deprecated",
                category=DeprecationWarning,
            )
            context.minimum_version = version
            context.maximum_version = version

        with socket.create_connection(
            (domain, port),
            timeout=timeout,
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=domain,
            ) as tls_socket:
                negotiated_protocol = tls_socket.version()

                if negotiated_protocol != version_name:
                    return TLSProtocolAssessment(
                        version=version_name,
                        status="inconclusive",
                        error=(
                            "The connection negotiated an unexpected "
                            f"protocol: {negotiated_protocol}."
                        ),
                    )

                cipher_info = tls_socket.cipher()
                return TLSProtocolAssessment(
                    version=version_name,
                    status="supported",
                    cipher=cipher_info[0] if cipher_info else None,
                )

    except (ssl.SSLError, OSError, OverflowError, TimeoutError, ValueError) as exc:
        return TLSProtocolAssessment(
            version=version_name,
            status="inconclusive",
            error=f"{type(exc).__name__}: {exc}",
        )


def _assess_protocols(
    domain: str,
    port: int,
    timeout: float,
) -> list[TLSProtocolAssessment]:
    """Assess TLS 1.0 through TLS 1.3 independently."""
    return [
        _probe_protocol(domain, port, timeout, version_name, version)
        for version_name, version in _PROTOCOL_VERSIONS
    ]


def _assess_certificate_findings(result: TLSAuditResult) -> None:
    """Add security findings based on verified certificate information."""
    certificate = result.certificate
    if certificate is None:
        return

    expiry_remaining = certificate.not_after - datetime.now(UTC)

    if expiry_remaining.total_seconds() < 0:
        result.findings.append(
            TLSFinding(
                code="TLS_CERTIFICATE_EXPIRED",
                severity="high",
                message="The TLS certificate has expired.",
            )
        )
    elif expiry_remaining <= timedelta(days=7):
        result.findings.append(
            TLSFinding(
                code="TLS_CERTIFICATE_EXPIRING_CRITICAL",
                severity="high",
                message="The TLS certificate expires within seven days.",
            )
        )
    elif expiry_remaining <= timedelta(days=30):
        result.findings.append(
            TLSFinding(
                code="TLS_CERTIFICATE_EXPIRING_SOON",
                severity="medium",
                message="The TLS certificate expires within 30 days.",
            )
        )

    if result.protocol == "TLSv1.2":
        result.findings.append(
            TLSFinding(
                code="TLS_1_2_NEGOTIATED",
                severity="info",
                message=(
                    "The server negotiated TLS 1.2. "
                    "TLS 1.3 is preferable where supported."
                ),
            )
        )

    if not certificate.subject_alt_names:
        result.findings.append(
            TLSFinding(
                code="TLS_CERTIFICATE_NO_SAN",
                severity="low",
                message=(
                    "The certificate does not expose DNS Subject Alternative Names."
                ),
            )
        )


def _assess_legacy_protocol_findings(result: TLSAuditResult) -> None:
    """Report support for deprecated TLS protocol versions."""
    for assessment in result.protocol_assessments:
        if assessment.status != "supported":
            continue

        if assessment.version == "TLSv1":
            result.findings.append(
                TLSFinding(
                    code="TLS_1_0_SUPPORTED",
                    severity="high",
                    message="The server supports deprecated TLS 1.0.",
                )
            )
        elif assessment.version == "TLSv1.1":
            result.findings.append(
                TLSFinding(
                    code="TLS_1_1_SUPPORTED",
                    severity="high",
                    message="The server supports deprecated TLS 1.1.",
                )
            )


def audit_tls(
    domain: str,
    port: int = 443,
    timeout: float = 5.0,
) -> TLSAuditResult:
    """Assess TLS connectivity, protocol support, and certificate security.

    The timeout applies to each connection attempt, so the total assessment
    may take longer when protocol probing requires multiple attempts.
    """
    normalized_domain = normalize_domain(domain)

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if not isfinite(timeout) or timeout <= 0:
        raise ValueError("Timeout must be finite and greater than zero.")

    result = TLSAuditResult(domain=normalized_domain, port=port)

    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        with socket.create_connection(
            (normalized_domain, port),
            timeout=timeout,
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=normalized_domain,
            ) as tls_socket:
                result.protocol = tls_socket.version()
                cipher_info = tls_socket.cipher()
                if cipher_info is not None:
                    result.cipher = cipher_info[0]

                peer_certificate = tls_socket.getpeercert()
                if not peer_certificate:
                    result.errors["certificate"] = (
                        "The server did not provide a readable certificate."
                    )
                else:
                    result.certificate = _extract_certificate(peer_certificate)

    except ssl.SSLCertVerificationError as exc:
        result.errors["connection"] = f"Certificate verification failed: {exc}"
        verification_message = getattr(exc, "verify_message", "") or str(exc)

        if (
            getattr(exc, "verify_code", None) == 10
            or "certificate has expired" in verification_message.lower()
        ):
            result.findings.append(
                TLSFinding(
                    code="TLS_CERTIFICATE_EXPIRED",
                    severity="high",
                    message="The TLS certificate has expired.",
                )
            )

        result.findings.append(
            TLSFinding(
                code="TLS_CERTIFICATE_VERIFICATION_FAILED",
                severity="high",
                message=(
                    "The TLS certificate could not be verified against "
                    "the system trust store or failed hostname validation."
                ),
            )
        )
    except ssl.SSLError as exc:
        result.errors["connection"] = f"TLS connection failed: {exc}"
    except TimeoutError:
        result.errors["connection"] = (
            f"TLS connection timed out after {timeout} seconds."
        )
    except OverflowError as exc:
        result.errors["connection"] = (
            f"TLS connection timeout is outside the supported range: {exc}"
        )
    except OSError as exc:
        result.errors["connection"] = f"Network connection failed: {exc}"

    result.protocol_assessments = _assess_protocols(
        normalized_domain,
        port,
        timeout,
    )
    _assess_certificate_findings(result)
    _assess_legacy_protocol_findings(result)

    return result
