"""Unit tests for combined security assessment scoring."""

import pytest

from domasentrix.checks.dns import DNSAuditResult, DNSFinding
from domasentrix.checks.http import HTTPAuditResult, HTTPFinding
from domasentrix.checks.tls import TLSAuditResult, TLSFinding
from domasentrix.scoring import score_assessment
from domasentrix.scoring.engine import _risk_level_for_score
from domasentrix.scoring.models import Severity


def _dns(
    findings: list[DNSFinding] | None = None,
    errors: dict[str, str] | None = None,
    domain: str = "example.com",
) -> DNSAuditResult:
    return DNSAuditResult(
        domain=domain,
        findings=[] if findings is None else findings,
        errors={} if errors is None else errors,
    )


def _tls(
    findings: list[TLSFinding] | None = None,
    errors: dict[str, str] | None = None,
    domain: str = "example.com",
) -> TLSAuditResult:
    return TLSAuditResult(
        domain=domain,
        port=443,
        findings=[] if findings is None else findings,
        errors={} if errors is None else errors,
    )


def _http(
    findings: list[HTTPFinding] | None = None,
    errors: dict[str, str] | None = None,
    domain: str = "example.com",
) -> HTTPAuditResult:
    return HTTPAuditResult(
        domain=domain,
        http_port=80,
        https_port=443,
        findings=[] if findings is None else findings,
        errors={} if errors is None else errors,
    )


def _http_finding(
    code: str,
    severity: Severity,
    message: str,
    evidence: str = "HTTPS response",
    remediation: str = "Review the security configuration.",
) -> HTTPFinding:
    return HTTPFinding(
        code=code,
        severity=severity,
        message=message,
        evidence=evidence,
        remediation=remediation,
    )


def test_complete_assessment_without_findings_scores_100() -> None:
    result = score_assessment(_dns(), _tls(), _http())

    assert result.target_domain == "example.com"
    assert result.overall_score == 100
    assert result.risk_level == "low"
    assert result.is_complete
    assert result.available_sources == ["dns", "tls", "http"]
    assert result.missing_sources == []
    assert result.findings == []
    assert result.total_deduction == 0
    assert result.category_deductions == {"dns": 0, "tls": 0, "http": 0}


def test_source_domains_are_normalized_before_consistency_check() -> None:
    result = score_assessment(
        _dns(domain="EXAMPLE.COM."),
        _tls(domain="example.com"),
        _http(domain="example.com"),
    )

    assert result.target_domain == "example.com"


def test_source_results_for_different_domains_are_rejected() -> None:
    with pytest.raises(ValueError, match="same domain"):
        score_assessment(_dns(), _tls(domain="other.example"), _http())


def test_complete_assessment_scores_findings_from_all_modules() -> None:
    result = score_assessment(
        _dns([DNSFinding("SPF_MISSING", "high", "No SPF policy was found.")]),
        _tls([TLSFinding("TLS_CERTIFICATE_EXPIRED", "medium", "Certificate expired.")]),
        _http(
            [
                _http_finding(
                    "HTTP_SERVER_DISCLOSURE",
                    "low",
                    "The Server header discloses implementation information.",
                )
            ]
        ),
    )

    assert result.category_deductions == {"dns": 12, "tls": 6, "http": 2}
    assert result.total_deduction == 20
    assert result.overall_score == 80
    assert result.risk_level == "moderate"
    assert {finding.source for finding in result.findings} == {"dns", "tls", "http"}
    assert all(
        finding.evidence is None and finding.remediation is None
        for finding in result.findings
        if finding.source in {"dns", "tls"}
    )


def test_severity_weights_and_informational_findings() -> None:
    findings = [
        _http_finding(f"HTTP_TEST_{severity}", severity, f"{severity} finding.")
        for severity in ("critical", "high", "medium", "low", "info")
    ]

    result = score_assessment(_dns(), _tls(), _http(findings))

    assert [finding.deduction for finding in result.findings] == [20, 12, 6, 2, 0]
    assert result.category_deductions["http"] == 40
    assert result.finding_counts_by_severity == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
        "info": 1,
    }


def test_dns_category_deduction_is_capped_at_25() -> None:
    findings = [
        DNSFinding(f"DNS_CRITICAL_{index}", "critical", "Critical DNS weakness.")
        for index in range(3)
    ]

    result = score_assessment(_dns(findings), _tls(), _http())

    assert result.category_deductions["dns"] == 25
    assert result.total_deduction == 25
    assert result.overall_score == 75


def test_tls_category_deduction_is_capped_at_35() -> None:
    findings = [
        TLSFinding(f"TLS_CRITICAL_{index}", "critical", "Critical TLS weakness.")
        for index in range(3)
    ]

    result = score_assessment(_dns(), _tls(findings), _http())

    assert result.category_deductions["tls"] == 35
    assert result.total_deduction == 35
    assert result.overall_score == 65


def test_http_category_deduction_is_capped_at_40() -> None:
    findings = [
        _http_finding(
            f"HTTP_CRITICAL_{index}",
            "critical",
            "Critical HTTP weakness.",
            evidence=f"Endpoint {index}",
        )
        for index in range(3)
    ]

    result = score_assessment(_dns(), _tls(), _http(findings))

    assert result.category_deductions["http"] == 40
    assert result.total_deduction == 40
    assert result.overall_score == 60


def test_overall_score_is_clamped_at_zero() -> None:
    dns_findings = [
        DNSFinding(f"DNS_{index}", "critical", "Critical DNS weakness.")
        for index in range(2)
    ]
    tls_findings = [
        TLSFinding(f"TLS_{index}", "critical", "Critical TLS weakness.")
        for index in range(2)
    ]
    http_findings = [
        _http_finding(
            f"HTTP_{index}",
            "critical",
            "Critical HTTP weakness.",
            evidence=f"Endpoint {index}",
        )
        for index in range(3)
    ]

    result = score_assessment(
        _dns(dns_findings),
        _tls(tls_findings),
        _http(http_findings),
    )

    assert result.category_deductions == {"dns": 25, "tls": 35, "http": 40}
    assert result.total_deduction == 100
    assert result.overall_score == 0
    assert result.risk_level == "critical"


@pytest.mark.parametrize(
    ("score", "expected_risk"),
    [
        (100, "low"),
        (90, "low"),
        (89, "moderate"),
        (75, "moderate"),
        (74, "high"),
        (50, "high"),
        (49, "critical"),
        (0, "critical"),
    ],
)
def test_risk_classification_boundaries(score: int, expected_risk: str) -> None:
    assert _risk_level_for_score(score) == expected_risk


def test_duplicate_expired_certificate_findings_are_scored_once() -> None:
    result = score_assessment(
        _dns(),
        _tls(
            [
                TLSFinding(
                    "TLS_CERTIFICATE_EXPIRED",
                    "high",
                    "The initial connection certificate has expired.",
                ),
                TLSFinding(
                    "TLS_CERTIFICATE_EXPIRED",
                    "high",
                    "A protocol probe found the same expired certificate.",
                ),
            ]
        ),
        _http(),
    )

    expiry_findings = [
        finding
        for finding in result.findings
        if finding.code == "TLS_CERTIFICATE_EXPIRED"
    ]
    assert len(expiry_findings) == 1
    assert result.category_deductions["tls"] == 12
    assert "initial connection" in expiry_findings[0].message
    assert "protocol probe" in expiry_findings[0].message


def test_http_disclosures_are_grouped_without_losing_evidence() -> None:
    result = score_assessment(
        _dns(),
        _tls(),
        _http(
            [
                _http_finding(
                    "HTTP_SERVER_DISCLOSURE",
                    "low",
                    "The Server header discloses implementation information.",
                    evidence="HTTP: nginx",
                ),
                _http_finding(
                    "HTTP_SERVER_DISCLOSURE",
                    "low",
                    "The Server header discloses implementation information.",
                    evidence="HTTPS: nginx",
                ),
            ]
        ),
    )

    disclosure = result.findings[0]
    assert len(result.findings) == 1
    assert result.category_deductions["http"] == 2
    assert disclosure.evidence == "HTTP: nginx; HTTPS: nginx"


@pytest.mark.parametrize("missing", ["dns", "tls", "http"])
def test_each_missing_module_makes_assessment_partial(missing: str) -> None:
    dns_result = _dns([DNSFinding("SPF_MISSING", "high", "No SPF policy.")])
    tls_result = _tls([TLSFinding("TLS_WEAK", "medium", "Weak TLS setting.")])
    http_result = _http([_http_finding("HTTP_CSP_MISSING", "low", "No CSP header.")])
    if missing == "dns":
        result = score_assessment(None, tls_result, http_result)
    elif missing == "tls":
        result = score_assessment(dns_result, None, http_result)
    else:
        result = score_assessment(dns_result, tls_result, None)

    assert not result.is_complete
    assert result.missing_sources == [missing]
    assert result.available_sources == [
        source for source in ("dns", "tls", "http") if source != missing
    ]
    assert result.overall_score is None
    assert result.risk_level is None
    assert result.total_deduction is None
    assert result.category_deductions[missing] == 0
    assert sum(result.category_deductions.values()) > 0
    assert result.findings


def test_all_missing_modules_return_partial_assessment() -> None:
    result = score_assessment()

    assert result.target_domain is None
    assert not result.is_complete
    assert result.available_sources == []
    assert result.missing_sources == ["dns", "tls", "http"]
    assert result.overall_score is None
    assert result.risk_level is None
    assert result.total_deduction is None
    assert result.findings == []


def test_operational_errors_are_separate_from_security_findings() -> None:
    result = score_assessment(
        _dns(errors={"A": "DNS query timed out."}),
        _tls(errors={"connection": "Connection timed out."}),
        _http(errors={"https_request": "timeout: timed out"}),
    )

    assert not result.is_complete
    assert result.overall_score is None
    assert result.risk_level is None
    assert result.total_deduction is None
    assert result.available_sources == ["dns", "tls", "http"]
    assert result.missing_sources == []
    assert result.findings == []
    assert result.category_deductions == {"dns": 0, "tls": 0, "http": 0}
    assert result.operational_errors == {
        "dns": {"A": "DNS query timed out."},
        "tls": {"connection": "Connection timed out."},
        "http": {"https_request": "timeout: timed out"},
    }


def test_operational_errors_withhold_overall_score_without_deducting_points() -> None:
    result = score_assessment(
        _dns(
            [DNSFinding("SPF_MISSING", "medium", "No SPF policy was found.")],
            errors={"TXT": "DNS query timed out."},
        ),
        _tls(),
        _http(),
    )

    assert not result.is_complete
    assert result.overall_score is None
    assert result.risk_level is None
    assert result.total_deduction is None
    assert result.category_deductions == {"dns": 6, "tls": 0, "http": 0}
    assert [finding.code for finding in result.findings] == ["SPF_MISSING"]
    assert result.operational_errors["dns"] == {"TXT": "DNS query timed out."}


def test_http_evidence_and_remediation_are_preserved() -> None:
    finding = _http_finding(
        "HTTP_CSP_WEAK_POLICY",
        "medium",
        "The CSP contains broad source expressions.",
        evidence="content-security-policy: script-src *",
        remediation="Narrow the policy source list.",
    )

    result = score_assessment(_dns(), _tls(), _http([finding]))

    scored = result.findings[0]
    assert scored.evidence == finding.evidence
    assert scored.remediation == finding.remediation
    assert scored.message == finding.message
    assert scored.code == finding.code
    assert scored.severity == finding.severity


def test_exact_duplicate_findings_are_deduplicated() -> None:
    finding = DNSFinding("SPF_MISSING", "high", "No SPF policy was found.")

    result = score_assessment(_dns([finding, finding]), _tls(), _http())

    assert len(result.findings) == 1
    assert result.category_deductions["dns"] == 12


def test_finding_order_is_deterministic() -> None:
    dns_findings = [
        DNSFinding("Z_DNS", "low", "Low DNS issue."),
        DNSFinding("A_DNS", "critical", "Critical DNS issue."),
    ]
    tls_findings = [
        TLSFinding("B_TLS", "medium", "Medium TLS issue."),
        TLSFinding("A_TLS", "high", "High TLS issue."),
    ]
    first = score_assessment(_dns(dns_findings), _tls(tls_findings), _http())
    second = score_assessment(
        _dns(list(reversed(dns_findings))),
        _tls(list(reversed(tls_findings))),
        _http(),
    )

    assert first.findings == second.findings
    assert [finding.source for finding in first.findings] == [
        "dns",
        "dns",
        "tls",
        "tls",
    ]
    assert [finding.severity for finding in first.findings] == [
        "critical",
        "low",
        "high",
        "medium",
    ]


def test_distinct_codes_and_source_categories_remain_distinguishable() -> None:
    result = score_assessment(
        _dns([DNSFinding("POLICY_MISSING", "high", "A policy is missing.")]),
        _tls([TLSFinding("POLICY_MISSING", "high", "A policy is missing.")]),
        _http(
            [
                _http_finding(
                    "HTTP_POLICY_MISSING",
                    "high",
                    "A policy is missing.",
                )
            ]
        ),
    )

    assert len(result.findings) == 3
    assert {finding.source for finding in result.findings} == {"dns", "tls", "http"}
    assert result.total_deduction == 36
