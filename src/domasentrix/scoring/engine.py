"""Scoring engine for combining DNS, TLS, and HTTP assessment results."""

from collections.abc import Sequence
from dataclasses import dataclass, field

from domasentrix.checks.dns import DNSAuditResult, DNSFinding
from domasentrix.checks.http import HTTPAuditResult, HTTPFinding
from domasentrix.checks.tls import TLSAuditResult, TLSFinding
from domasentrix.core.target import normalize_domain
from domasentrix.scoring.models import (
    RiskLevel,
    ScoredFinding,
    SecurityAssessment,
    Severity,
    SourceCategory,
)

SEVERITY_POINTS: dict[Severity, int] = {
    "critical": 20,
    "high": 12,
    "medium": 6,
    "low": 2,
    "info": 0,
}

CATEGORY_CAPS: dict[SourceCategory, int] = {
    "dns": 25,
    "tls": 35,
    "http": 40,
}

RISK_THRESHOLDS: tuple[tuple[int, RiskLevel], ...] = (
    (90, "low"),
    (75, "moderate"),
    (50, "high"),
    (0, "critical"),
)

SOURCE_ORDER: tuple[SourceCategory, ...] = ("dns", "tls", "http")
SEVERITY_ORDER: tuple[Severity, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)
_SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
_HTTP_DISCLOSURE_CODES = frozenset(
    {"HTTP_SERVER_DISCLOSURE", "HTTP_X_POWERED_BY_DISCLOSURE"}
)

type _SourceFinding = DNSFinding | TLSFinding | HTTPFinding
type _AssessmentResult = DNSAuditResult | TLSAuditResult | HTTPAuditResult


@dataclass
class _FindingGroup:
    """Accumulate equivalent findings without losing their distinct evidence."""

    source: SourceCategory
    code: str
    severity: Severity
    messages: set[str] = field(default_factory=set)
    evidence: set[str] = field(default_factory=set)
    remediations: set[str] = field(default_factory=set)


def _joined_optional(values: set[str]) -> str | None:
    return "; ".join(sorted(values)) if values else None


def _deduplication_key(
    source: SourceCategory,
    finding: _SourceFinding,
    evidence: str | None,
    remediation: str | None,
) -> tuple[object, ...]:
    if source == "tls" and finding.code == "TLS_CERTIFICATE_EXPIRED":
        return ("group", source, finding.code)
    if source == "http" and finding.code in _HTTP_DISCLOSURE_CODES:
        return ("group", source, finding.code)
    return (
        "exact",
        source,
        finding.code,
        finding.severity,
        finding.message,
        evidence,
        remediation,
    )


def _collect_findings(
    grouped: dict[tuple[object, ...], _FindingGroup],
    source: SourceCategory,
    findings: Sequence[_SourceFinding],
) -> None:
    for finding in findings:
        evidence = finding.evidence if isinstance(finding, HTTPFinding) else None
        remediation = finding.remediation if isinstance(finding, HTTPFinding) else None
        key = _deduplication_key(source, finding, evidence, remediation)
        group = grouped.get(key)
        if group is None:
            group = _FindingGroup(
                source=source,
                code=finding.code,
                severity=finding.severity,
            )
            grouped[key] = group
        elif _SEVERITY_RANK[finding.severity] < _SEVERITY_RANK[group.severity]:
            group.severity = finding.severity

        group.messages.add(finding.message)
        if evidence is not None:
            group.evidence.add(evidence)
        if remediation is not None:
            group.remediations.add(remediation)


def _normalize_findings(
    dns_result: DNSAuditResult | None,
    tls_result: TLSAuditResult | None,
    http_result: HTTPAuditResult | None,
) -> list[ScoredFinding]:
    grouped: dict[tuple[object, ...], _FindingGroup] = {}
    if dns_result is not None:
        _collect_findings(grouped, "dns", dns_result.findings)
    if tls_result is not None:
        _collect_findings(grouped, "tls", tls_result.findings)
    if http_result is not None:
        _collect_findings(grouped, "http", http_result.findings)

    scored = [
        ScoredFinding(
            source=group.source,
            code=group.code,
            severity=group.severity,
            message="; ".join(sorted(group.messages)),
            deduction=SEVERITY_POINTS[group.severity],
            evidence=_joined_optional(group.evidence),
            remediation=_joined_optional(group.remediations),
        )
        for group in grouped.values()
    ]
    source_order = {source: index for index, source in enumerate(SOURCE_ORDER)}
    return sorted(
        scored,
        key=lambda finding: (
            source_order[finding.source],
            _SEVERITY_RANK[finding.severity],
            finding.code,
            finding.message,
            finding.evidence or "",
            finding.remediation or "",
        ),
    )


def _risk_level_for_score(score: int) -> RiskLevel:
    for minimum_score, risk_level in RISK_THRESHOLDS:
        if score >= minimum_score:
            return risk_level
    return "critical"


def _errors_for_source(
    result: _AssessmentResult | None,
) -> dict[str, str]:
    return {} if result is None else dict(result.errors)


def _assessment_target_domain(
    results: dict[SourceCategory, _AssessmentResult | None],
) -> str | None:
    domains = {
        source: normalize_domain(result.domain)
        for source, result in results.items()
        if result is not None
    }
    if len(set(domains.values())) > 1:
        details = ", ".join(f"{source}={domain}" for source, domain in domains.items())
        raise ValueError(
            f"Assessment results must refer to the same domain: {details}."
        )
    return next(iter(domains.values()), None)


def score_assessment(
    dns_result: DNSAuditResult | None = None,
    tls_result: TLSAuditResult | None = None,
    http_result: HTTPAuditResult | None = None,
) -> SecurityAssessment:
    """Score findings while keeping missing modules and operational errors explicit.

    Exact duplicate findings are counted once. Expired-certificate findings
    are grouped by TLS code, and HTTP Server/X-Powered-By disclosures are
    grouped by source and code. Grouped evidence, messages, and remediations
    are combined deterministically rather than discarded. Each finding's
    deduction is its severity weight before the source category cap is applied.
    """
    results: dict[SourceCategory, _AssessmentResult | None] = {
        "dns": dns_result,
        "tls": tls_result,
        "http": http_result,
    }
    target_domain = _assessment_target_domain(results)
    available_sources = [
        source for source in SOURCE_ORDER if results[source] is not None
    ]
    missing_sources = [source for source in SOURCE_ORDER if results[source] is None]
    has_operational_errors = any(
        result is not None and bool(result.errors) for result in results.values()
    )
    is_complete = not missing_sources and not has_operational_errors

    findings = _normalize_findings(dns_result, tls_result, http_result)
    finding_counts: dict[Severity, int] = {severity: 0 for severity in SEVERITY_ORDER}
    category_deductions: dict[SourceCategory, int] = {
        source: 0 for source in SOURCE_ORDER
    }
    for finding in findings:
        finding_counts[finding.severity] += 1
        category_deductions[finding.source] += finding.deduction

    category_deductions = {
        source: min(deduction, CATEGORY_CAPS[source])
        for source, deduction in category_deductions.items()
    }
    total_deduction = sum(category_deductions.values()) if is_complete else None
    overall_score = (
        max(0, min(100, 100 - total_deduction)) if total_deduction is not None else None
    )
    risk_level = (
        _risk_level_for_score(overall_score) if overall_score is not None else None
    )

    return SecurityAssessment(
        overall_score=overall_score,
        risk_level=risk_level,
        is_complete=is_complete,
        available_sources=available_sources,
        missing_sources=missing_sources,
        findings=findings,
        finding_counts_by_severity=finding_counts,
        category_deductions=category_deductions,
        total_deduction=total_deduction,
        operational_errors={
            "dns": _errors_for_source(dns_result),
            "tls": _errors_for_source(tls_result),
            "http": _errors_for_source(http_result),
        },
        target_domain=target_domain,
    )
