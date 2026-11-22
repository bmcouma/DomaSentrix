"""Versioned JSON serialization for combined security assessments."""

import json
from collections.abc import Mapping
from datetime import UTC, datetime

from domasentrix.core.target import normalize_domain
from domasentrix.scoring.engine import CATEGORY_CAPS, SEVERITY_ORDER, SOURCE_ORDER
from domasentrix.scoring.models import SecurityAssessment, SourceCategory

SCHEMA_VERSION = "1.0"
REPORT_TYPE = "domain_security_assessment"


def build_assessment_report(
    domain: str,
    assessment: SecurityAssessment,
    unavailable_errors: Mapping[SourceCategory, str] | None = None,
) -> dict[str, object]:
    """Build a JSON-compatible report without exposing raw check responses."""
    normalized_domain = normalize_domain(domain)
    if assessment.target_domain is not None:
        assessment_domain = normalize_domain(assessment.target_domain)
        if normalized_domain != assessment_domain:
            raise ValueError(
                "Report target domain does not match the assessment target: "
                f"{normalized_domain} != {assessment_domain}."
            )

    operational_errors: list[dict[str, str]] = []
    for source in SOURCE_ORDER:
        for category, message in sorted(assessment.operational_errors[source].items()):
            operational_errors.append(
                {"source": source, "category": category, "message": message}
            )
        if unavailable_errors is not None and source in unavailable_errors:
            operational_errors.append(
                {
                    "source": source,
                    "category": "assessment",
                    "message": unavailable_errors[source],
                }
            )

    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "generated_at": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "target": {"domain": normalized_domain},
        "assessment": {
            "completeness": "complete" if assessment.is_complete else "partial",
            "score": assessment.overall_score,
            "risk": assessment.risk_level,
            "available_sources": list(assessment.available_sources),
            "missing_sources": list(assessment.missing_sources),
            "total_deduction": assessment.total_deduction,
            "category_deductions": {
                source: assessment.category_deductions[source]
                for source in SOURCE_ORDER
            },
            "category_caps": {source: CATEGORY_CAPS[source] for source in SOURCE_ORDER},
            "severity_counts": {
                severity: assessment.finding_counts_by_severity[severity]
                for severity in SEVERITY_ORDER
            },
        },
        "findings": [
            {
                "source": finding.source,
                "code": finding.code,
                "severity": finding.severity,
                "message": finding.message,
                "deduction": finding.deduction,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            }
            for finding in assessment.findings
        ],
        "operational_errors": operational_errors,
    }


def serialize_assessment_report(
    domain: str,
    assessment: SecurityAssessment,
    unavailable_errors: Mapping[SourceCategory, str] | None = None,
) -> str:
    """Serialize an assessment using stable, UTF-8-compatible JSON."""
    return json.dumps(
        build_assessment_report(domain, assessment, unavailable_errors),
        ensure_ascii=True,
        allow_nan=False,
        indent=2,
    )
