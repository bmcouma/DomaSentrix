"""Tests for the versioned JSON assessment report."""

import json
from datetime import UTC, datetime

import pytest

from domasentrix.checks.dns import DNSAuditResult, DNSFinding
from domasentrix.checks.http import HTTPAuditResult, HTTPFinding
from domasentrix.checks.tls import TLSAuditResult
from domasentrix.reporting.json import (
    REPORT_TYPE,
    SCHEMA_VERSION,
    build_assessment_report,
    serialize_assessment_report,
)
from domasentrix.scoring import score_assessment


def test_complete_report_has_versioned_metadata_and_typed_assessment_fields() -> None:
    assessment = score_assessment(
        DNSAuditResult(
            domain="example.com",
            findings=[
                DNSFinding(
                    "SPF_MISSING",
                    "medium",
                    "No SPF policy was found.",
                )
            ],
        ),
        TLSAuditResult(domain="example.com", port=443),
        HTTPAuditResult(
            domain="example.com",
            http_port=80,
            https_port=443,
            findings=[
                HTTPFinding(
                    "HTTP_SERVER_DISCLOSURE",
                    "low",
                    "The Server header discloses implementation information.",
                    "HTTPS: example-server/1.2",
                    "Remove unnecessary server identification.",
                )
            ],
        ),
    )

    serialized = serialize_assessment_report("EXAMPLE.COM.", assessment)
    report = json.loads(serialized)

    assert set(report) == {
        "schema_version",
        "report_type",
        "generated_at",
        "target",
        "assessment",
        "findings",
        "operational_errors",
    }
    assert report["schema_version"] == SCHEMA_VERSION == "1.0"
    assert report["report_type"] == REPORT_TYPE == "domain_security_assessment"
    assert report["target"] == {"domain": "example.com"}
    generated_at = datetime.fromisoformat(report["generated_at"].replace("Z", "+00:00"))
    assert generated_at.utcoffset() == UTC.utcoffset(generated_at)

    summary = report["assessment"]
    assert summary["completeness"] == "complete"
    assert summary["score"] == 92
    assert summary["risk"] == "low"
    assert summary["available_sources"] == ["dns", "tls", "http"]
    assert summary["missing_sources"] == []
    assert summary["total_deduction"] == 8
    assert summary["category_deductions"] == {"dns": 6, "tls": 0, "http": 2}
    assert summary["category_caps"] == {"dns": 25, "tls": 35, "http": 40}
    assert summary["severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 1,
        "low": 1,
        "info": 0,
    }
    assert report["findings"] == [
        {
            "source": "dns",
            "code": "SPF_MISSING",
            "severity": "medium",
            "message": "No SPF policy was found.",
            "deduction": 6,
            "evidence": None,
            "remediation": None,
        },
        {
            "source": "http",
            "code": "HTTP_SERVER_DISCLOSURE",
            "severity": "low",
            "message": "The Server header discloses implementation information.",
            "deduction": 2,
            "evidence": "HTTPS: example-server/1.2",
            "remediation": "Remove unnecessary server identification.",
        },
    ]
    assert report["operational_errors"] == []


def test_partial_report_uses_nulls_and_keeps_operational_errors_separate() -> None:
    assessment = score_assessment(
        DNSAuditResult(
            domain="example.com",
            errors={"A": "The DNS query timed out."},
        ),
        None,
        HTTPAuditResult(domain="example.com", http_port=80, https_port=443),
    )

    report = build_assessment_report(
        "example.com",
        assessment,
        unavailable_errors={"tls": "TimeoutError: TLS connection timed out."},
    )

    assert report["assessment"]["completeness"] == "partial"
    assert report["assessment"]["score"] is None
    assert report["assessment"]["risk"] is None
    assert report["assessment"]["total_deduction"] is None
    assert report["assessment"]["available_sources"] == ["dns", "http"]
    assert report["assessment"]["missing_sources"] == ["tls"]
    assert report["operational_errors"] == [
        {
            "source": "dns",
            "category": "A",
            "message": "The DNS query timed out.",
        },
        {
            "source": "tls",
            "category": "assessment",
            "message": "TimeoutError: TLS connection timed out.",
        },
    ]
    assert report["findings"] == []


def test_operational_errors_do_not_become_findings() -> None:
    assessment = score_assessment(
        DNSAuditResult(domain="example.com", errors={"TXT": "Resolver unavailable."}),
        TLSAuditResult(domain="example.com", port=443),
        HTTPAuditResult(domain="example.com", http_port=80, https_port=443),
    )

    report = json.loads(serialize_assessment_report("example.com", assessment))

    assert report["assessment"]["completeness"] == "partial"
    assert report["assessment"]["score"] is None
    assert report["findings"] == []
    assert report["operational_errors"] == [
        {
            "source": "dns",
            "category": "TXT",
            "message": "Resolver unavailable.",
        }
    ]


def test_json_report_is_deterministic_except_for_generation_timestamp() -> None:
    assessment = score_assessment(
        DNSAuditResult(domain="example.com"),
        TLSAuditResult(domain="example.com", port=443),
        HTTPAuditResult(domain="example.com", http_port=80, https_port=443),
    )

    first = json.loads(serialize_assessment_report("example.com", assessment))
    second = json.loads(serialize_assessment_report("example.com", assessment))
    first.pop("generated_at")
    second.pop("generated_at")

    assert first == second


def test_report_rejects_a_target_that_differs_from_the_assessment() -> None:
    assessment = score_assessment(
        DNSAuditResult(domain="example.com"),
        TLSAuditResult(domain="example.com", port=443),
        HTTPAuditResult(domain="example.com", http_port=80, https_port=443),
    )

    with pytest.raises(ValueError, match="does not match the assessment target"):
        build_assessment_report("other.example", assessment)
