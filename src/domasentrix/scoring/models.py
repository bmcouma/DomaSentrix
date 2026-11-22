"""Structured models for combined security assessments."""

from dataclasses import dataclass
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
SourceCategory = Literal["dns", "tls", "http"]
RiskLevel = Literal["low", "moderate", "high", "critical"]


@dataclass(frozen=True)
class ScoredFinding:
    """A finding with its uncapped severity weight and normalized details."""

    source: SourceCategory
    code: str
    severity: Severity
    message: str
    deduction: int
    evidence: str | None = None
    remediation: str | None = None


@dataclass
class SecurityAssessment:
    """Combined score, findings, completeness, and operational errors.

    The overall score, risk level, and total deduction are ``None`` when an
    input module is missing or any supplied module reports operational errors.
    Available and missing sources describe supplied result objects; a source
    with operational errors remains available but makes the assessment partial.
    """

    overall_score: int | None
    risk_level: RiskLevel | None
    is_complete: bool
    available_sources: list[SourceCategory]
    missing_sources: list[SourceCategory]
    findings: list[ScoredFinding]
    finding_counts_by_severity: dict[Severity, int]
    category_deductions: dict[SourceCategory, int]
    total_deduction: int | None
    operational_errors: dict[SourceCategory, dict[str, str]]
    target_domain: str | None = None
