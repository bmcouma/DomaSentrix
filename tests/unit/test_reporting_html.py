"""Tests for safe, self-contained HTML assessment reports."""

import json
from html import escape

from domasentrix.checks.dns import DNSAuditResult, DNSFinding
from domasentrix.checks.http import HTTPAuditResult, HTTPFinding
from domasentrix.checks.tls import TLSAuditResult
from domasentrix.reporting.html import render_html_report
from domasentrix.reporting.json import (
    build_assessment_report,
    serialize_assessment_report,
)
from domasentrix.scoring import score_assessment


def test_html_report_contains_summary_and_ordered_technical_details() -> None:
    assessment = score_assessment(
        DNSAuditResult(
            domain="example.com",
            findings=[DNSFinding("SPF_MISSING", "medium", "No SPF policy was found.")],
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

    report = build_assessment_report("EXAMPLE.COM.", assessment)
    html_report = render_html_report(report)

    assert "<!doctype html>" in html_report
    assert "<title>DomaSentrix Security Assessment: example.com</title>" in html_report
    assert "Executive summary" in html_report
    assert "92</span> / 100" in html_report
    assert "Risk classification" in html_report
    assert "Assessment coverage" in html_report
    assert "DNS</th><td>6 deduction</td><td>25</td>" in html_report
    assert "TLS</th><td>0 deduction</td><td>35</td>" in html_report
    assert "HTTP</th><td>2 deduction</td><td>40</td>" in html_report
    assert "SPF_MISSING" in html_report
    assert "HTTP_SERVER_DISCLOSURE" in html_report
    assert "HTTPS: example-server/1.2" in html_report
    assert "Operational errors</h2>\n<p>None reported.</p>" in html_report


def test_html_report_handles_partial_assessments_and_escapes_dynamic_content() -> None:
    assessment = score_assessment(
        DNSAuditResult(
            domain="example.com",
            errors={"A": '<img src=x onerror="alert(1)">'},
        ),
        None,
        HTTPAuditResult(
            domain="example.com",
            http_port=80,
            https_port=443,
            findings=[
                HTTPFinding(
                    'HTTP_TEST"><script>',
                    "low",
                    '<script>alert("finding")</script> &',
                    '<img src=x onerror="alert(2)">',
                    '" onclick="alert(3)',
                )
            ],
        ),
    )

    report = build_assessment_report("example.com", assessment)
    html_report = render_html_report(report)

    assert 'class="status status-partial">Partial</span>' in html_report
    assert 'Overall score</strong><br><span class="score">Not available</span>' in (
        html_report
    )
    assert "Risk classification</strong><br>Not available" in html_report
    assert "HTTP_TEST&quot;&gt;&lt;script&gt;" in html_report
    assert (
        "&lt;script&gt;alert(&quot;finding&quot;)&lt;/script&gt; &amp;" in html_report
    )
    assert "&lt;img src=x onerror=&quot;alert(2)&quot;&gt;" in html_report
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html_report
    assert "&quot; onclick=&quot;alert(3)" in html_report
    assert "<script" not in html_report.casefold()
    assert "<img" not in html_report.casefold()
    assert 'onclick="' not in html_report.casefold()
    assert "default-src 'none'" in html_report
    assert "<link " not in html_report.casefold()
    assert 'src="http' not in html_report.casefold()
    assert 'href="http' not in html_report.casefold()


def test_json_and_html_use_the_same_data_and_large_values_remain_escaped() -> None:
    large_untrusted_value = "<script>&" * 8192
    assessment = score_assessment(
        DNSAuditResult(
            domain="example.com",
            errors={"resolver": large_untrusted_value},
        ),
        TLSAuditResult(domain="example.com", port=443),
        HTTPAuditResult(
            domain="example.com",
            http_port=80,
            https_port=443,
            findings=[
                HTTPFinding(
                    "HTTP_LARGE_VALUE",
                    "high",
                    large_untrusted_value,
                    large_untrusted_value,
                    large_untrusted_value,
                )
            ],
        ),
    )

    report = build_assessment_report("example.com", assessment)
    serialized_report = json.loads(
        serialize_assessment_report("example.com", assessment)
    )
    serialized_report.pop("generated_at")
    comparable_report = dict(report)
    comparable_report.pop("generated_at")
    html_report = render_html_report(report)

    assert serialized_report == comparable_report
    assert render_html_report(report) == html_report
    assert escape(large_untrusted_value) in html_report
    assert "<script>" not in html_report
    assert "HTTP_LARGE_VALUE" in html_report
    assert "resolver" in html_report


def test_html_report_is_deterministic_except_for_generation_timestamp() -> None:
    assessment = score_assessment(
        DNSAuditResult(domain="example.com"),
        TLSAuditResult(domain="example.com", port=443),
        HTTPAuditResult(domain="example.com", http_port=80, https_port=443),
    )
    first_report = build_assessment_report("example.com", assessment)
    second_report = build_assessment_report("example.com", assessment)
    first_html = render_html_report(first_report)
    second_html = render_html_report(second_report)

    assert first_html.replace(str(first_report["generated_at"]), "<timestamp>") == (
        second_html.replace(str(second_report["generated_at"]), "<timestamp>")
    )
