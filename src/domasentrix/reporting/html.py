"""Self-contained HTML renderer for the versioned assessment report."""

from collections.abc import Mapping
from html import escape

from domasentrix.scoring.engine import SEVERITY_ORDER, SOURCE_ORDER

_STYLESHEET = """
:root { color-scheme: light; font-family: Arial, sans-serif; color: #172033; }
body { margin: 0; background: #f3f5f8; line-height: 1.5; }
header { padding: 2rem max(1.25rem, calc((100% - 68rem) / 2)); color: #fff;
  background: #14213d; }
header p { margin: .25rem 0; color: #d7e0f0; }
main { max-width: 68rem; margin: 1.5rem auto; padding: 0 1.25rem; }
section, .summary-card { margin: 1rem 0; padding: 1.25rem; background: #fff;
  border: 1px solid #dce2ea; border-radius: .5rem; }
h1, h2, h3 { line-height: 1.2; }
h1 { margin: .3rem 0; } h2 { margin-top: 0; }
.eyebrow { font-size: .8rem; font-weight: 700; letter-spacing: .08em; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
  gap: 1rem; }
.summary-card { margin: 0; }
.score { font-size: 2rem; font-weight: 700; }
.status { display: inline-block; padding: .2rem .55rem; border-radius: 1rem;
  font-weight: 700; background: #e8edf5; }
.status-complete { color: #14633a; background: #e2f4e9; }
.status-partial, .warning { color: #7a4b00; background: #fff1cf; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: .65rem; border-bottom: 1px solid #e4e8ee; text-align: left;
  vertical-align: top; }
th { background: #f7f8fa; }
.finding { margin: .8rem 0; padding: .9rem; border-left: .25rem solid #65758b;
  background: #f8f9fb; overflow-wrap: anywhere; }
.finding h4 { margin: .1rem 0 .45rem; }
.severity { font-size: .8rem; font-weight: 700; }
.severity-critical { color: #8d1717; } .severity-high { color: #a63c16; }
.severity-medium { color: #825a00; } .severity-low { color: #285d91; }
.severity-info { color: #536274; }
.warning { padding: .8rem; border-radius: .3rem; }
footer { margin: 2rem 0; color: #596579; font-size: .9rem; }
@media print { body { background: #fff; } main { max-width: none; }
  section, .summary-card { break-inside: avoid; } }
"""

_SEVERITY_CLASSES = frozenset({"critical", "high", "medium", "low", "info"})


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"Report field {field!r} must be an object.")
    return value


def _field(mapping: Mapping[str, object], key: str) -> object:
    if key not in mapping:
        raise ValueError(f"Report field {key!r} is missing.")
    return mapping[key]


def _list(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(f"Report field {field!r} must be an array.")
    return value


def _text(value: object, field: str) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if value is None:
        return "Not available"
    raise TypeError(f"Report field {field!r} must be a string, integer, or null.")


def _integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"Report field {field!r} must be an integer.")
    return value


def _source_list(value: object, field: str) -> list[str]:
    sources = _list(value, field)
    if any(not isinstance(source, str) for source in sources):
        raise TypeError(f"Report field {field!r} must contain strings.")
    return [str(source) for source in sources]


def _finding_html(finding_value: object) -> str:
    finding = _mapping(finding_value, "finding")
    source = escape(_text(_field(finding, "source"), "finding.source"))
    severity = _text(_field(finding, "severity"), "finding.severity")
    if severity not in _SEVERITY_CLASSES:
        raise ValueError(f"Unsupported finding severity: {severity}.")
    severity_class = severity
    code = escape(_text(_field(finding, "code"), "finding.code"))
    message = escape(_text(_field(finding, "message"), "finding.message"))
    deduction = escape(_text(_field(finding, "deduction"), "finding.deduction"))
    evidence_value = _field(finding, "evidence")
    remediation_value = _field(finding, "remediation")
    evidence = (
        ""
        if evidence_value is None
        else (
            "<p><strong>Evidence:</strong> "
            f"{escape(_text(evidence_value, 'finding.evidence'))}</p>"
        )
    )
    remediation = (
        ""
        if remediation_value is None
        else (
            "<p><strong>Remediation:</strong> "
            f"{escape(_text(remediation_value, 'finding.remediation'))}</p>"
        )
    )

    return (
        '<article class="finding">'
        f'<h4><span class="severity severity-{severity_class}">'
        f"{escape(severity.upper())}</span> {code}</h4>"
        f"<p>{message}</p>"
        f"<p><strong>Source:</strong> {source} | "
        f"<strong>Deduction:</strong> {deduction}</p>"
        f"{evidence}{remediation}"
        "</article>"
    )


def render_html_report(report: Mapping[str, object]) -> str:
    """Render a report produced by the shared versioned assessment schema."""
    target = _mapping(_field(report, "target"), "target")
    assessment = _mapping(_field(report, "assessment"), "assessment")
    domain = escape(_text(_field(target, "domain"), "target.domain"))
    generated_at = escape(_text(_field(report, "generated_at"), "generated_at"))
    completeness = _text(
        _field(assessment, "completeness"),
        "assessment.completeness",
    )
    if completeness not in {"complete", "partial"}:
        raise ValueError(f"Unsupported assessment completeness: {completeness}.")
    status_class = "complete" if completeness == "complete" else "partial"
    score = escape(_text(_field(assessment, "score"), "assessment.score"))
    risk = escape(_text(_field(assessment, "risk"), "assessment.risk"))
    total_deduction = escape(
        _text(
            _field(assessment, "total_deduction"),
            "assessment.total_deduction",
        )
    )
    available_sources = _source_list(
        _field(assessment, "available_sources"),
        "assessment.available_sources",
    )
    missing_sources = _source_list(
        _field(assessment, "missing_sources"),
        "assessment.missing_sources",
    )
    category_deductions = _mapping(
        _field(assessment, "category_deductions"),
        "assessment.category_deductions",
    )
    category_caps = _mapping(
        _field(assessment, "category_caps"),
        "assessment.category_caps",
    )
    severity_counts = _mapping(
        _field(assessment, "severity_counts"),
        "assessment.severity_counts",
    )
    findings = _list(_field(report, "findings"), "findings")
    errors = _list(_field(report, "operational_errors"), "operational_errors")
    schema_version = escape(_text(_field(report, "schema_version"), "schema_version"))
    report_type = escape(_text(_field(report, "report_type"), "report_type"))

    category_rows = "".join(
        "<tr>"
        f'<th scope="row">{escape(source.upper())}</th>'
        f"<td>{_integer(_field(category_deductions, source), f'{source} deduction')}"
        " deduction</td>"
        f"<td>{_integer(category_caps.get(source), f'{source} cap')}</td>"
        "</tr>"
        for source in SOURCE_ORDER
    )
    severity_rows = "".join(
        "<tr>"
        f'<th scope="row">{escape(severity.capitalize())}</th>'
        f"<td>{_integer(severity_counts.get(severity), f'{severity} count')}</td>"
        "</tr>"
        for severity in SEVERITY_ORDER
    )
    findings_by_source: dict[str, list[str]] = {source: [] for source in SOURCE_ORDER}
    for finding_value in findings:
        finding = _mapping(finding_value, "finding")
        source = _text(_field(finding, "source"), "finding.source")
        if source not in findings_by_source:
            raise ValueError(f"Unsupported finding source: {source}.")
        findings_by_source[source].append(_finding_html(finding))
    source_sections = "".join(
        f"<section><h3>{escape(source.upper())}</h3>"
        + "".join(findings_by_source[source])
        + "</section>"
        for source in SOURCE_ORDER
        if findings_by_source[source]
    )
    if not findings:
        findings_html = "<p>No findings were reported by the available assessments.</p>"
    else:
        findings_html = source_sections

    if errors:
        error_row_parts: list[str] = []
        for error_value in errors:
            error = _mapping(error_value, "operational error")
            source = escape(_text(_field(error, "source"), "error.source"))
            category = escape(_text(_field(error, "category"), "error.category"))
            message = escape(_text(_field(error, "message"), "error.message"))
            error_row_parts.append(
                f"<tr><td>{source}</td><td>{category}</td><td>{message}</td></tr>"
            )
        error_rows = "".join(error_row_parts)
        error_html = (
            '<p class="warning">Operational errors limited assessment coverage. '
            "Affected checks are not treated as secure.</p>"
            "<table><thead><tr><th>Source</th><th>Category</th><th>Message</th>"
            f"</tr></thead><tbody>{error_rows}</tbody></table>"
        )
    else:
        error_html = "<p>None reported.</p>"

    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'\">\n"
        f"<title>DomaSentrix Security Assessment: {domain}</title>\n"
        f"<style>{_STYLESHEET}</style>\n"
        "</head>\n<body>\n"
        "<header>\n"
        '<p class="eyebrow">DOMASENTRIX | DOMAIN SECURITY</p>\n'
        "<h1>Security Assessment Report</h1>\n"
        f"<p>Target: <strong>{domain}</strong></p>\n"
        f"<p>Generated: {generated_at}</p>\n"
        "</header>\n<main>\n"
        '<section aria-labelledby="overview-heading">\n'
        '<h2 id="overview-heading">Executive summary</h2>\n'
        '<div class="summary">\n'
        '<div class="summary-card"><strong>Assessment status</strong><br>'
        f'<span class="status status-{status_class}">'
        f"{escape(completeness.capitalize())}"
        "</span></div>\n"
        '<div class="summary-card"><strong>Overall score</strong><br>'
        f'<span class="score">{score}</span>'
        f"{'' if score == 'Not available' else ' / 100'}"
        "</div>\n"
        '<div class="summary-card"><strong>Risk classification</strong><br>'
        f"{risk.capitalize()}</div>\n"
        '<div class="summary-card"><strong>Total deduction</strong><br>'
        f"{total_deduction}</div>\n"
        "</div>\n"
        "<p>Security findings are observations; an assessment is not a guarantee "
        "that a domain is secure.</p>\n"
        "</section>\n"
        '<section aria-labelledby="coverage-heading">\n'
        '<h2 id="coverage-heading">Assessment coverage</h2>\n'
        "<p><strong>Available modules:</strong> "
        f"{escape(', '.join(source.upper() for source in available_sources) or 'None')}"
        "</p>\n"
        "<p><strong>Missing modules:</strong> "
        f"{escape(', '.join(source.upper() for source in missing_sources) or 'None')}"
        "</p>\n"
        "<h3>Category deductions</h3>\n"
        "<table><thead><tr><th>Module</th><th>Deduction</th><th>Maximum</th></tr>"
        f"</thead><tbody>{category_rows}</tbody></table>\n"
        f"<p><strong>Total deduction:</strong> {total_deduction}</p>\n"
        "</section>\n"
        '<section aria-labelledby="findings-heading">\n'
        '<h2 id="findings-heading">Findings</h2>\n'
        f"{findings_html}\n"
        "</section>\n"
        '<section aria-labelledby="statistics-heading">\n'
        '<h2 id="statistics-heading">Finding statistics</h2>\n'
        "<table><thead><tr><th>Severity</th><th>Count</th></tr></thead>"
        f"<tbody>{severity_rows}</tbody></table>\n"
        "</section>\n"
        '<section aria-labelledby="errors-heading">\n'
        '<h2 id="errors-heading">Operational errors</h2>\n'
        f"{error_html}\n"
        "</section>\n"
        "<footer>"
        f"Report type: {report_type} | Schema version: {schema_version}. "
        "For authorized defensive assessment use."
        "</footer>\n</main>\n</body>\n</html>\n"
    )
