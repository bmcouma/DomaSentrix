"""Tests for DNS security assessment."""

from unittest.mock import MagicMock

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from domasentrix.checks.dns import audit_dns


def _rdata(record_type: str, text: str) -> dns.rdata.Rdata:
    return dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.from_text(record_type),
        text,
    )


@pytest.fixture
def mock_resolver() -> MagicMock:
    """Provide a resolver with typed, predictable DNS responses."""
    resolver = MagicMock(spec=dns.resolver.Resolver)
    responses: dict[tuple[str, str], list[str]] = {
        ("example.com", "A"): ["93.184.216.34"],
        ("example.com", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "TXT"): ['"v=spf1 include:_spf.example.com -all"'],
        ("_dmarc.example.com", "TXT"): [
            '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
        ],
    }

    def resolve(
        name: str,
        record_type: str,
        lifetime: float,
    ) -> list[dns.rdata.Rdata]:
        key = (name, record_type)
        if key not in responses:
            raise dns.resolver.NoAnswer()
        return [_rdata(record_type, text) for text in responses[key]]

    resolver.resolve.side_effect = resolve
    return resolver


def test_audit_dns_returns_records(mock_resolver: MagicMock) -> None:
    result = audit_dns("EXAMPLE.COM", resolver=mock_resolver)

    assert result.domain == "example.com"
    assert result.records["A"] == ["93.184.216.34"]
    assert result.records["AAAA"] == ["2606:2800:220:1:248:1893:25c8:1946"]
    assert result.records["MX"] == ["10 mail.example.com"]
    assert result.errors == {}
    assert all(
        call.kwargs["lifetime"] == 3.0 for call in mock_resolver.resolve.call_args_list
    )


def test_valid_email_policies_produce_no_findings(
    mock_resolver: MagicMock,
) -> None:
    result = audit_dns("example.com", resolver=mock_resolver)

    assert result.findings == []


def test_missing_spf_and_dmarc_are_reported(mock_resolver: MagicMock) -> None:
    mock_resolver.resolve.return_value = []
    mock_resolver.resolve.side_effect = None

    result = audit_dns("example.com", resolver=mock_resolver)

    codes = {finding.code for finding in result.findings}
    assert "SPF_MISSING" in codes
    assert "DMARC_MISSING" in codes


def test_multiple_spf_records_are_reported(
    mock_resolver: MagicMock,
) -> None:
    def resolve(
        name: str,
        record_type: str,
        lifetime: float,
    ) -> list[dns.rdata.Rdata]:
        if name == "example.com" and record_type == "TXT":
            return [
                _rdata("TXT", '"v=spf1 -all"'),
                _rdata("TXT", '"v=spf1 ~all"'),
            ]
        if name == "_dmarc.example.com":
            return [_rdata("TXT", '"v=DMARC1; p=reject"')]
        raise dns.resolver.NoAnswer()

    mock_resolver.resolve.side_effect = resolve
    result = audit_dns("example.com", resolver=mock_resolver)
    codes = {finding.code for finding in result.findings}

    assert "SPF_MULTIPLE" in codes
    assert "SPF_MISSING" not in codes


def test_multiple_dmarc_records_are_reported(
    mock_resolver: MagicMock,
) -> None:
    def resolve(name: str, record_type: str, lifetime: float) -> list[dns.rdata.Rdata]:
        if name == "_dmarc.example.com":
            return [
                _rdata("TXT", '"v=DMARC1; p=reject"'),
                _rdata("TXT", '"v=DMARC1; p=none"'),
            ]
        if name == "example.com" and record_type == "TXT":
            return [_rdata("TXT", '"v=spf1 -all"')]
        raise dns.resolver.NoAnswer()

    mock_resolver.resolve.side_effect = resolve
    result = audit_dns("example.com", resolver=mock_resolver)
    codes = {finding.code for finding in result.findings}

    assert "DMARC_MULTIPLE" in codes
    assert "DMARC_MISSING" not in codes


def test_dns_timeout_is_recorded_without_missing_policy_findings(
    mock_resolver: MagicMock,
) -> None:
    mock_resolver.resolve.side_effect = dns.exception.Timeout

    result = audit_dns("example.com", resolver=mock_resolver)

    assert "A" in result.errors
    assert "timed out" in result.errors["A"]
    assert "SPF_MISSING" not in {finding.code for finding in result.findings}
    assert "DMARC_MISSING" not in {finding.code for finding in result.findings}


def test_nxdomain_is_recorded(mock_resolver: MagicMock) -> None:
    mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN

    result = audit_dns("example.com", resolver=mock_resolver)

    assert "A" in result.errors
    assert "does not exist" in result.errors["A"]


def test_invalid_domain_is_rejected() -> None:
    with pytest.raises(ValueError):
        audit_dns("127.0.0.1")
