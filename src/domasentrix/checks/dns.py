"""DNS security configuration assessment."""

from dataclasses import dataclass, field
from typing import Literal

import dns.exception
import dns.resolver
from dns.rdtypes.ANY.TXT import TXT

from domasentrix.core.target import normalize_domain

Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True)
class DNSFinding:
    """A security observation from a DNS assessment."""

    code: str
    severity: Severity
    message: str


@dataclass
class DNSAuditResult:
    """Structured results from a DNS assessment."""

    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    findings: list[DNSFinding] = field(default_factory=list)


def _txt_value(record: TXT) -> str:
    """Combine the character strings in a TXT record."""
    return b"".join(record.strings).decode("utf-8", errors="replace")


def _query_records(
    resolver: dns.resolver.Resolver,
    name: str,
    record_type: str,
) -> tuple[list[str], str | None]:
    """Query DNS and return normalized records or an error description."""
    try:
        answer = resolver.resolve(name, record_type, lifetime=3.0)
    except dns.resolver.NoAnswer:
        return [], None
    except dns.resolver.NXDOMAIN:
        return [], "The queried DNS name does not exist."
    except dns.resolver.NoNameservers:
        return [], "No DNS nameservers returned a usable response."
    except dns.exception.Timeout:
        return [], "The DNS query timed out."
    except dns.exception.DNSException as exc:
        return [], f"DNS query failed: {exc}"

    values: list[str] = []
    for record in answer:
        if record_type == "TXT":
            values.append(_txt_value(record))
        elif record_type == "MX":
            exchange = record.exchange.to_text(omit_final_dot=True)
            values.append(f"{record.preference} {exchange}")
        elif record_type in {"A", "AAAA"}:
            values.append(record.address)

    return values, None


def audit_dns(
    domain: str,
    resolver: dns.resolver.Resolver | None = None,
) -> DNSAuditResult:
    """Inspect basic DNS records and email authentication policies."""
    normalized_domain = normalize_domain(domain)
    dns_resolver = resolver if resolver is not None else dns.resolver.Resolver()
    result = DNSAuditResult(domain=normalized_domain)

    queries = {
        "A": (normalized_domain, "A"),
        "AAAA": (normalized_domain, "AAAA"),
        "MX": (normalized_domain, "MX"),
        "TXT": (normalized_domain, "TXT"),
        "DMARC": (f"_dmarc.{normalized_domain}", "TXT"),
    }

    for key, (name, record_type) in queries.items():
        records, error = _query_records(dns_resolver, name, record_type)
        result.records[key] = records
        if error is not None:
            result.errors[key] = error

    spf_records = [
        record
        for record in result.records["TXT"]
        if record.lower().startswith("v=spf1")
    ]

    if not spf_records and "TXT" not in result.errors:
        result.findings.append(
            DNSFinding(
                code="SPF_MISSING",
                severity="medium",
                message="No SPF policy was found in the domain TXT records.",
            )
        )
    elif len(spf_records) > 1:
        result.findings.append(
            DNSFinding(
                code="SPF_MULTIPLE",
                severity="high",
                message=(
                    "Multiple SPF policies were found. A domain should "
                    "publish only one SPF policy."
                ),
            )
        )

    dmarc_records = [
        record
        for record in result.records["DMARC"]
        if record.lower().startswith("v=dmarc1")
    ]

    if not dmarc_records and "DMARC" not in result.errors:
        result.findings.append(
            DNSFinding(
                code="DMARC_MISSING",
                severity="medium",
                message="No DMARC policy was found at the _dmarc subdomain.",
            )
        )
    elif len(dmarc_records) > 1:
        result.findings.append(
            DNSFinding(
                code="DMARC_MULTIPLE",
                severity="high",
                message="Multiple DMARC policies were found.",
            )
        )

    return result
