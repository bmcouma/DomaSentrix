"""Domain target normalization and validation."""

import ipaddress
import re

_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class TargetValidationError(ValueError):
    """Raised when a target is not a valid domain name."""


def normalize_domain(domain: str) -> str:
    """Normalize a domain and reject values that are not FQDNs."""
    if not isinstance(domain, str):
        raise TargetValidationError("Target must be a string.")

    domain = domain.strip()
    if not domain:
        raise TargetValidationError("Domain cannot be empty.")
    if any(char.isspace() for char in domain):
        raise TargetValidationError("Domain cannot contain whitespace.")
    if "://" in domain or "/" in domain or "@" in domain:
        raise TargetValidationError("Provide a hostname, not a URL or path.")
    if ":" in domain:
        raise TargetValidationError("Ports and IPv6 literals are not accepted.")

    if domain.endswith("."):
        domain = domain[:-1]
    if not domain:
        raise TargetValidationError("Invalid domain.")

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise TargetValidationError("IP addresses are not accepted. Provide a domain.")

    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetValidationError("Invalid internationalized domain name.") from exc

    if len(ascii_domain) > 253:
        raise TargetValidationError("Domain is too long.")

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        raise TargetValidationError("A fully qualified domain name is required.")
    if any(len(label) > 63 or not _LABEL_PATTERN.fullmatch(label) for label in labels):
        raise TargetValidationError("Domain contains an invalid label.")

    return ascii_domain
