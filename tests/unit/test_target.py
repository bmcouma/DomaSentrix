"""Unit tests for domain target validation."""

import pytest

from domasentrix.core.target import TargetValidationError, normalize_domain


@pytest.mark.parametrize(
    ("input_domain", "expected"),
    [
        ("EXAMPLE.COM", "example.com"),
        ("example.com.", "example.com"),
        ("sub.example.com", "sub.example.com"),
    ],
)
def test_normalize_valid_domains(input_domain: str, expected: str) -> None:
    assert normalize_domain(input_domain) == expected


@pytest.mark.parametrize(
    "invalid_domain",
    [
        "",
        "   ",
        "localhost",
        "127.0.0.1",
        "192.168.1.1",
        "https://example.com",
        "example.com/path",
        "example.com:8080",
        "user@example.com",
        "-example.com",
        "example-.com",
        "example..com",
        "example .com",
        "example.com..",
    ],
)
def test_reject_invalid_domains(invalid_domain: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_domain(invalid_domain)


def test_normalize_internationalized_domain() -> None:
    assert normalize_domain("münich.de") == "xn--mnich-kva.de"


def test_reject_domain_longer_than_253_characters() -> None:
    domain = ".".join(["a" * 63] * 4)
    with pytest.raises(TargetValidationError):
        normalize_domain(domain)
