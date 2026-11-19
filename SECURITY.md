# Security Policy

## Scope

DomaSentrix is designed for authorized domain security
configuration assessments.

## Current Security Boundaries

Version 0.1.0 validates domain syntax and performs DNS lookups for basic
records and email authentication policies.

It does not currently make HTTP requests, scan ports or exploit
vulnerabilities. DNS queries use the system-configured resolver and have a
three-second timeout per query.

## Security Requirements

Future assessment modules must implement:

- Public destination validation.
- Private and reserved IP rejection.
- DNS rebinding protections.
- Redirect destination validation.
- Connection timeouts.
- Response-size limits.
- Rate limiting.
- Evidence-based security findings.

Active scanning will require explicit authorization.

## Reporting Vulnerabilities

Please do not publish sensitive vulnerability details
in public issues.

Report security concerns privately to:

149688040+bmcouma@users.noreply.github.com

You may also use GitHub's private vulnerability reporting form:

https://github.com/bmcouma/domasentrix/security/advisories/new

## Responsible Use

Only assess domains and infrastructure you own
or have explicit permission to test.
