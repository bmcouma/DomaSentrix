# DomaSentrix

**Domain Security & Configuration Intelligence**

DomaSentrix is an open-source Python toolkit for assessing domain security
configurations and identifying common infrastructure weaknesses.

## Project Goals

DomaSentrix aims to provide evidence-based assessments of:

- TLS certificate configuration
- DNS security records
- HTTP security headers
- Domain configuration hygiene
- Security risk prioritization
- Actionable remediation recommendations

## Technology Stack

- Python 3.12+
- FastAPI
- Typer
- HTTPX
- Pydantic
- pytest
- Ruff

## Current Development Status

DomaSentrix is under active development.

Version 0.1.0 establishes the project foundation,
domain normalization, validation, CLI, REST API, and initial DNS and TLS
assessments, with HTTP security assessment available through the CLI.

## Installation

Clone the repository:

```bash
git clone https://github.com/bmcouma/domasentrix.git
cd domasentrix
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -e ".[dev]"
```

HTTP assessment uses HTTPX, which is installed as a runtime dependency with the
project.

## Usage

Validate a domain:

```bash
domasentrix validate example.com
```

Assess DNS records and email authentication policies:

```bash
domasentrix dns example.com
```

DNS findings do not make the command fail. A nonzero exit code indicates an
invalid target or DNS lookup errors that may make the assessment incomplete.

Run the combined DNS, TLS, and HTTP assessment:

```bash
domasentrix assess example.com
```

Text output is the default. To produce a versioned JSON report on stdout or
save it to a new file:

```bash
domasentrix assess example.com --format json
domasentrix assess example.com --format json --output report.json
```

For a self-contained HTML report with an executive summary and technical
findings, provide an output file:

```bash
domasentrix assess example.com --format html --output report.html
```

HTML reports include no scripts or external assets, and report data is escaped
before rendering. HTML output requires `--output`; like JSON file output, it
refuses to overwrite an existing report.

JSON reports include the normalized target, generation time, assessment
completeness, score and category deductions when available, findings, and
operational errors. Partial assessments use `null` for the overall score, risk,
and total deduction. The `--output` option refuses to overwrite an existing
file. Security findings alone do not cause a nonzero exit code; incomplete
assessments or operational errors do.

Display the version:

```bash
domasentrix version
```

Start the API:

```bash
uvicorn domasentrix.main:app --reload
```

API documentation:

http://127.0.0.1:8000/docs

Run a DNS assessment from Python:

```python
from domasentrix.checks.dns import audit_dns

result = audit_dns("example.com")
print(result.records)
print(result.errors)
for finding in result.findings:
    print(f"{finding.severity}: {finding.message}")
```

Assess a domain's verified TLS certificate and connection:

```bash
domasentrix tls example.com
domasentrix tls example.com --port 8443 --timeout 5
```

The TLS assessment verifies the server certificate and evaluates TLS 1.0,
TLS 1.1, TLS 1.2, and TLS 1.3 protocol support. A protocol is reported as
supported only when the connection successfully negotiates that exact
version. An inconclusive result means the local TLS environment or network
conditions prevented a reliable determination. It does not mean the server
does not support that protocol.

The assessment makes one initial verified connection and four independent
protocol probes. Each connection call may try multiple addresses returned by
DNS, and DNS resolution itself is not bounded by the socket timeout. The
timeout applies to each socket connection, not to the total assessment.
Protocol probes resolve the hostname independently, so DNS load balancing may
cause them to reach different endpoints. A supported result confirms a
verified handshake with the endpoint reached by that probe; it does not prove
that every endpoint behind the domain supports that protocol.

Assess HTTP security configuration:

```bash
domasentrix http example.com
domasentrix http example.com --http-port 8080 --https-port 8443 --timeout 5
```

The HTTP assessment records HTTP and HTTPS response status, final URL, protocol,
and selected headers. It checks same-domain HTTP-to-HTTPS redirects, redirect
loops and limits, HTTPS availability, HSTS (on HTTPS responses only), CSP,
content-type and framing protections, Referrer-Policy, Permissions-Policy, and
potential Server/X-Powered-By disclosure. CSP `frame-ancestors` is recognized
as an alternative to X-Frame-Options. Header findings are configuration
observations, not proof of an exploitable vulnerability.

Requests use GET without sending a request body. Responses are streamed and
closed without consuming their bodies. Redirects are manually followed only
when the scheme, normalized host, and port match the requested domain and
configured ports; external, credentialed, and HTTPS-to-HTTP redirects are not
followed. The redirect limit defaults to five per endpoint and can be set from
zero to ten with `--max-redirects`. TLS verification remains enabled.

Before each new TCP connection, DomaSentrix validates every resolved IPv4 and
IPv6 address and rejects destinations that are not globally routable. It
connects to a validated numeric address while retaining the domain name for the
HTTP Host header, TLS SNI, and certificate hostname verification. A mixture of
public and non-public DNS answers is rejected rather than partially used.

The timeout is applied to individual HTTP client connection/read operations,
not as a total assessment deadline. System DNS resolution may take longer than
the configured timeout, and the HTTP and HTTPS checks run separately.

DNS assessment uses the system-configured resolver and gives each lookup a
three-second timeout. It is available through the Python API and command-line
interface. REST API integration is planned for a future release.

## Testing

Run:

```bash
pytest
```

With coverage:

```bash
pytest --cov=domasentrix --cov-report=term-missing
```

Code quality:

```bash
ruff check .
ruff format --check .
```

## Security

DomaSentrix is intended for authorized security assessments.

The assessment modules validate the domain and perform DNS lookups, TLS checks,
or HTTP GET requests to the requested domain and configured ports using the
configured per-operation timeouts.
HTTP redirects are scope-restricted, TLS certificate verification is enabled,
and response bodies are not consumed. DomaSentrix is for authorized defensive
assessments only; it does not scan ports, exploit vulnerabilities, brute-force,
bypass authentication, submit forms, or modify remote resources.

See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

## License

MIT License.