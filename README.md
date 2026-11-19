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
- Pydantic
- pytest
- Ruff

## Current Development Status

DomaSentrix is under active development.

Version 0.1.0 establishes the project foundation,
domain normalization, validation, CLI, REST API, and initial DNS and TLS
assessments.

HTTP assessment is planned for a subsequent release.

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

The assessment modules validate the domain and perform DNS lookups or a TLS
connection to the requested domain (port 443 by default). They do not make
HTTP requests, scan ports or exploit vulnerabilities.

See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

## License

MIT License.