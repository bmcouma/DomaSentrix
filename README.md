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
domain normalization, validation, CLI, REST API and initial DNS assessment.

TLS and HTTP assessment modules are planned for subsequent releases.

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

The initial release validates domain syntax and performs DNS lookups for the
requested domain. It does not make HTTP requests, scan ports or exploit
vulnerabilities.

See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

## License

MIT License.