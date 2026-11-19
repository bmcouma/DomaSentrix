# Contributing to DomaSentrix

Thank you for considering a contribution.

## Development Process

1. Read the project documentation.
2. Open an issue describing the proposed change.
3. Discuss significant changes before implementation.
4. Create a focused branch.
5. Implement the change with appropriate tests.
6. Run the test suite and quality checks:
   ```bash
   python -m pytest -v
   python -m ruff check .
   python -m ruff format --check .
   python -m mypy src
   python -m pip check
   ```
7. Submit a pull request with a clear explanation.

## Code Standards

- Follow PEP 8 conventions.
- Use Python type hints.
- Write meaningful tests.
- Keep functions focused.
- Document security-sensitive decisions.
- Never introduce unverified security claims.

## Pull Requests

Every pull request should explain:

- The problem being solved.
- The implementation approach.
- Tests performed.
- Potential security implications.
