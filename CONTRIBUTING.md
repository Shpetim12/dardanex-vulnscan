# Contributing to vulnscan

Thanks for helping improve vulnscan. Please keep contributions focused on authorized security testing and education.

1. Fork the repository and create a focused branch.
2. Use Python 3.10+ and install dependencies with `pip install -r requirements.txt`.
3. Add or update tests for every behavior change, then run `python -m pytest -q`.
4. Keep user-facing errors clear and avoid adding behavior that scans without explicit permission.
5. Open a pull request describing the change, tests, and any security impact.

Do not include secrets, private target data, or reports generated from systems you are not authorized to test.

## Development

Create an isolated environment and install the project with development tools:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

Before opening a pull request, run:

```bash
ruff check .
ruff format .
python -m pytest
```
