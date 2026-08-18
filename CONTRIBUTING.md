# Contributing to ShadowGate

First off, thank you for considering contributing to ShadowGate!

## Code of Conduct
Please review our Code of Conduct before contributing.

## Reporting Bugs
- Use the issue template for bugs.
- Include OS, Python version, and steps to reproduce.

## Suggesting Features
- Open an issue describing the feature and its use cases.

## Development Setup
```bash
git clone https://github.com/oscer07/shadowgate.git
cd shadowgate
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

## Code Style
- We use `black` for formatting.
- `isort` for imports.
- Type hints are required for new code.

## Pull Request Process
1. Fork the repo and create your branch from `main`.
2. Write tests for your changes.
3. Ensure the test suite passes.
4. Submit a Pull Request.

## Commit Message Convention
We use conventional commits:
- `feat: add new proxy feature`
- `fix: resolve honeypot crash`
- `docs: update readme`
