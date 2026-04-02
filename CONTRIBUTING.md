# Contributing to AEGIS Protocol

Thank you for your interest in contributing! This guide will help you get
started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Issue Guidelines](#issue-guidelines)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you agree to uphold this code.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/aegis-protocol.git
   cd aegis-protocol
   ```
3. **Create a branch** for your change:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL (or use Docker)
- *(Optional)* Nargo CLI for ZK proof generation

### Backend (Python / FastAPI)

```bash
python -m venv .venv
source .venv/bin/activate          # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
pip install -r requirements-dev.txt
cp .env.example .env               # edit with your local settings
uvicorn main_app:app --reload
```

### Smart Contracts (Hardhat)

```bash
npm install
npx hardhat compile
npx hardhat test
```

### Docker (full stack)

```bash
cp .env.example .env
docker compose up --build
```

## Making Changes

1. Make your changes in a feature branch off `main`.
2. Write or update tests for your changes.
3. Run the full test suite before submitting:
   ```bash
   # Python tests
   pytest tests/ -v

   # Solidity tests
   npx hardhat test
   ```
4. Keep commits focused and use clear commit messages.

## Pull Request Process

1. Update documentation if your change affects public APIs or behavior.
2. Ensure all tests pass and there are no linting errors.
3. Fill out the pull request template completely.
4. Request a review from a maintainer.
5. PRs require at least one approving review before merge.
6. Squash commits if requested by a reviewer.

### Commit Messages

Use clear, descriptive commit messages:

```
Add MiCA velocity limit check to compliance engine

- Implement 5 tx/minute sliding window
- Add unit tests for edge cases
- Update API docs for /compliance/profile
```

## Coding Standards

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines.
- Use type hints for all function signatures.
- Write docstrings for public functions and classes.
- Keep functions focused and under 50 lines where practical.

### Solidity

- Target Solidity `^0.8.20`.
- Follow the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html).
- Use NatSpec comments for all public/external functions.
- Prefer OpenZeppelin contracts for standard patterns.

### JavaScript / TypeScript

- Use `const` by default, `let` when mutation is needed.
- Prefer async/await over raw promises.

## Testing

- **Python**: `pytest tests/ -v` — unit and integration tests.
- **Solidity**: `npx hardhat test` — contract unit tests.
- All new features must include tests.
- Bug fixes should include a regression test.

## Issue Guidelines

- Check existing issues before opening a new one.
- Use the provided issue templates (bug report or feature request).
- Include steps to reproduce for bug reports.
- Issues labelled `good-first-issue` are a great starting point.

## Questions?

Open a [Discussion](https://github.com/aletheiamanifesto-pixel/aegis-protocol/discussions)
or reach out in an existing issue. We're happy to help!
