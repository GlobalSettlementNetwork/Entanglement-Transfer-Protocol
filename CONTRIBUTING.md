# Contributing to the Entanglement Transfer Protocol

Thank you for your interest in contributing to ETP. This document provides guidelines
for contributing to the project.

## Prerequisites

- **Python 3.10+** (3.12 recommended)
- **Git** for version control
- No external dependencies required for the core library (stdlib only)

## Getting Started

```bash
# Clone the repository
git clone https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol.git
cd Entanglement-Transfer-Protocol

# Install in development mode
pip install -e ".[dev]"

# Verify installation
pytest tests/ -v
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run a specific test file
pytest tests/test_protocol.py -v

# Run a specific test
pytest tests/test_protocol.py::TestCommitMaterialize::test_basic_transfer -v

# Run with coverage
pytest tests/ --cov=src/ltp --cov-report=term-missing
```

All 821 tests should pass. If any fail on a clean checkout, please open an issue.

## Code Style

### General Principles

- **Zero external dependencies** for the core library (`src/ltp/`). All cryptographic
  primitives use stdlib-only PoC implementations. Production replacements (liboqs,
  PyNaCl, zfec) are documented in `docs/PRODUCTION_PLAN.md` but not required.
- **Logging, not print.** Use `logging.getLogger(__name__)` for all output.
  Never use `print()` in library code.
- **ValueError, not assert.** Use explicit `if ... raise ValueError(...)` for
  input validation at public API boundaries. Reserve `assert` for internal invariants.
- **Type annotations** on all public function signatures. Use `T | None` (Python 3.10+)
  instead of `Optional[T]`.

### Naming Conventions

- Classes: `PascalCase` (e.g., `CommitmentNetwork`, `ErasureCoder`)
- Functions/methods: `snake_case` (e.g., `commit_entity`, `fetch_encrypted_shards`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `EK_SIZE`, `DEFAULT_N`)
- Private methods: `_leading_underscore`

### Module Organization

- `src/ltp/` — Core protocol library
- `src/ltp/backends/` — Pluggable commitment backends
- `src/ltp/bridge/` — Cross-chain bridge components
- `tests/` — All test files (prefix: `test_`)

## Pull Request Workflow

1. **Fork** the repository and create a feature branch
2. **Write tests** for new functionality (maintain or improve coverage)
3. **Run the full test suite** before submitting: `pytest tests/ -v`
4. **Keep PRs focused** — one feature or fix per PR
5. **Write clear commit messages** describing the "why", not just the "what"

### PR Checklist

- [ ] All 821+ tests pass
- [ ] New code has corresponding tests
- [ ] No external dependencies added to core library
- [ ] Type annotations on public API
- [ ] `logging` used instead of `print()`
- [ ] `ValueError` used instead of `assert` for input validation

## Architecture

See [docs/design-decisions/ARCHITECTURE.md](docs/design-decisions/ARCHITECTURE.md) for
the system architecture and [docs/WHITEPAPER.md](docs/WHITEPAPER.md) for the full
protocol specification.

## Questions?

Open an issue for questions about the protocol design or implementation approach.
