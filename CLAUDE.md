# CLAUDE.md - SecureFS Development Guide

## Project Overview

SecureFS is a transparent, secure file storage system providing AES-256-GCM encryption
with SQLite metadata storage, integrity verification, thread-safe operations, and
optional caching. It uses a two-level encryption architecture: a master key (KM)
encrypts per-file keys (KF), which in turn encrypt file contents.

## Build & Setup

```bash
# Install in development mode with all dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
# Run all tests with coverage
pytest

# Run tests in parallel
pytest -n auto

# Run a specific test file
pytest tests/test_basic.py -v

# Run tests by marker
pytest -m integration
pytest -m "not slow"

# Run with HTML coverage report
pytest --cov-report=html
```

Minimum required coverage: 80%.

## Linting & Formatting

The project uses **Ruff** as a unified linter and formatter (replaces Black, isort, flake8).

```bash
# Check for lint issues
ruff check .

# Auto-fix lint issues
ruff check --fix .

# Format code
ruff format .

# Combined (recommended before commit)
ruff check --fix . && ruff format .
```

Line length: 100 characters. Target Python version: 3.11+.

## Type Checking

```bash
mypy securefs/
```

## Security Scanning

```bash
bandit -r securefs/
```

## Full Pre-Commit Check

```bash
ruff check --fix . && ruff format . && mypy securefs/ && pytest
```

## Project Structure

```
securefs/           # Main package
  __init__.py       # Public API exports
  __version__.py    # Version metadata
  core.py           # SecureFSWrapper - main class
  exceptions.py     # SecureFSError, FileCorruptionError, EncryptionError
  utils.py          # generate_master_key, compute_hash, format_size, validate_master_key
tests/              # Test suite (unittest + pytest)
examples/           # Usage examples
```

## Architecture Notes

- **Encryption**: AES-256-GCM with 12-byte random nonces. Per-file keys (KF, 32 bytes)
  encrypted with master key (KM, 32 bytes). GCM provides authenticated encryption (16-byte tag).
- **Storage**: Each file stored as `<sha256-of-path>.dat` containing `nonce || ciphertext || tag`.
- **Database**: SQLite with WAL mode for concurrency. Tables: `files` (metadata), `system_metadata`.
- **Thread safety**: All mutating operations protected by `threading.Lock`.
- **Plaintext mode**: Detected via all-zero nonce. Supports mixed encrypted/plaintext storage.
- **Cross-platform**: Designed to run on Windows, Linux, and macOS. Uses `pathlib` and
  `os.path` for path handling. Avoids platform-specific APIs.
