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
  utils.py          # generate_master_key, derive_master_key, generate_salt,
                    # compute_hash, format_size, validate_master_key
tests/              # Test suite (unittest + pytest)
  _helpers.py       # SecureFSTestCase: temp store, master key, make_fs() factory
examples/           # Usage examples
```

## Architecture Notes

- **Encryption**: AES-256-GCM with 12-byte random nonces. Per-file keys (KF, 32 bytes)
  encrypted with master key (KM, 32 bytes). GCM provides authenticated encryption (16-byte tag).
- **Storage**: Each file stored as `<hmac-sha256-of-path>.dat` containing
  `nonce || ciphertext || tag`. The filename is keyed by a master-key subkey and derived on
  every access via `_dat_path()`. It is deliberately not persisted: a stored copy would be
  a second, independently tamperable mapping from a row to a file on disk.
- **Database**: SQLite with WAL mode for concurrency. Tables: `files` (metadata), `system_metadata`.
- **Thread safety**: All mutating operations protected by `threading.Lock`. This buys
  correctness, not throughput -- and that is deliberate. Measured on a 4-core box:
  AES-GCM decryption does not release the GIL (4 threads run at 0.17x of sequential),
  and dropping the lock makes concurrent reads *slower* (0.52x) than keeping it (1.06x).
  A readers-writer lock would be strictly worse than the current design; don't add one.
- **Where read() time goes** (4 KiB file, measured): SQLite connect + query 55%, AES and
  Python overhead 41%, file I/O 3%, integrity HMAC 1%. The one real optimization left is
  reusing a per-thread SQLite connection instead of opening one per operation, worth ~3x
  on reads (0.45 ms -> 0.15 ms). Deliberately not done: per-operation connections keep
  every call fully isolated, which is worth more here than the speed.
- **Plaintext mode**: Marked by an all-zero nonce, and only honored when
  `encryption_enabled=False`. An encrypted instance refuses such entries, so it never
  serves content that is unprotected on disk; migrating legacy plaintext is explicit.
  Because nothing AEAD-authenticates those entries, their keyed integrity tag is always
  verified, even when `verify_integrity`/`skip_verification` would skip it.
- **Cross-platform**: Designed to run on Windows, Linux, and macOS. Uses `pathlib` and
  `os.path` for path handling. Avoids platform-specific APIs.
