# SecureFS

A transparent, secure file storage system with encryption.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Features

- 🔐 Transparent AES-256-GCM encryption
- 🗄️ SQLite metadata storage
- ✅ Integrity verification
- 🔄 Migration support
- 🚀 Thread-safe operations
- ⚡ Optional caching

## Installation

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from securefs import SecureFSWrapper
from securefs.utils import generate_master_key

# Generate key
key = generate_master_key()

# Initialize
fs = SecureFSWrapper(
    master_key=key,
    db_path="./db.db",
    storage_root="./storage"
)

# Use
fs.write("/file.txt", b"content")
content = fs.read("/file.txt")
fs.close()
```

## Development

This project uses Ruff for linting and formatting.

```bash
# Check and fix
ruff check --fix .

# Format
ruff format .

# Test
pytest
```

## Documentation

See `docs/` folder for complete documentation.

## License

MIT License - See LICENSE file.
