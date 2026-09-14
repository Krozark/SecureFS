# SecureFS

SecureFS est une petite librairie Python qui permet de stocker des fichiers de
façon chiffrée et sécurisée, de manière totalement locale (sans serveur ni
connexion internet nécessaire). Elle protège le contenu des fichiers avec un
chiffrement fort, vérifie qu'ils n'ont pas été altérés, et permet de dériver
la clé de chiffrement directement à partir du mot de passe d'un utilisateur.
C'est utilisable comme une brique de stockage sécurisé dans une application
qui a besoin de garder des fichiers confidentiels sur disque.

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
