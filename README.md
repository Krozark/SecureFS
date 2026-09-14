# SecureFS

SecureFS est une petite librairie Python qui permet de stocker des fichiers de
façon chiffrée et sécurisée, de manière totalement locale (sans serveur ni
connexion internet nécessaire). Elle protège le contenu des fichiers avec un
chiffrement fort, vérifie qu'ils n'ont pas été altérés, et permet de dériver
la clé de chiffrement directement à partir du mot de passe d'un utilisateur.
C'est utilisable comme une brique de stockage sécurisé dans une application
qui a besoin de garder des fichiers confidentiels sur disque.

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-green)](LICENSE)

## Fonctionnalités

- 🔐 Chiffrement transparent du contenu en AES-256-GCM
- 🔑 Architecture à deux niveaux : une clé maîtresse chiffre une clé unique par fichier
- 🔒 Dérivation de la clé maîtresse depuis un mot de passe (scrypt) — aucun serveur requis
- ✅ Vérification d'intégrité (détecte toute altération des fichiers sur le disque)
- 🗄️ Métadonnées indexées en SQLite (listing par préfixe, statistiques)
- 🚀 Thread-safe (les opérations de lecture/écriture sont protégées par un verrou)
- ⚡ Cache en mémoire optionnel, borné en taille (éviction LRU)
- 🧪 Mode "sans chiffrement" pour le développement/les tests (jamais en production)

## Installation

```bash
pip install -e ".[dev]"
```

## Démarrage rapide

```python
from securefs import SecureFSWrapper
from securefs.utils import generate_master_key

# Générer une clé maîtresse aléatoire (à conserver précieusement)
key = generate_master_key()

fs = SecureFSWrapper(
    master_key=key,
    db_path="./db.db",
    storage_root="./storage",
)

fs.write("/file.txt", b"content")
content = fs.read("/file.txt")
print(content)  # b"content"

fs.close()
```

## Dériver la clé depuis un mot de passe utilisateur

Plutôt qu'une clé aléatoire à conserver quelque part, la clé maîtresse peut
être dérivée du mot de passe d'un compte — pratique pour une application
mono ou multi-comptes, entièrement locale :

```python
from securefs import SecureFSWrapper
from securefs.utils import derive_master_key, generate_salt

# À la création du compte : générer et stocker le sel (non secret)
# à côté du compte, par exemple dans une table "users".
salt = generate_salt()

# À chaque connexion : redériver la même clé à partir du mot de passe saisi.
master_key = derive_master_key(account_password, salt)

fs = SecureFSWrapper(master_key=master_key, db_path="./db.db", storage_root="./storage")
```

Aucun secret supplémentaire n'est requis ni stocké : la sécurité repose
entièrement sur la force du mot de passe, étiré avec `scrypt` pour résister
au brute-force hors ligne.

## Vérification d'intégrité et gestion des erreurs

```python
from securefs import EncryptionError, FileCorruptionError, SecureFSWrapper

fs = SecureFSWrapper(
    master_key=key, db_path="./db.db", storage_root="./storage", verify_integrity=True
)
fs.write("/report.pdf", b"...")

try:
    fs.read("/report.pdf")
except FileCorruptionError:
    print("Le fichier a été altéré ou corrompu sur le disque")
except EncryptionError:
    print("Mauvaise clé, ou données chiffrées invalides")

# Vérifier l'intégrité de tous les fichiers d'un coup
results = fs.verify_all_files()  # {"/report.pdf": True, ...}
```

## Cache en mémoire

```python
fs = SecureFSWrapper(
    master_key=key,
    db_path="./db.db",
    storage_root="./storage",
    cache_enabled=True,
    cache_max_bytes=64 * 1024 * 1024,  # 64 Mio par défaut
)

fs.write("/big.bin", data)
fs.read("/big.bin")  # lu depuis le disque, mis en cache
fs.read("/big.bin")  # servi depuis le cache mémoire
```

## Mode développement (non chiffré)

```python
fs = SecureFSWrapper(
    master_key=key,
    db_path="./dev.db",
    storage_root="./dev_storage",
    encryption_enabled=False,  # ⚠️ stocke les fichiers en clair — dev/tests uniquement
)
```

D'autres exemples complets sont disponibles dans [`examples/`](examples/) :
cache, multi-threading, gestion d'erreurs et corruption, dérivation de clé
par compte, cohabitation de fichiers chiffrés/non chiffrés.

## Modèle de sécurité

- Ce qui est protégé, c'est le **contenu** des fichiers : chiffré en
  AES-256-GCM, avec vérification d'intégrité par HMAC.
- Les **chemins logiques** (ex. `/documents/secret.txt`) sont stockés en
  clair dans la base SQLite de métadonnées — c'est un choix assumé, la
  confidentialité ne porte que sur le contenu, pas sur l'arborescence.
- Il n'y a pas de rotation de clé maîtresse pour l'instant : en changer
  revient à repartir d'un stockage vide.
- Utilisable sans serveur ni secret externe : la sécurité du mode "mot de
  passe" (`derive_master_key`) repose entièrement sur la force de ce mot
  de passe.

## Développement

Le projet utilise Ruff (lint + format), mypy et bandit.

```bash
ruff check --fix . && ruff format . && mypy securefs/ && pytest
```

Voir [`CLAUDE.md`](CLAUDE.md) pour le détail de l'architecture et du
workflow de développement (dont le scan de sécurité `bandit`).

## Licence

BSD 2-Clause — voir [`LICENSE`](LICENSE).
