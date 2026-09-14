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
- 🔑 Architecture à deux niveaux : une clé unique par fichier, chiffrée sous la clé maîtresse
- 🔒 Dérivation de la clé maîtresse depuis un mot de passe (scrypt) — aucun serveur requis
- ✅ Vérification d'intégrité (détecte toute altération du contenu sur le disque)
- 🚫 Refus de servir un contenu non chiffré quand le chiffrement est actif
- 🗄️ Métadonnées indexées en SQLite (listing par préfixe, statistiques)
- 🧹 Nettoyage des fichiers résiduels laissés par une écriture interrompue
- 🚀 Thread-safe (voir [Concurrence](#concurrence) : correction, pas débit)
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
    # Le contenu ne s'authentifie pas : altéré, ou corrompu sur le disque.
    print("Le fichier a été altéré ou corrompu")
except EncryptionError:
    # Mauvaise clé, ou entrée marquée comme non chiffrée alors que le
    # chiffrement est actif — SecureFS refuse alors de la servir.
    print("Déchiffrement impossible")
except FileNotFoundError:
    print("Chemin inconnu, ou fichier .dat manquant")

# Vérifier l'intégrité de tous les fichiers d'un coup
results = fs.verify_all_files()  # {"/report.pdf": True, ...}
```

Toutes les exceptions de la librairie dérivent de `SecureFSError`, qu'on peut
donc attraper seule pour tout couvrir.

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

## Concurrence

Le thread-safety de SecureFS garantit la **correction**, pas le débit : les
opérations sont sérialisées par un verrou, donc plusieurs threads ne liront
pas plus vite qu'un seul. Ce n'est pas un défaut à corriger, c'est le plafond
de CPython — le déchiffrement AES-GCM ne relâche pas le GIL, et mesures à
l'appui, supprimer le verrou rend les lectures concurrentes **deux fois plus
lentes** plutôt que plus rapides.

Utilisez donc les threads pour ne pas bloquer votre application pendant une
lecture, jamais pour accélérer un traitement par lots : à volume égal, une
boucle séquentielle sera au moins aussi rapide.

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
par compte, migration de données en clair vers un store chiffré.

## Modèle de sécurité

**La garantie principale** : en mode normal (chiffrement actif), quelqu'un
qui copie la base de métadonnées **et** tout le répertoire de stockage, sans
connaître la clé maîtresse, ne peut retrouver aucun contenu de fichier. Les
clés par fichier ne sont stockées que chiffrées sous une sous-clé dérivée de
la clé maîtresse, et les noms de fichiers `.dat` sont eux-mêmes dérivés par
HMAC de cette clé. Cette garantie est couverte par
[`tests/test_at_rest_confidentiality.py`](tests/test_at_rest_confidentiality.py).

Un store chiffré **refuse** de servir une entrée non chiffrée (`EncryptionError`),
même si la vérification d'intégrité est désactivée. Sans ce refus, des fichiers
écrits en mode développement resteraient lisibles en clair sur disque tout en
étant servis comme s'ils étaient protégés. Migrer d'anciennes données en clair
est donc une étape explicite — voir
[`examples/migration_example.py`](examples/migration_example.py).

Ce qui n'est **pas** couvert :

- Les **chemins logiques** (ex. `/documents/secret.txt`), leur taille et leurs
  dates sont stockés en clair dans la base de métadonnées — choix assumé, la
  confidentialité ne porte que sur le contenu, pas sur l'arborescence.
- Deux fichiers au contenu identique produisent le même tag d'intégrité : un
  observateur de la base peut détecter cette égalité, sans pour autant
  deviner le contenu.
- Il n'y a pas de rotation de clé maîtresse : en changer revient à repartir
  d'un stockage vide.
- En mode "mot de passe" (`derive_master_key`), la sécurité repose
  entièrement sur la force de ce mot de passe.

## Entretien du stockage

Un arrêt brutal en pleine écriture peut laisser des fichiers `.tmp` ou `.bak`
derrière lui. `cleanup_orphaned_files()` les supprime :

```python
fs.cleanup_orphaned_files()
# {'tmp': 2, 'bak': 1, 'dat': 0}

# Supprime aussi les .dat qu'aucune entrée ne référence (du chiffré mort :
# la clé qui permettait de les lire a disparu avec leur ligne en base).
fs.cleanup_orphaned_files(include_orphaned_data=True)
```

## Développement

Le projet utilise Ruff (lint + format), mypy et bandit.

```bash
ruff check --fix . && ruff format . && mypy securefs/ && pytest
```

Voir [`CLAUDE.md`](CLAUDE.md) pour le détail de l'architecture et du
workflow de développement (dont le scan de sécurité `bandit`).

## Changelog

Voir [`CHANGELOG.md`](CHANGELOG.md). ⚠️ Le format de stockage a changé et
aucune migration n'est fournie : un store créé par une version antérieure
n'est pas lisible.

## Licence

BSD 2-Clause — voir [`LICENSE`](LICENSE).
