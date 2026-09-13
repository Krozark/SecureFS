"""
Utility functions for SecureFS

Provides helper functions for key generation, hashing, formatting,
and validation used throughout the SecureFS system.
"""

import hashlib
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# scrypt cost parameters for derive_master_key(): OWASP-recommended defaults for
# an interactive (login-time) password stretch, requiring ~128 MiB of memory.
_SCRYPT_N = 2**17  # CPU/memory cost factor (must be a power of two)
_SCRYPT_R = 8  # block size
_SCRYPT_P = 1  # parallelization factor

_MIN_PEPPER_BYTES = 32


def generate_master_key() -> bytes:
    """Generate a cryptographically secure random master key.

    Returns:
        A 32-byte (256-bit) random key suitable for use as a SecureFS master key.

    Example:
        >>> key = generate_master_key()
        >>> len(key)
        32
    """
    return secrets.token_bytes(32)


def generate_salt(size: int = 16) -> bytes:
    """Generate a random per-account salt for :func:`derive_master_key`.

    The salt is not secret. It only needs to be unique per account and stored
    alongside it (e.g. in the accounts table), so :func:`derive_master_key`
    reproduces the same master key on every login.

    Args:
        size: Salt length in bytes (default: 16).

    Returns:
        A random ``size``-byte salt.
    """
    return secrets.token_bytes(size)


def derive_master_key(
    account_secret: bytes | str,
    salt: bytes,
    server_pepper: bytes,
    *,
    n: int = _SCRYPT_N,
    r: int = _SCRYPT_R,
    p: int = _SCRYPT_P,
) -> bytes:
    """Derive a SecureFS master key from an account secret and a server pepper.

    Two independent secrets are required to obtain the resulting key, so that
    neither one on its own is enough:

    - ``account_secret``: provided by the account owner (typically their
      password). It may be low-entropy, so it is first stretched with
      ``scrypt`` -- a slow, memory-hard KDF -- to resist offline brute-forcing
      by anyone who only has ``account_secret`` and ``salt`` (e.g. after a
      database leak).
    - ``server_pepper``: a secret held only by the server/application (an
      environment variable, secrets manager, or KMS/HSM), shared by all
      accounts, and never stored alongside application data. Without it,
      ``account_secret`` and ``salt`` alone are *not* enough to recompute the
      master key -- this is what stops the account owner, or anyone who
      steals the database, from deriving it unassisted.

    Args:
        account_secret: Account-linked secret supplied by the user (e.g.
            their password). A ``str`` is UTF-8 encoded for convenience.
        salt: Random, unique-per-account value (not secret). Generate one
            per account with :func:`generate_salt` and store it next to the
            account (e.g. alongside its ``db_path``/``storage_root``).
        server_pepper: Secret held only by the server, at least 32 bytes.
            Never store it next to the data it protects.
        n: scrypt CPU/memory cost parameter (must be a power of two).
        r: scrypt block size parameter.
        p: scrypt parallelization parameter.

    Returns:
        A 32-byte key suitable for use as a SecureFS ``master_key``.

    Raises:
        ValueError: If ``server_pepper`` is shorter than 32 bytes.
    """
    if isinstance(account_secret, str):
        account_secret = account_secret.encode("utf-8")

    if len(server_pepper) < _MIN_PEPPER_BYTES:
        raise ValueError(f"server_pepper must be at least {_MIN_PEPPER_BYTES} bytes")

    # Slow, memory-hard stretch of the (possibly low-entropy) account secret.
    stretched = hashlib.scrypt(
        account_secret, salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * n * r * p * 2
    )

    # Bind in the server-only pepper: without it, `stretched` (i.e. everything
    # derivable from account_secret + salt) is not enough to get the master key.
    master_key: bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=server_pepper,
        info=b"securefs-account-master-key",
    ).derive(stretched)
    return master_key


def compute_hash(data: bytes) -> str:
    """Compute the SHA-256 hash of the given data.

    Args:
        data: The bytes to hash.

    Returns:
        Hexadecimal string representation of the SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest()


def format_size(size_bytes: int) -> str:
    """Format a byte count into a human-readable string.

    Uses binary units (KB = 1024 bytes) and rounds to one decimal place.

    Args:
        size_bytes: The size in bytes to format. Must be non-negative.

    Returns:
        A human-readable string like ``"1.5 MB"`` or ``"512.0 B"``.

    Example:
        >>> format_size(1536)
        '1.5 KB'
        >>> format_size(0)
        '0.0 B'
    """
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def validate_master_key(key: bytes) -> bool:
    """Validate that a master key has the correct type and length.

    Args:
        key: The key to validate.

    Returns:
        True if the key is a 32-byte bytes object, False otherwise.
    """
    return isinstance(key, bytes) and len(key) == 32
