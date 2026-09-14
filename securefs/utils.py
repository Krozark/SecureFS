"""
Utility functions for SecureFS

Provides helper functions for key derivation, key generation, formatting and
validation. Content integrity uses a master-key-derived HMAC inside
SecureFSWrapper, not a helper here.
"""

import hashlib
import secrets


# scrypt cost parameters for derive_master_key(): OWASP-recommended defaults for
# an interactive (login-time) password stretch, requiring ~128 MiB of memory.
_SCRYPT_N = 2**17  # CPU/memory cost factor (must be a power of two)
_SCRYPT_R = 8  # block size
_SCRYPT_P = 1  # parallelization factor


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
    *,
    n: int = _SCRYPT_N,
    r: int = _SCRYPT_R,
    p: int = _SCRYPT_P,
) -> bytes:
    """Derive a SecureFS master key from an account secret (e.g. a password).

    ``account_secret`` may be low-entropy (a human-chosen password), so it is
    stretched with ``scrypt`` -- a slow, memory-hard KDF -- rather than hashed
    directly. This raises the cost of brute-forcing it, per guess and per
    account (see ``salt`` below), if the storage is ever read by someone who
    doesn't know the secret.

    There is deliberately no second, separately-held secret ("pepper") mixed
    in here: for a fully local/offline library there is no trusted place to
    keep one that isn't just sitting next to the data it would be meant to
    protect (which defeats the point -- see the project's security notes).
    The security of the resulting key rests entirely on how hard
    ``account_secret`` is to guess; enforce a minimum length/strength on it
    the same way you would for any password.

    Args:
        account_secret: Account-linked secret supplied by the user (e.g.
            their password). A ``str`` is UTF-8 encoded for convenience.
        salt: Random, unique-per-account value (not secret). Generate one
            per account with :func:`generate_salt` and store it next to the
            account (e.g. alongside its ``db_path``/``storage_root``). It
            defeats precomputed dictionary attacks and stops two accounts
            that happen to share a secret from deriving the same key.
        n: scrypt CPU/memory cost parameter (must be a power of two).
        r: scrypt block size parameter.
        p: scrypt parallelization parameter.

    Returns:
        A 32-byte key suitable for use as a SecureFS ``master_key``.
    """
    if isinstance(account_secret, str):
        account_secret = account_secret.encode("utf-8")

    master_key: bytes = hashlib.scrypt(
        account_secret, salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * n * r * p * 2
    )
    return master_key


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
