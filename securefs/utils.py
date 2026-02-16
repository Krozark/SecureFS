"""
Utility functions for SecureFS

Provides helper functions for key generation, hashing, formatting,
and validation used throughout the SecureFS system.
"""

import hashlib
import secrets


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
