"""
Utility functions for SecureFS
"""

import hashlib
import secrets


def generate_master_key() -> bytes:
    """Generate a secure random master key"""
    return secrets.token_bytes(32)


def compute_hash(data: bytes) -> str:
    """Compute SHA-256 hash of data"""
    return hashlib.sha256(data).hexdigest()


def format_size(size_bytes: int) -> str:
    """Format byte size into human-readable string"""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def validate_master_key(key: bytes) -> bool:
    """Validate that a master key has correct length"""
    return isinstance(key, bytes) and len(key) == 32
