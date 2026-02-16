"""
Custom exceptions for SecureFS

All SecureFS-specific exceptions inherit from :class:`SecureFSError`,
making it easy to catch any SecureFS error with a single except clause.
"""


class SecureFSError(Exception):
    """Base exception for all SecureFS errors.

    All custom exceptions raised by SecureFS inherit from this class.
    Catch this to handle any SecureFS-specific error generically.
    """


class FileCorruptionError(SecureFSError):
    """Raised when a file's integrity check fails.

    This indicates that the stored content does not match its expected
    SHA-256 hash, meaning the data on disk has been tampered with or
    corrupted since it was written.
    """


class EncryptionError(SecureFSError):
    """Raised when an encryption or decryption operation fails.

    Common causes include using the wrong master key to decrypt data,
    or encountering corrupted ciphertext that produces an invalid
    GCM authentication tag.
    """
