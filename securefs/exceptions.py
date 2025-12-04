"""
Custom exceptions for SecureFS
"""


class SecureFSError(Exception):
    """Base exception for SecureFS errors"""


class FileCorruptionError(SecureFSError):
    """Raised when file integrity check fails"""


class EncryptionError(SecureFSError):
    """Raised when encryption/decryption fails"""
