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
    """Raised when stored content fails to authenticate.

    Either the AES-GCM tag on the content did not verify, or the content did
    not match the keyed integrity tag recorded when it was written. Both mean
    the same thing: what is on disk is not what was stored, whether through
    corruption or tampering.
    """


class EncryptionError(SecureFSError):
    """Raised when data cannot be encrypted, decrypted, or safely served.

    Common causes are the wrong master key, ciphertext whose authentication
    tag does not verify, and -- when encryption is enabled -- a record marked
    as stored in the clear, which is refused rather than served as if it had
    been protected.
    """
