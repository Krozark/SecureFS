"""
SecureFS - Transparent Encrypted File Storage System
"""

from securefs.__version__ import __author__, __email__, __license__, __version__
from securefs.core import SecureFSWrapper
from securefs.exceptions import (
    EncryptionError,
    FileCorruptionError,
    SecureFSError,
)


__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "SecureFSWrapper",
    "SecureFSError",
    "FileCorruptionError",
    "EncryptionError",
]
