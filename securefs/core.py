"""
Core SecureFS implementation

This module contains the main SecureFSWrapper class that provides
transparent encrypted file storage.
"""

import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import EncryptionError, FileCorruptionError, SecureFSError
from .utils import compute_hash


class SecureFSWrapper:
    """Enhanced transparent wrapper for encrypted file system"""

    def __init__(
        self,
        master_key: bytes,
        db_path: str,
        storage_root: str,
        verify_integrity: bool = True,
        cache_enabled: bool = False,
        encryption_enabled: bool = True,
    ):
        """
        Initialize the secure file system

        Args:
            master_key: Master key (KM) - must be 32 bytes (256 bits)
            db_path: Path to SQLite database
            storage_root: Root directory to store .dat files
            verify_integrity: Enable hash verification on read (default: True)
            cache_enabled: Enable in-memory caching (default: False)
            encryption_enabled: Enable encryption (default: True, set to False for development)

        Warning:
            Setting encryption_enabled=False stores data in PLAINTEXT.
            Use only for development/testing, never in production!
        """
        if len(master_key) != 32:
            raise ValueError("Master key must be 32 bytes (256 bits)")

        self.master_key = master_key
        self.db_path = db_path
        self.storage_root = Path(storage_root)
        self.verify_integrity = verify_integrity
        self.cache_enabled = cache_enabled
        self.encryption_enabled = encryption_enabled

        # Warn if encryption is disabled
        if not self.encryption_enabled:
            import warnings

            warnings.warn(
                "⚠️  ENCRYPTION IS DISABLED - Data will be stored in PLAINTEXT! "
                "This should ONLY be used for development/testing.",
                UserWarning,
                stacklevel=2,
            )

        # Thread safety
        self._lock = Lock()

        # Simple cache (path -> bytes)
        self._cache: Dict[str, bytes] = {}

        # Create storage directory if it doesn't exist
        self.storage_root.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_database()

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections with proper cleanup"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            # Enable foreign keys and WAL mode for better concurrency
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_database(self):
        """Initialize SQLite database structure with proper indexes"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Main files table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    logical_path TEXT PRIMARY KEY,
                    kf_encrypted BLOB NOT NULL,
                    kf_nonce BLOB NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    dat_filename TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes for better performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_files_hash 
                ON files(file_hash)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_files_modified 
                ON files(modified_at)
            """)

            # Metadata table for system info
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Store version info
            cursor.execute("""
                INSERT OR IGNORE INTO system_metadata (key, value)
                VALUES ('schema_version', '2.0')
            """)

            conn.commit()

    def _is_encrypted_nonce(self, nonce: bytes) -> bool:
        """
        Check if a nonce indicates encryption was used

        Args:
            nonce: Nonce to check

        Returns:
            True if file is encrypted, False if plaintext
        """
        # A nonce of all zeros indicates plaintext storage
        return nonce != b"\x00" * 12

    def _encrypt_with_km(self, data: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt data with master key (KM) using AES-256-GCM
        If encryption is disabled, returns data as-is with zero nonce

        Args:
            data: Data to encrypt

        Returns:
            Tuple (encrypted_data_with_tag, nonce)
        """
        if not self.encryption_enabled:
            # Return data as-is with a zero nonce to mark as plaintext
            return data, b"\x00" * 12

        try:
            nonce = secrets.token_bytes(12)
            cipher = Cipher(
                algorithms.AES(self.master_key), modes.GCM(nonce), backend=default_backend()
            )
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(data) + encryptor.finalize()
            ciphertext_with_tag = ciphertext + encryptor.tag

            return ciphertext_with_tag, nonce
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt with master key: {e}")

    def _decrypt_with_km(self, ciphertext_with_tag: bytes, nonce: bytes) -> bytes:
        """
        Decrypt data with master key (KM)
        Automatically detects if data is encrypted based on nonce

        Args:
            ciphertext_with_tag: Encrypted data + GCM tag (16 bytes) OR plaintext
            nonce: Nonce used for encryption (all zeros if plaintext)

        Returns:
            Plaintext data

        Raises:
            EncryptionError: If decryption fails (wrong key or corrupted data)
        """
        # Check if this was stored as plaintext (zero nonce)
        if not self._is_encrypted_nonce(nonce):
            # Return data as-is (it's plaintext)
            return ciphertext_with_tag

        # Data is encrypted, decrypt it
        try:
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]

            cipher = Cipher(
                algorithms.AES(self.master_key), modes.GCM(nonce, tag), backend=default_backend()
            )
            decryptor = cipher.decryptor()

            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            raise EncryptionError(
                "Decryption failed: Invalid authentication tag (wrong key or corrupted data)"
            )
        except Exception as e:
            raise EncryptionError(f"Failed to decrypt with master key: {e}")

    def _encrypt_file_content(self, content: bytes, kf: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt file content with file key (KF)
        If encryption is disabled, returns content as-is with zero nonce

        Args:
            content: Plaintext content
            kf: File key (32 bytes)

        Returns:
            Tuple (encrypted_content_with_tag, nonce)
        """
        if not self.encryption_enabled:
            # Return content as-is with a zero nonce to mark as plaintext
            return content, b"\x00" * 12

        try:
            nonce = secrets.token_bytes(12)
            cipher = Cipher(algorithms.AES(kf), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(content) + encryptor.finalize()
            ciphertext_with_tag = ciphertext + encryptor.tag

            return ciphertext_with_tag, nonce
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt file content: {e}")

    def _decrypt_file_content(self, ciphertext_with_tag: bytes, nonce: bytes, kf: bytes) -> bytes:
        """
        Decrypt file content with file key (KF)
        Automatically detects if data is encrypted based on nonce

        Args:
            ciphertext_with_tag: Encrypted content + tag OR plaintext
            nonce: Nonce used (all zeros if plaintext)
            kf: File key (32 bytes)

        Returns:
            Plaintext content

        Raises:
            EncryptionError: If decryption fails
        """
        # Check if this was stored as plaintext (zero nonce)
        if not self._is_encrypted_nonce(nonce):
            # Return data as-is (it's plaintext)
            return ciphertext_with_tag

        # Data is encrypted, decrypt it
        try:
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]

            cipher = Cipher(algorithms.AES(kf), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            raise FileCorruptionError("File decryption failed: Data may be corrupted")
        except Exception as e:
            raise EncryptionError(f"Failed to decrypt file content: {e}")

    def _generate_dat_filename(self, logical_path: str) -> str:
        """
        Generate a unique .dat filename based on path hash

        Args:
            logical_path: Logical file path

        Returns:
            .dat filename
        """
        path_hash = compute_hash(logical_path.encode())
        return f"{path_hash}.dat"

    def _compute_content_hash(self, content: bytes) -> str:
        """
        Compute SHA-256 hash of content

        Args:
            content: Content to hash

        Returns:
            Hexadecimal hash string
        """
        return compute_hash(content)

    def _verify_file_integrity(self, content: bytes, expected_hash: str) -> bool:
        """
        Verify file integrity by comparing hashes

        Args:
            content: File content
            expected_hash: Expected hash from database

        Returns:
            True if hashes match, False otherwise
        """
        actual_hash = self._compute_content_hash(content)
        return actual_hash == expected_hash

    def write(self, logical_path: str, plaintext_bytes: bytes) -> None:
        """
        Write an encrypted file (create or update) with atomic transaction

        Args:
            logical_path: Logical path (e.g., /secure/data/image.jpg)
            plaintext_bytes: Plaintext content to encrypt

        Raises:
            SecureFSError: If write operation fails
        """
        with self._lock:
            # Generate file key (KF)
            kf = secrets.token_bytes(32)

            # Encrypt content with KF
            content_encrypted, content_nonce = self._encrypt_file_content(plaintext_bytes, kf)

            # Generate .dat filename
            dat_filename = self._generate_dat_filename(logical_path)
            dat_path = self.storage_root / dat_filename

            # Compute hash
            content_hash = self._compute_content_hash(plaintext_bytes)

            # Encrypt KF with KM
            kf_encrypted, kf_nonce = self._encrypt_with_km(kf)

            # Use transaction for atomicity
            with self._get_connection() as conn:
                cursor = conn.cursor()

                try:
                    # Write .dat file first (can rollback DB if this fails)
                    temp_path = dat_path.with_suffix(".tmp")
                    with open(temp_path, "wb") as f:
                        f.write(content_nonce)
                        f.write(content_encrypted)

                    # Atomic rename
                    temp_path.replace(dat_path)

                    # Update database
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO files 
                        (logical_path, kf_encrypted, kf_nonce, file_hash, file_size, dat_filename, modified_at)
                        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                        (
                            logical_path,
                            kf_encrypted,
                            kf_nonce,
                            content_hash,
                            len(plaintext_bytes),
                            dat_filename,
                        ),
                    )

                    conn.commit()

                    # Update cache if enabled
                    if self.cache_enabled:
                        self._cache[logical_path] = plaintext_bytes

                except Exception as e:
                    # Rollback: remove .dat file if it was created
                    if dat_path.exists():
                        dat_path.unlink()
                    raise SecureFSError(f"Failed to write file {logical_path}: {e}")

    def read(self, logical_path: str, skip_verification: bool = False) -> bytes:
        """
        Read an encrypted file and return plaintext content

        Args:
            logical_path: Logical file path
            skip_verification: Skip hash verification (faster but less safe)

        Returns:
            Plaintext content

        Raises:
            FileNotFoundError: If file doesn't exist
            FileCorruptionError: If integrity check fails
            EncryptionError: If decryption fails
        """
        # Check cache first
        if self.cache_enabled and logical_path in self._cache:
            return self._cache[logical_path]

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT kf_encrypted, kf_nonce, dat_filename, file_hash
                    FROM files 
                    WHERE logical_path = ?
                """,
                    (logical_path,),
                )

                row = cursor.fetchone()

                if row is None:
                    raise FileNotFoundError(f"File not found: {logical_path}")

                kf_encrypted, kf_nonce, dat_filename, expected_hash = row

            # Decrypt KF with KM
            kf = self._decrypt_with_km(kf_encrypted, kf_nonce)

            # Read .dat file
            dat_path = self.storage_root / dat_filename

            if not dat_path.exists():
                raise FileNotFoundError(f"Missing .dat file: {dat_filename}")

            with open(dat_path, "rb") as f:
                content_nonce = f.read(12)
                content_encrypted = f.read()

            # Decrypt content with KF
            plaintext_bytes = self._decrypt_file_content(content_encrypted, content_nonce, kf)

            # Verify integrity if enabled
            if self.verify_integrity and not skip_verification:
                if not self._verify_file_integrity(plaintext_bytes, expected_hash):
                    raise FileCorruptionError(
                        f"Integrity check failed for {logical_path}: hash mismatch"
                    )

            # Update cache if enabled
            if self.cache_enabled:
                self._cache[logical_path] = plaintext_bytes

            return plaintext_bytes

    def exists(self, logical_path: str) -> bool:
        """
        Check if a file exists in the index

        Args:
            logical_path: Logical file path

        Returns:
            True if file exists, False otherwise
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM files WHERE logical_path = ?", (logical_path,))
            return cursor.fetchone() is not None

    def delete(self, logical_path: str) -> bool:
        """
        Delete a file (metadata + .dat file) atomically

        Args:
            logical_path: Logical file path

        Returns:
            True if deleted, False if file didn't exist
        """
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()

            # Get .dat filename
            cursor.execute("SELECT dat_filename FROM files WHERE logical_path = ?", (logical_path,))
            row = cursor.fetchone()

            if row is None:
                return False

            dat_filename = row[0]

            try:
                # Delete from database first
                cursor.execute("DELETE FROM files WHERE logical_path = ?", (logical_path,))
                conn.commit()

                # Delete .dat file
                dat_path = self.storage_root / dat_filename
                if dat_path.exists():
                    dat_path.unlink()

                # Remove from cache
                if self.cache_enabled and logical_path in self._cache:
                    del self._cache[logical_path]

                return True

            except Exception as e:
                raise SecureFSError(f"Failed to delete file {logical_path}: {e}")

    def list_files(self, prefix: str = "") -> List[str]:
        """
        List all files (optionally with a prefix)

        Args:
            prefix: Optional prefix to filter paths

        Returns:
            List of logical paths sorted alphabetically
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if prefix:
                cursor.execute(
                    """
                    SELECT logical_path FROM files 
                    WHERE logical_path LIKE ? 
                    ORDER BY logical_path
                """,
                    (f"{prefix}%",),
                )
            else:
                cursor.execute("SELECT logical_path FROM files ORDER BY logical_path")

            return [row[0] for row in cursor.fetchall()]

    def get_info(self, logical_path: str) -> Optional[Dict]:
        """
        Get information about a file

        Args:
            logical_path: Logical file path

        Returns:
            Dictionary with metadata or None if doesn't exist
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT file_size, file_hash, created_at, modified_at 
                FROM files 
                WHERE logical_path = ?
            """,
                (logical_path,),
            )

            row = cursor.fetchone()

            if row is None:
                return None

            return {
                "path": logical_path,
                "size": row[0],
                "hash": row[1],
                "created_at": row[2],
                "modified_at": row[3],
            }

    def verify_all_files(self) -> Dict[str, bool]:
        """
        Verify integrity of all files in the system

        Returns:
            Dictionary mapping paths to verification status (True = OK, False = corrupted)
        """
        results = {}

        for path in self.list_files():
            try:
                # Read with verification
                self.read(path, skip_verification=False)
                results[path] = True
            except FileCorruptionError:
                results[path] = False
            except Exception:
                results[path] = False

        return results

    def get_statistics(self) -> Dict:
        """
        Get system statistics

        Returns:
            Dictionary with system stats
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*), SUM(file_size) FROM files")
            count, total_size = cursor.fetchone()

            cursor.execute("SELECT MIN(created_at), MAX(modified_at) FROM files")
            oldest, newest = cursor.fetchone()

            return {
                "total_files": count or 0,
                "total_size_bytes": total_size or 0,
                "oldest_file": oldest,
                "newest_modification": newest,
                "cache_enabled": self.cache_enabled,
                "cache_entries": len(self._cache) if self.cache_enabled else 0,
                "encryption_enabled": self.encryption_enabled,
            }

    def clear_cache(self, path: Optional[str] = None):
        """
        Clear the in-memory cache

        Args:
            path: Optional logical path to remove from cache.
                  If None, clears the entire cache.

        Example:
            >>> fs.clear_cache()  # Clear all cache
            >>> fs.clear_cache("/file.txt")  # Remove one file from cache
        """
        with self._lock:
            if path is None:
                # Clear entire cache
                self._cache.clear()
            else:
                # Remove specific file from cache
                self._cache.pop(path, None)

    def is_cached(self, path: str) -> bool:
        """
        Check if a file is currently in cache

        Args:
            path: Logical file path

        Returns:
            True if file is in cache, False otherwise
        """
        return path in self._cache

    def get_cache_size(self) -> int:
        """
        Get total size of cached data in bytes

        Returns:
            Total size of all cached files in bytes
        """
        with self._lock:
            return sum(len(content) for content in self._cache.values())

    def get_cached_paths(self) -> List[str]:
        """
        Get list of all paths currently in cache

        Returns:
            List of logical paths in cache
        """
        with self._lock:
            return list(self._cache.keys())

    def close(self):
        """Clean up resources"""
        self.clear_cache()
