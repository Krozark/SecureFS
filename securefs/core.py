"""
Core SecureFS implementation

This module contains the main SecureFSWrapper class that provides
transparent encrypted file storage.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path
from threading import Lock

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import EncryptionError, FileCorruptionError, SecureFSError
from .utils import validate_master_key


class SecureFSWrapper:
    """Transparent encrypted file storage over a directory and a SQLite index.

    Content is encrypted with AES-256-GCM under a per-file key, itself stored
    wrapped under a subkey of the master key, so recovering any content
    requires the master key. Files are named on disk by a keyed HMAC of their
    logical path, and that name is always re-derived rather than stored.

    Paths, sizes and timestamps are kept in the clear in the index: only
    content confidentiality is in scope. See the project README for the full
    threat model.
    """

    # AES-GCM parameters. A nonce of all zeros marks data stored unencrypted.
    _NONCE_LEN = 12
    _TAG_LEN = 16
    _ZERO_NONCE = b"\x00" * _NONCE_LEN

    # HKDF "info" labels used to derive independent, single-purpose subkeys from
    # the master key -- see _derive_subkey().
    _HKDF_INFO_WRAP = b"securefs-v1-kf-wrap"
    _HKDF_INFO_PATH = b"securefs-v1-path-mac"
    _HKDF_INFO_INTEGRITY = b"securefs-v1-integrity-mac"

    # Default maximum amount of plaintext kept in the in-memory cache (64 MiB).
    # Prevents unbounded memory growth (a DoS vector) when many/large files are read.
    DEFAULT_CACHE_MAX_BYTES = 64 * 1024 * 1024

    def __init__(
        self,
        master_key: bytes,
        db_path: str | os.PathLike[str],
        storage_root: str | os.PathLike[str],
        verify_integrity: bool = True,
        cache_enabled: bool = False,
        encryption_enabled: bool = True,
        cache_max_bytes: int = DEFAULT_CACHE_MAX_BYTES,
    ):
        """
        Initialize the secure file system

        Args:
            master_key: Master key (KM) - must be 32 bytes (256 bits). Never stored
                as-is: independent subkeys are derived from it via HKDF for each
                internal purpose (see _derive_subkey).
            db_path: Path to SQLite database
            storage_root: Root directory to store .dat files
            verify_integrity: Enable hash verification on read (default: True)
            cache_enabled: Enable in-memory caching (default: False)
            encryption_enabled: Enable encryption (default: True, set to False for development)
            cache_max_bytes: Maximum total size of cached plaintext in bytes. When the
                cache grows beyond this budget, least-recently-used entries are evicted
                (default: 64 MiB). Must be positive.

        Warning:
            Setting encryption_enabled=False stores data in PLAINTEXT.
            Use only for development/testing, never in production!
        """
        if not validate_master_key(master_key):
            raise ValueError("Master key must be 32 bytes (256 bits)")

        if cache_max_bytes <= 0:
            raise ValueError("cache_max_bytes must be positive")

        # Derive independent, single-purpose subkeys from the master key instead
        # of reusing the same raw key material for AES-GCM and for HMAC. This is
        # a defense-in-depth measure (NIST SP 800-108 / RFC 5869): a future
        # weakness found in one use can't leak into the others. Only the derived
        # subkeys are kept; the master key itself is not retained beyond this.
        self._key_wrap = self._derive_subkey(master_key, self._HKDF_INFO_WRAP)
        self._key_path = self._derive_subkey(master_key, self._HKDF_INFO_PATH)
        self._key_integrity = self._derive_subkey(master_key, self._HKDF_INFO_INTEGRITY)
        self.db_path = Path(db_path)
        self.storage_root = Path(storage_root)
        self.verify_integrity = verify_integrity
        self.cache_enabled = cache_enabled
        self.encryption_enabled = encryption_enabled
        self.cache_max_bytes = cache_max_bytes

        # Development-mode records are stored unencrypted, so no AEAD tag
        # authenticates them: the keyed integrity tag is then the only thing
        # tying content back to the master key, and is verified even when the
        # caller asked to skip verification.
        self._integrity_check_mandatory = not encryption_enabled

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

        # LRU cache (path -> bytes) bounded by ``cache_max_bytes``.
        # Ordered by recency of use; the oldest entry is evicted first.
        self._cache: OrderedDict[str, bytes] = OrderedDict()
        self._cache_bytes = 0

        # Create storage directory if it doesn't exist
        self.storage_root.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_database()

    @staticmethod
    def _derive_subkey(master_key: bytes, info: bytes) -> bytes:
        """Derive a 32-byte subkey from the master key via HKDF-SHA256.

        ``info`` domain-separates each derived subkey so that, even though they
        all come from the same master key, they are cryptographically
        independent of one another.

        Args:
            master_key: The master key (KM) to derive from.
            info: Purpose-specific label (one of the ``_HKDF_INFO_*`` constants).

        Returns:
            A 32-byte subkey.
        """
        subkey: bytes = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
            master_key
        )
        return subkey

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections with proper cleanup"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_database(self):
        """Initialize SQLite database structure with proper indexes"""
        with self._get_connection() as conn:
            # WAL mode is persistent across connections; set once here
            conn.execute("PRAGMA journal_mode = WAL")

            cursor = conn.cursor()

            # Main files table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    logical_path TEXT PRIMARY KEY,
                    kf_encrypted BLOB NOT NULL,
                    kf_nonce BLOB NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
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
                VALUES ('schema_version', '3.0')
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
        return nonce != self._ZERO_NONCE

    def _seal(self, key: bytes, data: bytes) -> tuple[bytes, bytes]:
        """Encrypt data with AES-256-GCM under ``key``.

        When encryption is disabled the data is returned untouched, paired with
        the all-zero nonce that marks it as stored in the clear.

        Args:
            key: 32-byte AES key.
            data: Plaintext to encrypt.

        Returns:
            Tuple (ciphertext followed by the GCM tag, nonce).

        Raises:
            EncryptionError: If encryption fails.
        """
        if not self.encryption_enabled:
            return data, self._ZERO_NONCE

        try:
            nonce = secrets.token_bytes(self._NONCE_LEN)
            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return ciphertext + encryptor.tag, nonce
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt: {e}") from e

    def _open(
        self,
        key: bytes,
        sealed: bytes,
        nonce: bytes,
        *,
        description: str,
        on_invalid_tag: type[SecureFSError] = EncryptionError,
    ) -> bytes:
        """Decrypt data sealed by :meth:`_seal`.

        An all-zero nonce marks a value that was stored unencrypted, so nothing
        authenticated it. That marker comes from the database and the .dat file,
        which an attacker may be able to write without knowing the master key:
        they could mark a record as plaintext and supply a key of their own.
        Running with encryption on, such a record is therefore refused rather
        than trusted -- it is either that forgery attempt, or development-mode
        data whose content is sitting in the clear on disk and would be a lie to
        call protected. Auto-detection remains only in development mode, where
        unencrypted records are expected.

        Args:
            key: 32-byte AES key.
            sealed: Ciphertext followed by the GCM tag, or plaintext.
            nonce: Nonce used to seal, all zeros if stored in the clear.
            description: What is being opened, used in error messages.
            on_invalid_tag: Exception raised when the GCM tag doesn't verify.

        Returns:
            The plaintext.

        Raises:
            EncryptionError: If encryption is enabled and the record is marked
                as unencrypted, or if decryption fails.
            on_invalid_tag: If the GCM tag doesn't verify.
        """
        if not self._is_encrypted_nonce(nonce):
            if self.encryption_enabled:
                raise EncryptionError(
                    f"Refusing to read unencrypted {description} while encryption is "
                    "enabled: it is not protected on disk. Re-open with "
                    "encryption_enabled=False to read it, then write it back to an "
                    "encrypted store."
                )
            return sealed

        try:
            decryptor = Cipher(
                algorithms.AES(key), modes.GCM(nonce, sealed[-self._TAG_LEN :])
            ).decryptor()
            result: bytes = decryptor.update(sealed[: -self._TAG_LEN]) + decryptor.finalize()
            return result
        except InvalidTag as e:
            raise on_invalid_tag(
                f"Failed to authenticate {description}: wrong key or tampering"
            ) from e
        except Exception as e:
            raise EncryptionError(f"Failed to decrypt {description}: {e}") from e

    def _generate_dat_filename(self, logical_path: str) -> str:
        """
        Generate a unique .dat filename keyed by the master key.

        Using a keyed HMAC (rather than a plain hash of the path) means the
        storage directory alone does not let an attacker confirm guessed paths
        by recomputing their filename.

        Args:
            logical_path: Logical file path

        Returns:
            .dat filename
        """
        path_mac = hmac.new(self._key_path, logical_path.encode(), hashlib.sha256).hexdigest()
        return f"{path_mac}.dat"

    def _dat_path(self, logical_path: str) -> Path:
        """Locate the .dat file holding a logical path's content.

        Always derived, never read back from the database: the filename is the
        only thing binding a row to a file on disk, so a row tampered with
        independently of the master key (its kf_encrypted/kf_nonce/file_hash
        copied from another row, say) must not be able to redirect reads or
        deletes to that other row's file.

        Args:
            logical_path: Logical file path.

        Returns:
            Path to the .dat file, which may not exist yet.
        """
        return self.storage_root / self._generate_dat_filename(logical_path)

    def _compute_integrity_tag(self, content: bytes) -> str:
        """
        Compute a keyed integrity tag (HMAC-SHA256) of the content.

        A keyed MAC is used instead of a bare SHA-256 so the metadata database
        does not leak a verifiable fingerprint of the plaintext: without the
        master key, an attacker cannot confirm guessed contents or correlate
        identical files across paths.

        Args:
            content: Content to authenticate

        Returns:
            Hexadecimal HMAC-SHA256 string
        """
        return hmac.new(self._key_integrity, content, hashlib.sha256).hexdigest()

    def _verify_file_integrity(self, content: bytes, expected_tag: str) -> bool:
        """
        Verify file integrity by comparing keyed integrity tags

        Args:
            content: File content
            expected_tag: Expected integrity tag from database

        Returns:
            True if tags match, False otherwise
        """
        actual_tag = self._compute_integrity_tag(content)
        return hmac.compare_digest(actual_tag, expected_tag)

    def _cache_get(self, logical_path: str) -> bytes | None:
        """Return cached content for a path (marking it as recently used), or None.

        Caller must hold ``self._lock``.
        """
        content = self._cache.get(logical_path)
        if content is not None:
            self._cache.move_to_end(logical_path)
        return content

    def _cache_store(self, logical_path: str, content: bytes) -> None:
        """Insert/update a cache entry, evicting LRU entries to respect the budget.

        No-op when caching is disabled. Caller must hold ``self._lock``.
        """
        if not self.cache_enabled:
            return

        previous = self._cache.pop(logical_path, None)
        if previous is not None:
            self._cache_bytes -= len(previous)

        self._cache[logical_path] = content
        self._cache_bytes += len(content)

        # Evict least-recently-used entries until within budget (always keep the
        # entry we just added, even if it alone exceeds the budget).
        while self._cache_bytes > self.cache_max_bytes and len(self._cache) > 1:
            _, evicted = self._cache.popitem(last=False)
            self._cache_bytes -= len(evicted)

    def _cache_discard(self, logical_path: str) -> None:
        """Remove a single entry from the cache. Caller must hold ``self._lock``."""
        removed = self._cache.pop(logical_path, None)
        if removed is not None:
            self._cache_bytes -= len(removed)

    def write(self, logical_path: str, plaintext_bytes: bytes) -> None:
        """
        Write a file, creating it or replacing its content

        The new content is staged in a temporary file and moved into place, and
        any previous content is kept aside until the index is committed, so a
        failed write rolls back to the previous version. A process killed
        between the move and the commit can still leave the new content on disk
        with the old key in the index, which reads as corruption; the leftovers
        are removable with :meth:`cleanup_orphaned_files`.

        Args:
            logical_path: Logical path (e.g., /secure/data/image.jpg)
            plaintext_bytes: Plaintext content to encrypt

        Raises:
            SecureFSError: If the write fails
        """
        with self._lock:
            # Generate file key (KF)
            kf = secrets.token_bytes(32)

            # Encrypt content with KF
            content_encrypted, content_nonce = self._seal(kf, plaintext_bytes)

            dat_path = self._dat_path(logical_path)

            # Compute keyed integrity tag (HMAC) of the plaintext
            content_hash = self._compute_integrity_tag(plaintext_bytes)

            # Encrypt KF with KM
            kf_encrypted, kf_nonce = self._seal(self._key_wrap, kf)

            # Track whether this is an overwrite for proper rollback
            is_overwrite = dat_path.exists()
            temp_path = dat_path.with_suffix(".tmp")
            backup_path = dat_path.with_suffix(".bak")

            # Use transaction for atomicity
            with self._get_connection() as conn:
                cursor = conn.cursor()

                committed = False
                try:
                    # Write new content to a temp file first.
                    with temp_path.open("wb") as f:
                        f.write(content_nonce)
                        f.write(content_encrypted)

                    # On overwrite, move the existing content aside so we can
                    # restore it if the database update fails.
                    if is_overwrite:
                        dat_path.replace(backup_path)

                    # Atomically move the new content into place.
                    temp_path.replace(dat_path)

                    # Update database, preserving created_at on overwrite
                    cursor.execute(
                        """
                        INSERT INTO files
                        (logical_path, kf_encrypted, kf_nonce, file_hash, file_size,
                         created_at, modified_at)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        ON CONFLICT(logical_path) DO UPDATE SET
                            kf_encrypted = excluded.kf_encrypted,
                            kf_nonce = excluded.kf_nonce,
                            file_hash = excluded.file_hash,
                            file_size = excluded.file_size,
                            modified_at = CURRENT_TIMESTAMP
                    """,
                        (
                            logical_path,
                            kf_encrypted,
                            kf_nonce,
                            content_hash,
                            len(plaintext_bytes),
                        ),
                    )

                    conn.commit()
                    committed = True

                    # Write succeeded: drop the backup of the previous content.
                    if is_overwrite:
                        backup_path.unlink(missing_ok=True)

                    # Update cache if enabled
                    self._cache_store(logical_path, plaintext_bytes)

                except Exception as e:
                    # The DB transaction is rolled back by _get_connection. Only
                    # restore the filesystem if we never durably committed.
                    if not committed:
                        temp_path.unlink(missing_ok=True)
                        if is_overwrite:
                            # Restore the previous content if it was moved aside.
                            if backup_path.exists():
                                backup_path.replace(dat_path)
                        elif dat_path.exists():
                            # Brand new file: remove the partial write.
                            dat_path.unlink()
                    raise SecureFSError(f"Failed to write file {logical_path}: {e}") from e

    def read(
        self,
        logical_path: str,
        skip_verification: bool = False,
        bypass_cache: bool = False,
    ) -> bytes:
        """
        Read an encrypted file and return plaintext content

        Args:
            logical_path: Logical file path
            skip_verification: Skip the keyed integrity check (faster but less
                safe). Ignored in development mode, where nothing else
                authenticates the content.
            bypass_cache: Ignore the in-memory cache and read straight from disk,
                without populating the cache. Useful for integrity verification
                that must inspect the on-disk content.

        Returns:
            Plaintext content

        Raises:
            FileNotFoundError: If the path is not in the index, or its .dat
                file is missing
            FileCorruptionError: If the content fails to authenticate
            EncryptionError: If decryption fails, or if the record is marked as
                stored in the clear while encryption is enabled
        """
        with self._lock:
            # Check cache first (inside lock for thread safety)
            if self.cache_enabled and not bypass_cache:
                cached = self._cache_get(logical_path)
                if cached is not None:
                    return cached

            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT kf_encrypted, kf_nonce, file_hash
                    FROM files
                    WHERE logical_path = ?
                """,
                    (logical_path,),
                )

                row = cursor.fetchone()

                if row is None:
                    raise FileNotFoundError(f"File not found: {logical_path}")

                kf_encrypted, kf_nonce, expected_hash = row

            # Unwrap the file key. _open refuses a record marked as unencrypted
            # when running with encryption on, so this is also what stops a
            # tampered row from downgrading the read.
            kf = self._open(
                self._key_wrap,
                kf_encrypted,
                kf_nonce,
                description=f"file key for {logical_path}",
            )

            dat_path = self._dat_path(logical_path)
            try:
                with dat_path.open("rb") as f:
                    content_nonce = f.read(self._NONCE_LEN)
                    content_encrypted = f.read()
            except FileNotFoundError as e:
                raise FileNotFoundError(f"Missing .dat file: {dat_path.name}") from e

            plaintext_bytes = self._open(
                kf,
                content_encrypted,
                content_nonce,
                description=f"entry {logical_path}",
                on_invalid_tag=FileCorruptionError,
            )

            verification_requested = self.verify_integrity and not skip_verification

            if (
                self._integrity_check_mandatory or verification_requested
            ) and not self._verify_file_integrity(plaintext_bytes, expected_hash):
                raise FileCorruptionError(
                    f"Integrity check failed for {logical_path}: hash mismatch"
                )

            # Update cache if enabled (never cache on an explicit bypass read)
            if not bypass_cache:
                self._cache_store(logical_path, plaintext_bytes)

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
        Delete a file: its metadata row first, then its .dat file

        The metadata removal is committed before the file is unlinked, so an
        interrupted delete can only leave an unreferenced .dat file behind --
        never a row pointing at content that is already gone. Clean those up
        with :meth:`cleanup_orphaned_files`.

        Args:
            logical_path: Logical file path

        Returns:
            True if deleted, False if file didn't exist
        """
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()

            try:
                # Commit the metadata removal *before* touching the filesystem.
                # Unlinking first would destroy the content while leaving a row
                # that still claims the file exists if the commit then failed
                # (e.g. "database is locked"), making the entry permanently
                # unreadable. This order can only leave an orphan .dat file,
                # which is harmless and is overwritten by the next write to the
                # same path.
                cursor.execute("DELETE FROM files WHERE logical_path = ?", (logical_path,))
                if cursor.rowcount == 0:
                    return False
                conn.commit()

                # The file is logically gone from here on: drop it from the cache
                # before the unlink, so a failure below can't leave stale content
                # readable in memory.
                self._cache_discard(logical_path)

                self._dat_path(logical_path).unlink(missing_ok=True)

                return True

            except Exception as e:
                raise SecureFSError(f"Failed to delete file {logical_path}: {e}") from e

    def list_files(self, prefix: str = "") -> list[str]:
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
                # Escape LIKE wildcards so prefix is matched literally
                escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                cursor.execute(
                    """
                    SELECT logical_path FROM files
                    WHERE logical_path LIKE ? ESCAPE '\\'
                    ORDER BY logical_path
                """,
                    (f"{escaped}%",),
                )
            else:
                cursor.execute("SELECT logical_path FROM files ORDER BY logical_path")

            return [row[0] for row in cursor.fetchall()]

    def get_info(self, logical_path: str) -> dict | None:
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

    def verify_all_files(self) -> dict[str, bool]:
        """
        Verify that every indexed file still reads back

        Returns:
            Dictionary mapping each path to whether it verified.

        Raises:
            Exception: Anything other than a storage-level failure propagates,
                rather than being reported as a file that did not verify.
        """
        results = {}

        for path in self.list_files():
            try:
                # Read with verification, bypassing the cache so the on-disk
                # content is actually re-read and checked (not a stale cache hit).
                self.read(path, skip_verification=False, bypass_cache=True)
                results[path] = True
            except (SecureFSError, OSError):
                # A failed tag, a missing or unreadable .dat, a refused
                # unencrypted record: this path does not verify. Anything else
                # is a bug in SecureFS, and is left to surface instead of being
                # quietly reported as corrupted data.
                results[path] = False

        return results

    def cleanup_orphaned_files(self, include_orphaned_data: bool = False) -> dict[str, int]:
        """Remove leftover files in the storage directory that nothing references.

        A crash or a failed write can leave a ``.tmp`` file (a half-written new
        version) or a ``.bak`` file (the previous version, moved aside) behind.
        Neither is ever referenced by the index once the write is over, so both
        are always safe to remove.

        Orphaned ``.dat`` files -- ones no index entry points to -- are dead
        ciphertext: the file key needed to decrypt them lived in the row that is
        now gone, so nobody can ever read them again. They are still only removed
        when ``include_orphaned_data`` is set, so that pointing the wrapper at the
        wrong database cannot quietly delete live data.

        Args:
            include_orphaned_data: Also remove .dat files with no index entry.

        Returns:
            How many files were removed per extension, e.g.
            ``{"tmp": 2, "bak": 1, "dat": 0}``.

        Raises:
            SecureFSError: If a file could not be removed.
        """
        removed = {"tmp": 0, "bak": 0, "dat": 0}

        # Hold the lock so a concurrent write() can't have its in-flight .tmp or
        # .bak deleted from under it.
        with self._lock:
            referenced = (
                {self._generate_dat_filename(path) for path in self.list_files()}
                if include_orphaned_data
                else set()
            )

            try:
                # Test the name before stat()ing: in the common call only .tmp and
                # .bak can match, so the whole store need not be stat'ed while the
                # lock is held.
                with os.scandir(self.storage_root) as entries:
                    for entry in entries:
                        suffix = Path(entry.name).suffix.removeprefix(".")
                        if suffix not in removed:
                            continue
                        if suffix == "dat" and (
                            not include_orphaned_data or entry.name in referenced
                        ):
                            continue
                        if not entry.is_file():
                            continue

                        Path(entry.path).unlink(missing_ok=True)
                        removed[suffix] += 1
            except OSError as e:
                raise SecureFSError(f"Failed to clean up storage directory: {e}") from e

        return removed

    def get_statistics(self) -> dict:
        """
        Get system statistics

        Returns:
            Dictionary with system stats
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT COUNT(*), COALESCE(SUM(file_size), 0),"
                " MIN(created_at), MAX(modified_at) FROM files"
            )
            count, total_size, oldest, newest = cursor.fetchone()

        # Read the cache under the lock, like every other cache accessor. Taken
        # after the database work so the lock isn't held across any I/O.
        with self._lock:
            cache_entries = len(self._cache) if self.cache_enabled else 0

        return {
            "total_files": count,
            "total_size_bytes": total_size,
            "oldest_file": oldest,
            "newest_modification": newest,
            "cache_enabled": self.cache_enabled,
            "cache_entries": cache_entries,
            "encryption_enabled": self.encryption_enabled,
        }

    def clear_cache(self, path: str | None = None):
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
                self._cache_bytes = 0
            else:
                # Remove specific file from cache
                self._cache_discard(path)

    def is_cached(self, path: str) -> bool:
        """
        Check if a file is currently in cache

        Args:
            path: Logical file path

        Returns:
            True if file is in cache, False otherwise
        """
        with self._lock:
            return path in self._cache

    def get_cache_size(self) -> int:
        """
        Get total size of cached data in bytes

        Returns:
            Total size of all cached files in bytes
        """
        with self._lock:
            return self._cache_bytes

    def get_cached_paths(self) -> list[str]:
        """
        Get list of all paths currently in cache

        Returns:
            List of logical paths in cache
        """
        with self._lock:
            return list(self._cache.keys())

    def close(self):
        """Drop cached plaintext.

        There is nothing else to release: database connections live only for
        the length of one operation. Note that Python cannot reliably wipe the
        derived subkeys from memory, so closing is not a substitute for ending
        the process when handling sensitive material.
        """
        self.clear_cache()
