"""Tests defending against database-row tampering.

The ``dat_filename`` column stored in the ``files`` table is a deterministic
function of (logical_path, master_key). ``read()`` and ``delete()`` must
re-derive it themselves instead of trusting the stored column, otherwise an
attacker with write access to the SQLite database (but not the master key)
could redirect a logical path to another file's ciphertext, or make delete()
remove an unrelated .dat file.

The same adversary must not be able to use the zero-nonce "stored in
plaintext" marker to downgrade a file out of authenticated encryption and
hand us content of their choosing.
"""

import secrets
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from securefs import EncryptionError, FileCorruptionError, SecureFSError, SecureFSWrapper


class TestRowTampering(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.db_path = self.test_dir / "index.db"
        self.storage_root = self.test_dir / "storage"
        self.master_key = secrets.token_bytes(32)

        self.secure_fs = SecureFSWrapper(
            master_key=self.master_key, db_path=self.db_path, storage_root=self.storage_root
        )

    def tearDown(self):
        self.secure_fs.close()
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def _row(self, logical_path: str) -> tuple:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT kf_encrypted, kf_nonce, file_hash, file_size, dat_filename "
                "FROM files WHERE logical_path = ?",
                (logical_path,),
            )
            return cursor.fetchone()

    def test_tampered_dat_filename_is_not_trusted_on_read(self):
        """Pointing a row's dat_filename at another file's .dat must not redirect read()."""
        self.secure_fs.write("/public/report.txt", b"public content")
        self.secure_fs.write("/private/salary.txt", b"CONFIDENTIAL: 999999")

        private_dat_filename = self._row("/private/salary.txt")[4]

        with sqlite3.connect(self.db_path) as conn:
            # Remove the private row first (its .dat blob is left orphaned on disk)
            # so the UNIQUE constraint on dat_filename doesn't block repointing the
            # public row at it -- this is what an attacker with DB write access
            # (but not the master key) would have to do too.
            conn.execute("DELETE FROM files WHERE logical_path = ?", ("/private/salary.txt",))
            conn.execute(
                "UPDATE files SET dat_filename = ? WHERE logical_path = ?",
                (private_dat_filename, "/public/report.txt"),
            )
            conn.commit()

        # read() must ignore the tampered column and keep reading /public/report.txt's
        # own .dat file, so its content must be unchanged.
        self.assertEqual(self.secure_fs.read("/public/report.txt"), b"public content")

    def test_swapped_row_contents_raise_corruption_not_leak(self):
        """Copying another row's crypto material must be detected, not served silently."""
        self.secure_fs.write("/public/report.txt", b"public content")
        self.secure_fs.write("/private/salary.txt", b"CONFIDENTIAL: 999999")

        kf_encrypted, kf_nonce, file_hash, file_size, dat_filename = self._row(
            "/private/salary.txt"
        )

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM files WHERE logical_path = ?", ("/private/salary.txt",))
            conn.execute(
                """
                UPDATE files
                SET kf_encrypted = ?, kf_nonce = ?, file_hash = ?, file_size = ?,
                    dat_filename = ?
                WHERE logical_path = ?
                """,
                (kf_encrypted, kf_nonce, file_hash, file_size, dat_filename, "/public/report.txt"),
            )
            conn.commit()

        # Must never silently return the private file's content under the public path.
        with self.assertRaises(FileCorruptionError):
            self.secure_fs.read("/public/report.txt")

    def test_tampered_dat_filename_is_not_trusted_on_delete(self):
        """Pointing a row's dat_filename at another file's .dat must not redirect delete()."""
        self.secure_fs.write("/public/report.txt", b"public content")
        self.secure_fs.write("/private/salary.txt", b"CONFIDENTIAL: 999999")

        private_dat_filename = self._row("/private/salary.txt")[4]
        orphaned_dat_path = self.storage_root / private_dat_filename

        with sqlite3.connect(self.db_path) as conn:
            # Same setup as the read test above: orphan the private .dat blob and
            # point the public row's dat_filename column at it.
            conn.execute("DELETE FROM files WHERE logical_path = ?", ("/private/salary.txt",))
            conn.execute(
                "UPDATE files SET dat_filename = ? WHERE logical_path = ?",
                (private_dat_filename, "/public/report.txt"),
            )
            conn.commit()

        self.secure_fs.delete("/public/report.txt")

        # delete() must have removed /public/report.txt's own .dat file, not the
        # orphaned one merely named by the tampered column.
        self.assertFalse(self.secure_fs.exists("/public/report.txt"))
        self.assertTrue(orphaned_dat_path.exists())


class TestPlaintextMarkerDowngrade(unittest.TestCase):
    """The zero-nonce "stored in plaintext" marker must not be a forgery channel.

    An attacker who can write the database and the storage directory, but does
    not know the master key, can mark a row as plaintext and supply a file key
    of their own. Nothing derived from the master key would then authenticate
    the content -- unless the keyed integrity tag is checked, which is why that
    check is mandatory whenever AEAD did not authenticate the data.
    """

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.db_path = self.test_dir / "index.db"
        self.storage_root = self.test_dir / "storage"
        self.master_key = secrets.token_bytes(32)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def _make(self, **kwargs) -> SecureFSWrapper:
        return SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            **kwargs,
        )

    def _forge(self, forged: bytes) -> None:
        """Replace the single stored file with attacker-chosen content.

        The file key is chosen by the attacker and marked as "plaintext" (zero
        nonce) so that unwrapping it never involves the master key.
        """
        chosen_kf = b"\x00" * 32
        nonce = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(chosen_kf), modes.GCM(nonce)).encryptor()
        ciphertext = encryptor.update(forged) + encryptor.finalize() + encryptor.tag

        dat_path = next(self.storage_root.glob("*.dat"))
        dat_path.write_bytes(nonce + ciphertext)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE files SET kf_encrypted = ?, kf_nonce = ?, file_size = ?",
                (chosen_kf, b"\x00" * 12, len(forged)),
            )
            conn.commit()

    def test_forgery_rejected_when_integrity_checks_are_disabled(self):
        """verify_integrity=False must not make content forgery possible."""
        fs = self._make(verify_integrity=False)
        fs.write("/config/policy.json", b'{"admin": false}')
        fs.close()

        self._forge(b'{"admin": true}')

        # An encrypted instance refuses the plaintext marker outright.
        fs = self._make(verify_integrity=False)
        with self.assertRaises(EncryptionError):
            fs.read("/config/policy.json")
        fs.close()

    def test_forgery_rejected_when_caller_skips_verification(self):
        """skip_verification=True must not make content forgery possible either."""
        fs = self._make()
        fs.write("/config/policy.json", b'{"admin": false}')
        fs.close()

        self._forge(b'{"admin": true}')

        fs = self._make()
        with self.assertRaises(EncryptionError):
            fs.read("/config/policy.json", skip_verification=True)
        fs.close()

    def test_forgery_in_development_mode_rejected_by_integrity_tag(self):
        """In development mode the plaintext marker is legitimate, so the keyed
        integrity tag is what has to catch the forgery -- even with checks off."""
        fs = self._make(encryption_enabled=False, verify_integrity=False)
        fs.write("/config/policy.json", b'{"admin": false}')
        fs.close()

        self._forge(b'{"admin": true}')

        fs = self._make(encryption_enabled=False, verify_integrity=False)
        with self.assertRaises(FileCorruptionError):
            fs.read("/config/policy.json", skip_verification=True)
        fs.close()

    def test_encrypted_instance_refuses_legacy_plaintext_entries(self):
        """Content written in development mode sits in the clear on disk, so an
        encrypted instance must refuse it rather than pass it off as protected."""
        fs = self._make(encryption_enabled=False)
        fs.write("/legacy/secret.txt", b"PASSWORD: admin123")
        fs.close()

        # The content really is readable by anyone holding the storage directory.
        dat_path = next(self.storage_root.glob("*.dat"))
        self.assertIn(b"PASSWORD: admin123", dat_path.read_bytes())

        fs = self._make()
        with self.assertRaises(EncryptionError):
            fs.read("/legacy/secret.txt")
        fs.close()

    def test_genuine_plaintext_files_remain_readable(self):
        """Legitimate unencrypted files must still read back, checks or not.

        Guards against over-correcting: files written in development mode carry
        a valid integrity tag, so forcing the check must not break them.
        """
        fs = self._make(encryption_enabled=False, verify_integrity=False)
        fs.write("/dev/notes.txt", b"plaintext content")
        self.assertEqual(fs.read("/dev/notes.txt", bypass_cache=True), b"plaintext content")
        self.assertEqual(
            fs.read("/dev/notes.txt", skip_verification=True, bypass_cache=True),
            b"plaintext content",
        )
        fs.close()


class TestDeleteOrdering(unittest.TestCase):
    """delete() must not destroy content before the metadata removal is durable."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.secure_fs = SecureFSWrapper(
            master_key=secrets.token_bytes(32),
            db_path=self.test_dir / "index.db",
            storage_root=self.test_dir / "storage",
        )

    def tearDown(self):
        self.secure_fs.close()
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_failed_commit_leaves_content_readable(self):
        """If the metadata delete can't commit, the file must survive intact.

        Unlinking before committing would leave a row claiming the file exists
        while its content is gone -- unrecoverable, and invisible to exists().
        """
        from contextlib import contextmanager

        self.secure_fs.write("/important.txt", b"important data")

        class FailingCommitConnection:
            """Delegates everything except commit(), which fails as if locked."""

            def __init__(self, real):
                self._real = real

            def __getattr__(self, name):
                return getattr(self._real, name)

            def commit(self):
                raise sqlite3.OperationalError("database is locked")

        original = self.secure_fs._get_connection

        @contextmanager
        def failing_connection():
            with original() as conn:
                yield FailingCommitConnection(conn)

        self.secure_fs._get_connection = failing_connection
        try:
            with self.assertRaises(SecureFSError):
                self.secure_fs.delete("/important.txt")
        finally:
            self.secure_fs._get_connection = original

        self.assertTrue(self.secure_fs.exists("/important.txt"))
        self.assertEqual(
            self.secure_fs.read("/important.txt", bypass_cache=True), b"important data"
        )


if __name__ == "__main__":
    unittest.main()
