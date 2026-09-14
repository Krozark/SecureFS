"""Tests defending against database-row tampering.

The adversary here can write the SQLite index and the storage directory, but
does not hold the master key. They must not be able to redirect a logical path
to another path's ciphertext, nor use the zero-nonce "stored in plaintext"
marker to downgrade a file out of authenticated encryption and hand us content
of their choosing.
"""

import secrets
import sqlite3
import unittest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from securefs import EncryptionError, FileCorruptionError, SecureFSError
from tests._helpers import ZERO_NONCE, SecureFSTestCase, index_row


class TestRowTampering(SecureFSTestCase):
    """A tampered index row must not be able to redirect a read.

    Nothing in the index says which file on disk holds a path's content: the
    .dat filename is re-derived from (master key, logical path) on every read
    and delete. An attacker who can write the database but not hold the master
    key therefore cannot point a path at another path's ciphertext -- the best
    they can do is supply crypto material that fails to authenticate.
    """

    def setUp(self):
        super().setUp()
        self.secure_fs = self.make_fs()

    def test_swapped_row_contents_raise_corruption_not_leak(self):
        """Copying another row's crypto material must be detected, not served silently."""
        self.secure_fs.write("/public/report.txt", b"public content")
        self.secure_fs.write("/private/salary.txt", b"CONFIDENTIAL: 999999")

        private = index_row(
            self.db_path,
            "/private/salary.txt",
            "kf_encrypted",
            "kf_nonce",
            "file_hash",
            "file_size",
        )

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE files
                SET kf_encrypted = ?, kf_nonce = ?, file_hash = ?, file_size = ?
                WHERE logical_path = ?
                """,
                (*private, "/public/report.txt"),
            )
            conn.commit()

        # Must never silently return the private file's content under the public path.
        with self.assertRaises(FileCorruptionError):
            self.secure_fs.read("/public/report.txt", bypass_cache=True)

    def test_read_locates_content_by_path_alone(self):
        """Renaming a .dat file breaks that path, and only that path.

        Proves the storage filename really is derived from the logical path
        rather than looked up: a file under any other name is invisible.
        """
        self.secure_fs.write("/kept.txt", b"kept")
        self.secure_fs.write("/moved.txt", b"moved")

        dat = self.storage_root / self.secure_fs._generate_dat_filename("/moved.txt")
        dat.rename(self.storage_root / "renamed.dat")

        with self.assertRaises(FileNotFoundError):
            self.secure_fs.read("/moved.txt", bypass_cache=True)
        self.assertEqual(self.secure_fs.read("/kept.txt", bypass_cache=True), b"kept")


class TestPlaintextMarkerDowngrade(SecureFSTestCase):
    """The zero-nonce "stored in plaintext" marker must not be a forgery channel.

    An attacker who can write the database and the storage directory, but does
    not know the master key, can mark a row as plaintext and supply a file key
    of their own. Nothing derived from the master key would then authenticate
    the content -- unless the keyed integrity tag is checked, which is why that
    check is mandatory whenever AEAD did not authenticate the data.
    """

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
                (chosen_kf, ZERO_NONCE, len(forged)),
            )
            conn.commit()

    def test_forgery_rejected_when_integrity_checks_are_disabled(self):
        """verify_integrity=False must not make content forgery possible."""
        fs = self.make_fs(verify_integrity=False)
        fs.write("/config/policy.json", b'{"admin": false}')
        fs.close()

        self._forge(b'{"admin": true}')

        # An encrypted instance refuses the plaintext marker outright.
        fs = self.make_fs(verify_integrity=False)
        with self.assertRaises(EncryptionError):
            fs.read("/config/policy.json")
        fs.close()

    def test_forgery_rejected_when_caller_skips_verification(self):
        """skip_verification=True must not make content forgery possible either."""
        fs = self.make_fs()
        fs.write("/config/policy.json", b'{"admin": false}')
        fs.close()

        self._forge(b'{"admin": true}')

        fs = self.make_fs()
        with self.assertRaises(EncryptionError):
            fs.read("/config/policy.json", skip_verification=True)
        fs.close()

    def test_forgery_in_development_mode_rejected_by_integrity_tag(self):
        """In development mode the plaintext marker is legitimate, so the keyed
        integrity tag is what has to catch the forgery -- even with checks off."""
        fs = self.make_fs(encryption_enabled=False, verify_integrity=False)
        fs.write("/config/policy.json", b'{"admin": false}')
        fs.close()

        self._forge(b'{"admin": true}')

        fs = self.make_fs(encryption_enabled=False, verify_integrity=False)
        with self.assertRaises(FileCorruptionError):
            fs.read("/config/policy.json", skip_verification=True)
        fs.close()

    def test_encrypted_instance_refuses_legacy_plaintext_entries(self):
        """Content written in development mode sits in the clear on disk, so an
        encrypted instance must refuse it rather than pass it off as protected."""
        fs = self.make_fs(encryption_enabled=False)
        fs.write("/legacy/secret.txt", b"PASSWORD: admin123")
        fs.close()

        # The content really is readable by anyone holding the storage directory.
        dat_path = next(self.storage_root.glob("*.dat"))
        self.assertIn(b"PASSWORD: admin123", dat_path.read_bytes())

        fs = self.make_fs()
        with self.assertRaises(EncryptionError):
            fs.read("/legacy/secret.txt")
        fs.close()

    def test_genuine_plaintext_files_remain_readable(self):
        """Legitimate unencrypted files must still read back, checks or not.

        Guards against over-correcting: files written in development mode carry
        a valid integrity tag, so forcing the check must not break them.
        """
        fs = self.make_fs(encryption_enabled=False, verify_integrity=False)
        fs.write("/dev/notes.txt", b"plaintext content")
        self.assertEqual(fs.read("/dev/notes.txt", bypass_cache=True), b"plaintext content")
        self.assertEqual(
            fs.read("/dev/notes.txt", skip_verification=True, bypass_cache=True),
            b"plaintext content",
        )
        fs.close()


class TestDeleteOrdering(SecureFSTestCase):
    """delete() must not destroy content before the metadata removal is durable."""

    def setUp(self):
        super().setUp()
        self.secure_fs = self.make_fs()

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
