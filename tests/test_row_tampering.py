"""Tests defending against database-row tampering.

The ``dat_filename`` column stored in the ``files`` table is a deterministic
function of (logical_path, master_key). ``read()`` and ``delete()`` must
re-derive it themselves instead of trusting the stored column, otherwise an
attacker with write access to the SQLite database (but not the master key)
could redirect a logical path to another file's ciphertext, or make delete()
remove an unrelated .dat file.
"""

import secrets
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from securefs import FileCorruptionError, SecureFSWrapper


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


if __name__ == "__main__":
    unittest.main()
