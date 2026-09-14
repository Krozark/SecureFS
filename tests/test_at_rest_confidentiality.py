"""Confidentiality of stored content against an attacker holding the storage.

The threat model these tests pin down: someone copies the whole storage
directory and the metadata database -- everything SecureFS persists -- but does
not know the master key. They must not be able to recover any file content.
"""

import sqlite3
import unittest

from securefs import EncryptionError, SecureFSError, SecureFSWrapper
from securefs.utils import generate_master_key
from tests._helpers import ZERO_NONCE, SecureFSTestCase, index_row


SECRET = b"PASSWORD=hunter2; BALANCE=999999"


class TestAtRestConfidentiality(SecureFSTestCase):
    def setUp(self):
        super().setUp()
        self.secure_fs = self.make_fs()
        self.secure_fs.write("/vault/secret.txt", SECRET)

    def _everything_on_disk(self) -> bytes:
        """Every byte SecureFS persisted: the database plus the storage directory."""
        blobs = [p.read_bytes() for p in self.test_dir.rglob("*") if p.is_file()]
        return b"".join(blobs)

    def test_content_never_hits_the_disk_in_clear(self):
        """No persisted byte anywhere may contain the plaintext."""
        self.assertNotIn(SECRET, self._everything_on_disk())

    def test_fragments_of_content_never_hit_the_disk_in_clear(self):
        """Not even a recognizable fragment of the plaintext may appear."""
        on_disk = self._everything_on_disk()
        for fragment in (b"hunter2", b"PASSWORD", b"999999"):
            self.assertNotIn(fragment, on_disk)

    def test_wrong_master_key_cannot_decrypt(self):
        """Holding the database and the files, but the wrong key, yields nothing."""
        attacker_fs = SecureFSWrapper(
            master_key=generate_master_key(),
            db_path=self.db_path,
            storage_root=self.storage_root,
        )
        # The attacker can't even resolve the path to its storage file, because
        # the .dat name is itself derived from the master key.
        with self.assertRaises((SecureFSError, FileNotFoundError)):
            attacker_fs.read("/vault/secret.txt")
        attacker_fs.close()

    def test_stored_material_alone_does_not_yield_the_file_key(self):
        """Everything the database holds about a file still can't unwrap its key.

        kf_encrypted is only meaningful to whoever can derive the wrapping
        subkey from the master key, so an attacker reading the row directly
        gets ciphertext, not the file key.
        """
        kf_encrypted, kf_nonce = index_row(
            self.db_path, "/vault/secret.txt", "kf_encrypted", "kf_nonce"
        )

        # The wrapped key is not the key, and not the content.
        self.assertNotIn(SECRET, kf_encrypted)
        self.assertNotEqual(kf_nonce, ZERO_NONCE)  # never marked as plaintext

        # Feeding the stored material back through a wrong-key instance fails.
        attacker_fs = SecureFSWrapper(
            master_key=generate_master_key(),
            db_path=self.db_path,
            storage_root=self.storage_root,
        )
        with self.assertRaises(SecureFSError):
            attacker_fs._open(attacker_fs._key_wrap, kf_encrypted, kf_nonce, description="file key")
        attacker_fs.close()

    def test_encrypted_store_cannot_be_downgraded_to_plaintext(self):
        """Marking a row as plaintext must not turn the store readable."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE files SET kf_nonce = ?", (ZERO_NONCE,))
            conn.commit()

        with self.assertRaises(EncryptionError):
            self.secure_fs.read("/vault/secret.txt", bypass_cache=True)

    def test_correct_key_still_reads(self):
        """Sanity check: the guarantee isn't trivially met by breaking reads."""
        self.assertEqual(self.secure_fs.read("/vault/secret.txt", bypass_cache=True), SECRET)


if __name__ == "__main__":
    unittest.main()
