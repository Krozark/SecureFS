"""Tests for keyed (master-key-derived) storage identifiers and integrity tags.

These verify that the metadata database and the storage directory do not leak a
verifiable fingerprint of either the plaintext content or the logical paths to
someone who does not hold the master key.
"""

import hashlib
import secrets
import shutil
import tempfile
import unittest
from pathlib import Path

from securefs import SecureFSWrapper


class TestKeyedMac(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.master_key = secrets.token_bytes(32)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def _make(self, key, subdir):
        root = self.test_dir / subdir
        return SecureFSWrapper(
            master_key=key,
            db_path=root / "index.db",
            storage_root=root / "storage",
        )

    def test_integrity_tag_is_not_plain_sha256(self):
        """The stored integrity tag must not equal the bare SHA-256 of the content."""
        fs = self._make(self.master_key, "a")
        content = b"top secret content"
        fs.write("/f.txt", content)

        info = fs.get_info("/f.txt")
        self.assertNotEqual(info["hash"], hashlib.sha256(content).hexdigest())

    def test_integrity_tag_depends_on_master_key(self):
        """Same content + different keys must yield different integrity tags."""
        content = b"identical content"
        fs1 = self._make(self.master_key, "k1")
        fs2 = self._make(secrets.token_bytes(32), "k2")

        fs1.write("/f.txt", content)
        fs2.write("/f.txt", content)

        self.assertNotEqual(fs1.get_info("/f.txt")["hash"], fs2.get_info("/f.txt")["hash"])

    def test_dat_filename_depends_on_master_key(self):
        """The same path under different keys must map to different .dat filenames."""
        fs1 = self._make(self.master_key, "p1")
        fs2 = self._make(secrets.token_bytes(32), "p2")

        fs1.write("/same/path.txt", b"x")
        fs2.write("/same/path.txt", b"x")

        name1 = next(Path(fs1.storage_root).glob("*.dat")).name
        name2 = next(Path(fs2.storage_root).glob("*.dat")).name
        self.assertNotEqual(name1, name2)

    def test_dat_filename_not_plain_path_hash(self):
        """The .dat filename must not be the bare SHA-256 of the logical path."""
        fs = self._make(self.master_key, "p3")
        path = "/secret/location.txt"
        fs.write(path, b"x")

        name = next(Path(fs.storage_root).glob("*.dat")).stem
        self.assertNotEqual(name, hashlib.sha256(path.encode()).hexdigest())

    def test_roundtrip_and_integrity_still_work(self):
        """Read-back and corruption detection must still work with keyed tags."""
        fs = self._make(self.master_key, "rt")
        fs.write("/f.txt", b"hello world")
        self.assertEqual(fs.read("/f.txt"), b"hello world")

        # Corrupt the ciphertext on disk -> integrity verification must fail.
        dat = next(Path(fs.storage_root).glob("*.dat"))
        data = bytearray(dat.read_bytes())
        data[-1] ^= 0xFF
        dat.write_bytes(data)

        from securefs import SecureFSError

        with self.assertRaises(SecureFSError):
            fs.read("/f.txt", bypass_cache=True)


if __name__ == "__main__":
    unittest.main()
