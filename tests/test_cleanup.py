"""Tests for cleanup_orphaned_files()."""

import unittest

from tests._helpers import SecureFSTestCase


class TestCleanupOrphanedFiles(SecureFSTestCase):
    def setUp(self):
        super().setUp()
        self.secure_fs = self.make_fs()

    def test_removes_tmp_and_bak_leftovers(self):
        """Files left behind by an interrupted write must be removed."""
        self.secure_fs.write("/kept.txt", b"content")
        (self.storage_root / "abc123.tmp").write_bytes(b"half-written")
        (self.storage_root / "abc123.bak").write_bytes(b"previous version")

        removed = self.secure_fs.cleanup_orphaned_files()

        self.assertEqual(removed["tmp"], 1)
        self.assertEqual(removed["bak"], 1)
        self.assertEqual(list(self.storage_root.glob("*.tmp")), [])
        self.assertEqual(list(self.storage_root.glob("*.bak")), [])

    def test_keeps_live_data_files(self):
        """Cleanup must never touch a .dat file a live entry points to."""
        self.secure_fs.write("/kept.txt", b"content")

        removed = self.secure_fs.cleanup_orphaned_files(include_orphaned_data=True)

        self.assertEqual(removed["dat"], 0)
        self.assertEqual(self.secure_fs.read("/kept.txt", bypass_cache=True), b"content")

    def test_orphaned_dat_removed_only_when_requested(self):
        """Unreferenced .dat files are dead ciphertext, but only removed on demand."""
        self.secure_fs.write("/kept.txt", b"content")
        orphan = self.storage_root / ("0" * 64 + ".dat")
        orphan.write_bytes(b"dead ciphertext nobody can decrypt")

        # Default: left alone, so a wrong db_path can't wipe live data.
        self.assertEqual(self.secure_fs.cleanup_orphaned_files()["dat"], 0)
        self.assertTrue(orphan.exists())

        self.assertEqual(
            self.secure_fs.cleanup_orphaned_files(include_orphaned_data=True)["dat"], 1
        )
        self.assertFalse(orphan.exists())
        self.assertEqual(self.secure_fs.read("/kept.txt", bypass_cache=True), b"content")

    def test_empty_storage_is_a_no_op(self):
        """Cleaning a store with nothing to remove reports zero removals."""
        self.assertEqual(
            self.secure_fs.cleanup_orphaned_files(include_orphaned_data=True),
            {"tmp": 0, "bak": 0, "dat": 0},
        )


if __name__ == "__main__":
    unittest.main()
