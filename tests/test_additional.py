"""Additional tests for SecureFS covering bug fixes, cross-platform behaviour,
and areas not covered by the original test suite."""

import os
import secrets
import shutil
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from securefs import SecureFSWrapper


class TestCreatedAtPreservation(unittest.TestCase):
    """Verify that created_at is preserved when a file is overwritten."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)
        self.fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
        )

    def tearDown(self):
        self.fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_created_at_preserved_on_overwrite(self):
        """Overwriting a file must not change its created_at timestamp."""
        path = "/test/file.txt"
        self.fs.write(path, b"version 1")

        info1 = self.fs.get_info(path)
        created_at_original = info1["created_at"]

        # Overwrite the same path
        self.fs.write(path, b"version 2")

        info2 = self.fs.get_info(path)
        self.assertEqual(info2["created_at"], created_at_original)
        # modified_at should be updated (or at least not earlier)
        self.assertGreaterEqual(info2["modified_at"], info1["modified_at"])

    def test_content_updated_after_overwrite(self):
        """Overwritten file should return the new content."""
        path = "/test/file.txt"
        self.fs.write(path, b"old")
        self.fs.write(path, b"new")
        self.assertEqual(self.fs.read(path), b"new")


class TestDeleteAtomicity(unittest.TestCase):
    """Tests for the delete ordering fix (file removal before DB commit)."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)
        self.fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
        )

    def tearDown(self):
        self.fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_delete_removes_dat_and_db_entry(self):
        """After delete, both the .dat file and the DB entry should be gone."""
        path = "/file.txt"
        self.fs.write(path, b"content")

        dat_files_before = list(Path(self.storage_root).glob("*.dat"))
        self.assertEqual(len(dat_files_before), 1)

        self.fs.delete(path)

        # .dat file should be gone
        dat_files_after = list(Path(self.storage_root).glob("*.dat"))
        self.assertEqual(len(dat_files_after), 0)

        # DB entry should be gone
        self.assertFalse(self.fs.exists(path))

    def test_delete_with_already_missing_dat_file(self):
        """Delete should succeed even if .dat file was already removed externally."""
        path = "/file.txt"
        self.fs.write(path, b"content")

        # Manually remove the .dat file
        for f in Path(self.storage_root).glob("*.dat"):
            f.unlink()

        # delete should still succeed and clean up the DB entry
        result = self.fs.delete(path)
        self.assertTrue(result)
        self.assertFalse(self.fs.exists(path))


class TestCacheThreadSafety(unittest.TestCase):
    """Verify that cache operations are thread-safe."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)
        self.fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            cache_enabled=True,
        )

    def tearDown(self):
        self.fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_concurrent_read_and_clear_cache(self):
        """Reading and clearing cache concurrently should not raise."""
        path = "/file.txt"
        content = b"test content"
        self.fs.write(path, content)

        errors = []

        def reader():
            for _ in range(20):
                try:
                    result = self.fs.read(path)
                    assert result == content
                except Exception as e:
                    errors.append(e)

        def clearer():
            for _ in range(20):
                try:
                    self.fs.clear_cache()
                except Exception as e:
                    errors.append(e)

        t1 = threading.Thread(target=reader)
        t2 = threading.Thread(target=clearer)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(errors, [])

    def test_concurrent_writes_with_cache(self):
        """Concurrent writes with cache enabled should not corrupt data."""
        errors = []

        def writer(i):
            try:
                path = f"/file{i}.txt"
                content = f"content-{i}".encode()
                self.fs.write(path, content)
                result = self.fs.read(path)
                assert result == content
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])


class TestCrossplatformPaths(unittest.TestCase):
    """Ensure that the file system handles cross-platform path scenarios."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)
        self.fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
        )

    def tearDown(self):
        self.fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_forward_slashes_in_logical_path(self):
        """Logical paths with forward slashes should work on all platforms."""
        path = "/docs/sub/file.txt"
        self.fs.write(path, b"data")
        self.assertEqual(self.fs.read(path), b"data")

    def test_dot_in_path(self):
        """Paths with dots should work fine."""
        path = "/some.dir/file.v2.txt"
        self.fs.write(path, b"dotted")
        self.assertEqual(self.fs.read(path), b"dotted")

    def test_storage_root_as_pathlib_compatible(self):
        """storage_root should work whether passed as str or Path-coercible."""
        fs2 = SecureFSWrapper(
            master_key=self.master_key,
            db_path=os.path.join(self.test_dir, "test2.db"),
            storage_root=str(Path(self.test_dir) / "storage2"),
        )
        fs2.write("/f.txt", b"ok")
        self.assertEqual(fs2.read("/f.txt"), b"ok")
        fs2.close()

    def test_dat_files_stored_flat(self):
        """All .dat files should be stored flat in storage_root, regardless of logical path depth."""
        self.fs.write("/a/b/c/d/e/f.txt", b"deep")
        self.fs.write("/x.txt", b"shallow")

        dat_files = list(Path(self.storage_root).glob("*.dat"))
        self.assertEqual(len(dat_files), 2)
        # All in the same directory
        for f in dat_files:
            self.assertEqual(f.parent, Path(self.storage_root))


class TestCloseAndReopen(unittest.TestCase):
    """Test close/reopen semantics."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_data_persists_after_close_and_reopen(self):
        """Data written before close() should be readable after re-instantiation."""
        fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
        )
        fs.write("/persistent.txt", b"survive close")
        fs.close()

        fs2 = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
        )
        self.assertEqual(fs2.read("/persistent.txt"), b"survive close")
        fs2.close()

    def test_close_clears_cache(self):
        """close() should clear the in-memory cache."""
        fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            cache_enabled=True,
        )
        fs.write("/cached.txt", b"data")
        self.assertTrue(fs.is_cached("/cached.txt"))

        fs.close()
        self.assertFalse(fs.is_cached("/cached.txt"))
        self.assertEqual(fs.get_cache_size(), 0)

    def test_operations_work_after_close(self):
        """Because each operation creates a new connection, operations should work after close()."""
        fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
        )
        fs.write("/before.txt", b"before")
        fs.close()

        # Should still be usable (connections are per-operation)
        fs.write("/after.txt", b"after")
        self.assertTrue(fs.exists("/after.txt"))
        self.assertEqual(fs.read("/after.txt"), b"after")
        fs.close()


class TestEncryptionEdgeCases(unittest.TestCase):
    """Edge cases in encryption/decryption."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)
        self.fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
        )

    def tearDown(self):
        self.fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_single_byte_content(self):
        """A single byte should encrypt and decrypt correctly."""
        self.fs.write("/one.bin", b"\x42")
        self.assertEqual(self.fs.read("/one.bin"), b"\x42")

    def test_all_zero_bytes_content(self):
        """Content that is all zero bytes should not be confused with plaintext nonce."""
        content = b"\x00" * 100
        self.fs.write("/zeros.bin", content)
        self.assertEqual(self.fs.read("/zeros.bin"), content)

    def test_exact_block_size_content(self):
        """Content exactly at AES block boundary (16 bytes) should work."""
        content = b"A" * 16
        self.fs.write("/block.bin", content)
        self.assertEqual(self.fs.read("/block.bin"), content)

    def test_each_write_uses_unique_file_key(self):
        """Each write should generate a new file key, even for the same path."""
        path = "/rotating.txt"
        self.fs.write(path, b"version 1")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT kf_encrypted FROM files WHERE logical_path = ?", (path,))
            kf1 = cursor.fetchone()[0]

        self.fs.write(path, b"version 2")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT kf_encrypted FROM files WHERE logical_path = ?", (path,))
            kf2 = cursor.fetchone()[0]

        self.assertNotEqual(kf1, kf2)


class TestDatabaseIntegrity(unittest.TestCase):
    """Tests for database schema and metadata integrity."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)
        self.fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
        )

    def tearDown(self):
        self.fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_schema_version_stored(self):
        """system_metadata should contain the schema version."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM system_metadata WHERE key = 'schema_version'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], "2.0")

    def test_wal_mode_enabled(self):
        """Database should use WAL journal mode for better concurrency."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode")
            mode = cursor.fetchone()[0]
            self.assertEqual(mode.lower(), "wal")

    def test_dat_filename_unique_constraint(self):
        """dat_filename column should have a UNIQUE constraint."""
        self.fs.write("/file1.txt", b"content1")

        # Verify that the UNIQUE constraint exists by checking table info
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sql FROM sqlite_master WHERE name = 'files'")
            create_sql = cursor.fetchone()[0]
            self.assertIn("UNIQUE", create_sql)

    def test_indexes_exist(self):
        """Performance indexes should be created."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
            )
            indexes = {row[0] for row in cursor.fetchall()}
            self.assertIn("idx_files_hash", indexes)
            self.assertIn("idx_files_modified", indexes)

    def test_file_size_stored_accurately(self):
        """file_size in DB should match the actual plaintext size."""
        content = b"x" * 12345
        self.fs.write("/sized.bin", content)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_size FROM files WHERE logical_path = '/sized.bin'")
            stored_size = cursor.fetchone()[0]
            self.assertEqual(stored_size, 12345)


class TestInitValidation(unittest.TestCase):
    """Tests for constructor validation and edge cases."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_empty_master_key(self):
        """Empty master key should raise ValueError."""
        with self.assertRaises(ValueError):
            SecureFSWrapper(
                master_key=b"",
                db_path=os.path.join(self.test_dir, "db.db"),
                storage_root=os.path.join(self.test_dir, "storage"),
            )

    def test_16_byte_key_rejected(self):
        """A 16-byte key (AES-128) should be rejected."""
        with self.assertRaises(ValueError):
            SecureFSWrapper(
                master_key=b"\x00" * 16,
                db_path=os.path.join(self.test_dir, "db.db"),
                storage_root=os.path.join(self.test_dir, "storage"),
            )

    def test_storage_root_created_recursively(self):
        """Nested storage root directories should be created automatically."""
        deep_root = os.path.join(self.test_dir, "a", "b", "c", "storage")
        fs = SecureFSWrapper(
            master_key=secrets.token_bytes(32),
            db_path=os.path.join(self.test_dir, "db.db"),
            storage_root=deep_root,
        )
        self.assertTrue(Path(deep_root).is_dir())
        fs.close()

    def test_reinitialization_is_idempotent(self):
        """Creating multiple instances on the same DB should not corrupt data."""
        db_path = os.path.join(self.test_dir, "db.db")
        storage_root = os.path.join(self.test_dir, "storage")
        key = secrets.token_bytes(32)

        fs1 = SecureFSWrapper(master_key=key, db_path=db_path, storage_root=storage_root)
        fs1.write("/file.txt", b"data")
        fs1.close()

        fs2 = SecureFSWrapper(master_key=key, db_path=db_path, storage_root=storage_root)
        self.assertEqual(fs2.read("/file.txt"), b"data")

        # Re-init should not destroy existing data
        fs3 = SecureFSWrapper(master_key=key, db_path=db_path, storage_root=storage_root)
        self.assertEqual(fs3.read("/file.txt"), b"data")
        fs2.close()
        fs3.close()


class TestListFilesEdgeCases(unittest.TestCase):
    """Edge cases for list_files."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)
        self.fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
        )

    def tearDown(self):
        self.fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_prefix_with_no_matches(self):
        """list_files with a non-matching prefix should return empty list."""
        self.fs.write("/docs/file.txt", b"data")
        result = self.fs.list_files("/images/")
        self.assertEqual(result, [])

    def test_prefix_partial_match(self):
        """Prefix should match using LIKE 'prefix%', not substring."""
        self.fs.write("/abcdef.txt", b"data")
        self.fs.write("/abc.txt", b"data")
        self.fs.write("/ab.txt", b"data")

        result = self.fs.list_files("/abc")
        self.assertEqual(len(result), 2)  # /abc.txt and /abcdef.txt

    def test_empty_prefix_returns_all(self):
        """Empty prefix should return all files."""
        self.fs.write("/a.txt", b"1")
        self.fs.write("/b.txt", b"2")
        self.assertEqual(len(self.fs.list_files("")), 2)
        self.assertEqual(len(self.fs.list_files()), 2)


class TestVerifyAllFiles(unittest.TestCase):
    """Tests for verify_all_files method."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)
        self.fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
        )

    def tearDown(self):
        self.fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_empty_system_verification(self):
        """Verifying an empty system should return empty dict."""
        results = self.fs.verify_all_files()
        self.assertEqual(results, {})

    def test_all_files_pass_verification(self):
        """All freshly written files should pass verification."""
        for i in range(5):
            self.fs.write(f"/file{i}.txt", f"content{i}".encode())

        results = self.fs.verify_all_files()
        self.assertEqual(len(results), 5)
        self.assertTrue(all(results.values()))

    def test_missing_dat_file_detected(self):
        """verify_all_files should detect when a .dat file is missing."""
        self.fs.write("/file1.txt", b"content1")
        self.fs.write("/file2.txt", b"content2")

        # Remove one .dat file
        dat_files = sorted(Path(self.storage_root).glob("*.dat"))
        dat_files[0].unlink()

        results = self.fs.verify_all_files()
        self.assertIn(False, results.values())
