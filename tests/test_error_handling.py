import os
import secrets
import shutil
import sqlite3
import tempfile
import unittest

from securefs import EncryptionError, SecureFSError, SecureFSWrapper


class TestSecureFSWrapperErrorHandling(unittest.TestCase):
    """Test suite for error handling"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)

        self.secure_fs = SecureFSWrapper(
            master_key=self.master_key, db_path=self.db_path, storage_root=self.storage_root
        )

    def tearDown(self):
        """Clean up after tests"""
        self.secure_fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_read_with_wrong_master_key_raises_encryption_error(self):
        """Test that wrong master key raises EncryptionError"""
        path = "/test/file.txt"
        self.secure_fs.write(path, b"secret")

        wrong_key = secrets.token_bytes(32)
        wrong_fs = SecureFSWrapper(
            master_key=wrong_key, db_path=self.db_path, storage_root=self.storage_root
        )

        with self.assertRaises(EncryptionError):
            wrong_fs.read(path)

        wrong_fs.close()

    def test_corrupted_database_handling(self):
        """Test behavior with corrupted database"""
        self.secure_fs.write("/file1.txt", b"content1")

        # Corrupt the database by writing invalid data
        with open(self.db_path, "ab") as f:
            f.write(b"CORRUPTED DATA" * 100)

        # Creating a new instance should handle gracefully or fail predictably
        try:
            new_fs = SecureFSWrapper(
                master_key=self.master_key, db_path=self.db_path, storage_root=self.storage_root
            )
            new_fs.close()
        except Exception as e:
            # Should raise a clear error, not crash
            self.assertIsInstance(e, (sqlite3.DatabaseError, SecureFSError))

    def test_missing_storage_directory(self):
        """Test behavior when storage directory is deleted"""
        path = "/test/file.txt"
        self.secure_fs.write(path, b"content")

        # Delete storage directory
        shutil.rmtree(self.storage_root)

        # Read should fail with FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            self.secure_fs.read(path)

    def test_permission_errors_handling(self):
        """Test handling of permission errors (Unix-like systems)"""
        if os.name == "nt":
            self.skipTest("Permission test not applicable on Windows")

        path = "/test/file.txt"
        self.secure_fs.write(path, b"content")

        # Make storage directory read-only
        os.chmod(self.storage_root, 0o444)

        try:
            # Write should fail
            with self.assertRaises(Exception):
                self.secure_fs.write("/test/new.txt", b"new content")
        finally:
            # Restore permissions for cleanup
            os.chmod(self.storage_root, 0o755)

    def test_close_method_cleanup(self):
        """Test that close method properly cleans up"""
        self.secure_fs.write("/file1.txt", b"content1")

        # Get stats before close
        stats = self.secure_fs.get_statistics()
        self.assertIsNotNone(stats)

        # Close
        self.secure_fs.close()

        # Operations after close should still work (new connection each time)
        # but cache should be cleared
        self.secure_fs.write("/file2.txt", b"content2")
        self.assertTrue(self.secure_fs.exists("/file2.txt"))
