import os
import secrets
import shutil
import sqlite3
import tempfile
import unittest

from securefs import SecureFSWrapper


class TestSecureFSWrapperIntegration(unittest.TestCase):
    """Integration tests for complete workflows"""

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

    def test_complete_file_lifecycle(self):
        """Test complete file lifecycle: create, read, update, delete"""
        path = "/test/lifecycle.txt"

        # Create
        self.secure_fs.write(path, b"Initial content")
        self.assertTrue(self.secure_fs.exists(path))

        # Read
        content = self.secure_fs.read(path)
        self.assertEqual(content, b"Initial content")

        # Update
        self.secure_fs.write(path, b"Updated content")
        content = self.secure_fs.read(path)
        self.assertEqual(content, b"Updated content")

        # Delete
        self.secure_fs.delete(path)
        self.assertFalse(self.secure_fs.exists(path))

    def test_multiple_files_workflow(self):
        """Test working with multiple files simultaneously"""
        files = {
            "/docs/readme.txt": b"README content",
            "/docs/license.txt": b"MIT License",
            "/src/main.py": b"print('Hello')",
            "/src/utils.py": b"def helper(): pass",
            "/data/config.json": b'{"key": "value"}',
        }

        # Write all files
        for path, content in files.items():
            self.secure_fs.write(path, content)

        # Verify all exist
        for path in files:
            self.assertTrue(self.secure_fs.exists(path))

        # Verify correct content
        for path, expected_content in files.items():
            actual_content = self.secure_fs.read(path)
            self.assertEqual(actual_content, expected_content)

        # List by directory
        docs = self.secure_fs.list_files("/docs/")
        self.assertEqual(len(docs), 2)

        src = self.secure_fs.list_files("/src/")
        self.assertEqual(len(src), 2)

        # Delete one directory
        for path in src:
            self.secure_fs.delete(path)

        # Verify deletion
        remaining = self.secure_fs.list_files()
        self.assertEqual(len(remaining), 3)

    def test_system_recovery_after_partial_failure(self):
        """Test that system can recover after partial failures"""
        # Write some files
        self.secure_fs.write("/file1.txt", b"content1")
        self.secure_fs.write("/file2.txt", b"content2")

        # Simulate a failure by manually corrupting database
        # (but keeping .dat files intact)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM files WHERE logical_path = '/file1.txt'")
            conn.commit()

        # file1 should not exist in index
        self.assertFalse(self.secure_fs.exists("/file1.txt"))

        # But file2 should still work
        self.assertTrue(self.secure_fs.exists("/file2.txt"))
        content = self.secure_fs.read("/file2.txt")
        self.assertEqual(content, b"content2")

    def test_large_scale_operations(self):
        """Test system with many files"""
        num_files = 100

        # Write many files
        for i in range(num_files):
            path = f"/batch/file{i:03d}.txt"
            content = f"Content for file {i}".encode()
            self.secure_fs.write(path, content)

        # Verify count
        all_files = self.secure_fs.list_files()
        self.assertEqual(len(all_files), num_files)

        # Verify statistics
        stats = self.secure_fs.get_statistics()
        self.assertEqual(stats["total_files"], num_files)

        # Spot check some files
        for i in [0, 50, 99]:
            path = f"/batch/file{i:03d}.txt"
            content = self.secure_fs.read(path)
            expected = f"Content for file {i}".encode()
            self.assertEqual(content, expected)

        # Delete half
        for i in range(num_files // 2):
            path = f"/batch/file{i:03d}.txt"
            self.secure_fs.delete(path)

        # Verify remaining count
        remaining = self.secure_fs.list_files()
        self.assertEqual(len(remaining), num_files // 2)
