import os
import secrets
import shutil
import tempfile
import unittest
from pathlib import Path

from securefs import SecureFSWrapper


class TestSecureFSWrapperEdgeCases(unittest.TestCase):
    """Test suite for edge cases and special scenarios"""

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

    def test_special_characters_in_path(self):
        """Test paths with special characters"""
        paths = [
            "/test/file with spaces.txt",
            "/test/file-with-dashes.txt",
            "/test/file_with_underscores.txt",
            "/test/file.multiple.dots.txt",
            "/test/file@special#chars.txt",
        ]

        for path in paths:
            content = f"Content for {path}".encode()
            self.secure_fs.write(path, content)
            result = self.secure_fs.read(path)
            self.assertEqual(result, content)
            self.secure_fs.delete(path)

    def test_unicode_content(self):
        """Test writing and reading Unicode content"""
        unicode_content = "Hello 世界 🌍 Привет مرحبا".encode()
        path = "/test/unicode.txt"

        self.secure_fs.write(path, unicode_content)
        result = self.secure_fs.read(path)

        self.assertEqual(result, unicode_content)
        self.assertEqual(result.decode("utf-8"), "Hello 世界 🌍 Привет مرحبا")

    def test_unicode_in_path(self):
        """Test Unicode characters in file paths"""
        paths = ["/test/文件.txt", "/test/файл.txt", "/test/αρχείο.txt", "/test/emoji😀.txt"]

        for path in paths:
            content = b"Unicode path test"
            self.secure_fs.write(path, content)
            result = self.secure_fs.read(path)
            self.assertEqual(result, content)
            self.secure_fs.delete(path)

    def test_very_long_path(self):
        """Test handling of very long file paths"""
        # Create a very long but valid path
        long_path = "/" + "/".join(["dir" + str(i) for i in range(50)]) + "/file.txt"
        content = b"Long path content"

        self.secure_fs.write(long_path, content)
        result = self.secure_fs.read(long_path)

        self.assertEqual(result, content)

    def test_concurrent_operations_same_file(self):
        """Test updating same file multiple times"""
        path = "/test/file.txt"

        for i in range(10):
            content = f"Version {i}".encode()
            self.secure_fs.write(path, content)

        # Should have final version
        result = self.secure_fs.read(path)
        self.assertEqual(result, b"Version 9")

        # Should only have one .dat file
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        self.assertEqual(len(dat_files), 1)

    def test_deep_directory_structure(self):
        """Test paths with deep directory structure"""
        path = "/level1/level2/level3/level4/level5/file.txt"
        content = b"Deep file"

        self.secure_fs.write(path, content)
        result = self.secure_fs.read(path)

        self.assertEqual(result, content)

    def test_path_normalization(self):
        """Test that different path representations work correctly"""
        # These should be treated as different paths
        path1 = "/test/file.txt"
        path2 = "/test//file.txt"  # Double slash

        self.secure_fs.write(path1, b"content1")
        self.secure_fs.write(path2, b"content2")

        # They should be stored as separate files
        result1 = self.secure_fs.read(path1)
        result2 = self.secure_fs.read(path2)

        self.assertEqual(result1, b"content1")
        self.assertEqual(result2, b"content2")

    def test_maximum_file_size_handling(self):
        """Test handling of very large files (simulated)"""
        # Create a 10 MB file
        large_content = secrets.token_bytes(10 * 1024 * 1024)
        path = "/test/large.bin"

        self.secure_fs.write(path, large_content)
        result = self.secure_fs.read(path)

        self.assertEqual(len(result), len(large_content))
        self.assertEqual(result, large_content)

    def test_repeated_delete_operations(self):
        """Test that repeated deletes are idempotent"""
        path = "/test/file.txt"

        self.secure_fs.write(path, b"content")

        # First delete should succeed
        self.assertTrue(self.secure_fs.delete(path))

        # Subsequent deletes should return False
        self.assertFalse(self.secure_fs.delete(path))
        self.assertFalse(self.secure_fs.delete(path))
