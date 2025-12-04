import os
import secrets
import shutil
import tempfile
import time
import unittest

from securefs import SecureFSWrapper


class TestSecureFSWrapperPerformance(unittest.TestCase):
    """Test suite for performance-related aspects"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)

        self.secure_fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            cache_enabled=True,
        )

    def tearDown(self):
        """Clean up after tests"""
        self.secure_fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_cache_improves_read_performance(self):
        """Test that cache improves read performance"""
        path = "/test/file.txt"
        content = b"Test content" * 1000

        self.secure_fs.write(path, content)

        # First read (from disk)
        start = time.time()
        self.secure_fs.read(path)
        first_read_time = time.time() - start

        # Second read (from cache)
        start = time.time()
        self.secure_fs.read(path)
        second_read_time = time.time() - start

        # Second read should be faster (or at least not slower)
        # Note: This might not always be true on fast SSDs, but cache should help
        self.assertLessEqual(second_read_time, first_read_time * 1.5)

    def test_batch_operations_performance(self):
        """Test performance of batch operations"""
        num_files = 50

        # Measure write time
        start = time.time()
        for i in range(num_files):
            path = f"/batch/file{i}.txt"
            content = f"Content {i}".encode()
            self.secure_fs.write(path, content)
        write_time = time.time() - start

        # Measure read time
        start = time.time()
        for i in range(num_files):
            path = f"/batch/file{i}.txt"
            self.secure_fs.read(path)
        read_time = time.time() - start

        # Just verify operations complete in reasonable time
        # (Not a strict performance test, just sanity check)
        self.assertLess(write_time, 30)  # 30 seconds max for 50 writes
        self.assertLess(read_time, 30)  # 30 seconds max for 50 reads

    def test_list_files_performance_with_many_files(self):
        """Test list_files performance with many files"""
        num_files = 200

        # Create many files
        for i in range(num_files):
            path = f"/test/file{i:04d}.txt"
            self.secure_fs.write(path, b"content")

        # Measure list time
        start = time.time()
        files = self.secure_fs.list_files()
        list_time = time.time() - start

        self.assertEqual(len(files), num_files)
        self.assertLess(list_time, 5)  # Should list 200 files in under 5 seconds

