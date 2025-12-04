import contextlib
import os
import secrets
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

from securefs import SecureFSWrapper


class TestSecureFSWrapperThreadSafety(unittest.TestCase):
    """Test suite for thread safety"""

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
        if Path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_concurrent_writes_to_different_files(self):
        """Test concurrent writes to different files"""

        def write_file(file_num):
            path = f"/test/file{file_num}.txt"
            content = f"Content {file_num}".encode()
            self.secure_fs.write(path, content)

        threads = []
        for i in range(10):
            t = threading.Thread(target=write_file, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # All files should exist
        files = self.secure_fs.list_files()
        self.assertEqual(len(files), 10)

    def test_concurrent_reads(self):
        """Test concurrent reads of same file"""
        path = "/test/file.txt"
        content = b"Shared content"

        self.secure_fs.write(path, content)

        results = []

        def read_file():
            result = self.secure_fs.read(path)
            results.append(result)

        threads = []
        for _i in range(10):
            t = threading.Thread(target=read_file)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # All reads should succeed
        self.assertEqual(len(results), 10)
        self.assertTrue(all(r == content for r in results))

    def test_concurrent_write_and_read(self):
        """Test concurrent writes and reads"""
        path = "/test/file.txt"

        def writer():
            for i in range(5):
                content = f"Version {i}".encode()
                self.secure_fs.write(path, content)
                time.sleep(0.01)

        def reader():
            for _i in range(5):
                with contextlib.suppress(FileNotFoundError):
                    self.secure_fs.read(path)
                time.sleep(0.01)

        write_thread = threading.Thread(target=writer)
        read_thread = threading.Thread(target=reader)

        write_thread.start()
        read_thread.start()

        write_thread.join()
        read_thread.join()

        # Should complete without errors
        self.assertTrue(self.secure_fs.exists(path))

