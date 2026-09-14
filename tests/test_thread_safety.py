import contextlib
import threading
import time

from tests._helpers import SecureFSTestCase


class TestSecureFSWrapperThreadSafety(SecureFSTestCase):
    """Test suite for thread safety"""

    def setUp(self):
        super().setUp()
        self.secure_fs = self.make_fs()

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
