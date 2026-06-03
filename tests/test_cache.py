import secrets
import shutil
import tempfile
import unittest
from pathlib import Path

from securefs import SecureFSWrapper


class TestSecureFSWrapperCache(unittest.TestCase):
    """Test suite for caching functionality"""

    def setUp(self):
        """Set up test fixtures with cache enabled"""
        self.test_dir = Path(tempfile.mkdtemp())
        self.db_path = self.test_dir / "test_index.db"
        self.storage_root = self.test_dir / "test_storage"
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
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_cache_stores_content_after_write(self):
        """Test that cache stores content after write"""
        path = "/test/file.txt"
        content = b"Test content"

        self.secure_fs.write(path, content)

        stats = self.secure_fs.get_statistics()
        self.assertTrue(stats["cache_enabled"])
        self.assertEqual(stats["cache_entries"], 1)

    def test_cache_serves_content_on_read(self):
        """Test that cache serves content on subsequent reads"""
        path = "/test/file.txt"
        content = b"Test content"

        self.secure_fs.write(path, content)

        # Delete the .dat file to prove read comes from cache
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        dat_files[0].unlink()

        # Should still work because of cache
        result = self.secure_fs.read(path)
        self.assertEqual(result, content)

    def test_cache_cleared_on_delete(self):
        """Test that cache is cleared when file is deleted"""
        path = "/test/file.txt"
        content = b"Test content"

        self.secure_fs.write(path, content)
        self.assertEqual(self.secure_fs.get_statistics()["cache_entries"], 1)

        self.secure_fs.delete(path)
        self.assertEqual(self.secure_fs.get_statistics()["cache_entries"], 0)

    def test_clear_cache_method(self):
        """Test clear_cache method"""
        self.secure_fs.write("/file1.txt", b"content1")
        self.secure_fs.write("/file2.txt", b"content2")

        self.assertEqual(self.secure_fs.get_statistics()["cache_entries"], 2)

        self.secure_fs.clear_cache()

        self.assertEqual(self.secure_fs.get_statistics()["cache_entries"], 0)

    def test_clear_cache_specific_file(self):
        """Test clearing specific file from cache"""
        self.secure_fs.write("/file1.txt", b"content1")
        self.secure_fs.write("/file2.txt", b"content2")
        self.secure_fs.write("/file3.txt", b"content3")

        # Verify all in cache
        self.assertEqual(self.secure_fs.get_statistics()["cache_entries"], 3)

        # Remove one file from cache
        self.secure_fs.clear_cache("/file2.txt")

        # Should have 2 files in cache now
        self.assertEqual(self.secure_fs.get_statistics()["cache_entries"], 2)

        # Verify the right files are still cached
        self.assertTrue(self.secure_fs.is_cached("/file1.txt"))
        self.assertFalse(self.secure_fs.is_cached("/file2.txt"))
        self.assertTrue(self.secure_fs.is_cached("/file3.txt"))

    def test_is_cached_method(self):
        """Test is_cached method"""
        path = "/file.txt"

        # Not cached initially
        self.assertFalse(self.secure_fs.is_cached(path))

        # Write file (should be cached)
        self.secure_fs.write(path, b"content")
        self.assertTrue(self.secure_fs.is_cached(path))

        # Clear cache
        self.secure_fs.clear_cache(path)
        self.assertFalse(self.secure_fs.is_cached(path))

    def test_get_cache_size(self):
        """Test get_cache_size method"""
        # Empty cache
        self.assertEqual(self.secure_fs.get_cache_size(), 0)

        # Add files
        self.secure_fs.write("/file1.txt", b"12345")  # 5 bytes
        self.secure_fs.write("/file2.txt", b"1234567890")  # 10 bytes

        # Total should be 15 bytes
        self.assertEqual(self.secure_fs.get_cache_size(), 15)

        # Remove one file from cache
        self.secure_fs.clear_cache("/file1.txt")
        self.assertEqual(self.secure_fs.get_cache_size(), 10)

    def test_get_cached_paths(self):
        """Test get_cached_paths method"""
        # Empty initially
        self.assertEqual(self.secure_fs.get_cached_paths(), [])

        # Add files
        paths = ["/file1.txt", "/file2.txt", "/file3.txt"]
        for path in paths:
            self.secure_fs.write(path, b"content")

        # Check cached paths
        cached = self.secure_fs.get_cached_paths()
        self.assertEqual(len(cached), 3)
        self.assertEqual(set(cached), set(paths))

        # Remove one
        self.secure_fs.clear_cache("/file2.txt")
        cached = self.secure_fs.get_cached_paths()
        self.assertEqual(len(cached), 2)
        self.assertNotIn("/file2.txt", cached)

    def test_cache_updated_on_overwrite(self):
        """Test that cache is updated when file is overwritten"""
        path = "/test/file.txt"
        content1 = b"Original"
        content2 = b"Updated"

        self.secure_fs.write(path, content1)
        self.secure_fs.write(path, content2)

        # Delete .dat to prove it comes from cache
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        dat_files[0].unlink()

        result = self.secure_fs.read(path)
        self.assertEqual(result, content2)


class TestSecureFSWrapperCacheBounds(unittest.TestCase):
    """Test suite for the bounded (LRU) cache behavior."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.db_path = self.test_dir / "test_index.db"
        self.storage_root = self.test_dir / "test_storage"
        self.master_key = secrets.token_bytes(32)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def _make(self, **kwargs):
        return SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            cache_enabled=True,
            **kwargs,
        )

    def test_invalid_cache_max_bytes_rejected(self):
        """A non-positive cache budget should be rejected."""
        with self.assertRaises(ValueError):
            self._make(cache_max_bytes=0)

    def test_lru_eviction_respects_budget(self):
        """Cache evicts least-recently-used entries to stay within the budget."""
        fs = self._make(cache_max_bytes=25)  # room for ~2 ten-byte files

        fs.write("/a.txt", b"1234567890")  # 10 bytes
        fs.write("/b.txt", b"1234567890")  # 10 bytes -> total 20
        self.assertEqual(fs.get_cache_size(), 20)

        # Touch /a.txt so /b.txt becomes the least-recently-used entry.
        fs.read("/a.txt")

        # Adding a third entry exceeds the 25-byte budget; /b.txt is evicted.
        fs.write("/c.txt", b"1234567890")  # total would be 30 -> evict LRU

        self.assertLessEqual(fs.get_cache_size(), 25)
        self.assertTrue(fs.is_cached("/a.txt"))
        self.assertFalse(fs.is_cached("/b.txt"))
        self.assertTrue(fs.is_cached("/c.txt"))

    def test_verify_all_files_bypasses_cache(self):
        """verify_all_files must detect on-disk corruption even when cached."""
        fs = self._make()
        fs.write("/good.txt", b"good content")
        fs.write("/bad.txt", b"bad content that is cached")

        # Both files are now in the cache. Corrupt one on disk.
        dat_files = sorted(Path(self.storage_root).glob("*.dat"))
        data = bytearray(dat_files[0].read_bytes())
        data[20] ^= 0xFF
        dat_files[0].write_bytes(data)

        results = fs.verify_all_files()

        # A cache-trusting implementation would report everything OK; the
        # bypass forces a real disk read and surfaces the corruption.
        self.assertIn(False, results.values())
