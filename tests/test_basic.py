
import os
import secrets
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from securefs import EncryptionError, FileCorruptionError, SecureFSWrapper


class TestSecureFSWrapperBasic(unittest.TestCase):
    """Test suite for basic SecureFSWrapper functionality"""

    def setUp(self):
        """Set up test fixtures before each test"""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)

        self.secure_fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            verify_integrity=True,
            cache_enabled=False,
        )

    def tearDown(self):
        """Clean up after each test"""
        self.secure_fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    # ========================
    # Initialization Tests
    # ========================

    def test_initialization_creates_directories(self):
        """Test that initialization creates necessary directories"""
        self.assertTrue(os.path.exists(self.storage_root))
        self.assertTrue(os.path.isdir(self.storage_root))

    def test_initialization_creates_database(self):
        """Test that initialization creates SQLite database with indexes"""
        self.assertTrue(os.path.exists(self.db_path))

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Check files table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'")
            self.assertIsNotNone(cursor.fetchone())

            # Check system_metadata table
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='system_metadata'"
            )
            self.assertIsNotNone(cursor.fetchone())

            # Check indexes exist
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_files_hash'"
            )
            self.assertIsNotNone(cursor.fetchone())

    def test_initialization_invalid_key_length(self):
        """Test that invalid master key length raises error"""
        with self.assertRaises(ValueError) as context:
            SecureFSWrapper(
                master_key=b"short_key", db_path=self.db_path, storage_root=self.storage_root
            )
        self.assertIn("32 bytes", str(context.exception))

    # ========================
    # Write Operation Tests
    # ========================

    def test_write_creates_file(self):
        """Test that write operation creates encrypted file"""
        content = b"Test content"
        path = "/test/file.txt"

        self.secure_fs.write(path, content)
        self.assertTrue(self.secure_fs.exists(path))

    def test_write_creates_dat_file(self):
        """Test that write operation creates .dat file on disk"""
        content = b"Test content"
        path = "/test/file.txt"

        self.secure_fs.write(path, content)

        dat_files = list(Path(self.storage_root).glob("*.dat"))
        self.assertEqual(len(dat_files), 1)

    def test_write_stores_correct_metadata(self):
        """Test that write operation stores correct metadata"""
        content = b"Test content"
        path = "/test/file.txt"

        self.secure_fs.write(path, content)

        info = self.secure_fs.get_info(path)
        self.assertIsNotNone(info)
        self.assertEqual(info["size"], len(content))
        self.assertEqual(info["path"], path)
        self.assertIsNotNone(info["hash"])

    def test_write_overwrites_existing_file(self):
        """Test that write operation overwrites existing files"""
        path = "/test/file.txt"
        content1 = b"Original content"
        content2 = b"Updated content"

        self.secure_fs.write(path, content1)
        self.secure_fs.write(path, content2)

        result = self.secure_fs.read(path)
        self.assertEqual(result, content2)

    def test_write_binary_data(self):
        """Test writing binary data"""
        binary_data = bytes(range(256))
        path = "/images/test.jpg"

        self.secure_fs.write(path, binary_data)
        result = self.secure_fs.read(path)

        self.assertEqual(result, binary_data)

    def test_write_large_file(self):
        """Test writing a large file (5 MB)"""
        large_content = b"X" * (5 * 1024 * 1024)
        path = "/large/file.bin"

        self.secure_fs.write(path, large_content)
        result = self.secure_fs.read(path)

        self.assertEqual(len(result), len(large_content))
        self.assertEqual(result, large_content)

    def test_write_empty_file(self):
        """Test writing an empty file"""
        path = "/empty/file.txt"
        empty_content = b""

        self.secure_fs.write(path, empty_content)
        result = self.secure_fs.read(path)

        self.assertEqual(result, empty_content)

    # ========================
    # Read Operation Tests
    # ========================

    def test_read_returns_correct_content(self):
        """Test that read operation returns original content"""
        content = b"Secret message"
        path = "/secure/message.txt"

        self.secure_fs.write(path, content)
        result = self.secure_fs.read(path)

        self.assertEqual(result, content)

    def test_read_nonexistent_file_raises_error(self):
        """Test that reading nonexistent file raises FileNotFoundError"""
        with self.assertRaises(FileNotFoundError):
            self.secure_fs.read("/nonexistent/file.txt")

    def test_read_with_missing_dat_file(self):
        """Test that reading with missing .dat file raises error"""
        content = b"Test"
        path = "/test/file.txt"

        self.secure_fs.write(path, content)

        # Delete the .dat file
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        dat_files[0].unlink()

        with self.assertRaises(FileNotFoundError):
            self.secure_fs.read(path)

    def test_read_multiple_files(self):
        """Test reading multiple different files"""
        files = {"/doc1.txt": b"Content 1", "/doc2.txt": b"Content 2", "/doc3.txt": b"Content 3"}

        for path, content in files.items():
            self.secure_fs.write(path, content)

        for path, expected_content in files.items():
            result = self.secure_fs.read(path)
            self.assertEqual(result, expected_content)

    # ========================
    # Integrity Verification Tests
    # ========================

    def test_integrity_verification_detects_corruption(self):
        """Test that integrity verification detects corrupted files"""
        content = b"Original content"
        path = "/test/file.txt"

        self.secure_fs.write(path, content)

        # Corrupt the .dat file
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        with open(dat_files[0], "rb") as f:
            data = bytearray(f.read())

        # Flip some bits in the encrypted content (after nonce)
        if len(data) > 20:
            data[20] ^= 0xFF

        with open(dat_files[0], "wb") as f:
            f.write(data)

        # Should raise FileCorruptionError
        with self.assertRaises((FileCorruptionError, EncryptionError)):
            self.secure_fs.read(path)

    def test_skip_verification_option(self):
        """Test that skip_verification bypasses integrity check"""
        content = b"Test content"
        path = "/test/file.txt"

        self.secure_fs.write(path, content)

        # Should work with verification
        result = self.secure_fs.read(path, skip_verification=False)
        self.assertEqual(result, content)

        # Should also work without verification
        result = self.secure_fs.read(path, skip_verification=True)
        self.assertEqual(result, content)

    def test_verify_all_files(self):
        """Test verify_all_files method"""
        # Write several files
        self.secure_fs.write("/file1.txt", b"Content 1")
        self.secure_fs.write("/file2.txt", b"Content 2")
        self.secure_fs.write("/file3.txt", b"Content 3")

        # Verify all
        results = self.secure_fs.verify_all_files()

        self.assertEqual(len(results), 3)
        self.assertTrue(all(results.values()))

    def test_verify_all_files_detects_corruption(self):
        """Test that verify_all_files detects corrupted files"""
        self.secure_fs.write("/good.txt", b"Good content")
        self.secure_fs.write("/bad.txt", b"Bad content")

        # Corrupt one file
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        with open(dat_files[0], "rb") as f:
            data = bytearray(f.read())
        if len(data) > 20:
            data[20] ^= 0xFF
        with open(dat_files[0], "wb") as f:
            f.write(data)

        results = self.secure_fs.verify_all_files()

        # At least one should be False
        self.assertIn(False, results.values())

    # ========================
    # Exists Operation Tests
    # ========================

    def test_exists_returns_true_for_existing_file(self):
        """Test that exists returns True for existing files"""
        path = "/test/file.txt"
        self.secure_fs.write(path, b"content")

        self.assertTrue(self.secure_fs.exists(path))

    def test_exists_returns_false_for_nonexistent_file(self):
        """Test that exists returns False for nonexistent files"""
        self.assertFalse(self.secure_fs.exists("/nonexistent/file.txt"))

    # ========================
    # Delete Operation Tests
    # ========================

    def test_delete_removes_file(self):
        """Test that delete operation removes file"""
        path = "/test/file.txt"
        self.secure_fs.write(path, b"content")

        result = self.secure_fs.delete(path)

        self.assertTrue(result)
        self.assertFalse(self.secure_fs.exists(path))

    def test_delete_removes_dat_file(self):
        """Test that delete operation removes .dat file from disk"""
        path = "/test/file.txt"
        self.secure_fs.write(path, b"content")

        dat_files_before = list(Path(self.storage_root).glob("*.dat"))
        self.assertEqual(len(dat_files_before), 1)

        self.secure_fs.delete(path)

        dat_files_after = list(Path(self.storage_root).glob("*.dat"))
        self.assertEqual(len(dat_files_after), 0)

    def test_delete_nonexistent_file_returns_false(self):
        """Test that deleting nonexistent file returns False"""
        result = self.secure_fs.delete("/nonexistent/file.txt")
        self.assertFalse(result)

    def test_delete_removes_from_database(self):
        """Test that delete removes entry from database"""
        path = "/test/file.txt"
        self.secure_fs.write(path, b"content")

        self.secure_fs.delete(path)

        info = self.secure_fs.get_info(path)
        self.assertIsNone(info)

    # ========================
    # List Files Tests
    # ========================

    def test_list_files_empty_system(self):
        """Test listing files in empty system"""
        files = self.secure_fs.list_files()
        self.assertEqual(len(files), 0)

    def test_list_files_returns_all_files(self):
        """Test that list_files returns all files"""
        paths = ["/file1.txt", "/file2.txt", "/file3.txt"]

        for path in paths:
            self.secure_fs.write(path, b"content")

        result = self.secure_fs.list_files()

        self.assertEqual(len(result), 3)
        self.assertEqual(set(result), set(paths))

    def test_list_files_with_prefix(self):
        """Test listing files with prefix filter"""
        self.secure_fs.write("/docs/file1.txt", b"content1")
        self.secure_fs.write("/docs/file2.txt", b"content2")
        self.secure_fs.write("/images/pic.jpg", b"content3")

        docs_files = self.secure_fs.list_files("/docs/")

        self.assertEqual(len(docs_files), 2)
        self.assertTrue(all(f.startswith("/docs/") for f in docs_files))

    def test_list_files_sorted(self):
        """Test that list_files returns sorted results"""
        paths = ["/c.txt", "/a.txt", "/b.txt"]

        for path in paths:
            self.secure_fs.write(path, b"content")

        result = self.secure_fs.list_files()

        self.assertEqual(result, sorted(paths))

    # ========================
    # Get Info Tests
    # ========================

    def test_get_info_returns_metadata(self):
        """Test that get_info returns correct metadata"""
        content = b"Test content"
        path = "/test/file.txt"

        self.secure_fs.write(path, content)
        info = self.secure_fs.get_info(path)

        self.assertIsNotNone(info)
        self.assertEqual(info["path"], path)
        self.assertEqual(info["size"], len(content))
        self.assertIn("hash", info)
        self.assertIn("created_at", info)
        self.assertIn("modified_at", info)

    def test_get_info_nonexistent_file(self):
        """Test that get_info returns None for nonexistent file"""
        info = self.secure_fs.get_info("/nonexistent.txt")
        self.assertIsNone(info)

    def test_get_info_hash_consistency(self):
        """Test that file hash is consistent for same content"""
        content = b"Test content"
        path1 = "/file1.txt"
        path2 = "/file2.txt"

        self.secure_fs.write(path1, content)
        self.secure_fs.write(path2, content)

        info1 = self.secure_fs.get_info(path1)
        info2 = self.secure_fs.get_info(path2)

        self.assertEqual(info1["hash"], info2["hash"])

    # ========================
    # Statistics Tests
    # ========================

    def test_get_statistics_empty_system(self):
        """Test statistics on empty system"""
        stats = self.secure_fs.get_statistics()

        self.assertEqual(stats["total_files"], 0)
        self.assertEqual(stats["total_size_bytes"], 0)
        self.assertFalse(stats["cache_enabled"])

    def test_get_statistics_with_files(self):
        """Test statistics with files"""
        self.secure_fs.write("/file1.txt", b"12345")
        self.secure_fs.write("/file2.txt", b"67890")

        stats = self.secure_fs.get_statistics()

        self.assertEqual(stats["total_files"], 2)
        self.assertEqual(stats["total_size_bytes"], 10)
        self.assertIsNotNone(stats["oldest_file"])
        self.assertIsNotNone(stats["newest_modification"])

    # ========================
    # Encryption Tests
    # ========================

    def test_content_is_encrypted_on_disk(self):
        """Test that content on disk is actually encrypted"""
        plaintext = b"Secret message"
        path = "/test/file.txt"

        self.secure_fs.write(path, plaintext)

        dat_files = list(Path(self.storage_root).glob("*.dat"))
        with open(dat_files[0], "rb") as f:
            raw_content = f.read()

        self.assertNotIn(plaintext, raw_content)

    def test_different_keys_produce_different_ciphertext(self):
        """Test that different master keys produce different encrypted data"""
        content = b"Same content"
        path = "/test/file.txt"

        self.secure_fs.write(path, content)
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        with open(dat_files[0], "rb") as f:
            ciphertext1 = f.read()

        new_key = secrets.token_bytes(32)
        new_db = os.path.join(self.test_dir, "new_index.db")
        new_storage = os.path.join(self.test_dir, "new_storage")

        secure_fs2 = SecureFSWrapper(master_key=new_key, db_path=new_db, storage_root=new_storage)

        secure_fs2.write(path, content)
        dat_files2 = list(Path(new_storage).glob("*.dat"))
        with open(dat_files2[0], "rb") as f:
            ciphertext2 = f.read()

        self.assertNotEqual(ciphertext1, ciphertext2)
        secure_fs2.close()

    def test_wrong_master_key_cannot_decrypt(self):
        """Test that wrong master key cannot decrypt files"""
        content = b"Secret"
        path = "/test/file.txt"

        self.secure_fs.write(path, content)

        wrong_key = secrets.token_bytes(32)
        secure_fs_wrong = SecureFSWrapper(
            master_key=wrong_key, db_path=self.db_path, storage_root=self.storage_root
        )

        with self.assertRaises(EncryptionError):
            secure_fs_wrong.read(path)

        secure_fs_wrong.close()

    # ========================
    # SQL Injection Security Tests
    # ========================

    def test_sql_injection_single_quote_in_path(self):
        """Test that single quotes in path don't cause SQL injection"""
        malicious_paths = [
            "/test/file'; DROP TABLE files; --",
            "/test/O'Brien.txt",
            "/test/it's a file.txt",
            "'; DELETE FROM files WHERE '1'='1",
            "/test/' OR '1'='1.txt",
        ]

        for path in malicious_paths:
            content = f"Content for {path}".encode()

            self.secure_fs.write(path, content)
            result = self.secure_fs.read(path)
            self.assertEqual(result, content)
            self.assertTrue(self.secure_fs.exists(path))
            self.assertTrue(self.secure_fs.delete(path))

    def test_sql_injection_table_intact_after_malicious_paths(self):
        """Test that database table remains intact after malicious path attempts"""
        self.secure_fs.write("/legitimate/file.txt", b"Legitimate content")

        injection_attempts = [
            "'; DROP TABLE files; --",
            "' OR 1=1; DELETE FROM files; --",
            "'; UPDATE files SET logical_path='hacked'; --",
        ]

        for attempt in injection_attempts:
            try:
                self.secure_fs.write(attempt, b"Injection attempt")
            except Exception:
                pass

        self.assertTrue(self.secure_fs.exists("/legitimate/file.txt"))
        content = self.secure_fs.read("/legitimate/file.txt")
        self.assertEqual(content, b"Legitimate content")

    def test_sql_injection_with_special_sql_keywords(self):
        """Test paths containing SQL keywords are handled safely"""
        sql_keyword_paths = [
            "/SELECT/FROM/WHERE.txt",
            "/DROP TABLE users.txt",
            "/INSERT INTO files.txt",
        ]

        for path in sql_keyword_paths:
            content = b"SQL keyword test"
            self.secure_fs.write(path, content)
            result = self.secure_fs.read(path)
            self.assertEqual(result, content)
            self.secure_fs.delete(path)
