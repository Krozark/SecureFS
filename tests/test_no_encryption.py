import os
import secrets
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from securefs import FileCorruptionError, SecureFSWrapper


class TestSecureFSWrapperNoEncryption(unittest.TestCase):
    """Test suite for development mode (encryption disabled)"""

    def setUp(self):
        """Set up test fixtures with encryption disabled"""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_index.db")
        self.storage_root = os.path.join(self.test_dir, "test_storage")
        self.master_key = secrets.token_bytes(32)

        # Suppress the encryption warning for tests
        import warnings

        warnings.filterwarnings("ignore", category=UserWarning)

        self.secure_fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            encryption_enabled=False,  # Development mode
        )

    def tearDown(self):
        """Clean up after tests"""
        self.secure_fs.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_write_and_read_work_without_encryption(self):
        """Test that basic operations work without encryption"""
        path = "/test/file.txt"
        content = b"Test content without encryption"

        self.secure_fs.write(path, content)
        result = self.secure_fs.read(path)

        self.assertEqual(result, content)

    def test_content_is_plaintext_on_disk(self):
        """Test that content is stored as plaintext when encryption is disabled"""
        path = "/test/plaintext.txt"
        content = b"This should be plaintext on disk"

        self.secure_fs.write(path, content)

        # Read raw .dat file
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        self.assertEqual(len(dat_files), 1)

        with open(dat_files[0], "rb") as f:
            raw_content = f.read()

        # Content should be found in the raw file (after nonce)
        self.assertIn(content, raw_content)

    def test_statistics_show_encryption_disabled(self):
        """Test that statistics correctly report encryption status"""
        stats = self.secure_fs.get_statistics()

        self.assertFalse(stats["encryption_enabled"])

    def test_all_operations_work_without_encryption(self):
        """Test that all file operations work without encryption"""
        # Write
        self.secure_fs.write("/file1.txt", b"content1")
        self.secure_fs.write("/file2.txt", b"content2")

        # Read
        self.assertEqual(self.secure_fs.read("/file1.txt"), b"content1")
        self.assertEqual(self.secure_fs.read("/file2.txt"), b"content2")

        # Exists
        self.assertTrue(self.secure_fs.exists("/file1.txt"))

        # List
        files = self.secure_fs.list_files()
        self.assertEqual(len(files), 2)

        # Get info
        info = self.secure_fs.get_info("/file1.txt")
        self.assertIsNotNone(info)

        # Delete
        self.assertTrue(self.secure_fs.delete("/file1.txt"))
        self.assertFalse(self.secure_fs.exists("/file1.txt"))

    def test_integrity_verification_still_works(self):
        """Test that integrity verification works even without encryption"""
        path = "/test/file.txt"
        content = b"Test content"

        self.secure_fs.write(path, content)

        # Should pass verification
        result = self.secure_fs.read(path, skip_verification=False)
        self.assertEqual(result, content)

        # Corrupt the file
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        with open(dat_files[0], "rb") as f:
            data = bytearray(f.read())

        # Modify content
        if len(data) > 20:
            data[20] ^= 0xFF

        with open(dat_files[0], "wb") as f:
            f.write(data)

        # Should detect corruption
        with self.assertRaises(FileCorruptionError):
            self.secure_fs.read(path, skip_verification=False)

    def test_can_switch_between_encryption_modes(self):
        """Test that files from encrypted and non-encrypted modes are separate"""
        # Write with encryption disabled
        self.secure_fs.write("/no_encrypt.txt", b"plaintext")

        # Create new instance with encryption enabled
        encrypted_fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=os.path.join(self.test_dir, "encrypted_index.db"),
            storage_root=os.path.join(self.test_dir, "encrypted_storage"),
            encryption_enabled=True,
        )

        # Write with encryption
        encrypted_fs.write("/encrypted.txt", b"ciphertext")

        # Verify plaintext file is plaintext
        dat_files_plain = list(Path(self.storage_root).glob("*.dat"))
        with open(dat_files_plain[0], "rb") as f:
            plain_raw = f.read()
        self.assertIn(b"plaintext", plain_raw)

        # Verify encrypted file is encrypted
        dat_files_enc = list(Path(encrypted_fs.storage_root).glob("*.dat"))
        with open(dat_files_enc[0], "rb") as f:
            enc_raw = f.read()
        self.assertNotIn(b"ciphertext", enc_raw)

        encrypted_fs.close()

    def test_warning_is_issued_when_encryption_disabled(self):
        """Test that a warning is issued when encryption is disabled"""
        import warnings

        # Capture warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            # Create instance with encryption disabled
            test_fs = SecureFSWrapper(
                master_key=secrets.token_bytes(32),
                db_path=os.path.join(self.test_dir, "warn_test.db"),
                storage_root=os.path.join(self.test_dir, "warn_storage"),
                encryption_enabled=False,
            )

            # Check that a warning was issued
            self.assertEqual(len(w), 1)
            self.assertIn("ENCRYPTION IS DISABLED", str(w[0].message))
            self.assertIn("PLAINTEXT", str(w[0].message))

            test_fs.close()

    def test_large_file_without_encryption(self):
        """Test handling large files without encryption"""
        # Create a 5 MB file
        large_content = b"X" * (5 * 1024 * 1024)
        path = "/large/file.bin"

        self.secure_fs.write(path, large_content)
        result = self.secure_fs.read(path)

        self.assertEqual(len(result), len(large_content))
        self.assertEqual(result, large_content)

    def test_binary_data_without_encryption(self):
        """Test binary data handling without encryption"""
        binary_data = bytes(range(256))
        path = "/binary/data.bin"

        self.secure_fs.write(path, binary_data)
        result = self.secure_fs.read(path)

        self.assertEqual(result, binary_data)

    def test_migration_from_unencrypted_to_encrypted(self):
        """Test reading plaintext files after enabling encryption"""
        # Start with encryption disabled
        path1 = "/file_plain.txt"
        path2 = "/file_also_plain.txt"

        self.secure_fs.write(path1, b"This was stored without encryption")
        self.secure_fs.write(path2, b"Also plaintext")

        # Verify files are plaintext on disk
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        self.assertEqual(len(dat_files), 2)

        # Close and reopen with encryption ENABLED
        self.secure_fs.close()

        import warnings

        warnings.filterwarnings("ignore", category=UserWarning)

        encrypted_fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            encryption_enabled=True,  # Now encryption is ON
        )

        # Should still be able to read old plaintext files
        result1 = encrypted_fs.read(path1)
        result2 = encrypted_fs.read(path2)

        self.assertEqual(result1, b"This was stored without encryption")
        self.assertEqual(result2, b"Also plaintext")

        # Write a new file with encryption enabled
        path3 = "/file_encrypted.txt"
        encrypted_fs.write(path3, b"This is encrypted")

        # Verify the new file is encrypted on disk
        # Find the newest .dat file
        dat_files = sorted(Path(self.storage_root).glob("*.dat"), key=os.path.getmtime)
        newest_dat = dat_files[-1]

        with open(newest_dat, "rb") as f:
            raw = f.read()

        self.assertNotIn(b"This is encrypted", raw)

        # Should be able to read all files
        self.assertEqual(encrypted_fs.read(path1), b"This was stored without encryption")
        self.assertEqual(encrypted_fs.read(path3), b"This is encrypted")

        encrypted_fs.close()

    def test_migration_from_encrypted_to_unencrypted(self):
        """Test reading encrypted files after disabling encryption"""
        import warnings

        warnings.filterwarnings("ignore", category=UserWarning)

        # Start with encryption ENABLED
        encrypted_fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            encryption_enabled=True,
        )

        path1 = "/encrypted_file.txt"
        encrypted_fs.write(path1, b"This is encrypted content")

        # Verify it's encrypted on disk
        dat_files = list(Path(self.storage_root).glob("*.dat"))
        with open(dat_files[0], "rb") as f:
            raw = f.read()
        self.assertNotIn(b"This is encrypted content", raw)

        encrypted_fs.close()

        # Reopen with encryption DISABLED
        plain_fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            encryption_enabled=False,
        )

        # Should still be able to read the encrypted file
        result = plain_fs.read(path1)
        self.assertEqual(result, b"This is encrypted content")

        # Write a new file with encryption disabled
        path2 = "/plain_file.txt"
        plain_fs.write(path2, b"This is plaintext")

        # Verify new file is plaintext
        dat_files = sorted(Path(self.storage_root).glob("*.dat"), key=os.path.getmtime)
        newest_dat = dat_files[-1]

        with open(newest_dat, "rb") as f:
            raw = f.read()
        self.assertIn(b"This is plaintext", raw)

        plain_fs.close()

    def test_mixed_encrypted_and_plaintext_files(self):
        """Test system with mix of encrypted and plaintext files"""
        import warnings

        warnings.filterwarnings("ignore", category=UserWarning)

        # Create some plaintext files
        self.secure_fs.write("/plain1.txt", b"Plain content 1")
        self.secure_fs.write("/plain2.txt", b"Plain content 2")
        self.secure_fs.close()

        # Switch to encrypted mode
        encrypted_fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            encryption_enabled=True,
        )

        # Add encrypted files
        encrypted_fs.write("/encrypted1.txt", b"Encrypted content 1")
        encrypted_fs.write("/encrypted2.txt", b"Encrypted content 2")
        encrypted_fs.close()

        # Switch back to plaintext mode
        plain_fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            encryption_enabled=False,
        )

        # Should be able to read ALL files regardless of mode
        self.assertEqual(plain_fs.read("/plain1.txt"), b"Plain content 1")
        self.assertEqual(plain_fs.read("/plain2.txt"), b"Plain content 2")
        self.assertEqual(plain_fs.read("/encrypted1.txt"), b"Encrypted content 1")
        self.assertEqual(plain_fs.read("/encrypted2.txt"), b"Encrypted content 2")

        # List all files
        all_files = plain_fs.list_files()
        self.assertEqual(len(all_files), 4)

        plain_fs.close()

    def test_nonce_detection_logic(self):
        """Test that nonce correctly identifies encrypted vs plaintext"""
        import warnings

        warnings.filterwarnings("ignore", category=UserWarning)

        # Write plaintext file
        self.secure_fs.write("/plain.txt", b"plaintext")

        # Get the nonce from database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT kf_nonce FROM files WHERE logical_path = '/plain.txt'")
            plain_nonce = cursor.fetchone()[0]

        # Plaintext nonce should be all zeros
        self.assertEqual(plain_nonce, b"\x00" * 12)

        self.secure_fs.close()

        # Write encrypted file
        encrypted_fs = SecureFSWrapper(
            master_key=self.master_key,
            db_path=self.db_path,
            storage_root=self.storage_root,
            encryption_enabled=True,
        )

        encrypted_fs.write("/encrypted.txt", b"encrypted")

        # Get the nonce from database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT kf_nonce FROM files WHERE logical_path = '/encrypted.txt'")
            enc_nonce = cursor.fetchone()[0]

        # Encrypted nonce should NOT be all zeros
        self.assertNotEqual(enc_nonce, b"\x00" * 12)

        encrypted_fs.close()
