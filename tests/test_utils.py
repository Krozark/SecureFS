"""Tests for securefs.utils module."""

import unittest

from securefs.utils import compute_hash, format_size, generate_master_key, validate_master_key


class TestGenerateMasterKey(unittest.TestCase):
    """Tests for generate_master_key()."""

    def test_returns_bytes(self):
        """Key should be a bytes object."""
        key = generate_master_key()
        self.assertIsInstance(key, bytes)

    def test_correct_length(self):
        """Key should be exactly 32 bytes."""
        key = generate_master_key()
        self.assertEqual(len(key), 32)

    def test_keys_are_unique(self):
        """Successive calls should produce different keys."""
        keys = {generate_master_key() for _ in range(50)}
        self.assertEqual(len(keys), 50)


class TestComputeHash(unittest.TestCase):
    """Tests for compute_hash()."""

    def test_returns_hex_string(self):
        """Hash should be a 64-character hex string."""
        result = compute_hash(b"hello")
        self.assertEqual(len(result), 64)
        # Should only contain hex characters
        int(result, 16)

    def test_deterministic(self):
        """Same input should always produce the same hash."""
        h1 = compute_hash(b"test data")
        h2 = compute_hash(b"test data")
        self.assertEqual(h1, h2)

    def test_different_inputs_different_hashes(self):
        """Different inputs should produce different hashes."""
        h1 = compute_hash(b"input1")
        h2 = compute_hash(b"input2")
        self.assertNotEqual(h1, h2)

    def test_empty_input(self):
        """Empty bytes should produce a valid hash."""
        result = compute_hash(b"")
        self.assertEqual(len(result), 64)

    def test_known_sha256(self):
        """Verify against a known SHA-256 value."""
        # SHA-256 of empty string
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(compute_hash(b""), expected)


class TestFormatSize(unittest.TestCase):
    """Tests for format_size()."""

    def test_bytes(self):
        """Small values should display in bytes."""
        self.assertEqual(format_size(0), "0.0 B")
        self.assertEqual(format_size(512), "512.0 B")
        self.assertEqual(format_size(1023), "1023.0 B")

    def test_kilobytes(self):
        """Values >= 1024 should display in KB."""
        self.assertEqual(format_size(1024), "1.0 KB")
        self.assertEqual(format_size(1536), "1.5 KB")

    def test_megabytes(self):
        """Values >= 1 MB should display in MB."""
        self.assertEqual(format_size(1024 * 1024), "1.0 MB")

    def test_gigabytes(self):
        """Values >= 1 GB should display in GB."""
        self.assertEqual(format_size(1024**3), "1.0 GB")

    def test_terabytes(self):
        """Values >= 1 TB should display in TB."""
        self.assertEqual(format_size(1024**4), "1.0 TB")

    def test_petabytes(self):
        """Values >= 1 PB should display in PB."""
        self.assertEqual(format_size(1024**5), "1.0 PB")


class TestValidateMasterKey(unittest.TestCase):
    """Tests for validate_master_key()."""

    def test_valid_key(self):
        """A 32-byte bytes object should be valid."""
        self.assertTrue(validate_master_key(b"\x00" * 32))
        self.assertTrue(validate_master_key(generate_master_key()))

    def test_wrong_length(self):
        """Keys with wrong length should be invalid."""
        self.assertFalse(validate_master_key(b"short"))
        self.assertFalse(validate_master_key(b"\x00" * 31))
        self.assertFalse(validate_master_key(b"\x00" * 33))
        self.assertFalse(validate_master_key(b""))

    def test_wrong_type(self):
        """Non-bytes types should be invalid."""
        self.assertFalse(validate_master_key("not bytes" * 4))
        self.assertFalse(validate_master_key(12345))
        self.assertFalse(validate_master_key(None))
        self.assertFalse(validate_master_key([0] * 32))
