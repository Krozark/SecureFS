"""Tests for securefs.utils module."""

import unittest

from securefs.utils import (
    derive_master_key,
    format_size,
    generate_master_key,
    generate_salt,
    validate_master_key,
)


# Cheap scrypt cost parameters so tests run fast; production code should use
# derive_master_key()'s (much stronger, and much slower) defaults instead.
_FAST_KDF = {"n": 2**10, "r": 8, "p": 1}


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


class TestGenerateSalt(unittest.TestCase):
    """Tests for generate_salt()."""

    def test_default_length(self):
        """Default salt should be 16 bytes."""
        self.assertEqual(len(generate_salt()), 16)

    def test_custom_length(self):
        """Salt length should be configurable."""
        self.assertEqual(len(generate_salt(32)), 32)

    def test_salts_are_unique(self):
        """Successive calls should produce different salts."""
        salts = {generate_salt() for _ in range(50)}
        self.assertEqual(len(salts), 50)


class TestDeriveMasterKey(unittest.TestCase):
    """Tests for derive_master_key()."""

    def setUp(self):
        self.salt = generate_salt()

    def test_returns_valid_master_key(self):
        """Result should be a 32-byte key usable as a SecureFS master key."""
        key = derive_master_key("hunter2", self.salt, **_FAST_KDF)
        self.assertTrue(validate_master_key(key))

    def test_deterministic(self):
        """Same inputs should always derive the same key."""
        key1 = derive_master_key("hunter2", self.salt, **_FAST_KDF)
        key2 = derive_master_key("hunter2", self.salt, **_FAST_KDF)
        self.assertEqual(key1, key2)

    def test_accepts_str_and_bytes_identically(self):
        """A str account_secret should be UTF-8 encoded the same as raw bytes."""
        key_str = derive_master_key("hunter2", self.salt, **_FAST_KDF)
        key_bytes = derive_master_key(b"hunter2", self.salt, **_FAST_KDF)
        self.assertEqual(key_str, key_bytes)

    def test_different_account_secret_different_key(self):
        """Changing the account secret must change the derived key."""
        key1 = derive_master_key("hunter2", self.salt, **_FAST_KDF)
        key2 = derive_master_key("correct-horse-battery-staple", self.salt, **_FAST_KDF)
        self.assertNotEqual(key1, key2)

    def test_different_salt_different_key(self):
        """Changing the salt must change the derived key -- this is what stops two
        accounts that happen to share the same secret from deriving the same key."""
        key1 = derive_master_key("hunter2", self.salt, **_FAST_KDF)
        key2 = derive_master_key("hunter2", generate_salt(), **_FAST_KDF)
        self.assertNotEqual(key1, key2)

    def test_default_parameters_produce_valid_key(self):
        """Sanity check with the real (slow) production defaults, run only once."""
        key = derive_master_key("hunter2", self.salt)
        self.assertTrue(validate_master_key(key))


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
