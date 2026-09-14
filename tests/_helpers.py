"""Shared fixtures for the SecureFS test suite."""

import shutil
import tempfile
import unittest
import warnings
from pathlib import Path

from securefs import SecureFSWrapper
from securefs.utils import generate_master_key


class SecureFSTestCase(unittest.TestCase):
    """Base for tests needing a throwaway SecureFS store.

    Provides a temporary ``test_dir`` holding ``db_path`` and ``storage_root``,
    a fresh ``master_key``, and :meth:`make_fs` to open wrappers on that store.
    Everything is released on teardown, so subclasses need neither a
    ``tearDown`` nor explicit ``close()`` calls.
    """

    def setUp(self):
        super().setUp()
        self.test_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.test_dir, ignore_errors=True)

        self.db_path = self.test_dir / "index.db"
        self.storage_root = self.test_dir / "storage"
        self.master_key = generate_master_key()

    def make_fs(self, **kwargs) -> SecureFSWrapper:
        """Open a wrapper on this test's store, closed automatically on teardown.

        Keyword arguments override the defaults, so a test asks only for what it
        cares about (``cache_enabled=True``, ``encryption_enabled=False``, ...)
        without repeating the key and the paths.

        Development mode warns on purpose; tests opting into it have already
        made that choice, so the warning is silenced here. A test that wants to
        assert the warning should build a ``SecureFSWrapper`` directly.
        """
        options = {
            "master_key": self.master_key,
            "db_path": self.db_path,
            "storage_root": self.storage_root,
            **kwargs,
        }

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            fs = SecureFSWrapper(**options)

        self.addCleanup(fs.close)
        return fs
