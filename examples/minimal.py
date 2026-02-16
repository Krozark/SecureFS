"""
Minimal SecureFS example — write, read, delete in ~20 lines.
"""

import tempfile
from pathlib import Path

from securefs import SecureFSWrapper
from securefs.utils import generate_master_key


# Create a temporary directory so nothing is left behind
with tempfile.TemporaryDirectory() as tmp:
    # 1. Setup
    key = generate_master_key()
    fs = SecureFSWrapper(
        master_key=key,
        db_path=Path(tmp) / "index.db",
        storage_root=Path(tmp) / "data",
    )

    # 2. Write
    fs.write("/hello.txt", b"Hello, SecureFS!")

    # 3. Read
    content = fs.read("/hello.txt")
    print(content.decode())  # => Hello, SecureFS!

    # 4. List
    print(fs.list_files())  # => ['/hello.txt']

    # 5. Delete
    fs.delete("/hello.txt")
    print(fs.exists("/hello.txt"))  # => False

    fs.close()
