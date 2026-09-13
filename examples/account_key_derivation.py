"""
Per-account master key derivation from a password, for local/offline apps.

Use this when each user account should get its own SecureFS storage, keyed
from a secret the account owner provides (e.g. their password), with no
server or other external secret store involved -- everything needed to
re-derive the key is either the password itself (never stored) or the
non-secret salt stored alongside the account.

See derive_master_key() in securefs.utils for why the salt is needed even
though the password is already account-specific, and why there is no
"pepper": in a fully local/offline app there is no trusted place to keep a
second secret that isn't just sitting next to the data it would protect.
"""

import tempfile
from pathlib import Path

from securefs import SecureFSWrapper
from securefs.utils import derive_master_key, generate_salt


def open_account_storage(account_password: str, account_salt: bytes, root: Path) -> SecureFSWrapper:
    """Open (or create) the SecureFS storage for one account.

    `account_salt` is generated once per account (generate_salt()) and stored
    next to the account row -- it is not secret, just unique per account.
    """
    master_key = derive_master_key(account_password, account_salt)
    return SecureFSWrapper(
        master_key=master_key, db_path=root / "index.db", storage_root=root / "data"
    )


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)

    # --- Account creation (once) ---
    # A real app stores `salt` in the accounts table, next to the (separately
    # hashed) login credentials.
    salt = generate_salt()

    # --- Login (every session) ---
    fs = open_account_storage("correct horse battery staple", salt, root)
    fs.write("/notes.txt", b"Only someone who knows the password can read this.")
    fs.close()

    # --- A later login with the same password re-derives the identical key ---
    fs = open_account_storage("correct horse battery staple", salt, root)
    print(fs.read("/notes.txt").decode())
    fs.close()

    # --- A wrong password derives a different (unusable) key ---
    wrong_key = derive_master_key("some other guess", salt)
    right_key = derive_master_key("correct horse battery staple", salt)
    assert wrong_key != right_key, "different passwords must derive different keys"
    print("Confirmed: guessing the wrong password yields a different key.")
