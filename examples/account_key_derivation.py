"""
Per-account master key derivation, with a server-only pepper.

Use this when each user account should get its own SecureFS storage, keyed
from something the account owner provides (e.g. their password), while still
guaranteeing that the account owner -- or anyone who steals the database --
cannot derive the master key without a secret that only the server holds.

See derive_master_key() in securefs.utils for the full explanation of why
two independent secrets (account_secret + server_pepper) are required.
"""

import os
import tempfile
from pathlib import Path

from securefs import SecureFSWrapper
from securefs.utils import derive_master_key, generate_salt


# The pepper lives only in server configuration (env var, secrets manager,
# KMS/HSM) -- NEVER in the same database/table as the accounts it protects.
# `os.environ["SECUREFS_PEPPER"]` (raising if unset) is what production code
# should do; a fixed value is used here only so the example is runnable.
SERVER_PEPPER = bytes.fromhex(os.environ.get("SECUREFS_PEPPER", "ab" * 32))


def open_account_storage(account_password: str, account_salt: bytes, root: Path) -> SecureFSWrapper:
    """Open (or create) the SecureFS storage for one account.

    `account_salt` is generated once per account (generate_salt()) and stored
    next to the account row -- it is not secret, just unique per account.
    """
    master_key = derive_master_key(account_password, account_salt, SERVER_PEPPER)
    return SecureFSWrapper(
        master_key=master_key, db_path=root / "index.db", storage_root=root / "data"
    )


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)

    # --- Account creation (once) ---
    # A real app stores `salt` in the accounts table, next to the (separately
    # hashed, e.g. with the same account_password) login credentials.
    salt = generate_salt()

    # --- Login (every session) ---
    fs = open_account_storage("correct horse battery staple", salt, root)
    fs.write("/notes.txt", b"Only this account (with the server pepper) can read this.")
    fs.close()

    # --- A later login re-derives the identical master key ---
    fs = open_account_storage("correct horse battery staple", salt, root)
    print(fs.read("/notes.txt").decode())
    fs.close()

    # --- Without the server pepper, the password + salt are not enough ---
    real_key = derive_master_key("correct horse battery staple", salt, SERVER_PEPPER)
    guessed_key = derive_master_key("correct horse battery staple", salt, b"\x00" * 32)
    assert real_key != guessed_key, "the pepper must matter"
    print("Confirmed: guessing without the server pepper yields a different key.")
