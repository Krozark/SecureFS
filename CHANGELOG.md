# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

Security-driven rework. The on-disk format changed several times and no
migration is provided: **stores created before this release cannot be read**.

### Security

- Refuse to serve unencrypted records when `encryption_enabled=True`. Files
  written in development mode sit in the clear on disk; serving them from an
  encrypted instance presented unprotected content as protected.
- Verify the keyed integrity tag unconditionally when nothing else
  authenticated the content, so `verify_integrity=False` and
  `skip_verification=True` can no longer be used to accept forged content.
- Re-derive the storage filename from the logical path on every read and
  delete instead of trusting a database column, so a tampered index cannot
  redirect a read to another file's content.
- Derive three independent HKDF subkeys from the master key (content-key
  wrapping, path MAC, integrity MAC) rather than reusing the master key
  directly across AES-GCM and HMAC.
- Commit the metadata removal before unlinking in `delete()`. The previous
  order could destroy content while leaving a row claiming it existed.

### Added

- `derive_master_key()` and `generate_salt()`: derive a master key from an
  account password with scrypt, for fully local/offline use.
- `cleanup_orphaned_files()`: remove `.tmp`/`.bak` leftovers, and optionally
  unreferenced `.dat` files.
- `py.typed`, so the type hints the package already had actually ship.

### Changed

- Schema version 3.0: the `dat_filename` column is gone. It duplicated a pure
  function of (master key, logical path) and gave a tamperable second mapping
  from a row to a file.
- Reading legacy plaintext from an encrypted instance is no longer supported;
  migrating is now an explicit step (see `examples/migration_example.py`).
- `get_statistics()` reads the cache under the lock, like every other accessor.

### Documentation

- Thread-safety buys correctness, not throughput: measured, concurrent reads
  do not go faster, and removing the lock makes them slower.
- README documents the threat model, including what is deliberately *not*
  protected.

### Removed

- "Migration support" as an advertised feature: no such API existed.

## [1.0.0] - 2024-12-04

### Added
- Initial release of SecureFS
- Transparent file encryption with AES-256-GCM
- Two-level encryption architecture
- SQLite metadata storage
- Integrity verification
- Thread-safe operations
- Optional caching
- Development mode
- Modern tooling with Ruff
