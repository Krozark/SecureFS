"""
Migration example: moving development (plaintext) data into encrypted storage.

Files written with encryption_enabled=False sit in the clear on disk. An
encrypted instance deliberately refuses to read them -- serving them would mean
calling "protected" something that anyone able to copy the storage directory
can already read. Migrating them is therefore explicit: read them in
development mode, then write them back through an encrypted instance.
"""

import tempfile
from pathlib import Path

from securefs import EncryptionError, SecureFSWrapper
from securefs.utils import generate_master_key


def main():
    print("SecureFS - Migration Example")
    print("=" * 60)

    master_key = generate_master_key()

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        db_path = root / "migration_index.db"
        storage_root = root / "migration_data"

        def open_store(*, encrypted: bool) -> SecureFSWrapper:
            return SecureFSWrapper(
                master_key=master_key,
                db_path=db_path,
                storage_root=storage_root,
                encryption_enabled=encrypted,
            )

        # Phase 1: development mode -- content is stored in the clear.
        print("\n📝 Phase 1: Development mode (plaintext)")
        print("-" * 60)

        dev_fs = open_store(encrypted=False)
        dev_fs.write("/app/config.txt", b"Debug mode enabled")
        dev_fs.write("/app/data.txt", b"Development data")
        legacy_paths = dev_fs.list_files()
        dev_fs.close()

        print(f"✅ Created {len(legacy_paths)} plaintext files: {legacy_paths}")

        # The content really is readable without any key.
        sample = next(storage_root.glob("*.dat")).read_bytes()
        print(f"⚠️  Raw on disk, no key needed: {sample[12:]!r}")

        # Phase 2: an encrypted instance refuses to serve that unprotected data.
        print("\n📝 Phase 2: Production mode (encrypted)")
        print("-" * 60)

        prod_fs = open_store(encrypted=True)
        try:
            prod_fs.read(legacy_paths[0])
        except EncryptionError:
            print("✅ Encrypted instance refused the unprotected legacy file")

        # Phase 3: migrate explicitly -- read in development mode, write back
        # through the encrypted instance.
        print("\n📝 Phase 3: Migrating the legacy files")
        print("-" * 60)

        dev_fs = open_store(encrypted=False)
        recovered = {path: dev_fs.read(path, bypass_cache=True) for path in legacy_paths}
        dev_fs.close()

        for path, content in recovered.items():
            prod_fs.write(path, content)
            print(f"  ✅ {path}: {len(content)} bytes re-encrypted")

        prod_fs.write("/app/secrets.txt", b"Production secrets")

        # Everything is now encrypted and readable again.
        print("\n🔍 Verifying all files:")
        for path in prod_fs.list_files():
            content = prod_fs.read(path, bypass_cache=True)
            print(f"  ✅ {path}: {len(content)} bytes")

        on_disk = b"".join(p.read_bytes() for p in storage_root.glob("*.dat"))
        assert b"Debug mode enabled" not in on_disk, "migrated content must not stay in clear"
        print("\n✅ No plaintext left in the storage directory")

        # Phase 4: clear out what the migration left behind.
        removed = prod_fs.cleanup_orphaned_files(include_orphaned_data=True)
        print(f"🧹 Cleanup removed: {removed}")

        prod_fs.close()

    print("\n✅ Migration example completed!")
    print("\n💡 Key takeaway: an encrypted store never serves unencrypted content.")
    print("   Migrating legacy plaintext is an explicit, deliberate step.")


if __name__ == "__main__":
    main()
