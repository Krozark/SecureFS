"""
Migration example: switching between encrypted and plaintext modes
"""

import os
import shutil

from securefs import SecureFSWrapper
from securefs.utils import generate_master_key


def cleanup():
    """Clean up example files"""
    if os.path.exists("./migration_index.db"):
        os.remove("./migration_index.db")
    if os.path.exists("./migration_data"):
        shutil.rmtree("./migration_data")


def main():
    print("SecureFS - Migration Example")
    print("=" * 60)

    # Generate a master key
    master_key = generate_master_key()

    # Phase 1: Development (plaintext)
    print("\\n📝 Phase 1: Development mode (plaintext)")
    print("-" * 60)

    dev_fs = SecureFSWrapper(
        master_key=master_key,
        db_path="./migration_index.db",
        storage_root="./migration_data",
        encryption_enabled=False,  # Plaintext mode
    )

    dev_fs.write("/app/config.txt", b"Debug mode enabled")
    dev_fs.write("/app/data.txt", b"Development data")

    print("✅ Created 2 plaintext files")
    print(f"📋 Files: {dev_fs.list_files()}")

    dev_fs.close()

    # Phase 2: Production (encrypted)
    print("\\n📝 Phase 2: Production mode (encrypted)")
    print("-" * 60)

    prod_fs = SecureFSWrapper(
        master_key=master_key,
        db_path="./migration_index.db",
        storage_root="./migration_data",
        encryption_enabled=True,  # Encrypted mode
    )

    # Read old plaintext files
    print("📖 Reading old plaintext files:")
    config = prod_fs.read("/app/config.txt")
    data = prod_fs.read("/app/data.txt")
    print(f"  - config.txt: {config.decode()}")
    print(f"  - data.txt: {data.decode()}")

    # Write new encrypted files
    prod_fs.write("/app/secrets.txt", b"Production secrets")
    print("\\n✅ Created new encrypted file")

    # List all files (mix of plaintext and encrypted)
    print(f"\\n📋 All files: {prod_fs.list_files()}")

    # Verify all files are accessible
    print("\\n🔍 Verifying all files are readable:")
    for path in prod_fs.list_files():
        content = prod_fs.read(path)
        print(f"  ✅ {path}: {len(content)} bytes")

    prod_fs.close()

    print("\\n✅ Migration example completed!")
    print("\\n💡 Key takeaway: SecureFS automatically handles mixed")
    print("   encrypted/plaintext files based on the nonce in the database.")

    # Clean up
    cleanup()


if __name__ == "__main__":
    main()
