"""
Basic usage example for SecureFS
"""

import shutil
from pathlib import Path

from securefs import SecureFSWrapper
from securefs.utils import generate_master_key


def main():
    print("SecureFS - Basic Usage Example")
    print("=" * 60)

    # Generate a master key
    master_key = generate_master_key()
    print(f"\\nGenerated master key: {master_key.hex()}")
    print("⚠️  Store this key securely! You'll need it to access your files.")

    # Initialize SecureFS
    fs = SecureFSWrapper(
        master_key=master_key,
        db_path="./example_index.db",
        storage_root="./example_data",
        encryption_enabled=True,
        verify_integrity=True,
    )

    print("\\n✅ SecureFS initialized")

    # Write some files
    print("\\n📝 Writing files...")
    fs.write("/documents/readme.txt", b"Hello, SecureFS!")
    fs.write("/documents/secret.txt", b"This is a secret message")
    fs.write("/data/config.json", b'{"debug": false, "version": "1.0"}')
    print("✅ Files written")

    # List all files
    print("\\n📋 Files in storage:")
    for path in fs.list_files():
        info = fs.get_info(path)
        print(f"  - {path} ({info['size']} bytes)")

    # Read a file
    print("\\n📖 Reading /documents/readme.txt:")
    content = fs.read("/documents/readme.txt")
    print(f"  Content: {content.decode()}")

    # Get statistics
    stats = fs.get_statistics()
    print("\\n📊 Statistics:")
    print(f"  - Total files: {stats['total_files']}")
    print(f"  - Total size: {stats['total_size_bytes']} bytes")
    print(f"  - Encryption: {'Enabled' if stats['encryption_enabled'] else 'Disabled'}")

    # Verify integrity
    print("\\n🔍 Verifying file integrity...")
    results = fs.verify_all_files()
    all_ok = all(results.values())
    print(f"  {'✅ All files OK' if all_ok else '❌ Some files corrupted'}")

    # Clean up
    fs.close()
    print("\\n✅ Example completed!")

    # Clean up example files
    db = Path("./example_index.db")
    data = Path("./example_data")
    if db.exists():
        db.unlink()
    if data.exists():
        shutil.rmtree(data)


if __name__ == "__main__":
    main()
