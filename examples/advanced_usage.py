"""
Advanced usage examples for SecureFS
"""

import os
import shutil
import threading

from securefs import FileCorruptionError, SecureFSWrapper
from securefs.utils import generate_master_key


def cleanup():
    """Clean up example files"""
    for path in ["./advanced_index.db", "./advanced_data"]:
        if os.path.exists(path):
            if os.path.isfile(path):
                os.remove(path)
            else:
                shutil.rmtree(path)


def example_caching():
    """Example: Using cache for better performance"""
    print("\\n📦 Example: Caching")
    print("-" * 60)

    master_key = generate_master_key()

    # With cache enabled
    fs = SecureFSWrapper(
        master_key=master_key,
        db_path="./advanced_index.db",
        storage_root="./advanced_data",
        cache_enabled=True,
    )

    # Write a file
    large_data = b"X" * 1024 * 1024  # 1 MB
    fs.write("/large_file.bin", large_data)

    # First read (from disk)
    import time

    start = time.time()
    fs.read("/large_file.bin")
    first_time = time.time() - start

    # Second read (from cache)
    start = time.time()
    fs.read("/large_file.bin")
    cached_time = time.time() - start

    print(f"First read: {first_time:.4f}s")
    print(f"Cached read: {cached_time:.4f}s")
    print(f"Speed improvement: {first_time / cached_time:.1f}x faster")

    # Check cache statistics
    stats = fs.get_statistics()
    print(f"\\nCache entries: {stats['cache_entries']}")

    # Clear cache
    fs.clear_cache()
    print("Cache cleared")

    fs.close()
    cleanup()


def example_threading():
    """Example: Thread-safe operations"""
    print("\\n🧵 Example: Multi-threading")
    print("-" * 60)

    master_key = generate_master_key()

    fs = SecureFSWrapper(
        master_key=master_key, db_path="./advanced_index.db", storage_root="./advanced_data"
    )

    def writer_thread(thread_id, count):
        for i in range(count):
            path = f"/thread{thread_id}/file{i}.txt"
            content = f"Thread {thread_id}, File {i}".encode()
            fs.write(path, content)

    # Start multiple threads
    threads = []
    for i in range(5):
        t = threading.Thread(target=writer_thread, args=(i, 10))
        threads.append(t)
        t.start()

    # Wait for all threads
    for t in threads:
        t.join()

    # Verify all files
    files = fs.list_files()
    print(f"Created {len(files)} files across 5 threads")
    print("✅ All operations completed successfully")

    fs.close()
    cleanup()


def example_error_handling():
    """Example: Error handling and integrity checks"""
    print("\\n⚠️  Example: Error handling")
    print("-" * 60)

    master_key = generate_master_key()

    fs = SecureFSWrapper(
        master_key=master_key,
        db_path="./advanced_index.db",
        storage_root="./advanced_data",
        verify_integrity=True,
    )

    # Write a file
    fs.write("/test.txt", b"Test content")

    # Try to read with wrong key
    wrong_key = generate_master_key()
    fs_wrong = SecureFSWrapper(
        master_key=wrong_key, db_path="./advanced_index.db", storage_root="./advanced_data"
    )

    try:
        fs_wrong.read("/test.txt")
        print("❌ Should have failed with wrong key")
    except Exception as e:
        print(f"✅ Correctly rejected wrong key: {type(e).__name__}")

    fs_wrong.close()

    # Simulate file corruption
    from pathlib import Path

    dat_files = list(Path("./advanced_data").glob("*.dat"))
    if dat_files:
        with open(dat_files[0], "rb") as f:
            data = bytearray(f.read())
        data[20] ^= 0xFF  # Corrupt one byte
        with open(dat_files[0], "wb") as f:
            f.write(data)

        try:
            fs.read("/test.txt")
            print("❌ Should have detected corruption")
        except FileCorruptionError:
            print("✅ Correctly detected file corruption")

    fs.close()
    cleanup()


def main():
    print("SecureFS - Advanced Usage Examples")
    print("=" * 60)

    example_caching()
    example_threading()
    example_error_handling()

    print("\\n✅ All advanced examples completed!")


if __name__ == "__main__":
    main()
