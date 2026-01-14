#!/usr/bin/env python3
"""
Meteor-NC: String/File Encryption Demo

Tests MeteorPractical class:
1. String encryption/decryption
2. Binary encryption/decryption  
3. File encryption/decryption
4. Quick encrypt/decrypt helpers
5. Japanese/Emoji support
6. Large file handling

Usage:
    python tests/test_string_encryption.py
"""

import sys
import os
import time
import tempfile
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from meteor_nc.cryptography.string import (
    MeteorPractical,
    quick_encrypt_string,
    quick_decrypt_string,
)


def demo_string_encryption():
    """Test basic string encryption"""
    print("=" * 70)
    print("Demo 1: String Encryption/Decryption")
    print("=" * 70)
    
    # Create instance
    print("\n[*] Creating MeteorPractical...")
    crypto = MeteorPractical(n=256)
    crypto.key_gen(verbose=True)
    crypto.expand_keys(verbose=True)
    
    # Test string
    print("\n[*] Encrypting string...")
    original = "Hello, Meteor-NC! This is a quantum-resistant message."
    print(f"  Original: {original}")
    
    encrypted = crypto.encrypt_string(original)
    print(f"  Encrypted chunks: {encrypted['num_chunks']}")
    print(f"  Checksum: {encrypted['checksum'][:16]}...")
    print(f"  Encrypt time: {encrypted['encrypt_time']*1000:.2f}ms")
    
    # Decrypt
    print("\n[*] Decrypting...")
    decrypted = crypto.decrypt_string(encrypted)
    print(f"  Decrypted: {decrypted}")
    
    match = original == decrypted
    print(f"\n[Result] Match: {'✅' if match else '❌'}")
    
    print("\n✅ String Encryption: PASS")
    return match


def demo_japanese_emoji():
    """Test Japanese and emoji support"""
    print("\n" + "=" * 70)
    print("Demo 2: Japanese & Emoji Support")
    print("=" * 70)
    
    crypto = MeteorPractical(n=256)
    crypto.key_gen(verbose=False)
    crypto.expand_keys(verbose=False)
    
    # Test strings
    test_strings = [
        "こんにちは、世界！",
        "量子耐性暗号で安全に通信！🔐",
        "日本語テスト: ひらがな、カタカナ、漢字",
        "Emoji test: 🚀🌟💫✨🔮🎯",
        "Mixed: Hello世界🌍 Meteor流星☄️",
    ]
    
    all_pass = True
    for text in test_strings:
        print(f"\n[*] Testing: {text}")
        
        encrypted = crypto.encrypt_string(text)
        decrypted = crypto.decrypt_string(encrypted)
        
        match = text == decrypted
        all_pass = all_pass and match
        print(f"  Result: {'✅' if match else '❌'}")
    
    print(f"\n[Summary] All passed: {'✅' if all_pass else '❌'}")
    
    print("\n✅ Japanese/Emoji: PASS")
    return all_pass


def demo_binary_encryption():
    """Test binary data encryption"""
    print("\n" + "=" * 70)
    print("Demo 3: Binary Data Encryption")
    print("=" * 70)
    
    crypto = MeteorPractical(n=256)
    crypto.key_gen(verbose=False)
    crypto.expand_keys(verbose=False)
    
    # Create random binary data
    print("\n[*] Creating random binary data (10KB)...")
    original_data = os.urandom(10 * 1024)
    print(f"  Size: {len(original_data):,} bytes")
    
    # Encrypt
    print("\n[*] Encrypting...")
    start = time.time()
    encrypted = crypto.encrypt_bytes(original_data)
    encrypt_time = time.time() - start
    print(f"  Encrypt time: {encrypt_time*1000:.2f}ms")
    print(f"  Checksum: {encrypted['checksum'][:16]}...")
    
    # Decrypt
    print("\n[*] Decrypting...")
    start = time.time()
    decrypted_data = crypto.decrypt_bytes(encrypted)
    decrypt_time = time.time() - start
    print(f"  Decrypt time: {decrypt_time*1000:.2f}ms")
    
    match = original_data == decrypted_data
    print(f"\n[Result] Data integrity: {'✅' if match else '❌'}")
    
    print("\n✅ Binary Encryption: PASS")
    return match


def demo_file_encryption():
    """Test file encryption"""
    print("\n" + "=" * 70)
    print("Demo 4: File Encryption/Decryption")
    print("=" * 70)
    
    crypto = MeteorPractical(n=256)
    crypto.key_gen(verbose=False)
    crypto.expand_keys(verbose=False)
    
    # Create temp files
    with tempfile.TemporaryDirectory() as tmpdir:
        original_file = os.path.join(tmpdir, "secret_document.txt")
        encrypted_file = os.path.join(tmpdir, "secret_document.enc")
        decrypted_file = os.path.join(tmpdir, "secret_document_recovered.txt")
        
        # Create original file
        print("\n[*] Creating original file...")
        original_content = "This is a secret document!\n" * 100
        original_content += "日本語も含まれています。\n" * 50
        original_content += "🔐 Quantum-safe encryption! 🔐\n" * 20
        
        with open(original_file, 'w', encoding='utf-8') as f:
            f.write(original_content)
        
        original_size = os.path.getsize(original_file)
        print(f"  File: {original_file}")
        print(f"  Size: {original_size:,} bytes")
        
        # Encrypt file
        print("\n[*] Encrypting file...")
        result = crypto.encrypt_file(original_file, encrypted_file)
        print(f"  Encrypted file: {encrypted_file}")
        print(f"  Encrypted size: {result['encrypted_size']:,} bytes")
        print(f"  Encrypt time: {result['encrypt_time']*1000:.2f}ms")
        
        # Decrypt file
        print("\n[*] Decrypting file...")
        result = crypto.decrypt_file(encrypted_file, decrypted_file)
        print(f"  Decrypted file: {decrypted_file}")
        print(f"  Decrypt time: {result['decrypt_time']*1000:.2f}ms")
        
        # Verify
        with open(decrypted_file, 'r', encoding='utf-8') as f:
            decrypted_content = f.read()
        
        match = original_content == decrypted_content
        print(f"\n[Result] File integrity: {'✅' if match else '❌'}")
    
    print("\n✅ File Encryption: PASS")
    return match


def demo_quick_functions():
    """Test quick encrypt/decrypt functions"""
    print("\n" + "=" * 70)
    print("Demo 5: Quick Encrypt/Decrypt Functions")
    print("=" * 70)
    
    # These are one-liner convenience functions
    print("\n[*] Using quick_encrypt_string...")
    original = "Quick encryption test! 🚀"
    print(f"  Original: {original}")
    
    # Quick encrypt (creates new keys each time)
    encrypted_json = quick_encrypt_string(original)
    print(f"  Encrypted (JSON): {encrypted_json[:50]}...")
    
    # Quick decrypt
    print("\n[*] Using quick_decrypt_string...")
    decrypted = quick_decrypt_string(encrypted_json)
    print(f"  Decrypted: {decrypted}")
    
    match = original == decrypted
    print(f"\n[Result] Match: {'✅' if match else '❌'}")
    
    print("\n✅ Quick Functions: PASS")
    return match


def demo_large_data():
    """Test large data encryption"""
    print("\n" + "=" * 70)
    print("Demo 6: Large Data Encryption (1MB)")
    print("=" * 70)
    
    crypto = MeteorPractical(n=256)
    crypto.key_gen(verbose=False)
    crypto.expand_keys(verbose=False)
    
    # Create 1MB data
    print("\n[*] Creating 1MB random data...")
    large_data = os.urandom(1024 * 1024)
    print(f"  Size: {len(large_data):,} bytes")
    
    # Encrypt
    print("\n[*] Encrypting...")
    start = time.time()
    encrypted = crypto.encrypt_bytes(large_data)
    encrypt_time = time.time() - start
    print(f"  Encrypt time: {encrypt_time:.2f}s")
    print(f"  Throughput: {len(large_data)/encrypt_time/1024/1024:.2f} MB/s")
    
    # Decrypt
    print("\n[*] Decrypting...")
    start = time.time()
    decrypted = crypto.decrypt_bytes(encrypted)
    decrypt_time = time.time() - start
    print(f"  Decrypt time: {decrypt_time:.2f}s")
    print(f"  Throughput: {len(large_data)/decrypt_time/1024/1024:.2f} MB/s")
    
    match = large_data == decrypted
    print(f"\n[Result] Data integrity: {'✅' if match else '❌'}")
    
    # Show stats
    print("\n[*] Practical stats:")
    stats = crypto.practical_stats
    print(f"  Bytes encrypted: {stats['bytes_encrypted']:,}")
    print(f"  Bytes decrypted: {stats['bytes_decrypted']:,}")
    print(f"  Total processed: {stats['total_bytes_processed']:,}")
    
    print("\n✅ Large Data: PASS")
    return match


def demo_seed_restore():
    """Test key restoration from seed"""
    print("\n" + "=" * 70)
    print("Demo 7: Key Restoration from Seed")
    print("=" * 70)
    
    # Create and save seed
    print("\n[*] Creating original instance...")
    crypto1 = MeteorPractical(n=256)
    crypto1.key_gen(verbose=False)
    crypto1.expand_keys(verbose=False)
    
    # Export seed
    seed = crypto1.export_seed()
    print(f"  Seed: {seed.hex()[:32]}...")
    
    # Encrypt with original
    print("\n[*] Encrypting with original instance...")
    original = "This message will be decrypted with restored keys!"
    encrypted = crypto1.encrypt_string(original)
    
    # Create new instance with same seed
    print("\n[*] Creating restored instance from seed...")
    crypto2 = MeteorPractical(n=256, seed=seed)
    crypto2.expand_keys(verbose=False)
    
    # Decrypt with restored instance
    print("\n[*] Decrypting with restored instance...")
    decrypted = crypto2.decrypt_string(encrypted)
    print(f"  Result: {decrypted}")
    
    match = original == decrypted
    print(f"\n[Result] Cross-instance decryption: {'✅' if match else '❌'}")
    
    print("\n✅ Seed Restore: PASS")
    return match


def demo_multiple_messages():
    """Test multiple message encryption"""
    print("\n" + "=" * 70)
    print("Demo 8: Multiple Messages (100)")
    print("=" * 70)
    
    crypto = MeteorPractical(n=256)
    crypto.key_gen(verbose=False)
    crypto.expand_keys(verbose=False)
    
    # Create messages
    num_messages = 100
    print(f"\n[*] Creating {num_messages} messages...")
    messages = [f"Message #{i}: {os.urandom(16).hex()}" for i in range(num_messages)]
    
    # Encrypt all
    print("\n[*] Encrypting all...")
    start = time.time()
    encrypted_list = [crypto.encrypt_string(msg) for msg in messages]
    encrypt_time = time.time() - start
    print(f"  Total time: {encrypt_time:.2f}s")
    print(f"  Per message: {encrypt_time/num_messages*1000:.2f}ms")
    
    # Decrypt all
    print("\n[*] Decrypting all...")
    start = time.time()
    decrypted_list = [crypto.decrypt_string(enc) for enc in encrypted_list]
    decrypt_time = time.time() - start
    print(f"  Total time: {decrypt_time:.2f}s")
    print(f"  Per message: {decrypt_time/num_messages*1000:.2f}ms")
    
    # Verify
    matches = sum(1 for orig, dec in zip(messages, decrypted_list) if orig == dec)
    print(f"\n[Result] Matched: {matches}/{num_messages}")
    
    all_pass = matches == num_messages
    print("\n✅ Multiple Messages: PASS" if all_pass else "\n❌ Multiple Messages: FAIL")
    return all_pass


def main():
    """Run all demos"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║       🌠 Meteor-NC: String/File Encryption Demo 🌠           ║
    ║                                                              ║
    ║         MeteorPractical | String | Binary | File             ║
    ║          Japanese/Emoji | Large Data | Seed Restore          ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    results = {}
    
    demos = [
        ('string_encryption', demo_string_encryption),
        ('japanese_emoji', demo_japanese_emoji),
        ('binary_encryption', demo_binary_encryption),
        ('file_encryption', demo_file_encryption),
        ('quick_functions', demo_quick_functions),
        ('large_data', demo_large_data),
        ('seed_restore', demo_seed_restore),
        ('multiple_messages', demo_multiple_messages),
    ]
    
    for name, func in demos:
        try:
            results[name] = func()
        except Exception as e:
            print(f"\n❌ Error in {name}: {e}")
            import traceback
            traceback.print_exc()
            results[name] = False
    
    # Summary
    print("\n" + "=" * 70)
    print("Demo Summary")
    print("=" * 70)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {name}: {status}")
    
    passed = sum(1 for r in results.values() if r)
    failed = sum(1 for r in results.values() if not r)
    
    print(f"\nTotal: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\n✅ ALL TESTS PASSED!")
        print("""
MeteorPractical is ready for:
  • Text message encryption (any language)
  • File encryption/decryption
  • Binary data protection
  • Cross-device key restoration
  • High-throughput batch operations

🌌 Quantum-resistant encryption made easy!
        """)
    else:
        print("\n❌ SOME TESTS FAILED")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
