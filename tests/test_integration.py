# tests/test_integration.py
"""
Meteor-NC P2P Protocol Integration Test Suite for TCHES

End-to-end tests for complete P2P communication flow:
  I1. Basic P2P Message Exchange (Alice ↔ Bob)
  I2. Multi-Party Communication (Alice, Bob, Charlie)
  I3. Identity & Authentication (seed-based key recovery)
  I4. Tamper Detection (cascade failure)
  I5. File Transfer
  I6. Performance Benchmark
"""

import secrets
import time
import json
import numpy as np
from typing import Dict

import sys
sys.path.insert(0, '/content/meteor-nc')

from meteor_nc.cryptography.common import (
    _sha256, GPU_AVAILABLE, CRYPTO_AVAILABLE,
)


# =============================================================================
# I1. Basic P2P Message Exchange
# =============================================================================

def test_i1_basic_p2p_exchange() -> Dict:
    """
    I1: Complete P2P message exchange
    
    Flow:
    1. Alice & Bob create identities
    2. Exchange public identities
    3. Alice → Bob: "Hello Bob!"
    4. Bob decrypts
    5. Bob → Alice: "Hello Alice!"
    6. Alice decrypts
    """
    print("\n[I1] Basic P2P Message Exchange")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.practical import MeteorPractical
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # === Step 1: Create identities ===
    print("  Step 1: Creating identities...")
    alice = MeteorPractical(name="Alice", security_level=128, gpu=GPU_AVAILABLE)
    bob = MeteorPractical(name="Bob", security_level=128, gpu=GPU_AVAILABLE)
    
    results['tests'].append(("Create identities", "PASS"))
    results['pass'] += 1
    
    # === Step 2: Exchange public identities ===
    print("  Step 2: Exchanging public identities...")
    alice_pub = alice.get_public_identity()
    bob_pub = bob.get_public_identity()
    
    alice.add_contact("Bob", bob_pub)
    bob.add_contact("Alice", alice_pub)
    
    results['tests'].append(("Exchange identities", "PASS"))
    results['pass'] += 1
    
    # === Step 3: Alice → Bob ===
    print("  Step 3: Alice encrypts message for Bob...")
    message_to_bob = "Hello Bob! This is a secret message from Alice."
    encrypted = alice.encrypt_string("Bob", message_to_bob)
    
    results['tests'].append(("Alice encrypts", "PASS"))
    results['pass'] += 1
    
    # === Step 4: Bob decrypts ===
    print("  Step 4: Bob decrypts message...")
    try:
        decrypted = bob.decrypt_string(encrypted)
        if decrypted == message_to_bob:
            results['tests'].append(("Bob decrypts", "PASS"))
            results['pass'] += 1
        else:
            results['tests'].append(("Bob decrypts", f"FAIL (mismatch)"))
            results['fail'] += 1
    except Exception as e:
        results['tests'].append(("Bob decrypts", f"ERROR: {e}"))
        results['fail'] += 1
    
    # === Step 5: Bob → Alice ===
    print("  Step 5: Bob encrypts reply for Alice...")
    message_to_alice = "Hello Alice! Got your message. This is Bob's reply."
    encrypted_reply = bob.encrypt_string("Alice", message_to_alice)
    
    results['tests'].append(("Bob encrypts", "PASS"))
    results['pass'] += 1
    
    # === Step 6: Alice decrypts ===
    print("  Step 6: Alice decrypts reply...")
    try:
        decrypted_reply = alice.decrypt_string(encrypted_reply)
        if decrypted_reply == message_to_alice:
            results['tests'].append(("Alice decrypts", "PASS"))
            results['pass'] += 1
        else:
            results['tests'].append(("Alice decrypts", f"FAIL (mismatch)"))
            results['fail'] += 1
    except Exception as e:
        results['tests'].append(("Alice decrypts", f"ERROR: {e}"))
        results['fail'] += 1
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# I2. Multi-Party Communication
# =============================================================================

def test_i2_multi_party() -> Dict:
    """
    I2: Multi-party communication (Alice, Bob, Charlie)
    
    Each person can encrypt to any other person.
    """
    print("\n[I2] Multi-Party Communication")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.practical import MeteorPractical
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Create 3 parties
    print("  Creating 3 parties...")
    alice = MeteorPractical(name="Alice", security_level=128, gpu=GPU_AVAILABLE)
    bob = MeteorPractical(name="Bob", security_level=128, gpu=GPU_AVAILABLE)
    charlie = MeteorPractical(name="Charlie", security_level=128, gpu=GPU_AVAILABLE)
    
    parties = {"Alice": alice, "Bob": bob, "Charlie": charlie}
    
    # Exchange all public identities
    print("  Exchanging identities...")
    for name1, party1 in parties.items():
        for name2, party2 in parties.items():
            if name1 != name2:
                party1.add_contact(name2, party2.get_public_identity())
    
    # Test all communication pairs
    pairs = [
        ("Alice", "Bob"),
        ("Alice", "Charlie"),
        ("Bob", "Alice"),
        ("Bob", "Charlie"),
        ("Charlie", "Alice"),
        ("Charlie", "Bob"),
    ]
    
    for sender_name, receiver_name in pairs:
        sender = parties[sender_name]
        receiver = parties[receiver_name]
        
        message = f"Secret from {sender_name} to {receiver_name}"
        
        try:
            encrypted = sender.encrypt_string(receiver_name, message)
            decrypted = receiver.decrypt_string(encrypted)
            
            if decrypted == message:
                results['pass'] += 1
                results['tests'].append((f"{sender_name}→{receiver_name}", "PASS"))
            else:
                results['fail'] += 1
                results['tests'].append((f"{sender_name}→{receiver_name}", "FAIL"))
        except Exception as e:
            results['fail'] += 1
            results['tests'].append((f"{sender_name}→{receiver_name}", f"ERROR: {e}"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# I3. Identity & Authentication
# =============================================================================

def test_i3_identity_auth() -> Dict:
    """
    I3: Identity recovery from seed
    
    Same seed → same keys → can decrypt old messages
    """
    print("\n[I3] Identity & Authentication")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.practical import MeteorPractical
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # === Test 1: Seed-based identity recovery ===
    print("  Test 1: Seed-based identity recovery...")
    
    # Alice creates identity with specific seed
    seed_alice = secrets.token_bytes(32)
    alice1 = MeteorPractical(name="Alice", seed=seed_alice, gpu=GPU_AVAILABLE)
    
    # Bob sends message to Alice
    bob = MeteorPractical(name="Bob", gpu=GPU_AVAILABLE)
    bob.add_contact("Alice", alice1.get_public_identity())
    
    message = "Important secret message"
    encrypted = bob.encrypt_string("Alice", message)
    
    # Alice "loses" her device but recovers with same seed
    alice2 = MeteorPractical(name="Alice", seed=seed_alice, gpu=GPU_AVAILABLE)
    
    # Verify same meteor_id
    same_id = alice1.meteor_id == alice2.meteor_id
    if same_id:
        results['pass'] += 1
        results['tests'].append(("Same seed → same meteor_id", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Same seed → same meteor_id", "FAIL"))
    
    # Verify can decrypt with recovered identity
    try:
        decrypted = alice2.decrypt_string(encrypted)
        if decrypted == message:
            results['pass'] += 1
            results['tests'].append(("Recovered identity decrypts", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("Recovered identity decrypts", "FAIL"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Recovered identity decrypts", f"ERROR: {e}"))
    
    # === Test 2: Different seed → different identity ===
    print("  Test 2: Different seed → different identity...")
    
    seed_different = secrets.token_bytes(32)
    alice3 = MeteorPractical(name="Alice", seed=seed_different, gpu=GPU_AVAILABLE)
    
    different_id = alice1.meteor_id != alice3.meteor_id
    if different_id:
        results['pass'] += 1
        results['tests'].append(("Different seed → different id", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Different seed → different id", "FAIL"))
    
    # Cannot decrypt with different seed
    try:
        alice3.decrypt_string(encrypted)
        results['fail'] += 1
        results['tests'].append(("Wrong seed rejected", "FAIL (not rejected)"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("Wrong seed rejected", "PASS"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# I4. Tamper Detection
# =============================================================================

def test_i4_tamper_detection() -> Dict:
    """
    I4: Tamper detection
    
    Any modification to ciphertext → decryption fails
    """
    print("\n[I4] Tamper Detection")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.practical import MeteorPractical, EncryptedMessage
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Setup
    alice = MeteorPractical(name="Alice", gpu=GPU_AVAILABLE)
    bob = MeteorPractical(name="Bob", gpu=GPU_AVAILABLE)
    
    alice.add_contact("Bob", bob.get_public_identity())
    bob.add_contact("Alice", alice.get_public_identity())
    
    message = "Authentic message"
    encrypted = alice.encrypt_string("Bob", message)
    
    # === Test 1: Valid message decrypts ===
    try:
        decrypted = bob.decrypt_string(encrypted)
        if decrypted == message:
            results['pass'] += 1
            results['tests'].append(("Valid message", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("Valid message", "FAIL"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Valid message", f"ERROR: {e}"))
    
    # === Test 2: Tampered ciphertext rejected ===
    print("  Testing ciphertext tamper...")
    try:
        # Create tampered message
        ct_tampered = bytearray(encrypted.ciphertext)
        ct_tampered[0] ^= 1
        
        msg_tampered = EncryptedMessage(
            kem_ciphertext=encrypted.kem_ciphertext,
            ciphertext=bytes(ct_tampered),
            tag=encrypted.tag,
            nonce=encrypted.nonce,
            sender_id=encrypted.sender_id,
        )
        
        bob.decrypt_string(msg_tampered)
        results['fail'] += 1
        results['tests'].append(("CT tamper rejected", "FAIL (not rejected)"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("CT tamper rejected", "PASS"))
    
    # === Test 3: Tampered tag rejected ===
    print("  Testing tag tamper...")
    try:
        tag_tampered = bytearray(encrypted.tag)
        tag_tampered[0] ^= 1
        
        msg_tampered = EncryptedMessage(
            kem_ciphertext=encrypted.kem_ciphertext,
            ciphertext=encrypted.ciphertext,
            tag=bytes(tag_tampered),
            nonce=encrypted.nonce,
            sender_id=encrypted.sender_id,
        )
        
        bob.decrypt_string(msg_tampered)
        results['fail'] += 1
        results['tests'].append(("Tag tamper rejected", "FAIL (not rejected)"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("Tag tamper rejected", "PASS"))
    
    # === Test 4: Tampered KEM CT rejected ===
    print("  Testing KEM CT tamper...")
    try:
        kem_ct_tampered = bytearray(encrypted.kem_ciphertext)
        kem_ct_tampered[50] ^= 1  # Tamper somewhere in the middle
        
        msg_tampered = EncryptedMessage(
            kem_ciphertext=bytes(kem_ct_tampered),
            ciphertext=encrypted.ciphertext,
            tag=encrypted.tag,
            nonce=encrypted.nonce,
            sender_id=encrypted.sender_id,
        )
        
        bob.decrypt_string(msg_tampered)
        results['fail'] += 1
        results['tests'].append(("KEM CT tamper rejected", "FAIL (not rejected)"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("KEM CT tamper rejected", "PASS"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# I5. File Transfer
# =============================================================================

def test_i5_file_transfer() -> Dict:
    """
    I5: Encrypted file transfer
    """
    print("\n[I5] File Transfer")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.practical import MeteorPractical
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Setup
    alice = MeteorPractical(name="Alice", gpu=GPU_AVAILABLE)
    bob = MeteorPractical(name="Bob", gpu=GPU_AVAILABLE)
    
    alice.add_contact("Bob", bob.get_public_identity())
    bob.add_contact("Alice", alice.get_public_identity())
    
    # Test different file sizes
    file_sizes = [
        (1024, "1KB"),
        (64 * 1024, "64KB"),
        (1024 * 1024, "1MB"),
    ]
    
    for size, label in file_sizes:
        print(f"  Testing {label} file...")
        
        file_data = secrets.token_bytes(size)
        
        try:
            encrypted = alice.encrypt_bytes("Bob", file_data)
            decrypted = bob.decrypt_bytes(encrypted)
            
            if decrypted == file_data:
                results['pass'] += 1
                results['tests'].append((f"File {label}", "PASS"))
            else:
                results['fail'] += 1
                results['tests'].append((f"File {label}", "FAIL (mismatch)"))
        except Exception as e:
            results['fail'] += 1
            results['tests'].append((f"File {label}", f"ERROR: {e}"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# I6. Serialization & Transport
# =============================================================================

def test_i6_serialization() -> Dict:
    """
    I6: Message serialization for network transport
    
    JSON roundtrip: encrypt → to_json → [network] → from_json → decrypt
    """
    print("\n[I6] Serialization & Transport")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.practical import MeteorPractical, EncryptedMessage
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Setup
    alice = MeteorPractical(name="Alice", gpu=GPU_AVAILABLE)
    bob = MeteorPractical(name="Bob", gpu=GPU_AVAILABLE)
    
    alice.add_contact("Bob", bob.get_public_identity())
    bob.add_contact("Alice", alice.get_public_identity())
    
    message = "This message will be serialized and transported!"
    
    # === Test 1: JSON roundtrip ===
    print("  Testing JSON roundtrip...")
    try:
        encrypted = alice.encrypt_string("Bob", message)
        
        # Serialize to JSON (simulates network transport)
        json_str = encrypted.to_json()
        
        # Deserialize from JSON
        encrypted_received = EncryptedMessage.from_json(json_str)
        
        # Decrypt
        decrypted = bob.decrypt_string(encrypted_received)
        
        if decrypted == message:
            results['pass'] += 1
            results['tests'].append(("JSON roundtrip", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("JSON roundtrip", "FAIL"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("JSON roundtrip", f"ERROR: {e}"))
    
    # === Test 2: Dict roundtrip ===
    print("  Testing Dict roundtrip...")
    try:
        encrypted = alice.encrypt_string("Bob", message)
        
        # Serialize to dict
        msg_dict = encrypted.to_dict()
        
        # Deserialize from dict
        encrypted_received = EncryptedMessage.from_dict(msg_dict)
        
        # Decrypt
        decrypted = bob.decrypt_string(encrypted_received)
        
        if decrypted == message:
            results['pass'] += 1
            results['tests'].append(("Dict roundtrip", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("Dict roundtrip", "FAIL"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Dict roundtrip", f"ERROR: {e}"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# I7. Performance Benchmark
# =============================================================================

def test_i7_performance() -> Dict:
    """
    I7: End-to-end performance benchmark
    """
    print("\n[I7] Performance Benchmark")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.practical import MeteorPractical
    
    results = {}
    
    # Setup
    alice = MeteorPractical(name="Alice", gpu=GPU_AVAILABLE)
    bob = MeteorPractical(name="Bob", gpu=GPU_AVAILABLE)
    
    alice.add_contact("Bob", bob.get_public_identity())
    bob.add_contact("Alice", alice.get_public_identity())
    
    # Warmup
    for _ in range(3):
        enc = alice.encrypt_string("Bob", "warmup")
        bob.decrypt_string(enc)
    
    # Benchmark: 100 messages
    num_messages = 100
    message = "Benchmark message " + "x" * 100  # ~120 bytes
    
    print(f"  Benchmarking {num_messages} message roundtrips...")
    
    start = time.perf_counter()
    
    for _ in range(num_messages):
        encrypted = alice.encrypt_string("Bob", message)
        decrypted = bob.decrypt_string(encrypted)
    
    total_time = time.perf_counter() - start
    
    msgs_per_sec = num_messages / total_time
    avg_latency_ms = (total_time / num_messages) * 1000
    
    results['num_messages'] = num_messages
    results['total_time_s'] = total_time
    results['msgs_per_sec'] = msgs_per_sec
    results['avg_latency_ms'] = avg_latency_ms
    results['passed'] = True
    
    print(f"    Messages: {num_messages}")
    print(f"    Total time: {total_time:.2f}s")
    print(f"    Throughput: {msgs_per_sec:.1f} msg/s")
    print(f"    Avg latency: {avg_latency_ms:.2f} ms/msg")
    print(f"  Result: PASS ✓ (benchmark)")
    
    return results


# =============================================================================
# I8. Device Binding (Auth)
# =============================================================================

def test_i8_device_binding() -> Dict:
    """
    I8: Device-bound authentication
    
    Same seed + same device → same MeteorID
    Same seed + different device → different MeteorID → auth fails
    """
    print("\n[I8] Device Binding")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    try:
        from meteor_nc.auth.core import MeteorAuth
    except ImportError:
        print("  SKIPPED: auth module not available")
        return {'passed': True, 'skipped': True}
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # === Test 1: Same seed + same device → same ID ===
    print("  Test 1: Same seed + same device...")
    auth1 = MeteorAuth(gpu=GPU_AVAILABLE)
    auth2 = MeteorAuth(gpu=GPU_AVAILABLE)
    
    user_seed = auth1.generate_seed()
    
    id1 = auth1.get_meteor_id(user_seed)
    id2 = auth2.get_meteor_id(user_seed)
    
    if id1 == id2:
        results['pass'] += 1
        results['tests'].append(("Same device same ID", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Same device same ID", "FAIL"))
    
    # === Test 2: Different seed → different ID ===
    print("  Test 2: Different seed → different ID...")
    different_seed = auth1.generate_seed()
    id3 = auth1.get_meteor_id(different_seed)
    
    if id1 != id3:
        results['pass'] += 1
        results['tests'].append(("Different seed different ID", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Different seed different ID", "FAIL"))
    
    # === Test 3: Device fingerprint deterministic ===
    print("  Test 3: Device fingerprint deterministic...")
    fp1 = auth1.get_device_fingerprint()
    fp2 = auth1.get_device_fingerprint()
    
    if fp1 == fp2 and len(fp1) == 32:
        results['pass'] += 1
        results['tests'].append(("Fingerprint deterministic", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Fingerprint deterministic", "FAIL"))
    
    # === Test 4: Device-bound seed ===
    print("  Test 4: Device-bound seed deterministic...")
    bound1 = auth1.create_device_bound_seed(user_seed)
    bound2 = auth1.create_device_bound_seed(user_seed)
    
    if bound1 == bound2 and len(bound1) == 32:
        results['pass'] += 1
        results['tests'].append(("Device-bound seed", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Device-bound seed", "FAIL"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# I9. Seed Authentication
# =============================================================================

def test_i9_seed_auth() -> Dict:
    """
    I9: Seed-based authentication
    
    Correct seed → can decrypt messages
    Wrong seed → cannot decrypt (different keys)
    """
    print("\n[I9] Seed Authentication")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.practical import MeteorPractical
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Alice creates identity with specific seed
    alice_seed = secrets.token_bytes(32)
    alice = MeteorPractical(name="Alice", seed=alice_seed, gpu=GPU_AVAILABLE)
    
    # Bob sends message to Alice
    bob = MeteorPractical(name="Bob", gpu=GPU_AVAILABLE)
    bob.add_contact("Alice", alice.get_public_identity())
    
    message = "Secret message for Alice"
    encrypted = bob.encrypt_string("Alice", message)
    
    # === Test 1: Correct seed can decrypt ===
    print("  Test 1: Correct seed decrypts...")
    alice_correct = MeteorPractical(name="Alice", seed=alice_seed, gpu=GPU_AVAILABLE)
    
    try:
        decrypted = alice_correct.decrypt_string(encrypted)
        if decrypted == message:
            results['pass'] += 1
            results['tests'].append(("Correct seed decrypts", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("Correct seed decrypts", "FAIL (mismatch)"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Correct seed decrypts", f"ERROR: {e}"))
    
    # === Test 2: Wrong seed cannot decrypt ===
    print("  Test 2: Wrong seed rejected...")
    wrong_seed = secrets.token_bytes(32)
    alice_wrong = MeteorPractical(name="Alice", seed=wrong_seed, gpu=GPU_AVAILABLE)
    
    try:
        alice_wrong.decrypt_string(encrypted)
        results['fail'] += 1
        results['tests'].append(("Wrong seed rejected", "FAIL (not rejected)"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("Wrong seed rejected", "PASS"))
    
    # === Test 3: Same seed = same meteor_id ===
    print("  Test 3: Same seed = same identity...")
    if alice.meteor_id == alice_correct.meteor_id:
        results['pass'] += 1
        results['tests'].append(("Same seed same identity", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Same seed same identity", "FAIL"))
    
    # === Test 4: Different seed = different meteor_id ===
    print("  Test 4: Different seed = different identity...")
    if alice.meteor_id != alice_wrong.meteor_id:
        results['pass'] += 1
        results['tests'].append(("Different seed different identity", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Different seed different identity", "FAIL"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# I10. Man-in-the-Middle Prevention
# =============================================================================

def test_i10_mitm_prevention() -> Dict:
    """
    I10: Man-in-the-Middle attack prevention
    
    Eve intercepts Alice ↔ Bob communication but cannot:
    - Decrypt messages (no private key)
    - Forge messages (would fail authentication)
    """
    print("\n[I10] Man-in-the-Middle Prevention")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.practical import MeteorPractical, EncryptedMessage
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Setup: Alice, Bob, Eve
    alice = MeteorPractical(name="Alice", gpu=GPU_AVAILABLE)
    bob = MeteorPractical(name="Bob", gpu=GPU_AVAILABLE)
    eve = MeteorPractical(name="Eve", gpu=GPU_AVAILABLE)  # Attacker
    
    # Alice and Bob exchange keys
    alice.add_contact("Bob", bob.get_public_identity())
    bob.add_contact("Alice", alice.get_public_identity())
    
    # Eve knows public keys (these are public!)
    eve.add_contact("Alice", alice.get_public_identity())
    eve.add_contact("Bob", bob.get_public_identity())
    
    # === Scenario 1: Alice → Bob, Eve intercepts ===
    print("  Scenario 1: Eve intercepts Alice → Bob...")
    
    secret_message = "Top secret: launch codes are 12345"
    encrypted = alice.encrypt_string("Bob", secret_message)
    
    # Eve tries to decrypt
    try:
        eve.decrypt_string(encrypted)
        results['fail'] += 1
        results['tests'].append(("Eve cannot decrypt A→B", "FAIL (decrypted!)"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("Eve cannot decrypt A→B", "PASS"))
    
    # Bob can decrypt
    try:
        decrypted = bob.decrypt_string(encrypted)
        if decrypted == secret_message:
            results['pass'] += 1
            results['tests'].append(("Bob decrypts A→B", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("Bob decrypts A→B", "FAIL"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Bob decrypts A→B", f"ERROR: {e}"))
    
    # === Scenario 2: Eve forges message "from Alice" ===
    print("  Scenario 2: Eve forges message as Alice...")
    
    # Eve encrypts to Bob (she can do this, Bob's key is public)
    eve_forged = eve.encrypt_string("Bob", "Fake message from Alice")
    
    # But sender_id reveals it's from Eve, not Alice!
    if eve_forged.sender_id != alice.meteor_id:
        results['pass'] += 1
        results['tests'].append(("Forgery has wrong sender_id", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Forgery has wrong sender_id", "FAIL"))
    
    # === Scenario 3: Eve modifies ciphertext in transit ===
    print("  Scenario 3: Eve modifies ciphertext...")
    
    original = alice.encrypt_string("Bob", "Original message")
    
    # Eve tampers with ciphertext
    tampered_ct = bytearray(original.ciphertext)
    tampered_ct[0] ^= 0xFF
    
    tampered = EncryptedMessage(
        kem_ciphertext=original.kem_ciphertext,
        ciphertext=bytes(tampered_ct),
        tag=original.tag,
        nonce=original.nonce,
        sender_id=original.sender_id,
    )
    
    # Bob detects tampering
    try:
        bob.decrypt_string(tampered)
        results['fail'] += 1
        results['tests'].append(("Tampering detected", "FAIL (not detected)"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("Tampering detected", "PASS"))
    
    # === Scenario 4: Eve replays old message ===
    print("  Scenario 4: Eve replays old message...")
    
    # Same encrypted message sent twice is still valid
    # (replay protection is application layer responsibility)
    try:
        decrypted1 = bob.decrypt_string(original)
        decrypted2 = bob.decrypt_string(original)
        
        # Both decrypt to same message (replay detection is app-level)
        if decrypted1 == decrypted2:
            results['pass'] += 1
            results['tests'].append(("Replay semantics correct", "PASS (app handles)"))
        else:
            results['fail'] += 1
            results['tests'].append(("Replay semantics correct", "FAIL"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Replay semantics correct", f"ERROR: {e}"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# I11. Full Auth + P2P Flow
# =============================================================================

def test_i11_full_auth_p2p_flow() -> Dict:
    """
    I11: Complete Auth + P2P communication flow
    
    1. Alice & Bob generate seeds (like creating accounts)
    2. Exchange public identities
    3. Authenticated P2P communication
    4. Identity recovery with same seed
    5. Wrong seed cannot access
    """
    print("\n[I11] Full Auth + P2P Flow")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.practical import MeteorPractical
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # === Step 1: Account creation (seed generation) ===
    print("  Step 1: Account creation...")
    alice_seed = secrets.token_bytes(32)
    bob_seed = secrets.token_bytes(32)
    
    alice = MeteorPractical(name="Alice", seed=alice_seed, gpu=GPU_AVAILABLE)
    bob = MeteorPractical(name="Bob", seed=bob_seed, gpu=GPU_AVAILABLE)
    
    results['pass'] += 1
    results['tests'].append(("Account creation", "PASS"))
    
    # === Step 2: Key exchange ===
    print("  Step 2: Key exchange...")
    alice.add_contact("Bob", bob.get_public_identity())
    bob.add_contact("Alice", alice.get_public_identity())
    
    results['pass'] += 1
    results['tests'].append(("Key exchange", "PASS"))
    
    # === Step 3: Bidirectional communication ===
    print("  Step 3: Bidirectional communication...")
    
    # Alice → Bob
    msg1 = "Hello Bob, this is Alice!"
    enc1 = alice.encrypt_string("Bob", msg1)
    dec1 = bob.decrypt_string(enc1)
    
    # Bob → Alice
    msg2 = "Hi Alice, Bob here!"
    enc2 = bob.encrypt_string("Alice", msg2)
    dec2 = alice.decrypt_string(enc2)
    
    if dec1 == msg1 and dec2 == msg2:
        results['pass'] += 1
        results['tests'].append(("Bidirectional communication", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Bidirectional communication", "FAIL"))
    
    # === Step 4: Alice loses device, recovers with seed ===
    print("  Step 4: Identity recovery...")
    
    # Bob sends another message
    msg3 = "Important update for Alice"
    enc3 = bob.encrypt_string("Alice", msg3)
    
    # Alice "loses device" but recovers with same seed
    alice_recovered = MeteorPractical(name="Alice", seed=alice_seed, gpu=GPU_AVAILABLE)
    
    # Verify same identity
    same_id = alice.meteor_id == alice_recovered.meteor_id
    
    # Can decrypt message sent to original Alice
    try:
        dec3 = alice_recovered.decrypt_string(enc3)
        recovery_ok = same_id and dec3 == msg3
        
        if recovery_ok:
            results['pass'] += 1
            results['tests'].append(("Identity recovery", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("Identity recovery", "FAIL"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Identity recovery", f"ERROR: {e}"))
    
    # === Step 5: Attacker with wrong seed ===
    print("  Step 5: Wrong seed blocked...")
    
    attacker_seed = secrets.token_bytes(32)
    attacker = MeteorPractical(name="Alice", seed=attacker_seed, gpu=GPU_AVAILABLE)
    
    # Attacker has different meteor_id
    different_id = alice.meteor_id != attacker.meteor_id
    
    # Attacker cannot decrypt Alice's messages
    try:
        attacker.decrypt_string(enc3)
        attacker_blocked = False
    except Exception:
        attacker_blocked = True
    
    if different_id and attacker_blocked:
        results['pass'] += 1
        results['tests'].append(("Wrong seed blocked", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Wrong seed blocked", "FAIL"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# Updated Main Test Runner
# =============================================================================

def run_all_integration_tests() -> Dict:
    """Run all P2P protocol integration tests."""
    print("=" * 70)
    print("Meteor-NC P2P Protocol Integration Test Suite (TCHES)")
    print("=" * 70)
    print(f"GPU Available: {GPU_AVAILABLE}")
    print(f"Crypto Available: {CRYPTO_AVAILABLE}")
    
    all_results = {}
    
    # I1. Basic P2P Exchange
    print("\n" + "=" * 70)
    print("I1. BASIC P2P MESSAGE EXCHANGE")
    print("=" * 70)
    all_results['i1_basic_p2p'] = test_i1_basic_p2p_exchange()
    
    # I2. Multi-Party
    print("\n" + "=" * 70)
    print("I2. MULTI-PARTY COMMUNICATION")
    print("=" * 70)
    all_results['i2_multi_party'] = test_i2_multi_party()
    
    # I3. Identity & Auth
    print("\n" + "=" * 70)
    print("I3. IDENTITY & AUTHENTICATION")
    print("=" * 70)
    all_results['i3_identity_auth'] = test_i3_identity_auth()
    
    # I4. Tamper Detection
    print("\n" + "=" * 70)
    print("I4. TAMPER DETECTION")
    print("=" * 70)
    all_results['i4_tamper'] = test_i4_tamper_detection()
    
    # I5. File Transfer
    print("\n" + "=" * 70)
    print("I5. FILE TRANSFER")
    print("=" * 70)
    all_results['i5_file_transfer'] = test_i5_file_transfer()
    
    # I6. Serialization
    print("\n" + "=" * 70)
    print("I6. SERIALIZATION & TRANSPORT")
    print("=" * 70)
    all_results['i6_serialization'] = test_i6_serialization()
    
    # I7. Performance
    print("\n" + "=" * 70)
    print("I7. PERFORMANCE BENCHMARK")
    print("=" * 70)
    all_results['i7_performance'] = test_i7_performance()
    
    # I8. Device Binding
    print("\n" + "=" * 70)
    print("I8. DEVICE BINDING (AUTH)")
    print("=" * 70)
    all_results['i8_device_binding'] = test_i8_device_binding()
    
    # I9. Seed Authentication
    print("\n" + "=" * 70)
    print("I9. SEED AUTHENTICATION")
    print("=" * 70)
    all_results['i9_seed_auth'] = test_i9_seed_auth()
    
    # I10. MITM Prevention
    print("\n" + "=" * 70)
    print("I10. MAN-IN-THE-MIDDLE PREVENTION")
    print("=" * 70)
    all_results['i10_mitm'] = test_i10_mitm_prevention()
    
    # I11. Full Auth + P2P Flow
    print("\n" + "=" * 70)
    print("I11. FULL AUTH + P2P FLOW")
    print("=" * 70)
    all_results['i11_full_flow'] = test_i11_full_auth_p2p_flow()
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    passed = 0
    failed = 0
    skipped = 0
    
    for name, result in all_results.items():
        if result.get('skipped'):
            status = "SKIP"
            skipped += 1
        elif result.get('passed'):
            status = "PASS"
            passed += 1
        else:
            status = "FAIL"
            failed += 1
        print(f"  {name}: {status}")
    
    print(f"\nTotal: {passed} passed, {failed} failed, {skipped} skipped")
    
    all_pass = failed == 0
    print(f"\n{'=' * 70}")
    print(f"RESULT: {'ALL TESTS PASSED ✓' if all_pass else 'SOME TESTS FAILED ✗'}")
    print(f"{'=' * 70}")
    
    return {
        'results': all_results,
        'passed': passed,
        'failed': failed,
        'skipped': skipped,
        'all_pass': all_pass,
    }


if __name__ == "__main__":
    run_all_integration_tests()
