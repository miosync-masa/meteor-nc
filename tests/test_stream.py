# tests/test_stream.py
"""
Meteor-NC Stream DEM Test Suite for TCHES

Tests for: StreamDEM (Fixed Chunk AEAD)
Categories:
  S1. Correctness (encrypt/decrypt, chunks, seq)
  S2. Robustness (loss, reorder, replay)
  S3. Security-in-practice (tamper detection, nonce)
  S4. Reproducibility (determinism)
  S5. Performance (throughput, latency)
"""

import secrets
import time
import numpy as np
from typing import Dict, List

import sys
sys.path.insert(0, '/content/meteor-nc')

from meteor_nc.cryptography.common import (
    _sha256, GPU_AVAILABLE, CRYPTO_AVAILABLE,
)

if not CRYPTO_AVAILABLE:
    print("WARNING: cryptography library not available. Stream tests require it.")


# =============================================================================
# S1. Correctness Tests
# =============================================================================

def test_s1_1_size_boundary() -> Dict:
    """
    S1.1: Size boundary tests
    
    Test: 0B, 1B, 15B, 16B, 17B, 1KB, 1MB
    """
    print("\n[S1.1] Size Boundary Tests")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    session_key = secrets.token_bytes(32)
    stream_id = secrets.token_bytes(16)
    
    test_sizes = [0, 1, 15, 16, 17, 100, 1000, 1024*1024]  # 1MB max
    
    for size in test_sizes:
        try:
            enc = StreamDEM(session_key=session_key, stream_id=stream_id)
            dec = StreamDEM(session_key=session_key, stream_id=stream_id)
            
            plaintext = secrets.token_bytes(size) if size > 0 else b""
            chunk = enc.encrypt_chunk(plaintext)
            recovered = dec.decrypt_chunk(chunk)
            
            if plaintext == recovered:
                results['pass'] += 1
                size_str = f"{size}B" if size < 1024 else f"{size//1024}KB" if size < 1024*1024 else f"{size//(1024*1024)}MB"
                results['tests'].append((f"size={size_str}", "PASS"))
            else:
                results['fail'] += 1
                results['tests'].append((f"size={size}", "FAIL"))
        except Exception as e:
            results['fail'] += 1
            results['tests'].append((f"size={size}", f"ERROR: {e}"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_s1_2_chunk_sequence() -> Dict:
    """
    S1.2: Multi-chunk sequence (10MB as 64KB chunks)
    """
    print("\n[S1.2] Multi-Chunk Sequence")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {}
    
    session_key = secrets.token_bytes(32)
    stream_id = secrets.token_bytes(16)
    
    # 1MB total, 64KB chunks
    total_size = 1 * 1024 * 1024
    chunk_size = 64 * 1024
    num_chunks = total_size // chunk_size
    
    enc = StreamDEM(session_key=session_key, stream_id=stream_id)
    dec = StreamDEM(session_key=session_key, stream_id=stream_id)
    
    # Generate full plaintext
    plaintext = secrets.token_bytes(total_size)
    
    # Encrypt chunks
    chunks = []
    for i in range(num_chunks):
        pt_chunk = plaintext[i*chunk_size:(i+1)*chunk_size]
        ct_chunk = enc.encrypt_chunk(pt_chunk)
        chunks.append(ct_chunk)
    
    # Decrypt and reassemble
    recovered_parts = []
    for ct_chunk in chunks:
        pt_chunk = dec.decrypt_chunk(ct_chunk)
        recovered_parts.append(pt_chunk)
    
    recovered = b"".join(recovered_parts)
    
    results['num_chunks'] = num_chunks
    results['total_size'] = total_size
    results['passed'] = plaintext == recovered
    
    print(f"  Chunks: {num_chunks}")
    print(f"  Total: {total_size // 1024}KB")
    print(f"  Match: {results['passed']}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_s1_3_seq_management() -> Dict:
    """S1.3: Sequence number management"""
    print("\n[S1.3] Sequence Number Management")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    session_key = secrets.token_bytes(32)
    stream_id = secrets.token_bytes(16)
    
    # Test 1: Auto-increment seq
    try:
        enc = StreamDEM(session_key=session_key, stream_id=stream_id, gpu=False)
        
        chunks = []
        for i in range(5):
            chunk = enc.encrypt_chunk(f"message {i}".encode())
            chunks.append(chunk)
        
        # Verify seq incremented - chunk.header.seq !!!
        seqs = [c.header.seq for c in chunks]
        if seqs == list(range(5)):
            results['pass'] += 1
            results['tests'].append(("Auto-increment seq", f"PASS ({seqs})"))
        else:
            results['fail'] += 1
            results['tests'].append(("Auto-increment seq", f"FAIL ({seqs})"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Auto-increment seq", f"ERROR: {e}"))
    
    # Test 2: Custom start_seq (if supported)
    try:
        enc2 = StreamDEM(session_key=session_key, stream_id=stream_id, gpu=False, start_seq=100)
        chunk = enc2.encrypt_chunk(b"test")
        
        # chunk.header.seq !!!
        if chunk.header.seq == 100:
            results['pass'] += 1
            results['tests'].append(("Custom start_seq", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("Custom start_seq", f"FAIL (seq={chunk.header.seq})"))
    except TypeError:
        # start_seq not supported in StreamDEM.__init__
        results['tests'].append(("Custom start_seq", "SKIPPED (not supported)"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Custom start_seq", f"ERROR: {e}"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results

# =============================================================================
# S2. Robustness Tests (Streaming scenarios)
# =============================================================================

def test_s2_1_chunk_loss() -> Dict:
    """
    S2.1: Chunk loss (missing chunk in sequence)
    """
    print("\n[S2.1] Chunk Loss Handling")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {}
    
    session_key = secrets.token_bytes(32)
    stream_id = secrets.token_bytes(16)
    
    enc = StreamDEM(session_key=session_key, stream_id=stream_id)
    
    # Encrypt 5 chunks
    chunks = []
    plaintexts = []
    for i in range(5):
        pt = f"chunk {i}".encode()
        plaintexts.append(pt)
        chunks.append(enc.encrypt_chunk(pt))
    
    # Simulate loss: skip chunk 2
    received = [chunks[0], chunks[1], chunks[3], chunks[4]]  # Missing chunk 2
    
    # Decrypt what we have
    dec = StreamDEM(session_key=session_key, stream_id=stream_id)
    
    recovered = []
    for ct in received:
        try:
            pt = dec.decrypt_chunk(ct)
            recovered.append((ct.header.seq, pt))
        except Exception as e:
            recovered.append((ct.header.seq, f"ERROR: {e}"))
    
    # Verify: chunks 0,1,3,4 should decrypt correctly
    expected_seqs = [0, 1, 3, 4]
    expected_pts = [plaintexts[i] for i in expected_seqs]
    
    actual_seqs = [r[0] for r in recovered]
    actual_pts = [r[1] for r in recovered if isinstance(r[1], bytes)]
    
    results['recovered_seqs'] = actual_seqs
    results['passed'] = (actual_seqs == expected_seqs) and (actual_pts == expected_pts)
    
    print(f"  Lost chunk: seq=2")
    print(f"  Recovered seqs: {actual_seqs}")
    print(f"  Expected: {expected_seqs}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results

def test_s2_2_reorder() -> Dict:
    """S2.2: Out-of-order chunks"""
    print("\n[S2.2] Out-of-Order Handling")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {}
    
    session_key = secrets.token_bytes(32)
    stream_id = secrets.token_bytes(16)
    
    enc = StreamDEM(session_key=session_key, stream_id=stream_id, gpu=False)
    
    # Encrypt 5 chunks
    chunks = []
    plaintexts = []
    for i in range(5):
        pt = f"chunk {i}".encode()
        plaintexts.append(pt)
        chunks.append(enc.encrypt_chunk(pt))
    
    # Reorder: 0, 2, 1, 4, 3
    reordered = [chunks[0], chunks[2], chunks[1], chunks[4], chunks[3]]
    
    # Decrypt in reordered sequence
    dec = StreamDEM(session_key=session_key, stream_id=stream_id, gpu=False)
    
    recovered = []
    for ct in reordered:
        try:
            pt = dec.decrypt_chunk(ct)
            recovered.append((ct.header.seq, pt))  # ← header.seq
        except Exception as e:
            recovered.append((ct.header.seq, f"ERROR: {e}"))  # ← header.seq
    
    # All should decrypt (nonce is per-chunk)
    success = all(isinstance(r[1], bytes) for r in recovered)
    
    # Verify content is correct
    seq_to_pt = {r[0]: r[1] for r in recovered if isinstance(r[1], bytes)}
    content_correct = all(seq_to_pt.get(i) == plaintexts[i] for i in range(5))
    
    results['all_decrypted'] = success
    results['content_correct'] = content_correct
    results['passed'] = success and content_correct
    
    print(f"  Receive order: [0, 2, 1, 4, 3]")
    print(f"  All decrypted: {success}")
    print(f"  Content correct: {content_correct}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results

def test_s2_3_replay() -> Dict:
    """
    S2.3: Replay attack detection
    
    StreamDEM has built-in replay protection.
    - First decrypt: succeeds
    - Second decrypt (same chunk): raises ValueError
    - With check_replay=False: succeeds (for recovery scenarios)
    """
    print("\n[S2.3] Replay Protection")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    session_key = secrets.token_bytes(32)
    stream_id = secrets.token_bytes(16)
    
    enc = StreamDEM(session_key=session_key, stream_id=stream_id)
    dec = StreamDEM(session_key=session_key, stream_id=stream_id)
    
    plaintext = b"important message"
    chunk = enc.encrypt_chunk(plaintext)
    
    # Test 1: First decrypt succeeds
    try:
        pt1 = dec.decrypt_chunk(chunk)
        if pt1 == plaintext:
            results['pass'] += 1
            results['tests'].append(("First decrypt", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("First decrypt", "FAIL (wrong plaintext)"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("First decrypt", f"ERROR: {e}"))
    
    # Test 2: Replay is rejected
    try:
        pt2 = dec.decrypt_chunk(chunk)
        results['fail'] += 1
        results['tests'].append(("Replay rejected", "FAIL (not rejected)"))
    except ValueError as e:
        if "Replay" in str(e) or "already seen" in str(e):
            results['pass'] += 1
            results['tests'].append(("Replay rejected", "PASS (ValueError)"))
        else:
            results['fail'] += 1
            results['tests'].append(("Replay rejected", f"FAIL (wrong error: {e})"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Replay rejected", f"ERROR: {e}"))
    
    # Test 3: check_replay=False allows replay (for recovery)
    try:
        pt3 = dec.decrypt_chunk(chunk, check_replay=False)
        if pt3 == plaintext:
            results['pass'] += 1
            results['tests'].append(("check_replay=False", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("check_replay=False", "FAIL (wrong plaintext)"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("check_replay=False", f"ERROR: {e}"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Note: Replay protection is built-in (can disable with check_replay=False)")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results

# =============================================================================
# S3. Security-in-Practice Tests
# =============================================================================

def test_s3_1_tamper_detection() -> Dict:
    """S3.1: Tamper detection (ciphertext, tag, header)"""
    print("\n[S3.1] Tamper Detection")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.stream import StreamDEM, EncryptedChunk, StreamHeader
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    session_key = secrets.token_bytes(32)
    stream_id = secrets.token_bytes(16)
    
    enc = StreamDEM(session_key=session_key, stream_id=stream_id, gpu=False)
    dec = StreamDEM(session_key=session_key, stream_id=stream_id, gpu=False)
    
    plaintext = b"sensitive data"
    chunk = enc.encrypt_chunk(plaintext)
    
    # Test 1: Ciphertext tamper
    try:
        ct_bad = bytearray(chunk.ciphertext)
        ct_bad[0] ^= 1
        chunk_bad = EncryptedChunk(
            header=chunk.header,
            ciphertext=bytes(ct_bad),
            tag=chunk.tag,
        )
        dec.decrypt_chunk(chunk_bad)
        results['fail'] += 1
        results['tests'].append(("Ciphertext tamper", "NOT REJECTED ✗"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("Ciphertext tamper", "REJECTED ✓"))
    
    # Test 2: Tag tamper
    try:
        tag_bad = bytearray(chunk.tag)
        tag_bad[0] ^= 1
        chunk_bad = EncryptedChunk(
            header=chunk.header,
            ciphertext=chunk.ciphertext,
            tag=bytes(tag_bad),
        )
        dec.decrypt_chunk(chunk_bad)
        results['fail'] += 1
        results['tests'].append(("Tag tamper", "NOT REJECTED ✗"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("Tag tamper", "REJECTED ✓"))
    
    # Test 3: Header seq tamper (affects AAD)
    try:
        header_bad = StreamHeader(
            stream_id=chunk.header.stream_id,
            seq=chunk.header.seq + 1,  # Wrong seq
            chunk_len=chunk.header.chunk_len,
            flags=chunk.header.flags,
        )
        chunk_bad = EncryptedChunk(
            header=header_bad,
            ciphertext=chunk.ciphertext,
            tag=chunk.tag,
        )
        dec.decrypt_chunk(chunk_bad)
        results['fail'] += 1
        results['tests'].append(("Header seq tamper", "NOT REJECTED ✗"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("Header seq tamper", "REJECTED ✓"))
    
    # Test 4: Header chunk_len tamper
    try:
        header_bad = StreamHeader(
            stream_id=chunk.header.stream_id,
            seq=chunk.header.seq,
            chunk_len=chunk.header.chunk_len + 1,  # Wrong len
            flags=chunk.header.flags,
        )
        chunk_bad = EncryptedChunk(
            header=header_bad,
            ciphertext=chunk.ciphertext,
            tag=chunk.tag,
        )
        dec.decrypt_chunk(chunk_bad)
        results['fail'] += 1
        results['tests'].append(("Header len tamper", "NOT REJECTED ✗"))
    except Exception:
        results['pass'] += 1
        results['tests'].append(("Header len tamper", "REJECTED ✓"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results

def test_s3_2_kem_integration() -> Dict:
    """
    S3.2: KEM → StreamDEM integration
    
    KEM CT tamper → different key → all chunks fail
    """
    print("\n[S3.2] KEM-StreamDEM Integration")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.core import LWEKEM, LWECiphertext
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {}
    
    # Setup KEM
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    # Good path
    K_good, ct = kem.encaps()
    session_key = _sha256(b"stream-session", K_good)
    stream_id = _sha256(b"stream-id", K_good)[:16]
    
    enc = StreamDEM(session_key=session_key, stream_id=stream_id)
    
    # Encrypt some chunks
    chunks = []
    for i in range(3):
        chunks.append(enc.encrypt_chunk(f"message {i}".encode()))
    
    # Bad path: tampered KEM CT
    if hasattr(ct.u, 'get'):
        ct_u = ct.u.get().copy()
        ct_v = ct.v.get().copy()
    else:
        ct_u = ct.u.copy()
        ct_v = ct.v.copy()
    
    ct_u[0] ^= 1
    ct_bad = LWECiphertext(u=ct_u, v=ct_v)
    K_bad = kem.decaps(ct_bad)
    
    # Different key → different session
    session_key_bad = _sha256(b"stream-session", K_bad)
    stream_id_bad = _sha256(b"stream-id", K_bad)[:16]
    
    dec_bad = StreamDEM(session_key=session_key_bad, stream_id=stream_id_bad)
    
    # All decryptions should fail
    all_failed = True
    for chunk in chunks:
        try:
            dec_bad.decrypt_chunk(chunk)
            all_failed = False
            break
        except Exception:
            pass
    
    results['all_failed'] = all_failed
    results['passed'] = all_failed
    
    print(f"  KEM CT tampered → different session key")
    print(f"  All chunks rejected: {all_failed}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# S4. Reproducibility Tests
# =============================================================================

def test_s4_determinism() -> Dict:
    """
    S4: Encryption determinism
    
    Same key + stream_id + seq + plaintext → same ciphertext
    """
    print("\n[S4] Encryption Determinism")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    session_key = secrets.token_bytes(32)
    stream_id = secrets.token_bytes(16)
    plaintext = b"deterministic test"
    
    # Test 1: Same everything → same output
    enc1 = StreamDEM(session_key=session_key, stream_id=stream_id)
    enc2 = StreamDEM(session_key=session_key, stream_id=stream_id)
    
    chunk1 = enc1.encrypt_chunk(plaintext)
    chunk2 = enc2.encrypt_chunk(plaintext)
    
    if chunk1.ciphertext == chunk2.ciphertext and chunk1.tag == chunk2.tag:
        results['pass'] += 1
        results['tests'].append(("Same input → same output", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Same input → same output", "FAIL"))
    
    # Test 2: Different stream_id → different output
    stream_id_2 = secrets.token_bytes(16)
    enc3 = StreamDEM(session_key=session_key, stream_id=stream_id_2)
    chunk3 = enc3.encrypt_chunk(plaintext)
    
    if chunk1.ciphertext != chunk3.ciphertext:
        results['pass'] += 1
        results['tests'].append(("Different stream_id → different output", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Different stream_id → different output", "FAIL"))
    
    # Test 3: Different session_key → different output
    session_key_2 = secrets.token_bytes(32)
    enc4 = StreamDEM(session_key=session_key_2, stream_id=stream_id)
    chunk4 = enc4.encrypt_chunk(plaintext)
    
    if chunk1.ciphertext != chunk4.ciphertext:
        results['pass'] += 1
        results['tests'].append(("Different session_key → different output", "PASS"))
    else:
        results['fail'] += 1
        results['tests'].append(("Different session_key → different output", "FAIL"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# S5. Performance Tests
# =============================================================================

def test_s5_throughput() -> Dict:
    """
    S5: Throughput benchmark
    """
    print("\n[S5] Throughput Benchmark")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {}
    
    session_key = secrets.token_bytes(32)
    stream_id = secrets.token_bytes(16)
    
    # Test different chunk sizes
    chunk_sizes = [4*1024, 16*1024, 64*1024, 256*1024, 1024*1024]  # 4KB to 1MB
    
    for chunk_size in chunk_sizes:
        plaintext = secrets.token_bytes(chunk_size)
        
        enc = StreamDEM(session_key=session_key, stream_id=stream_id)
        dec = StreamDEM(session_key=session_key, stream_id=stream_id)
        
        # Warmup
        for _ in range(3):
            chunk = enc.encrypt_chunk(plaintext)
            dec.decrypt_chunk(chunk)
        
        # Encrypt benchmark
        iterations = max(10, 100 * 1024 * 1024 // chunk_size)  # ~100MB total
        
        start = time.perf_counter()
        for _ in range(iterations):
            chunk = enc.encrypt_chunk(plaintext)
        enc_time = time.perf_counter() - start
        
        # Decrypt benchmark
        start = time.perf_counter()
        for _ in range(iterations):
            dec.decrypt_chunk(chunk)
        dec_time = time.perf_counter() - start
        
        enc_mbps = (iterations * chunk_size) / enc_time / (1024 * 1024)
        dec_mbps = (iterations * chunk_size) / dec_time / (1024 * 1024)
        
        size_str = f"{chunk_size//1024}KB" if chunk_size < 1024*1024 else f"{chunk_size//(1024*1024)}MB"
        results[f'enc_{size_str}'] = enc_mbps
        results[f'dec_{size_str}'] = dec_mbps
        
        print(f"    {size_str:>6}: Enc {enc_mbps:>6.1f} MB/s, Dec {dec_mbps:>6.1f} MB/s")
    
    results['passed'] = True
    print(f"  Result: PASS ✓ (benchmark)")
    
    return results


# =============================================================================
# Main Test Runner
# =============================================================================

def run_all_stream_tests() -> Dict:
    """Run all stream tests."""
    print("=" * 70)
    print("Meteor-NC Stream DEM Test Suite (TCHES)")
    print("=" * 70)
    print(f"Crypto Available: {CRYPTO_AVAILABLE}")
    
    if not CRYPTO_AVAILABLE:
        print("\nWARNING: Stream tests require cryptography library. Skipping.")
        return {'all_pass': True, 'skipped': True}
    
    all_results = {}
    
    # S1. Correctness
    print("\n" + "=" * 70)
    print("S1. CORRECTNESS")
    print("=" * 70)
    
    all_results['s1_1_size_boundary'] = test_s1_1_size_boundary()
    all_results['s1_2_chunk_sequence'] = test_s1_2_chunk_sequence()
    all_results['s1_3_seq_management'] = test_s1_3_seq_management()
    
    # S2. Robustness
    print("\n" + "=" * 70)
    print("S2. ROBUSTNESS (Streaming Scenarios)")
    print("=" * 70)
    
    all_results['s2_1_chunk_loss'] = test_s2_1_chunk_loss()
    all_results['s2_2_reorder'] = test_s2_2_reorder()
    all_results['s2_3_replay'] = test_s2_3_replay()
    
    # S3. Security
    print("\n" + "=" * 70)
    print("S3. SECURITY-IN-PRACTICE")
    print("=" * 70)
    
    all_results['s3_1_tamper_detection'] = test_s3_1_tamper_detection()
    all_results['s3_2_kem_integration'] = test_s3_2_kem_integration()
    
    # S4. Reproducibility
    print("\n" + "=" * 70)
    print("S4. REPRODUCIBILITY")
    print("=" * 70)
    
    all_results['s4_determinism'] = test_s4_determinism()
    
    # S5. Performance
    print("\n" + "=" * 70)
    print("S5. PERFORMANCE")
    print("=" * 70)
    
    all_results['s5_throughput'] = test_s5_throughput()
    
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
    run_all_stream_tests()
