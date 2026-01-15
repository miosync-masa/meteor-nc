# tests/test_integration.py
"""
Meteor-NC Integration Test Suite for TCHES

End-to-end: KEM key establishment → StreamDEM media delivery
"""

import secrets
import time
import numpy as np
from typing import Dict

import sys
sys.path.insert(0, '/content/meteor-nc')

from meteor_nc.cryptography.common import (
    _sha256, GPU_AVAILABLE, CRYPTO_AVAILABLE,
)


def test_i1_kem_to_stream_flow() -> Dict:
    """
    I1: Complete KEM → StreamDEM flow
    
    Alice (sender): encaps → derive session_key → encrypt stream
    Bob (receiver): decaps → derive session_key → decrypt stream
    """
    print("\n[I1] KEM → StreamDEM Complete Flow")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.core import LWEKEM
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {}
    
    # === Bob: Generate key pair ===
    print("  Bob: Generating key pair...")
    kem_bob = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem_bob.key_gen()
    
    # === Alice: Encapsulate and stream ===
    print("  Alice: Encapsulating shared secret...")
    K_alice, ct = kem_bob.encaps()
    
    # Derive stream keys
    session_key_alice = _sha256(b"session", K_alice)
    stream_id = _sha256(b"stream-id", K_alice)[:16]
    
    print("  Alice: Encrypting media stream...")
    stream_alice = StreamDEM(session_key=session_key_alice, stream_id=stream_id, gpu=False)
    
    # Simulate 10 video frames
    frames = [f"frame_{i}_data_" .encode() + secrets.token_bytes(1000) for i in range(10)]
    encrypted_chunks = [stream_alice.encrypt_chunk(frame) for frame in frames]
    
    # === Bob: Decapsulate and receive ===
    print("  Bob: Decapsulating shared secret...")
    K_bob = kem_bob.decaps(ct)
    
    # Derive same stream keys
    session_key_bob = _sha256(b"session", K_bob)
    
    print("  Bob: Decrypting media stream...")
    stream_bob = StreamDEM(session_key=session_key_bob, stream_id=stream_id, gpu=False)
    
    recovered_frames = [stream_bob.decrypt_chunk(chunk) for chunk in encrypted_chunks]
    
    # === Verify ===
    all_match = all(orig == recv for orig, recv in zip(frames, recovered_frames))
    
    results['frames_sent'] = len(frames)
    results['frames_recovered'] = len(recovered_frames)
    results['all_match'] = all_match
    results['passed'] = all_match
    
    print(f"  Frames: {len(frames)} sent, {len(recovered_frames)} recovered")
    print(f"  All match: {all_match}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_i2_batch_kem_to_multi_stream() -> Dict:
    """
    I2: Batch KEM → Multiple StreamDEM sessions
    
    Server establishes 1000 sessions via batch KEM,
    each client gets unique stream.
    """
    print("\n[I2] Batch KEM → Multi-Stream")
    print("-" * 50)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {}
    
    num_clients = 100  # Simulate 100 concurrent clients
    
    # === Server: Batch key generation ===
    print(f"  Server: Generating keys for {num_clients} clients...")
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    # Batch encapsulation
    K_server, U, V = kem.encaps_batch(num_clients, return_ct=True)
    
    # === Clients: Each decapsulates and creates stream ===
    print(f"  Clients: Establishing {num_clients} stream sessions...")
    K_clients = kem.decaps_batch(U, V)
    
    # Verify all keys match
    keys_match = np.all(K_server == K_clients)
    
    # Test a few streams
    test_clients = [0, 50, 99]
    streams_ok = True
    
    for client_id in test_clients:
        session_key = _sha256(b"session", K_server[client_id].tobytes())
        stream_id = _sha256(b"stream", K_server[client_id].tobytes())[:16]
        
        # Server encrypts
        server_stream = StreamDEM(session_key=session_key, stream_id=stream_id, gpu=False)
        message = f"Hello client {client_id}!".encode()
        chunk = server_stream.encrypt_chunk(message)
        
        # Client decrypts
        client_key = _sha256(b"session", K_clients[client_id].tobytes())
        client_stream = StreamDEM(session_key=client_key, stream_id=stream_id, gpu=False)
        recovered = client_stream.decrypt_chunk(chunk)
        
        if recovered != message:
            streams_ok = False
            break
    
    results['num_clients'] = num_clients
    results['keys_match'] = bool(keys_match)
    results['streams_ok'] = streams_ok
    results['passed'] = keys_match and streams_ok
    
    print(f"  Keys match: {keys_match}")
    print(f"  Stream test: {streams_ok}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_i3_tampered_kem_cascade_failure() -> Dict:
    """
    I3: KEM tamper → complete stream failure
    
    Verify that KEM CT tampering causes ALL subsequent
    stream operations to fail (cascade security).
    """
    print("\n[I3] KEM Tamper → Cascade Failure")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.core import LWEKEM, LWECiphertext
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {}
    
    # Setup
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    K_good, ct = kem.encaps()
    
    # Good path: encrypt some data
    session_key_good = _sha256(b"session", K_good)
    stream_id = _sha256(b"stream", K_good)[:16]
    
    stream_enc = StreamDEM(session_key=session_key_good, stream_id=stream_id, gpu=False)
    
    messages = [f"secret message {i}".encode() for i in range(5)]
    chunks = [stream_enc.encrypt_chunk(msg) for msg in messages]
    
    # Tamper KEM CT
    if hasattr(ct.u, 'get'):
        ct_u = ct.u.get().copy()
        ct_v = ct.v.get().copy()
    else:
        ct_u = ct.u.copy()
        ct_v = ct.v.copy()
    
    ct_u[0] ^= 1  # 1-bit flip
    ct_bad = LWECiphertext(u=ct_u, v=ct_v)
    
    # Bad path: derive wrong key
    K_bad = kem.decaps(ct_bad)
    session_key_bad = _sha256(b"session", K_bad)
    
    # Try to decrypt with wrong key
    stream_dec_bad = StreamDEM(session_key=session_key_bad, stream_id=stream_id, gpu=False)
    
    all_failed = True
    for chunk in chunks:
        try:
            stream_dec_bad.decrypt_chunk(chunk)
            all_failed = False  # Should not succeed!
            break
        except Exception:
            pass  # Expected: authentication failure
    
    results['all_rejected'] = all_failed
    results['passed'] = all_failed
    
    print(f"  KEM CT tampered: 1-bit flip")
    print(f"  All stream chunks rejected: {all_failed}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_i4_end_to_end_performance() -> Dict:
    """
    I4: End-to-end performance benchmark
    
    Measure complete flow: KEM + Stream encryption
    """
    print("\n[I4] End-to-End Performance")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.core import LWEKEM
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {}
    
    # Setup
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    # Benchmark: 10MB stream
    data_size = 10 * 1024 * 1024
    chunk_size = 64 * 1024
    data = secrets.token_bytes(data_size)
    
    # Warm up
    K, ct = kem.encaps()
    
    # Full flow timing
    start = time.perf_counter()
    
    # 1. KEM encaps
    K, ct = kem.encaps()
    
    # 2. Derive keys
    session_key = _sha256(b"session", K)
    stream_id = _sha256(b"stream", K)[:16]
    
    # 3. Stream encrypt
    stream = StreamDEM(session_key=session_key, stream_id=stream_id, gpu=False)
    headers, ct_data, tags = stream.encrypt_batch_fixed(data, chunk_size)
    
    total_time = time.perf_counter() - start
    
    throughput = data_size / total_time / (1024 * 1024)
    
    results['data_size_mb'] = data_size / (1024 * 1024)
    results['total_time_ms'] = total_time * 1000
    results['throughput_mbps'] = throughput
    results['passed'] = True
    
    print(f"  Data: {results['data_size_mb']:.0f} MB")
    print(f"  Total time: {results['total_time_ms']:.1f} ms")
    print(f"  Throughput: {throughput:.1f} MB/s")
    print(f"  Result: PASS ✓ (benchmark)")
    
    return results


# =============================================================================
# Main Test Runner
# =============================================================================

def run_all_integration_tests() -> Dict:
    """Run all integration tests."""
    print("=" * 70)
    print("Meteor-NC Integration Test Suite (TCHES)")
    print("=" * 70)
    print(f"GPU Available: {GPU_AVAILABLE}")
    print(f"Crypto Available: {CRYPTO_AVAILABLE}")
    
    all_results = {}
    
    # I1. KEM → Stream
    print("\n" + "=" * 70)
    print("I1. KEM → STREAM FLOW")
    print("=" * 70)
    
    all_results['i1_kem_to_stream'] = test_i1_kem_to_stream_flow()
    
    # I2. Batch KEM → Multi-Stream
    print("\n" + "=" * 70)
    print("I2. BATCH KEM → MULTI-STREAM")
    print("=" * 70)
    
    all_results['i2_batch_multi_stream'] = test_i2_batch_kem_to_multi_stream()
    
    # I3. Tamper Cascade
    print("\n" + "=" * 70)
    print("I3. TAMPER CASCADE FAILURE")
    print("=" * 70)
    
    all_results['i3_tamper_cascade'] = test_i3_tampered_kem_cascade_failure()
    
    # I4. Performance
    print("\n" + "=" * 70)
    print("I4. END-TO-END PERFORMANCE")
    print("=" * 70)
    
    all_results['i4_performance'] = test_i4_end_to_end_performance()
    
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
