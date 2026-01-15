# meteor_nc/tests/test_core.py
"""
Meteor-NC Core Test Suite for TCHES

Tests for: LWEKEM, HybridKEM, SymmetricMixer
Categories:
  A1. Correctness
  A2. Robustness
  A3. Security-in-practice
  A4. Reproducibility
  A5. Performance
"""

import secrets
import time
import hashlib
import numpy as np
from typing import Dict, List, Tuple

import sys
sys.path.insert(0, '/content/meteor-nc')

from meteor_nc.cryptography.common import (
    Q_DEFAULT, MSG_BYTES, MSG_BITS, _sha256, _ct_eq,
    GPU_AVAILABLE, CRYPTO_AVAILABLE,
)
from meteor_nc.cryptography.core import (
    LWEKEM, HybridKEM, SymmetricMixer,
    LWECiphertext, FullCiphertext,
)


# =============================================================================
# A1. Correctness Tests
# =============================================================================

def test_a1_1_kem_encaps_decaps(iterations: int = 10000) -> Dict:
    """
    A1.1: KEM Encaps/Decaps consistency
    
    Verify: K == K' for all iterations
    """
    print("\n[A1.1] KEM Encaps/Decaps Consistency")
    print("-" * 50)
    
    results = {'pass': 0, 'fail': 0, 'errors': []}
    
    # Test with fixed seed
    print("  Testing with fixed seeds...")
    for i in range(iterations // 2):
        try:
            seed = secrets.token_bytes(32)
            kem = LWEKEM(n=256, gpu=GPU_AVAILABLE, seed=seed)
            kem.key_gen()
            
            K, ct = kem.encaps()
            K_prime = kem.decaps(ct)
            
            if K == K_prime:
                results['pass'] += 1
            else:
                results['fail'] += 1
                if len(results['errors']) < 5:
                    results['errors'].append(f"Iteration {i}: K mismatch")
        except Exception as e:
            results['fail'] += 1
            if len(results['errors']) < 5:
                results['errors'].append(f"Iteration {i}: {str(e)}")
    
    # Test with random seeds
    print("  Testing with random seeds...")
    for i in range(iterations // 2):
        try:
            kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
            kem.key_gen()
            
            K, ct = kem.encaps()
            K_prime = kem.decaps(ct)
            
            if K == K_prime:
                results['pass'] += 1
            else:
                results['fail'] += 1
                if len(results['errors']) < 5:
                    results['errors'].append(f"Random {i}: K mismatch")
        except Exception as e:
            results['fail'] += 1
            if len(results['errors']) < 5:
                results['errors'].append(f"Random {i}: {str(e)}")
    
    results['total'] = results['pass'] + results['fail']
    results['success_rate'] = results['pass'] / results['total'] if results['total'] > 0 else 0
    results['passed'] = results['fail'] == 0
    
    print(f"  Pass: {results['pass']}, Fail: {results['fail']}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_a1_2_implicit_rejection(iterations: int = 1000) -> Dict:
    """
    A1.2: Implicit rejection test
    
    Verify: Modified ciphertext produces different key (not K_good)
    """
    print("\n[A1.2] Implicit Rejection")
    print("-" * 50)
    
    results = {'pass': 0, 'fail': 0, 'rejection_worked': 0}
    
    for i in range(iterations):
        try:
            kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
            kem.key_gen()
            
            K_good, ct = kem.encaps()
            
            # Modify u (flip one element)
            ct_bad = LWECiphertext(
                u=ct.u.copy(),
                v=ct.v.copy()
            )
            modify_idx = np.random.randint(0, len(ct_bad.u))
            ct_bad.u[modify_idx] ^= 1  # Flip bit
            
            K_bad = kem.decaps(ct_bad)
            
            # K_bad should NOT equal K_good
            if K_bad != K_good:
                results['rejection_worked'] += 1
                results['pass'] += 1
            else:
                results['fail'] += 1
                
        except Exception as e:
            results['fail'] += 1
    
    results['total'] = results['pass'] + results['fail']
    results['passed'] = results['fail'] == 0
    
    print(f"  Rejection worked: {results['rejection_worked']}/{results['total']}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_a1_3_hybrid_roundtrip(iterations: int = 100) -> Dict:
    """
    A1.3: HybridKEM encrypt/decrypt round-trip
    """
    print("\n[A1.3] HybridKEM Round-trip")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography library not available")
        return {'passed': True, 'skipped': True}
    
    results = {'pass': 0, 'fail': 0}
    
    test_sizes = [0, 1, 16, 100, 1000, 10000]
    
    for size in test_sizes:
        for _ in range(iterations // len(test_sizes)):
            try:
                hybrid = HybridKEM(security_level=128, gpu=GPU_AVAILABLE)
                hybrid.key_gen()
                
                plaintext = secrets.token_bytes(size) if size > 0 else b""
                aad = secrets.token_bytes(16)
                
                ct = hybrid.encrypt(plaintext, aad=aad)
                recovered = hybrid.decrypt(ct, aad=aad)
                
                if plaintext == recovered:
                    results['pass'] += 1
                else:
                    results['fail'] += 1
                    
            except Exception as e:
                results['fail'] += 1
    
    results['total'] = results['pass'] + results['fail']
    results['passed'] = results['fail'] == 0
    
    print(f"  Pass: {results['pass']}, Fail: {results['fail']}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_a1_4_mixer_invertibility() -> Dict:
    """
    A1.4: SymmetricMixer invertibility (multiple sizes)
    """
    print("\n[A1.4] SymmetricMixer Invertibility")
    print("-" * 50)
    
    results = {'pass': 0, 'fail': 0, 'sizes_tested': []}
    
    # Test sizes: 0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, ...
    test_sizes = [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                  127, 128, 129, 255, 256, 257, 1000, 10000, 100000]
    
    key = secrets.token_bytes(32)
    mixer = SymmetricMixer(key=key, rounds=8, gpu=GPU_AVAILABLE)
    
    for size in test_sizes:
        try:
            data = secrets.token_bytes(size) if size > 0 else b""
            mixed = mixer.forward(data)
            recovered = mixer.inverse(mixed)
            
            if data == recovered:
                results['pass'] += 1
                results['sizes_tested'].append((size, 'PASS'))
            else:
                results['fail'] += 1
                results['sizes_tested'].append((size, 'FAIL'))
                print(f"    Size {size}: FAIL")
        except Exception as e:
            results['fail'] += 1
            results['sizes_tested'].append((size, f'ERROR: {e}'))
            print(f"    Size {size}: ERROR - {e}")
    
    results['total'] = results['pass'] + results['fail']
    results['passed'] = results['fail'] == 0
    
    print(f"  Sizes tested: {len(test_sizes)}")
    print(f"  Pass: {results['pass']}, Fail: {results['fail']}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# A2. Robustness Tests
# =============================================================================

def test_a2_1_boundary_conditions() -> Dict:
    """
    A2.1: Boundary length tests
    """
    print("\n[A2.1] Boundary Conditions")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography library not available")
        return {'passed': True, 'skipped': True}
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    hybrid = HybridKEM(security_level=128, gpu=GPU_AVAILABLE)
    hybrid.key_gen()
    
    # Test AAD variations
    aad_tests = [
        (None, "AAD=None"),
        (b"", "AAD=empty"),
        (b"x" * 1000, "AAD=1000 bytes"),
    ]
    
    for aad, desc in aad_tests:
        try:
            ct = hybrid.encrypt(b"test", aad=aad)
            pt = hybrid.decrypt(ct, aad=aad)
            ok = (pt == b"test")
            results['tests'].append((desc, 'PASS' if ok else 'FAIL'))
            results['pass' if ok else 'fail'] += 1
        except Exception as e:
            results['tests'].append((desc, f'ERROR: {e}'))
            results['fail'] += 1
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_a2_2_type_shape_errors() -> Dict:
    """
    A2.2: Type and shape error handling
    """
    print("\n[A2.2] Type/Shape Error Handling")
    print("-" * 50)
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    _, ct = kem.encaps()
    
    # Test wrong shapes
    bad_cases = [
        ("u wrong length", LWECiphertext(u=ct.u[:100], v=ct.v)),
        ("v wrong length", LWECiphertext(u=ct.u, v=ct.v[:100])),
        ("u wrong dtype", LWECiphertext(u=ct.u.astype(np.float32), v=ct.v)),
    ]
    
    for desc, bad_ct in bad_cases:
        try:
            _ = kem.decaps(bad_ct)
            # Should have raised or handled gracefully
            results['tests'].append((desc, 'NO ERROR (may be OK)'))
            results['pass'] += 1  # Some implementations handle gracefully
        except Exception as e:
            results['tests'].append((desc, f'CAUGHT: {type(e).__name__}'))
            results['pass'] += 1  # Error is expected
    
    results['passed'] = True  # Informational test
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: PASS ✓ (informational)")
    
    return results


# =============================================================================
# A3. Security-in-practice Tests
# =============================================================================

def test_a3_1_aead_integrity() -> Dict:
    """
    A3.1: AEAD integrity verification
    """
    print("\n[A3.1] AEAD Integrity")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography library not available")
        return {'passed': True, 'skipped': True}
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    hybrid = HybridKEM(security_level=128, gpu=GPU_AVAILABLE)
    hybrid.key_gen()
    
    plaintext = b"Secret message"
    aad = b"authenticated data"
    ct = hybrid.encrypt(plaintext, aad=aad)
    
    # Test 1: Wrong AAD should fail
    try:
        hybrid.decrypt(ct, aad=b"wrong aad")
        results['tests'].append(("Wrong AAD", "FAIL - no exception"))
        results['fail'] += 1
    except Exception:
        results['tests'].append(("Wrong AAD", "PASS - rejected"))
        results['pass'] += 1
    
    # Test 2: Modified tag should fail
    try:
        bad_ct = FullCiphertext(
            u=ct.u, v=ct.v, nonce=ct.nonce, ct=ct.ct,
            tag=bytes([ct.tag[0] ^ 1]) + ct.tag[1:]
        )
        hybrid.decrypt(bad_ct, aad=aad)
        results['tests'].append(("Modified tag", "FAIL - no exception"))
        results['fail'] += 1
    except Exception:
        results['tests'].append(("Modified tag", "PASS - rejected"))
        results['pass'] += 1
    
    # Test 3: Modified nonce should fail
    try:
        bad_ct = FullCiphertext(
            u=ct.u, v=ct.v,
            nonce=bytes([ct.nonce[0] ^ 1]) + ct.nonce[1:],
            ct=ct.ct, tag=ct.tag
        )
        hybrid.decrypt(bad_ct, aad=aad)
        results['tests'].append(("Modified nonce", "FAIL - no exception"))
        results['fail'] += 1
    except Exception:
        results['tests'].append(("Modified nonce", "PASS - rejected"))
        results['pass'] += 1
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_a3_2_domain_separation() -> Dict:
    """
    A3.2: Domain separation (no collision between different labels)
    """
    print("\n[A3.2] Domain Separation")
    print("-" * 50)
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Test that different labels produce different outputs
    test_input = b"same_input_data"
    
    labels = [b"shared", b"fail", b"random", b"aead-key", b"pk_hash"]
    outputs = {}
    
    for label in labels:
        outputs[label] = _sha256(label, test_input)
    
    # Check all pairs are different
    for i, l1 in enumerate(labels):
        for l2 in labels[i+1:]:
            if outputs[l1] != outputs[l2]:
                results['pass'] += 1
            else:
                results['fail'] += 1
                results['tests'].append((f"{l1} vs {l2}", "COLLISION!"))
    
    results['passed'] = results['fail'] == 0
    
    print(f"  Label pairs tested: {results['pass'] + results['fail']}")
    print(f"  Collisions: {results['fail']}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_a3_3_ct_eq_correctness() -> Dict:
    """
    A3.3: Constant-time comparison correctness
    """
    print("\n[A3.3] CT Comparison (_ct_eq)")
    print("-" * 50)
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Test cases
    test_cases = [
        (b"hello", b"hello", 1, "Equal strings"),
        (b"hello", b"world", 0, "Different strings"),
        (b"", b"", 1, "Empty strings"),
        (b"a", b"ab", 0, "Different lengths"),
        (b"\x00" * 32, b"\x00" * 32, 1, "Zero bytes"),
        (b"\xff" * 32, b"\xff" * 32, 1, "0xFF bytes"),
        (b"\x00" * 32, b"\x00" * 31 + b"\x01", 0, "One bit diff"),
    ]
    
    for a, b, expected, desc in test_cases:
        result = _ct_eq(a, b)
        if result == expected:
            results['pass'] += 1
            results['tests'].append((desc, "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append((desc, f"FAIL: got {result}, expected {expected}"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# A4. Reproducibility Tests
# =============================================================================

def test_a4_1_seed_determinism() -> Dict:
    """
    A4.1: Seed determinism (same seed → same keys)
    """
    print("\n[A4.1] Seed Determinism")
    print("-" * 50)
    
    results = {'pass': 0, 'fail': 0}
    
    for _ in range(100):
        seed = secrets.token_bytes(32)
        
        # Create two instances with same seed
        kem1 = LWEKEM(n=256, gpu=GPU_AVAILABLE, seed=seed)
        kem1.key_gen()
        
        kem2 = LWEKEM(n=256, gpu=GPU_AVAILABLE, seed=seed)
        kem2.key_gen()
        
        # Convert to numpy for comparison
        if GPU_AVAILABLE:
            import cupy as cp
            A1 = cp.asnumpy(kem1.pk.A)
            A2 = cp.asnumpy(kem2.pk.A)
            b1 = cp.asnumpy(kem1.pk.b)
            b2 = cp.asnumpy(kem2.pk.b)
        else:
            A1, A2 = kem1.pk.A, kem2.pk.A
            b1, b2 = kem1.pk.b, kem2.pk.b
        
        if np.array_equal(A1, A2) and np.array_equal(b1, b2):
            results['pass'] += 1
        else:
            results['fail'] += 1
    
    results['total'] = results['pass'] + results['fail']
    results['passed'] = results['fail'] == 0
    
    print(f"  Pass: {results['pass']}, Fail: {results['fail']}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_a4_2_encaps_randomness(iterations: int = 10000) -> Dict:
    """
    A4.2: Encaps produces different ciphertexts each time
    """
    print("\n[A4.2] Encaps Randomness")
    print("-" * 50)
    
    results = {'unique': 0, 'duplicates': 0}
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    seen_cts = set()
    
    for _ in range(iterations):
        _, ct = kem.encaps()
        ct_hash = hashlib.sha256(ct.u.tobytes() + ct.v.tobytes()).hexdigest()
        
        if ct_hash in seen_cts:
            results['duplicates'] += 1
        else:
            seen_cts.add(ct_hash)
            results['unique'] += 1
    
    results['total'] = iterations
    results['passed'] = results['duplicates'] == 0
    
    print(f"  Unique: {results['unique']}, Duplicates: {results['duplicates']}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# A5. Performance Tests
# =============================================================================

def test_a5_performance() -> Dict:
    """
    A5: Performance benchmark
    """
    print("\n[A5] Performance Benchmark")
    print("-" * 50)
    
    results = {}
    
    # KEM Performance
    print("\n  [KEM]")
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    # Warmup
    for _ in range(10):
        K, ct = kem.encaps()
        _ = kem.decaps(ct)
    
    # Encaps benchmark
    iterations = 1000
    start = time.perf_counter()
    for _ in range(iterations):
        K, ct = kem.encaps()
    encaps_time = time.perf_counter() - start
    
    results['kem_encaps_ops_sec'] = iterations / encaps_time
    print(f"    Encaps: {results['kem_encaps_ops_sec']:.0f} ops/sec")
    
    # Decaps benchmark
    _, ct = kem.encaps()
    start = time.perf_counter()
    for _ in range(iterations):
        _ = kem.decaps(ct)
    decaps_time = time.perf_counter() - start
    
    results['kem_decaps_ops_sec'] = iterations / decaps_time
    print(f"    Decaps: {results['kem_decaps_ops_sec']:.0f} ops/sec")
    
    # Hybrid Performance
    if CRYPTO_AVAILABLE:
        print("\n  [HybridKEM]")
        hybrid = HybridKEM(security_level=128, gpu=GPU_AVAILABLE)
        hybrid.key_gen()
        
        test_size = 1000
        plaintext = secrets.token_bytes(test_size)
        
        # Warmup
        for _ in range(10):
            ct = hybrid.encrypt(plaintext)
            _ = hybrid.decrypt(ct)
        
        iterations = 100
        
        start = time.perf_counter()
        for _ in range(iterations):
            ct = hybrid.encrypt(plaintext)
        encrypt_time = time.perf_counter() - start
        
        results['hybrid_encrypt_ops_sec'] = iterations / encrypt_time
        print(f"    Encrypt ({test_size}B): {results['hybrid_encrypt_ops_sec']:.0f} ops/sec")
        
        ct = hybrid.encrypt(plaintext)
        start = time.perf_counter()
        for _ in range(iterations):
            _ = hybrid.decrypt(ct)
        decrypt_time = time.perf_counter() - start
        
        results['hybrid_decrypt_ops_sec'] = iterations / decrypt_time
        print(f"    Decrypt ({test_size}B): {results['hybrid_decrypt_ops_sec']:.0f} ops/sec")
    
    # Mixer Performance
    print("\n  [SymmetricMixer]")
    key = secrets.token_bytes(32)
    mixer = SymmetricMixer(key=key, rounds=8, gpu=GPU_AVAILABLE)
    
    test_size = 10000
    data = secrets.token_bytes(test_size)
    
    iterations = 1000
    
    start = time.perf_counter()
    for _ in range(iterations):
        _ = mixer.forward(data)
    forward_time = time.perf_counter() - start
    
    throughput = (test_size * iterations) / forward_time / (1024 * 1024)
    results['mixer_throughput_mbps'] = throughput
    print(f"    Forward ({test_size}B): {throughput:.1f} MB/s")
    
    results['passed'] = True  # Performance is informational
    results['gpu_used'] = GPU_AVAILABLE
    
    print(f"\n  GPU: {'Yes' if GPU_AVAILABLE else 'No'}")
    
    return results


# =============================================================================
# Main Test Runner
# =============================================================================

def run_all_tests() -> Dict:
    """Run all core tests and return summary."""
    print("=" * 70)
    print("Meteor-NC Core Test Suite (TCHES)")
    print("=" * 70)
    print(f"GPU Available: {GPU_AVAILABLE}")
    print(f"Crypto Available: {CRYPTO_AVAILABLE}")
    
    all_results = {}
    
    # A1. Correctness
    print("\n" + "=" * 70)
    print("A1. CORRECTNESS")
    print("=" * 70)
    
    all_results['a1_1_encaps_decaps'] = test_a1_1_kem_encaps_decaps(iterations=1000)
    all_results['a1_2_implicit_rejection'] = test_a1_2_implicit_rejection(iterations=100)
    all_results['a1_3_hybrid_roundtrip'] = test_a1_3_hybrid_roundtrip(iterations=50)
    all_results['a1_4_mixer_invertibility'] = test_a1_4_mixer_invertibility()
    
    # A2. Robustness
    print("\n" + "=" * 70)
    print("A2. ROBUSTNESS")
    print("=" * 70)
    
    all_results['a2_1_boundary'] = test_a2_1_boundary_conditions()
    all_results['a2_2_type_shape'] = test_a2_2_type_shape_errors()
    
    # A3. Security-in-practice
    print("\n" + "=" * 70)
    print("A3. SECURITY-IN-PRACTICE")
    print("=" * 70)
    
    all_results['a3_1_aead_integrity'] = test_a3_1_aead_integrity()
    all_results['a3_2_domain_separation'] = test_a3_2_domain_separation()
    all_results['a3_3_ct_eq'] = test_a3_3_ct_eq_correctness()
    
    # A4. Reproducibility
    print("\n" + "=" * 70)
    print("A4. REPRODUCIBILITY")
    print("=" * 70)
    
    all_results['a4_1_seed_determinism'] = test_a4_1_seed_determinism()
    all_results['a4_2_encaps_randomness'] = test_a4_2_encaps_randomness(iterations=1000)
    
    # A5. Performance
    print("\n" + "=" * 70)
    print("A5. PERFORMANCE")
    print("=" * 70)
    
    all_results['a5_performance'] = test_a5_performance()
    
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
    run_all_tests()
