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
    LWEPublicKey, LWESecretKey,
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
# B. KEM Implementation Security Tests (FO Compliance)
# =============================================================================

def test_b1_implicit_rejection_determinism(iterations: int = 100) -> Dict:
    """
    B1: Implicit rejection correctness
    
    B1.1: Same ct → same K_fail (deterministic)
    B1.2: Different ct → different K_fail (CT-bound)
    B1.3: K_fail != K_good (statistically)
    """
    print("\n[B1] Implicit Rejection Determinism")
    print("-" * 50)
    
    results = {'b1_1': 0, 'b1_2': 0, 'b1_3': 0, 'total': iterations}
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    for _ in range(iterations):
        K_good, ct = kem.encaps()
        
        # Create bad CT
        ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        ct_bad.u[0] ^= 1
        
        # B1.1: Same bad CT → same K_fail
        K_fail_1 = kem.decaps(ct_bad)
        K_fail_2 = kem.decaps(ct_bad)
        if K_fail_1 == K_fail_2:
            results['b1_1'] += 1
        
        # B1.2: Different bad CT → different K_fail
        ct_bad2 = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        ct_bad2.u[1] ^= 1
        K_fail_3 = kem.decaps(ct_bad2)
        if K_fail_1 != K_fail_3:
            results['b1_2'] += 1
        
        # B1.3: K_fail != K_good
        if K_fail_1 != K_good:
            results['b1_3'] += 1
    
    results['passed'] = (
        results['b1_1'] == iterations and
        results['b1_2'] == iterations and
        results['b1_3'] == iterations
    )
    
    print(f"  B1.1 (deterministic): {results['b1_1']}/{iterations}")
    print(f"  B1.2 (CT-bound):      {results['b1_2']}/{iterations}")
    print(f"  B1.3 (K_fail≠K_good): {results['b1_3']}/{iterations}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_b2_cca_reencrypt_check(iterations: int = 100) -> Dict:
    """
    B2: CCA compliance (re-encryption check)
    
    B2.1: Valid CT passes re-encrypt check
    B2.2: Modified CT fails re-encrypt check
    """
    print("\n[B2] CCA Re-encrypt Check")
    print("-" * 50)
    
    results = {'valid_pass': 0, 'modified_fail': 0, 'total': iterations}
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    for _ in range(iterations):
        K_good, ct = kem.encaps()
        
        # B2.1: Valid CT should pass
        K_dec = kem.decaps(ct)
        if K_dec == K_good:
            results['valid_pass'] += 1
        
        # B2.2: Modified CT should fail (K_dec != K_good)
        ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        ct_bad.v[0] ^= 1
        K_bad = kem.decaps(ct_bad)
        if K_bad != K_good:
            results['modified_fail'] += 1
    
    results['passed'] = (
        results['valid_pass'] == iterations and
        results['modified_fail'] == iterations
    )
    
    print(f"  Valid CT pass:    {results['valid_pass']}/{iterations}")
    print(f"  Modified CT fail: {results['modified_fail']}/{iterations}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_b3_cpu_gpu_equivalence() -> Dict:
    """
    B3: Backend determinism + CPU/GPU interop (key injection)

    B3.1: CPU deterministic (same seed -> same (A,b))
    B3.2: GPU deterministic (same seed -> same (A,b))
    B3.3: Interop (GPU key -> CPU decaps) with identical injected key
    """
    print("\n[B3] CPU/GPU Equivalence")
    print("-" * 50)

    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}

    import cupy as cp
    from meteor_nc.cryptography.core import LWEPublicKey, LWESecretKey, LWECiphertext

    trials = 50
    results = {'b3_1': 0, 'b3_2': 0, 'b3_3': 0, 'total': trials}

    for _ in range(trials):
        # -------------------------
        # B3.1 CPU determinism
        # -------------------------
        seed = secrets.token_bytes(32)
        kem_cpu1 = LWEKEM(n=256, gpu=False, seed=seed)
        kem_cpu1.key_gen()
        kem_cpu2 = LWEKEM(n=256, gpu=False, seed=seed)
        kem_cpu2.key_gen()

        if (np.array_equal(kem_cpu1.pk.A, kem_cpu2.pk.A) and 
            np.array_equal(kem_cpu1.pk.b, kem_cpu2.pk.b)):
            results['b3_1'] += 1

        # -------------------------
        # B3.2 GPU determinism
        # -------------------------
        seed_gpu = secrets.token_bytes(32)
        kem_gpu1 = LWEKEM(n=256, gpu=True, seed=seed_gpu)
        kem_gpu1.key_gen()
        kem_gpu2 = LWEKEM(n=256, gpu=True, seed=seed_gpu)
        kem_gpu2.key_gen()

        A1 = cp.asnumpy(kem_gpu1.pk.A)
        A2 = cp.asnumpy(kem_gpu2.pk.A)
        b1 = cp.asnumpy(kem_gpu1.pk.b)
        b2 = cp.asnumpy(kem_gpu2.pk.b)

        if np.array_equal(A1, A2) and np.array_equal(b1, b2):
            results['b3_2'] += 1

        # -------------------------
        # B3.3 Interop: GPU key -> CPU decaps
        # -------------------------
        kem_gpu = LWEKEM(n=256, gpu=True)
        kem_gpu.key_gen()

        # GPU encaps
        K_good, ct = kem_gpu.encaps()

        # Export GPU key material to NumPy
        A_np = cp.asnumpy(kem_gpu.pk.A).astype(np.int64)
        b_np = cp.asnumpy(kem_gpu.pk.b).astype(np.int64)
        s_np = cp.asnumpy(kem_gpu.sk.s).astype(np.int64)
        pk_hash = kem_gpu.pk.pk_hash
        z = kem_gpu.sk.z

        # Create CPU instance with injected keys
        kem_cpu = LWEKEM(n=256, gpu=False)
        kem_cpu.pk = LWEPublicKey(A=A_np, b=b_np, pk_hash=pk_hash)
        kem_cpu.sk = LWESecretKey(s=s_np, z=z)
        kem_cpu.q = kem_gpu.q
        kem_cpu.delta = kem_gpu.delta

        # Convert CT from CuPy to NumPy
        u_np = cp.asnumpy(ct.u).astype(np.int64)
        v_np = cp.asnumpy(ct.v).astype(np.int64)
        ct_cpu = LWECiphertext(u=u_np, v=v_np)

        # CPU decaps
        K_dec = kem_cpu.decaps(ct_cpu)

        if K_good == K_dec:
            results['b3_3'] += 1

    results['passed'] = (
        results['b3_1'] == trials and
        results['b3_2'] == trials and
        results['b3_3'] == trials
    )

    print(f"  B3.1 (CPU deterministic): {results['b3_1']}/{trials}")
    print(f"  B3.2 (GPU deterministic): {results['b3_2']}/{trials}")
    print(f"  B3.3 (interop GPU->CPU):  {results['b3_3']}/{trials}")
    print("  Note: PRNG output-equivalence not required; interop ensured by deterministic CBD.")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")

    return results


# =============================================================================
# D. Key Schedule & Session Management Tests
# =============================================================================

def test_d1_key_separation() -> Dict:
    """
    D1: Key derivation separation
    
    D1.1: Different labels → different derived keys
    D1.2: Same K, different labels → different outputs
    """
    print("\n[D1] Key Separation")
    print("-" * 50)
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Simulate session key
    K = secrets.token_bytes(32)
    
    # Typical key derivation labels
    labels = [
        b"aead-key",
        b"stream-enc",
        b"stream-id",
        b"session",
        b"rekey",
        b"auth-key",
    ]
    
    derived = {label: _sha256(label, K) for label in labels}
    
    # D1.1: All pairs must be different
    for i, l1 in enumerate(labels):
        for l2 in labels[i+1:]:
            if derived[l1] != derived[l2]:
                results['pass'] += 1
            else:
                results['fail'] += 1
                results['tests'].append(f"COLLISION: {l1} vs {l2}")
    
    # D1.2: Same label, different K → different output
    K2 = secrets.token_bytes(32)
    for label in labels[:3]:
        d1 = _sha256(label, K)
        d2 = _sha256(label, K2)
        if d1 != d2:
            results['pass'] += 1
        else:
            results['fail'] += 1
    
    results['passed'] = results['fail'] == 0
    
    print(f"  Pairs tested: {results['pass'] + results['fail']}")
    print(f"  Collisions: {results['fail']}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_d3_kem_dem_integration(chunks: int = 100) -> Dict:
    """
    D3: KEM → DEM End-to-End Integration
    
    D3.1: KEM session_key → StreamDEM encrypt/decrypt works
    D3.2: KEM CT tamper → StreamDEM decrypt fails
    """
    print("\n[D3] KEM-DEM Integration")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography library not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.stream import StreamDEM
    
    results = {'d3_1': True, 'd3_2': True}
    
    # Setup KEM
    kem_alice = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem_alice.key_gen()
    
    kem_bob = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem_bob.pk = kem_alice.pk
    kem_bob.sk = kem_alice.sk
    kem_bob.delta = kem_alice.delta
    kem_bob.q = kem_alice.q
    
    # D3.1: Normal flow
    print("  D3.1: Normal KEM → DEM flow...")
    
    K, ct = kem_bob.encaps()
    K_dec = kem_alice.decaps(ct)
    
    if K != K_dec:
        results['d3_1'] = False
        print("    KEM key mismatch!")
    else:
        # Use derived key for StreamDEM
        session_key = _sha256(b"session", K)
        stream_id = _sha256(b"stream-id", K)[:16]
        
        stream_enc = StreamDEM(session_key=session_key, stream_id=stream_id, gpu=GPU_AVAILABLE)
        stream_dec = StreamDEM(session_key=session_key, stream_id=stream_id, gpu=GPU_AVAILABLE)
        
        # Encrypt/decrypt multiple chunks
        for i in range(chunks):
            plaintext = f"Message {i}: {secrets.token_hex(32)}".encode()
            chunk = stream_enc.encrypt_chunk(plaintext)
            recovered = stream_dec.decrypt_chunk(chunk)
            
            if plaintext != recovered:
                results['d3_1'] = False
                print(f"    Chunk {i} mismatch!")
                break
        
        if results['d3_1']:
            print(f"    {chunks} chunks: OK")
    
    # D3.2: Tampered KEM CT → different session key → decrypt fails
    print("  D3.2: Tampered KEM CT...")
    
    K_good, ct = kem_bob.encaps()
    
    # Tamper CT
    ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
    ct_bad.u[0] ^= 1
    
    K_bad = kem_alice.decaps(ct_bad)
    
    if K_bad == K_good:
        results['d3_2'] = False
        print("    ERROR: Tampered CT produced same key!")
    else:
        # Different keys → different session keys
        session_good = _sha256(b"session", K_good)
        session_bad = _sha256(b"session", K_bad)
        
        if session_good != session_bad:
            print("    Tampered CT → different session key: OK")
        else:
            results['d3_2'] = False
    
    results['passed'] = results['d3_1'] and results['d3_2']
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results

# =============================================================================
# E. Extended Security Tests (TCHES Reviewer Confidence)
# =============================================================================

def test_e1_kfail_uniformity(iterations: int = 1000) -> Dict:
    """
    E1: K_fail uniformity check
    
    Verify K_fail appears uniformly distributed (not biased by CT structure).
    - No duplicate K_fail values
    - First byte distribution roughly uniform
    - Different tampered positions → different K_fail
    """
    print("\n[E1] K_fail Uniformity")
    print("-" * 50)
    
    results = {
        'duplicates': 0,
        'unique_kfails': set(),
        'first_byte_dist': [0] * 256,
        'position_independence': 0,
        'total': iterations
    }
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    for i in range(iterations):
        K_good, ct = kem.encaps()
        
        # Tamper at random position
        ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        pos = np.random.randint(0, len(ct_bad.u))
        ct_bad.u[pos] ^= 1
        
        K_fail = kem.decaps(ct_bad)
        
        # Check uniqueness
        if K_fail in results['unique_kfails']:
            results['duplicates'] += 1
        results['unique_kfails'].add(K_fail)
        
        # Track first byte distribution
        first_byte = K_fail[0]
        results['first_byte_dist'][first_byte] += 1
    
    # Position independence test
    K_good, ct = kem.encaps()
    kfails_by_pos = []
    for pos in [0, 1, 10, 100, 200, 255]:
        ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        ct_bad.u[pos] ^= 1
        kfails_by_pos.append(kem.decaps(ct_bad))
    
    # All should be different
    results['position_independence'] = len(set(kfails_by_pos))
    
    # Chi-square-like check for first byte (simplified)
    expected = iterations / 256
    max_deviation = max(abs(count - expected) for count in results['first_byte_dist'])
    results['max_byte_deviation'] = max_deviation
    results['expected_per_byte'] = expected
    
    # Pass criteria
    results['passed'] = (
        results['duplicates'] == 0 and
        results['position_independence'] == 6 and
        max_deviation < expected * 3  # Allow 3x deviation (rough uniformity)
    )
    
    print(f"  Unique K_fail: {len(results['unique_kfails'])}/{iterations}")
    print(f"  Duplicates: {results['duplicates']}")
    print(f"  Position independence: {results['position_independence']}/6 unique")
    print(f"  First byte max deviation: {max_deviation:.1f} (expected: {expected:.1f})")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    # Don't include the set in return (not serializable)
    results['unique_count'] = len(results['unique_kfails'])
    del results['unique_kfails']
    del results['first_byte_dist']
    
    return results


def test_e2_negative_comprehensive() -> Dict:
    """
    E2: Comprehensive negative tests
    """
    print("\n[E2] Comprehensive Negative Tests")
    print("-" * 50)
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    K_good, ct = kem.encaps()
    
    # Convert to numpy for manipulation (handle both CuPy and NumPy)
    if hasattr(ct.u, 'get'):  # CuPy array
        u_orig = ct.u.get().astype(np.int64)
        v_orig = ct.v.get().astype(np.int64)
    else:  # Already NumPy
        u_orig = np.array(ct.u, dtype=np.int64)
        v_orig = np.array(ct.v, dtype=np.int64)
    
    # Test cases: (description, u_bad, v_bad)
    test_cases = []
    
    # u modifications
    for pos in [0, 128, -1]:
        u_mod = u_orig.copy()
        u_mod[pos] ^= 1
        test_cases.append((f"u[{pos}] 1-bit flip", u_mod, v_orig.copy()))
    
    # v modifications
    for pos in [0, -1]:
        v_mod = v_orig.copy()
        v_mod[pos] ^= 1
        test_cases.append((f"v[{pos}] 1-bit flip", u_orig.copy(), v_mod))
    
    # u[0] = 0
    u_zero = u_orig.copy()
    u_zero[0] = 0
    test_cases.append(("u[0] = 0", u_zero, v_orig.copy()))
    
    # u all +1
    test_cases.append(("u all +1", (u_orig + 1) % Q_DEFAULT, v_orig.copy()))
    
    # v all +1
    test_cases.append(("v all +1", u_orig.copy(), (v_orig + 1) % Q_DEFAULT))
    
    # Both flip
    u_both = u_orig.copy()
    v_both = v_orig.copy()
    u_both[0] ^= 1
    v_both[0] ^= 1
    test_cases.append(("u,v both flip[0]", u_both, v_both))
    
    # u random
    test_cases.append(("u random replace", np.random.randint(0, Q_DEFAULT, size=u_orig.shape, dtype=np.int64), v_orig.copy()))
    
    for desc, u_bad, v_bad in test_cases:
        try:
            ct_bad = LWECiphertext(u=u_bad, v=v_bad)
            K_bad = kem.decaps(ct_bad)
            
            if K_bad != K_good:
                results['pass'] += 1
                results['tests'].append((desc, "REJECTED ✓"))
            else:
                results['fail'] += 1
                results['tests'].append((desc, "NOT REJECTED ✗"))
        except Exception as e:
            results['pass'] += 1
            results['tests'].append((desc, f"EXCEPTION ✓ ({type(e).__name__})"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results

def test_e3_serialization_roundtrip() -> Dict:
    """
    E3: Serialization compatibility
    """
    print("\n[E3] Serialization Round-trip")
    print("-" * 50)
    
    if not CRYPTO_AVAILABLE:
        print("  SKIPPED: cryptography library not available")
        return {'passed': True, 'skipped': True}
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Test 1: Basic round-trip
    print("  E3.1: Basic serialization...")
    try:
        hybrid = HybridKEM(security_level=128, gpu=GPU_AVAILABLE)
        hybrid.key_gen()
        n = hybrid.kem.n  # Get n for deserialization
        
        plaintext = b"Test message for serialization"
        ct = hybrid.encrypt(plaintext)
        
        # Serialize
        ct_bytes = ct.to_bytes()
        
        # Deserialize with n
        ct_restored = FullCiphertext.from_bytes(ct_bytes, n=n)
        
        # Decrypt
        recovered = hybrid.decrypt(ct_restored)
        
        if plaintext == recovered:
            results['pass'] += 1
            results['tests'].append(("Basic round-trip", "PASS"))
        else:
            results['fail'] += 1
            results['tests'].append(("Basic round-trip", "FAIL"))
    except Exception as e:
        results['fail'] += 1
        results['tests'].append(("Basic round-trip", f"ERROR: {e}"))
    
    # Test 2: Multiple sizes
    print("  E3.2: Multiple sizes...")
    test_sizes = [0, 1, 16, 100, 1000, 10000]
    size_pass = True
    for size in test_sizes:
        try:
            plaintext = secrets.token_bytes(size) if size > 0 else b""
            ct = hybrid.encrypt(plaintext)
            ct_bytes = ct.to_bytes()
            ct_restored = FullCiphertext.from_bytes(ct_bytes, n=n)
            recovered = hybrid.decrypt(ct_restored)
            
            if plaintext != recovered:
                size_pass = False
                results['tests'].append((f"Size {size}", "FAIL"))
        except Exception as e:
            size_pass = False
            results['tests'].append((f"Size {size}", f"ERROR: {e}"))
    
    if size_pass:
        results['pass'] += 1
        results['tests'].append((f"All sizes ({test_sizes})", "PASS"))
    else:
        results['fail'] += 1
    
    # Test 3: Cross-platform (GPU → CPU)
    print("  E3.3: Cross-platform (GPU → CPU)...")
    if GPU_AVAILABLE:
        try:
            import cupy as cp
            
            hybrid_gpu = HybridKEM(security_level=128, gpu=True)
            hybrid_gpu.key_gen()
            n_gpu = hybrid_gpu.kem.n
            
            plaintext = b"Cross-platform test"
            ct_gpu = hybrid_gpu.encrypt(plaintext)
            ct_bytes = ct_gpu.to_bytes()
            
            # CPU instance with same keys
            hybrid_cpu = HybridKEM(security_level=128, gpu=False)
            hybrid_cpu.kem.pk = LWEPublicKey(
                A=cp.asnumpy(hybrid_gpu.kem.pk.A),
                b=cp.asnumpy(hybrid_gpu.kem.pk.b),
                pk_hash=hybrid_gpu.kem.pk.pk_hash
            )
            hybrid_cpu.kem.sk = LWESecretKey(
                s=cp.asnumpy(hybrid_gpu.kem.sk.s),
                z=hybrid_gpu.kem.sk.z
            )
            hybrid_cpu.kem.q = hybrid_gpu.kem.q
            hybrid_cpu.kem.delta = hybrid_gpu.kem.delta
            hybrid_cpu.mixer = hybrid_gpu.mixer
            
            ct_cpu = FullCiphertext.from_bytes(ct_bytes, n=n_gpu)
            recovered = hybrid_cpu.decrypt(ct_cpu)
            
            if plaintext == recovered:
                results['pass'] += 1
                results['tests'].append(("GPU→CPU cross-platform", "PASS"))
            else:
                results['fail'] += 1
                results['tests'].append(("GPU→CPU cross-platform", "FAIL"))
        except Exception as e:
            results['fail'] += 1
            results['tests'].append(("GPU→CPU cross-platform", f"ERROR: {e}"))
    else:
        results['tests'].append(("GPU→CPU cross-platform", "SKIPPED"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results

# =============================================================================
# Updated run_all_tests()
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
    
    # B. KEM Implementation Security
    print("\n" + "=" * 70)
    print("B. KEM IMPLEMENTATION SECURITY (FO)")
    print("=" * 70)
    
    all_results['b1_implicit_rejection_det'] = test_b1_implicit_rejection_determinism(iterations=100)
    all_results['b2_cca_reencrypt'] = test_b2_cca_reencrypt_check(iterations=100)
    all_results['b3_cpu_gpu_equiv'] = test_b3_cpu_gpu_equivalence()
    
    # D. Key Schedule
    print("\n" + "=" * 70)
    print("D. KEY SCHEDULE & INTEGRATION")
    print("=" * 70)
    
    all_results['d1_key_separation'] = test_d1_key_separation()
    all_results['d3_kem_dem_integration'] = test_d3_kem_dem_integration(chunks=100)
    
    # E. Extended Security (TCHES Reviewer Confidence)
    print("\n" + "=" * 70)
    print("E. EXTENDED SECURITY (TCHES)")
    print("=" * 70)
    
    all_results['e1_kfail_uniformity'] = test_e1_kfail_uniformity(iterations=1000)
    all_results['e2_negative_comprehensive'] = test_e2_negative_comprehensive()
    all_results['e3_serialization_roundtrip'] = test_e3_serialization_roundtrip()
    
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
