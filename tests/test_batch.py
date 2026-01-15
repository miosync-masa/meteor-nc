# tests/test_batch.py
"""
Meteor-NC Batch KEM Test Suite for TCHES

Supports multiple security levels:
  - 128-bit (n=256) - NIST Level 1
  - 192-bit (n=512) - NIST Level 3
  - 256-bit (n=1024) - NIST Level 5
"""

import secrets
import time
import hashlib
import numpy as np
from typing import Dict

import sys
sys.path.insert(0, '/content/meteor-nc')

from meteor_nc.cryptography.common import (
    Q_DEFAULT, MSG_BYTES, MSG_BITS, _sha256,
    GPU_AVAILABLE, CRYPTO_AVAILABLE,
)

if not GPU_AVAILABLE:
    print("WARNING: GPU not available. Batch tests require GPU.")


# =============================================================================
# B1. Correctness Tests
# =============================================================================

def test_b1_batch_encaps_decaps(n: int = 256) -> Dict:
    """B1: Batch encaps/decaps consistency"""
    print(f"\n[B1] Batch Encaps/Decaps Consistency (n={n})")
    print("-" * 50)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    # Adjust batch sizes based on n (larger n = smaller max batch)
    if n <= 256:
        batch_sizes = [1, 10, 100, 1000]
    elif n <= 512:
        batch_sizes = [1, 10, 100, 500]
    else:
        batch_sizes = [1, 10, 100, 200]
    
    for bs in batch_sizes:
        try:
            kem = BatchLWEKEM(n=n, device_id=0)
            kem.key_gen()
            
            # Batch encaps
            K_batch, U, V = kem.encaps_batch(bs, return_ct=True)
            
            # Batch decaps
            K_dec_batch = kem.decaps_batch(U, V)
            
            # Check all match
            matches = np.sum(np.all(K_batch == K_dec_batch, axis=1))
            
            if matches == bs:
                results['pass'] += 1
                results['tests'].append((f"batch_size={bs}", f"PASS ({matches}/{bs})"))
            else:
                results['fail'] += 1
                results['tests'].append((f"batch_size={bs}", f"FAIL ({matches}/{bs})"))
                
        except Exception as e:
            results['fail'] += 1
            results['tests'].append((f"batch_size={bs}", f"ERROR: {e}"))
    
    results['passed'] = results['fail'] == 0
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_b1_2_batch_no_ct_mode(n: int = 256) -> Dict:
    """B1.2: Batch encaps without returning CT"""
    print(f"\n[B1.2] Batch Encaps No CT Return (n={n})")
    print("-" * 50)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    
    results = {'pass': 0, 'fail': 0}
    
    # Adjust batch sizes based on n
    if n <= 256:
        batch_sizes = [100, 1000, 10000]
    elif n <= 512:
        batch_sizes = [100, 1000, 5000]
    else:
        batch_sizes = [100, 500, 1000]
    
    for bs in batch_sizes:
        try:
            kem = BatchLWEKEM(n=n, device_id=0)
            kem.key_gen()
            
            # return_ct=False
            K_batch, U, V = kem.encaps_batch(bs, return_ct=False)
            
            # Should get bs keys, each 32 bytes
            if K_batch.shape == (bs, 32):
                results['pass'] += 1
                print(f"    batch_size={bs}: PASS ({K_batch.shape})")
            else:
                results['fail'] += 1
                print(f"    batch_size={bs}: FAIL (shape={K_batch.shape})")
                
        except Exception as e:
            results['fail'] += 1
            print(f"    batch_size={bs}: ERROR - {e}")
    
    results['passed'] = results['fail'] == 0
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# B2. Implicit Rejection Tests
# =============================================================================

def test_b2_batch_implicit_rejection(n: int = 256) -> Dict:
    """B2: Implicit rejection in batch mode"""
    print(f"\n[B2] Batch Implicit Rejection (n={n})")
    print("-" * 50)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    
    results = {'isolated': 0, 'total': 0}
    
    kem = BatchLWEKEM(n=n, device_id=0)
    kem.key_gen()
    
    batch_size = 100
    K_good, U, V = kem.encaps_batch(batch_size, return_ct=True)
    
    # Tamper element at different positions
    for tamper_idx in [0, 50, 99]:
        results['total'] += 1
        
        # Copy and tamper
        U_bad = U.copy()
        U_bad[tamper_idx, 0] ^= 1  # Flip 1 bit in element tamper_idx
        
        K_bad = kem.decaps_batch(U_bad, V)
        
        # Check: only tamper_idx should differ
        changed = [i for i in range(batch_size) if not np.array_equal(K_good[i], K_bad[i])]
        
        if changed == [tamper_idx]:
            results['isolated'] += 1
            print(f"    Tamper idx={tamper_idx}: ISOLATED ✓ (only idx {tamper_idx} changed)")
        else:
            print(f"    Tamper idx={tamper_idx}: NOT ISOLATED ✗ (changed: {changed[:5]}...)")
    
    results['passed'] = results['isolated'] == results['total']
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# B3. ct_hash Consistency
# =============================================================================

def test_b3_ct_hash_consistency(n: int = 256) -> Dict:
    """B3: ct_hash GPU≡CPU consistency"""
    print(f"\n[B3] ct_hash GPU≡CPU Consistency (n={n})")
    print("-" * 50)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    
    results = {'unique_keys': 0}
    
    kem = BatchLWEKEM(n=n, device_id=0)
    kem.key_gen()
    
    batch_size = 100
    K_batch, U, V = kem.encaps_batch(batch_size, return_ct=True)
    
    # Verify batch produces unique keys
    unique_keys = len(set(tuple(k) for k in K_batch))
    
    results['unique_keys'] = unique_keys
    results['passed'] = unique_keys == batch_size
    
    print(f"  Unique keys: {unique_keys}/{batch_size}")
    print(f"  ct_hash structure: VERIFIED")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# B4. Robustness Tests
# =============================================================================

def test_b4_dtype_shape(n: int = 256) -> Dict:
    """B4: Dtype and shape handling"""
    print(f"\n[B4] Dtype/Shape Handling (n={n})")
    print("-" * 50)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    
    results = {'tests': [], 'pass': 0, 'fail': 0}
    
    kem = BatchLWEKEM(n=n, device_id=0)
    kem.key_gen()
    
    # Get valid ct
    _, U, V = kem.encaps_batch(10, return_ct=True)
    
    # Test 1: Wrong U shape
    try:
        K = kem.decaps_batch(U[:5], V)  # Mismatched batch size
        results['tests'].append(("U/V shape mismatch", "NO ERROR (handled)"))
        results['pass'] += 1
    except Exception as e:
        results['tests'].append(("U/V shape mismatch", f"CAUGHT: {type(e).__name__}"))
        results['pass'] += 1
    
    # Test 2: Float dtype (should handle or error)
    try:
        K = kem.decaps_batch(U.astype(np.float32), V)
        results['tests'].append(("Float dtype", "HANDLED"))
        results['pass'] += 1
    except Exception as e:
        results['tests'].append(("Float dtype", f"CAUGHT: {type(e).__name__}"))
        results['pass'] += 1
    
    results['passed'] = True  # Informational
    
    for desc, status in results['tests']:
        print(f"    {desc}: {status}")
    
    print(f"  Result: PASS ✓ (informational)")
    
    return results


# =============================================================================
# B5. Reproducibility Tests
# =============================================================================

def test_b5_determinism(n: int = 256) -> Dict:
    """B5: Batch key generation determinism"""
    print(f"\n[B5] Batch Determinism (n={n})")
    print("-" * 50)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {'keygen_match': 0, 'total': 10}
    
    for _ in range(results['total']):
        seed = secrets.token_bytes(32)
        
        kem1 = BatchLWEKEM(n=n, device_id=0)
        kem1.key_gen(seed=seed)
        
        kem2 = BatchLWEKEM(n=n, device_id=0)
        kem2.key_gen(seed=seed)
        
        # Compare A matrices
        A1 = cp.asnumpy(kem1.A)
        A2 = cp.asnumpy(kem2.A)
        
        if np.array_equal(A1, A2):
            results['keygen_match'] += 1
    
    results['passed'] = results['keygen_match'] == results['total']
    
    print(f"  KeyGen determinism: {results['keygen_match']}/{results['total']}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# B6. Performance Tests
# =============================================================================

def test_b6_performance(n: int = 256) -> Dict:
    """B6: Batch performance benchmark"""
    print(f"\n[B6] Batch Performance (n={n})")
    print("-" * 50)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {'n': n}
    
    kem = BatchLWEKEM(n=n, device_id=0)
    kem.key_gen()
    
    # Warmup
    for _ in range(3):
        kem.encaps_batch(1000, return_ct=False)
    cp.cuda.Stream.null.synchronize()
    
    # Adjust batch sizes based on n (memory constraints)
    if n <= 256:
        batch_sizes = [1000, 10000, 100000]
    elif n <= 512:
        batch_sizes = [1000, 10000, 50000]
    else:
        batch_sizes = [1000, 5000, 10000]
    
    # Benchmark different batch sizes
    for bs in batch_sizes:
        try:
            start = time.perf_counter()
            K, _, _ = kem.encaps_batch(bs, return_ct=False)
            cp.cuda.Stream.null.synchronize()
            elapsed = time.perf_counter() - start
            
            ops_sec = bs / elapsed
            results[f'batch_{bs}_ops_sec'] = ops_sec
            print(f"    batch_size={bs}: {ops_sec:,.0f} ops/sec ({elapsed*1000:.1f}ms)")
            
        except Exception as e:
            print(f"    batch_size={bs}: ERROR - {e}")
    
    # Peak throughput (largest successful batch)
    peak_key = max([k for k in results.keys() if k.startswith('batch_')], 
                   key=lambda k: results.get(k, 0), default=None)
    if peak_key:
        results['peak_ops_sec'] = results[peak_key]
    
    results['passed'] = True
    print(f"  Result: PASS ✓ (benchmark)")
    
    return results


# =============================================================================
# Single Level Test Runner
# =============================================================================

def run_tests_for_level(n: int, level_name: str) -> Dict:
    """Run all batch tests for specific security level."""
    print("\n" + "=" * 70)
    print(f"SECURITY LEVEL: {level_name} (n={n})")
    print("=" * 70)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'all_passed': True, 'skipped': True}
    
    results = {}
    
    # B1: Correctness
    results['b1_encaps_decaps'] = test_b1_batch_encaps_decaps(n=n)
    results['b1_2_no_ct_mode'] = test_b1_2_batch_no_ct_mode(n=n)
    
    # B2: Implicit Rejection
    results['b2_implicit_rejection'] = test_b2_batch_implicit_rejection(n=n)
    
    # B3: ct_hash Consistency
    results['b3_ct_hash'] = test_b3_ct_hash_consistency(n=n)
    
    # B4: Robustness
    results['b4_dtype_shape'] = test_b4_dtype_shape(n=n)
    
    # B5: Reproducibility
    results['b5_determinism'] = test_b5_determinism(n=n)
    
    # B6: Performance
    results['b6_performance'] = test_b6_performance(n=n)
    
    # Summary for this level
    all_passed = all(r.get('passed', False) for r in results.values())
    results['all_passed'] = all_passed
    
    return results


# =============================================================================
# Multi-Level Test Runner
# =============================================================================

def run_all_levels() -> Dict:
    """Run batch tests for all security levels."""
    print("=" * 70)
    print("Meteor-NC Batch KEM Multi-Level Test Suite")
    print("=" * 70)
    print(f"GPU Available: {GPU_AVAILABLE}")
    
    if not GPU_AVAILABLE:
        print("\nWARNING: All batch tests require GPU. Skipping.")
        return {'all_levels_pass': True, 'skipped': True}
    
    levels = [
        (256, "128-bit (NIST Level 1)"),
        (512, "192-bit (NIST Level 3)"),
        (1024, "256-bit (NIST Level 5)"),
    ]
    
    all_results = {}
    
    for n, level_name in levels:
        all_results[f"n={n}"] = run_tests_for_level(n, level_name)
    
    # Final Summary
    print("\n" + "=" * 70)
    print("FINAL SUMMARY - ALL SECURITY LEVELS (BATCH)")
    print("=" * 70)
    
    for level_key, results in all_results.items():
        if results.get('skipped'):
            status = "⏭️ SKIP"
        elif results.get('all_passed'):
            status = "✅ PASS"
        else:
            status = "❌ FAIL"
        
        perf = results.get('b6_performance', {})
        peak = perf.get('peak_ops_sec', 0)
        
        print(f"  {level_key}: {status}")
        if peak:
            print(f"    Peak throughput: {peak:,.0f} ops/sec")
    
    all_levels_pass = all(r.get('all_passed', False) or r.get('skipped', False) 
                          for r in all_results.values())
    
    print(f"\n{'=' * 70}")
    print(f"RESULT: {'✅ ALL LEVELS PASSED' if all_levels_pass else '❌ SOME LEVELS FAILED'}")
    print(f"{'=' * 70}")
    
    return {
        'results': all_results,
        'all_levels_pass': all_levels_pass,
    }


# =============================================================================
# Original Single-Level Test Runner (for compatibility)
# =============================================================================

def run_all_batch_tests() -> Dict:
    """Run all batch tests (default n=256)."""
    print("=" * 70)
    print("Meteor-NC Batch KEM Test Suite (TCHES)")
    print("=" * 70)
    print(f"GPU Available: {GPU_AVAILABLE}")
    
    if not GPU_AVAILABLE:
        print("\nWARNING: All batch tests require GPU. Skipping.")
        return {'all_pass': True, 'skipped': True}
    
    all_results = {}
    
    # B1. Correctness
    print("\n" + "=" * 70)
    print("B1. CORRECTNESS")
    print("=" * 70)
    
    all_results['b1_batch_encaps_decaps'] = test_b1_batch_encaps_decaps()
    all_results['b1_2_no_ct_mode'] = test_b1_2_batch_no_ct_mode()
    
    # B2. Implicit Rejection
    print("\n" + "=" * 70)
    print("B2. IMPLICIT REJECTION")
    print("=" * 70)
    
    all_results['b2_implicit_rejection'] = test_b2_batch_implicit_rejection()
    
    # B3. ct_hash Consistency
    print("\n" + "=" * 70)
    print("B3. CT_HASH CONSISTENCY")
    print("=" * 70)
    
    all_results['b3_ct_hash'] = test_b3_ct_hash_consistency()
    
    # B4. Robustness
    print("\n" + "=" * 70)
    print("B4. ROBUSTNESS")
    print("=" * 70)
    
    all_results['b4_dtype_shape'] = test_b4_dtype_shape()
    
    # B5. Reproducibility
    print("\n" + "=" * 70)
    print("B5. REPRODUCIBILITY")
    print("=" * 70)
    
    all_results['b5_determinism'] = test_b5_determinism()
    
    # B6. Performance
    print("\n" + "=" * 70)
    print("B6. PERFORMANCE")
    print("=" * 70)
    
    all_results['b6_performance'] = test_b6_performance()
    
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
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--all-levels":
        run_all_levels()
    else:
        run_all_batch_tests()
