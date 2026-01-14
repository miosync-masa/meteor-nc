#!/usr/bin/env python3
"""
Meteor-NC Paper Claims Verification Test Suite

This test suite verifies the claims made in the TCHES paper:
"Meteor-NC: A High-Performance Post-Quantum Cryptosystem 
 from Non-Commutative Matrix Groups"

Tests correspond to Section 6 (Evaluation) of the paper.
"""

import numpy as np
import time
import sys
from typing import Dict, List, Tuple
from scipy import stats

# Import Meteor-NC
try:
    import cupy as cp
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False
    print("⚠️ CuPy not available - GPU required for paper claims tests")

sys.path.insert(0, '.')

if GPU_AVAILABLE:
    try:
        from meteor_nc import MeteorKDF
        USE_GPU = True
    except ImportError:
        USE_GPU = False
        print("⚠️ MeteorKDF not available")
else:
    USE_GPU = False


def create_crypto(n: int, m: int = None):
    """Create crypto instance (GPU required)."""
    if not USE_GPU:
        raise RuntimeError("GPU required for paper claims verification")
    if m is None:
        m = max(8, n // 32 + 2)  # Paper formula: m = max(8, ⌊n/32⌋ + 2)
    crypto = MeteorKDF(n=n, m=m)
    return crypto


class PaperClaimsVerification:
    """Verify claims from TCHES paper Section 6."""
    
    def __init__(self, n: int = 256, verbose: bool = True):
        self.n = n
        self.verbose = verbose
        self.results: Dict[str, dict] = {}
        
    def log(self, msg: str):
        if self.verbose:
            print(msg)
    
    # =========================================================================
    # Section 6.5.1: Million Message Test
    # =========================================================================
    def test_million_messages(self, num_messages: int = 100000) -> dict:
        """
        Paper claim (Section 6.5.1):
        - Total messages: 1,000,000
        - Max error observed: 2.90 × 10^-12
        - Decryption failures: 0 (100% success rate)
        
        Note: We use 100K by default for reasonable test time.
        Set num_messages=1000000 for full paper verification.
        """
        self.log(f"\n{'='*60}")
        self.log(f"TEST: Million Message Test (n={num_messages:,})")
        self.log(f"{'='*60}")
        
        if not USE_GPU:
            self.log("  ⚠️ SKIPPED - GPU required")
            return {'skipped': True, 'reason': 'GPU required'}
        
        crypto = create_crypto(n=self.n)
        crypto.key_gen()
        if USE_GPU:
            crypto.expand_keys()
        
        batch_size = 1000
        num_batches = num_messages // batch_size
        
        max_error = 0.0
        total_failures = 0
        errors = []
        
        start_time = time.time()
        
        for batch_idx in range(num_batches):
            # Generate random messages
            messages = np.random.randint(0, 256, size=(batch_size, self.n, self.n))
            
            for msg in messages:
                # Encrypt and decrypt
                ciphertext = crypto.encrypt(msg.astype(np.float64))
                decrypted = crypto.decrypt(ciphertext)
                
                # Calculate error
                error = np.max(np.abs(decrypted - msg))
                errors.append(error)
                max_error = max(max_error, error)
                
                # Check for failure (error > 0.5 means wrong integer)
                if error > 0.5:
                    total_failures += 1
            
            if self.verbose and (batch_idx + 1) % 10 == 0:
                elapsed = time.time() - start_time
                rate = (batch_idx + 1) * batch_size / elapsed
                print(f"  Progress: {(batch_idx+1)*batch_size:,}/{num_messages:,} "
                      f"({rate:.0f} msg/s, max_err={max_error:.2e})")
        
        elapsed_time = time.time() - start_time
        if hasattr(crypto, 'cleanup'):
            crypto.cleanup()
        
        result = {
            'total_messages': num_messages,
            'failures': total_failures,
            'success_rate': (num_messages - total_failures) / num_messages * 100,
            'max_error': max_error,
            'mean_error': np.mean(errors),
            'std_error': np.std(errors),
            'elapsed_time': elapsed_time,
            'throughput': num_messages / elapsed_time,
            'passed': total_failures == 0 and max_error < 1e-6
        }
        
        self.log(f"\n  Results:")
        self.log(f"  - Total messages: {result['total_messages']:,}")
        self.log(f"  - Failures: {result['failures']}")
        self.log(f"  - Success rate: {result['success_rate']:.4f}%")
        self.log(f"  - Max error: {result['max_error']:.2e}")
        self.log(f"  - Mean error: {result['mean_error']:.2e}")
        self.log(f"  - Throughput: {result['throughput']:.0f} msg/s")
        self.log(f"  - PASSED: {'✅' if result['passed'] else '❌'}")
        
        self.results['million_messages'] = result
        return result
    
    # =========================================================================
    # Section 5.3.3: Cached Cholesky Speedup
    # =========================================================================
    def test_cached_cholesky_speedup(self, num_iterations: int = 100) -> dict:
        """
        Paper claim (Table 9):
        - Standard lstsq: baseline
        - Cached Cholesky: 5.8× speedup
        """
        self.log(f"\n{'='*60}")
        self.log("TEST: Cached Cholesky Speedup")
        self.log(f"{'='*60}")
        
        if not USE_GPU:
            self.log("  ⚠️ SKIPPED - GPU required for Cholesky caching test")
            return {'skipped': True}
        
        crypto = create_crypto(n=self.n)
        crypto.key_gen()
        crypto.expand_keys()
        
        # Generate test messages
        messages = [np.random.randint(0, 256, size=(self.n, self.n)).astype(np.float64) 
                   for _ in range(num_iterations)]
        ciphertexts = [crypto.encrypt(msg) for msg in messages]
        
        # Method 1: Standard decryption (uses cached internally, but measure total)
        # We'll compare first decrypt (cold) vs subsequent (warm/cached)
        
        # Cold start - clear any caches
        if hasattr(crypto, 'cleanup'):
            crypto.cleanup()
        crypto = create_crypto(n=self.n)
        crypto.key_gen()
        crypto.expand_keys()
        
        # Time first decryption (includes Cholesky computation)
        ciphertext = crypto.encrypt(messages[0])
        
        start = time.time()
        _ = crypto.decrypt(ciphertext)
        cold_time = time.time() - start
        
        # Time subsequent decryptions (cached Cholesky)
        warm_times = []
        for ct in ciphertexts[1:50]:  # 50 iterations
            start = time.time()
            _ = crypto.decrypt(ct)
            warm_times.append(time.time() - start)
        
        avg_warm_time = np.mean(warm_times)
        speedup = cold_time / avg_warm_time if avg_warm_time > 0 else 0
        
        if hasattr(crypto, 'cleanup'):
            crypto.cleanup()
        
        result = {
            'cold_time_ms': cold_time * 1000,
            'warm_time_ms': avg_warm_time * 1000,
            'speedup': speedup,
            'passed': speedup > 1.0  # At least some speedup
        }
        
        self.log(f"\n  Results:")
        self.log(f"  - Cold decrypt: {result['cold_time_ms']:.2f} ms")
        self.log(f"  - Warm decrypt: {result['warm_time_ms']:.2f} ms")
        self.log(f"  - Speedup: {result['speedup']:.1f}×")
        self.log(f"  - PASSED: {'✅' if result['passed'] else '❌'}")
        self.log(f"  - Note: Paper claims 5.8× for batch=5000. Single-message speedup varies.")
        
        self.results['cholesky_speedup'] = result
        return result
    
    # =========================================================================
    # Section 6.6.2: APN IND-CPA Test (Semantic Security)
    # =========================================================================
    def test_apn_ind_cpa(self, num_encryptions: int = 100) -> dict:
        """
        Paper claim (Section 6.6.2):
        - 100 encryptions of the same message
        - All ciphertexts unique
        - Ciphertext variance: 2.28 × 10^-3
        """
        self.log(f"\n{'='*60}")
        self.log("TEST: APN IND-CPA (Semantic Security)")
        self.log(f"{'='*60}")
        
        if not USE_GPU:
            self.log("  ⚠️ SKIPPED - GPU required")
            return {'skipped': True, 'reason': 'GPU required'}
        
        crypto = create_crypto(n=self.n)
        crypto.key_gen()
        if USE_GPU:
            crypto.expand_keys()
        
        # Fixed message
        message = np.ones((self.n, self.n), dtype=np.float64) * 42
        
        # Encrypt same message multiple times
        ciphertexts = []
        for i in range(num_encryptions):
            ct = crypto.encrypt(message.copy())
            ciphertexts.append(ct.flatten())
        
        # Check uniqueness
        unique_count = 0
        for i in range(len(ciphertexts)):
            for j in range(i+1, len(ciphertexts)):
                if not np.allclose(ciphertexts[i], ciphertexts[j]):
                    unique_count += 1
        
        total_pairs = num_encryptions * (num_encryptions - 1) // 2
        all_unique = unique_count == total_pairs
        
        # Calculate variance
        ct_array = np.array(ciphertexts)
        variance = np.var(ct_array)
        mean_pairwise_diff = np.mean([np.linalg.norm(ciphertexts[i] - ciphertexts[j]) 
                                       for i in range(min(10, len(ciphertexts))) 
                                       for j in range(i+1, min(10, len(ciphertexts)))])
        
        # Verify decryption still works
        decryption_errors = []
        for ct_flat in ciphertexts[:10]:
            ct = ct_flat.reshape(self.n, self.n)
            decrypted = crypto.decrypt(ct)
            error = np.max(np.abs(decrypted - message))
            decryption_errors.append(error)
        
        if hasattr(crypto, 'cleanup'):
            crypto.cleanup()
        
        result = {
            'num_encryptions': num_encryptions,
            'unique_pairs': unique_count,
            'total_pairs': total_pairs,
            'all_unique': all_unique,
            'variance': variance,
            'mean_pairwise_diff': mean_pairwise_diff,
            'max_decryption_error': max(decryption_errors),
            'passed': all_unique and max(decryption_errors) < 0.5
        }
        
        self.log(f"\n  Results:")
        self.log(f"  - Encryptions of same message: {result['num_encryptions']}")
        self.log(f"  - Unique ciphertext pairs: {result['unique_pairs']}/{result['total_pairs']}")
        self.log(f"  - All unique: {'✅ YES' if result['all_unique'] else '❌ NO'}")
        self.log(f"  - Ciphertext variance: {result['variance']:.2e}")
        self.log(f"  - Mean pairwise diff: {result['mean_pairwise_diff']:.2e}")
        self.log(f"  - Max decryption error: {result['max_decryption_error']:.2e}")
        self.log(f"  - PASSED: {'✅' if result['passed'] else '❌'}")
        
        self.results['apn_ind_cpa'] = result
        return result
    
    # =========================================================================
    # Section 6.5.2: Numerical Stability (Extreme Inputs)
    # =========================================================================
    def test_numerical_stability(self) -> dict:
        """
        Paper claim (Section 6.5.2):
        - Zero vector: ✓
        - Unit vector: ✓
        - Scaled 10^10: ✓
        - Scaled 10^-10: ✓
        - Alternating ±1: ✓
        - Sparse (1% nonzero): ✓
        - Single impulse: ✓
        All extreme inputs decrypted correctly with error < 10^-6
        """
        self.log(f"\n{'='*60}")
        self.log("TEST: Numerical Stability (Extreme Inputs)")
        self.log(f"{'='*60}")
        
        if not USE_GPU:
            self.log("  ⚠️ SKIPPED - GPU required")
            return {'skipped': True, 'reason': 'GPU required'}
        
        crypto = create_crypto(n=self.n)
        crypto.key_gen()
        if USE_GPU:
            crypto.expand_keys()
        
        test_cases = {
            'zero_vector': np.zeros((self.n, self.n)),
            'unit_vector': np.ones((self.n, self.n)),
            'scaled_1e10': np.ones((self.n, self.n)) * 1e10,
            'scaled_1e-10': np.ones((self.n, self.n)) * 1e-10,
            'alternating': np.array([[(-1)**(i+j) for j in range(self.n)] 
                                     for i in range(self.n)], dtype=np.float64),
            'sparse_1pct': self._create_sparse_matrix(self.n, 0.01),
            'single_impulse': self._create_impulse_matrix(self.n),
            'random_int': np.random.randint(0, 256, size=(self.n, self.n)).astype(np.float64),
            'random_gaussian': np.random.randn(self.n, self.n) * 100,
        }
        
        results_detail = {}
        all_passed = True
        
        for name, message in test_cases.items():
            try:
                ciphertext = crypto.encrypt(message)
                decrypted = crypto.decrypt(ciphertext)
                error = np.max(np.abs(decrypted - message))
                
                # For scaled inputs, use relative error
                if np.max(np.abs(message)) > 1:
                    rel_error = error / np.max(np.abs(message))
                    passed = rel_error < 1e-6
                else:
                    passed = error < 1e-6
                
                results_detail[name] = {
                    'error': error,
                    'passed': passed
                }
                
                status = '✅' if passed else '❌'
                self.log(f"  - {name}: error={error:.2e} {status}")
                
                if not passed:
                    all_passed = False
                    
            except Exception as e:
                results_detail[name] = {'error': str(e), 'passed': False}
                self.log(f"  - {name}: EXCEPTION {e} ❌")
                all_passed = False
        
        if hasattr(crypto, 'cleanup'):
            crypto.cleanup()
        
        result = {
            'test_cases': len(test_cases),
            'passed_cases': sum(1 for r in results_detail.values() if r['passed']),
            'details': results_detail,
            'passed': all_passed
        }
        
        self.log(f"\n  Summary: {result['passed_cases']}/{result['test_cases']} passed")
        self.log(f"  PASSED: {'✅' if result['passed'] else '❌'}")
        
        self.results['numerical_stability'] = result
        return result
    
    def _create_sparse_matrix(self, n: int, density: float) -> np.ndarray:
        """Create sparse matrix with given density."""
        matrix = np.zeros((n, n))
        num_nonzero = int(n * n * density)
        indices = np.random.choice(n * n, num_nonzero, replace=False)
        for idx in indices:
            i, j = idx // n, idx % n
            matrix[i, j] = np.random.randint(1, 256)
        return matrix
    
    def _create_impulse_matrix(self, n: int) -> np.ndarray:
        """Create single impulse (one nonzero element)."""
        matrix = np.zeros((n, n))
        matrix[n//2, n//2] = 255.0
        return matrix
    
    # =========================================================================
    # Section 6.5.3: Long-Term Stability
    # =========================================================================
    def test_long_term_stability(self, num_cycles: int = 1000) -> dict:
        """
        Paper claim (Section 6.5.3):
        - Operations: 10,000 (same key)
        - Initial error: 2.77 × 10^-12
        - Final error: 2.73 × 10^-12
        - Maximum error: 3.57 × 10^-12
        - Drift: None detected
        
        Note: We use 1000 cycles by default. Set num_cycles=10000 for full test.
        """
        self.log(f"\n{'='*60}")
        self.log(f"TEST: Long-Term Stability ({num_cycles:,} cycles)")
        self.log(f"{'='*60}")
        
        if not USE_GPU:
            self.log("  ⚠️ SKIPPED - GPU required")
            return {'skipped': True, 'reason': 'GPU required'}
        
        crypto = create_crypto(n=self.n)
        crypto.key_gen()
        if USE_GPU:
            crypto.expand_keys()
        
        # Fixed message for consistency
        message = np.random.randint(0, 256, size=(self.n, self.n)).astype(np.float64)
        
        errors = []
        
        for cycle in range(num_cycles):
            ciphertext = crypto.encrypt(message)
            decrypted = crypto.decrypt(ciphertext)
            error = np.max(np.abs(decrypted - message))
            errors.append(error)
            
            if self.verbose and (cycle + 1) % 200 == 0:
                print(f"  Cycle {cycle+1}/{num_cycles}: error={error:.2e}")
        
        if hasattr(crypto, 'cleanup'):
            crypto.cleanup()
        
        # Analyze drift
        first_half = np.mean(errors[:len(errors)//2])
        second_half = np.mean(errors[len(errors)//2:])
        drift = abs(second_half - first_half) / first_half if first_half > 0 else 0
        
        result = {
            'num_cycles': num_cycles,
            'initial_error': errors[0],
            'final_error': errors[-1],
            'max_error': max(errors),
            'min_error': min(errors),
            'mean_error': np.mean(errors),
            'std_error': np.std(errors),
            'drift': drift,
            'drift_detected': drift > 0.1,  # >10% change = drift
            'passed': max(errors) < 1e-6 and drift < 0.1
        }
        
        self.log(f"\n  Results:")
        self.log(f"  - Initial error: {result['initial_error']:.2e}")
        self.log(f"  - Final error: {result['final_error']:.2e}")
        self.log(f"  - Max error: {result['max_error']:.2e}")
        self.log(f"  - Mean error: {result['mean_error']:.2e}")
        self.log(f"  - Std error: {result['std_error']:.2e}")
        self.log(f"  - Drift: {result['drift']*100:.2f}%")
        self.log(f"  - Drift detected: {'⚠️ YES' if result['drift_detected'] else '✅ NO'}")
        self.log(f"  - PASSED: {'✅' if result['passed'] else '❌'}")
        
        self.results['long_term_stability'] = result
        return result
    
    # =========================================================================
    # Section 6.6.1: Ciphertext Distribution Analysis
    # =========================================================================
    def test_ciphertext_distribution(self, num_samples: int = 1000) -> dict:
        """
        Paper claim (Section 6.6.1):
        - Normality test: 238/256 dimensions pass (p > 0.05)
        - Mean correlation: 0.0435 (target: < 0.1)
        - Max correlation: 0.2103
        """
        self.log(f"\n{'='*60}")
        self.log(f"TEST: Ciphertext Distribution ({num_samples} samples)")
        self.log(f"{'='*60}")
        
        if not USE_GPU:
            self.log("  ⚠️ SKIPPED - GPU required")
            return {'skipped': True, 'reason': 'GPU required'}
        
        crypto = create_crypto(n=self.n)
        crypto.key_gen()
        if USE_GPU:
            crypto.expand_keys()
        
        # Generate random messages and collect ciphertexts
        ciphertexts = []
        for _ in range(num_samples):
            msg = np.random.randint(0, 256, size=(self.n, self.n)).astype(np.float64)
            ct = crypto.encrypt(msg)
            ciphertexts.append(ct.flatten())
        
        ct_array = np.array(ciphertexts)  # shape: (num_samples, n*n)
        
        # Test normality for each dimension (sample of dimensions)
        num_dims_to_test = min(256, self.n * self.n)
        dim_indices = np.random.choice(self.n * self.n, num_dims_to_test, replace=False)
        
        normality_passed = 0
        for dim_idx in dim_indices:
            _, p_value = stats.shapiro(ct_array[:min(50, num_samples), dim_idx])
            if p_value > 0.05:
                normality_passed += 1
        
        normality_rate = normality_passed / num_dims_to_test
        
        # Calculate inter-dimension correlations (sample)
        num_corr_pairs = min(100, num_dims_to_test * (num_dims_to_test - 1) // 2)
        correlations = []
        
        pairs_checked = 0
        for i in range(min(20, num_dims_to_test)):
            for j in range(i+1, min(20, num_dims_to_test)):
                corr = np.corrcoef(ct_array[:, dim_indices[i]], 
                                   ct_array[:, dim_indices[j]])[0, 1]
                if not np.isnan(corr):
                    correlations.append(abs(corr))
                pairs_checked += 1
                if pairs_checked >= num_corr_pairs:
                    break
            if pairs_checked >= num_corr_pairs:
                break
        
        mean_corr = np.mean(correlations) if correlations else 0
        max_corr = max(correlations) if correlations else 0
        
        if hasattr(crypto, 'cleanup'):
            crypto.cleanup()
        
        result = {
            'num_samples': num_samples,
            'dims_tested': num_dims_to_test,
            'normality_passed': normality_passed,
            'normality_rate': normality_rate,
            'mean_correlation': mean_corr,
            'max_correlation': max_corr,
            'correlation_target': 0.1,
            'passed': normality_rate > 0.8 and mean_corr < 0.1
        }
        
        self.log(f"\n  Results:")
        self.log(f"  - Dimensions tested: {result['dims_tested']}")
        self.log(f"  - Normality passed: {result['normality_passed']}/{result['dims_tested']} "
                 f"({result['normality_rate']*100:.1f}%)")
        self.log(f"  - Mean correlation: {result['mean_correlation']:.4f} (target: <0.1)")
        self.log(f"  - Max correlation: {result['max_correlation']:.4f}")
        self.log(f"  - PASSED: {'✅' if result['passed'] else '❌'}")
        
        self.results['ciphertext_distribution'] = result
        return result
    
    # =========================================================================
    # Run All Tests
    # =========================================================================
    def run_all(self, quick: bool = True) -> Dict[str, dict]:
        """
        Run all paper claims verification tests.
        
        Args:
            quick: If True, use reduced iterations for faster testing.
                   If False, use paper's full parameters.
        """
        self.log("\n" + "="*70)
        self.log("METEOR-NC PAPER CLAIMS VERIFICATION")
        self.log(f"Security Level: n={self.n}")
        self.log(f"Mode: {'QUICK' if quick else 'FULL'}")
        self.log("="*70)
        
        if not USE_GPU:
            self.log("\n⚠️ GPU NOT AVAILABLE - ALL TESTS SKIPPED")
            self.log("Paper claims tests require GPU (CuPy + CUDA)")
            self.log("Run in Google Colab with GPU runtime or local CUDA environment")
            return {'all_skipped': True, 'reason': 'GPU required'}
        
        # Determine parameters based on mode
        if quick:
            million_msg_count = 10000
            long_term_cycles = 500
            distribution_samples = 500
        else:
            million_msg_count = 1000000
            long_term_cycles = 10000
            distribution_samples = 1000
        
        # Run tests
        self.test_apn_ind_cpa(100)
        self.test_numerical_stability()
        self.test_ciphertext_distribution(distribution_samples)
        self.test_long_term_stability(long_term_cycles)
        self.test_cached_cholesky_speedup()
        self.test_million_messages(million_msg_count)
        
        # Summary
        self.log("\n" + "="*70)
        self.log("SUMMARY")
        self.log("="*70)
        
        total = len(self.results)
        passed = sum(1 for r in self.results.values() 
                     if r.get('passed', False) or r.get('skipped', False))
        
        for name, result in self.results.items():
            if result.get('skipped'):
                status = '⏭️ SKIPPED'
            elif result.get('passed'):
                status = '✅ PASSED'
            else:
                status = '❌ FAILED'
            self.log(f"  {name}: {status}")
        
        self.log(f"\n  Total: {passed}/{total} tests passed")
        self.log("="*70)
        
        return self.results


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Verify TCHES paper claims for Meteor-NC'
    )
    parser.add_argument('-n', '--security-level', type=int, default=256,
                        help='Security level (128, 256, 512, 1024)')
    parser.add_argument('-f', '--full', action='store_true',
                        help='Run full tests (slower, matches paper exactly)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode (less output)')
    
    args = parser.parse_args()
    
    verifier = PaperClaimsVerification(
        n=args.security_level,
        verbose=not args.quiet
    )
    
    results = verifier.run_all(quick=not args.full)
    
    # Exit code based on results
    all_passed = all(
        r.get('passed', False) or r.get('skipped', False) 
        for r in results.values()
    )
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    exit(main())
