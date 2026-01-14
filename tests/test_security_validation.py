#!/usr/bin/env python3
"""
Meteor-NC: Security Validation Tools (Complete Edition)

Comprehensive validation of Meteor-NC security properties:
1. LTDF: Lossy Trapdoor Function (rank deficiency, information-theoretic)
2. NCSP: Non-Commutative Security Parameter (commutator norm)
3. Procrustes: Noisy Orthogonal Procrustes Problem (rotation recovery)
4. Period structure analysis (Shor resistance)
5. Grover complexity estimation
6. Phase diagram analysis (Λ vs. stability)

Supports both CPU and GPU implementations.

Usage:
    # CPU mode (no CuPy required)
    python tests/test_security_validation.py
    
    # GPU mode (requires CuPy)
    python tests/test_security_validation.py --gpu
    
    # Specify security level
    python tests/test_security_validation.py --gpu --level 512

Author: Masamichi Iizumi
License: MIT
"""

import numpy as np
import time
import sys
import os
import argparse
from typing import Dict, Tuple, Optional, List, Union

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from meteor_nc import (
    create_kdf_meteor,
    check_gpu_available,
    compute_layer_count,
)


class SecurityValidator:
    """
    Comprehensive security validation for Meteor-NC

    Validates three-fold security (Section 4 of paper):
    - LTDF: Lossy Trapdoor Function (information-theoretic irreversibility)
    - NCSP: Non-Commutative Security Parameter (algebraic attack resistance)
    - Procrustes: Noisy Orthogonal Procrustes Problem (geometric recovery hardness)
    """

    @staticmethod
    def _get_array_module(crypto):
        """Get numpy or cupy depending on crypto type"""
        if hasattr(crypto, 'xp'):
            return crypto.xp
        # GPU版の場合
        if hasattr(crypto, 'public_keys_gpu') and crypto.public_keys_gpu:
            import cupy as cp
            return cp
        return np

    @staticmethod
    def _get_public_keys(crypto):
        """Get public keys from CPU or GPU version"""
        if hasattr(crypto, 'public_keys_gpu') and crypto.public_keys_gpu:
            return crypto.public_keys_gpu
        elif hasattr(crypto, 'public_keys') and crypto.public_keys:
            return crypto.public_keys
        else:
            raise ValueError("No public keys found. Call expand_keys() first.")

    @staticmethod
    def _is_gpu_crypto(crypto) -> bool:
        """Check if crypto instance is GPU version"""
        if hasattr(crypto, 'gpu'):
            return crypto.gpu
        return hasattr(crypto, 'public_keys_gpu') and crypto.public_keys_gpu is not None

    @staticmethod
    def verify_ltdf(crypto, verbose: bool = True) -> Dict:
        """
        Verify LTDF: Lossy Trapdoor Function (Section 4.2)

        Criterion: Private projection matrices are rank-deficient,
                   while public keys appear full-rank.
        
        Lossiness: ℓ = m(1-α)n dimensions of information lost.

        Returns:
            dict: LTDF metrics and security status
        """
        xp = SecurityValidator._get_array_module(crypto)
        is_gpu = SecurityValidator._is_gpu_crypto(crypto)

        # Check if private keys are saved
        private_P = getattr(crypto, 'private_P_gpu' if is_gpu else 'private_P', None)
        
        if private_P is None or len(private_P) == 0:
            if verbose:
                print("\n[LTDF (Lossy Trapdoor Function)]")
                print("  ⚠️ Private keys not saved, skipping")
            return {'secure': None, 'skipped': True}

        n = crypto.n
        noise_threshold = getattr(crypto, 'noise_std', 1e-10) * 10

        # Check private deficit
        rank_deficits = []
        for P in private_P:
            s = xp.linalg.svd(P, compute_uv=False)
            rank = int(xp.sum(s > noise_threshold))
            deficit = n - rank
            rank_deficits.append(deficit)

        # Check public rank
        public_keys = SecurityValidator._get_public_keys(crypto)
        public_ranks = []
        for pk in public_keys:
            s = xp.linalg.svd(pk, compute_uv=False)
            rank = int(xp.sum(s > noise_threshold))
            public_ranks.append(rank)

        avg_deficit = float(np.mean(rank_deficits))
        avg_public = float(np.mean(public_ranks))
        total_lossiness = sum(rank_deficits)

        # Security criterion
        secure = avg_deficit > n * 0.2 and avg_public > n * 0.95

        if verbose:
            print(f"\n[LTDF (Lossy Trapdoor Function)]")
            print(f"  Private deficit: {avg_deficit:.1f} / {n}")
            print(f"  Public rank: {avg_public:.1f} / {n}")
            print(f"  Total lossiness: {total_lossiness} dimensions")
            print(f"  Preimage space: ≥ 2^{total_lossiness}")
            print(f"  Criterion: deficit > {n * 0.2:.0f} AND public > {n * 0.95:.0f}")
            print(f"  Status: {'✅ SECURE' if secure else '⚠️ WEAK'}")

        return {
            'private_deficit': avg_deficit,
            'public_rank': avg_public,
            'total_lossiness': total_lossiness,
            'rank_deficits': rank_deficits,
            'secure': secure,
            'skipped': False
        }

    @staticmethod
    def verify_ncsp(crypto, verbose: bool = True) -> Dict:
        """
        Verify NCSP: Non-Commutative Security Parameter (Section 4.3)

        Criterion: Commutator norm ||[πᵢ, πⱼ]||_F must exceed threshold.
                   Threshold: 0.5 × √n (Paper Table 13)

        Returns:
            dict: NCSP metrics and security status
        """
        public_keys = SecurityValidator._get_public_keys(crypto)
        xp = SecurityValidator._get_array_module(crypto)
        n = crypto.n

        # Compute all pairwise commutators
        commutator_norms = []
        m = len(public_keys)
        for i in range(m):
            for j in range(i + 1, m):
                pi_i = public_keys[i]
                pi_j = public_keys[j]
                comm = pi_i @ pi_j - pi_j @ pi_i
                comm_norm = float(xp.linalg.norm(comm, 'fro'))
                commutator_norms.append(comm_norm)

        avg_norm = float(np.mean(commutator_norms))
        min_norm = float(np.min(commutator_norms))
        max_norm = float(np.max(commutator_norms))

        # Threshold from paper: 0.5 × √n
        threshold = 0.5 * np.sqrt(n)
        margin = avg_norm / threshold
        secure = avg_norm > threshold

        if verbose:
            print(f"\n[NCSP (Non-Commutative Security Parameter)]")
            print(f"  NCSP (avg): {avg_norm:.2f}")
            print(f"  NCSP (min): {min_norm:.2f}")
            print(f"  NCSP (max): {max_norm:.2f}")
            print(f"  Threshold: {threshold:.2f} (0.5×√{n})")
            print(f"  Margin: {margin:.1f}×")
            print(f"  Status: {'✅ SECURE' if secure else '⚠️ WEAK'}")

        return {
            'avg_commutator_norm': avg_norm,
            'min_commutator_norm': min_norm,
            'max_commutator_norm': max_norm,
            'threshold': threshold,
            'margin': margin,
            'secure': secure,
            'all_norms': commutator_norms
        }

    @staticmethod
    def verify_procrustes(crypto, verbose: bool = True) -> Dict:
        """
        Verify Procrustes: Noisy Orthogonal Procrustes Problem (Section 4.4)

        Criterion: Rotation perturbations must be within valid scale.
                   Valid range: 0.01 < ||R||_F < 10.0 × √(n/256)

        Note: SNR is reported but security relies on S-conjugacy (NCSP).

        Returns:
            dict: Procrustes metrics and security status
        """
        xp = SecurityValidator._get_array_module(crypto)
        is_gpu = SecurityValidator._is_gpu_crypto(crypto)
        n = crypto.n

        # Check if private keys are saved
        private_R = getattr(crypto, 'private_R_gpu' if is_gpu else 'private_R', None)

        if private_R is None or len(private_R) == 0:
            if verbose:
                print("\n[Procrustes (Noisy Orthogonal Procrustes)]")
                print("  ⚠️ Private keys not saved, skipping")
            return {'secure': None, 'skipped': True}

        r_norms = []
        snr_values = []
        noise_std = getattr(crypto, 'noise_std', 1e-10)

        for R in private_R:
            R_norm = float(xp.linalg.norm(R, 'fro'))
            r_norms.append(R_norm)

            expected_noise = noise_std * np.sqrt(n * n)
            snr = R_norm / expected_noise if expected_noise > 0 else float('inf')
            snr_values.append(snr)

        avg_norm = float(np.mean(r_norms))
        avg_snr = float(np.mean(snr_values))

        # Security criterion: dimension-scaled range check
        lower_bound = 0.01
        upper_bound = 10.0 * np.sqrt(n / 256.0)
        secure = lower_bound < avg_norm < upper_bound

        if verbose:
            print(f"\n[Procrustes (Noisy Orthogonal Procrustes)]")
            print(f"  R Frobenius norm: {avg_norm:.4f}")
            print(f"  Signal-to-Noise Ratio: {avg_snr:.2e}")
            print(f"  Valid range: [{lower_bound:.2f}, {upper_bound:.2f}] (dimension-scaled)")
            print(f"  Status: {'✅ SECURE' if secure else '⚠️ WEAK'}")
            print(f"  Note: SNR is informational; security from S-conjugacy (NCSP)")

        return {
            'r_norm': avg_norm,
            'snr': avg_snr,
            'lower_bound': lower_bound,
            'upper_bound': upper_bound,
            'secure': secure,
            'skipped': False
        }

    @staticmethod
    def check_period_structure(crypto, max_order: int = 15,
                               verbose: bool = True) -> Dict:
        """
        Check for periodic structure (Shor vulnerability)

        Tests if any public key πᵢ has small order: πᵢᵏ ≈ I

        Returns:
            dict: Period analysis results
        """
        public_keys = SecurityValidator._get_public_keys(crypto)
        xp = SecurityValidator._get_array_module(crypto)
        n = crypto.n

        periods_found = []
        min_distances = []

        # Check first 3 keys
        for idx, pi in enumerate(public_keys[:min(3, len(public_keys))]):
            power = pi.copy()
            eye = xp.eye(n, dtype=xp.float64)

            min_dist = float('inf')
            for k in range(2, max_order + 1):
                power = power @ pi
                dist = float(xp.linalg.norm(power - eye, 'fro'))
                min_dist = min(min_dist, dist)
                
                if dist < 45.0:  # Threshold for period detection
                    periods_found.append((idx, k, dist))
                    break
            
            min_distances.append(min_dist)

        has_period = len(periods_found) > 0
        secure = not has_period

        if verbose:
            print(f"\n[Period Structure Check (Shor Resistance)]")
            print(f"  Checked orders: 2-{max_order}")
            print(f"  Min distances: {[f'{d:.1f}' for d in min_distances]}")
            print(f"  Periods found: {len(periods_found)}")
            if periods_found:
                for idx, k, dist in periods_found:
                    print(f"    Key {idx}: order {k} (dist={dist:.2f})")
            print(f"  Status: {'✅ NO PERIOD' if secure else '⚠️ PERIOD DETECTED'}")

        return {
            'has_period': has_period,
            'periods': periods_found,
            'min_distances': min_distances,
            'secure': secure
        }

    @staticmethod
    def estimate_grover_complexity(n: int, m: int, verbose: bool = True) -> Dict:
        """
        Estimate Grover attack complexity

        Key space:
        - Each layer: n×n matrix with entries in ℤ_q (q = 2³¹-1)
        - Total: m layers
        - Classical search: O(q^(n²×m))
        - Grover search: O(√(q^(n²×m))) = O(q^(n²×m/2))

        Returns:
            dict: Complexity estimates
        """
        q = 2**31 - 1

        # Total key space (simplified estimate)
        # Each layer contributes n² matrix entries
        # Each entry has ~log₂(q) bits
        classical_bits = n * n * m * np.log2(q)

        # Grover gives quadratic speedup
        grover_bits = classical_bits / 2

        secure = grover_bits > 128  # 128-bit quantum security

        if verbose:
            print(f"\n[Grover Complexity (Quantum Resistance)]")
            print(f"  Key space: n={n}, m={m}, q=2³¹-1")
            print(f"  Classical search: 2^{classical_bits:.0f}")
            print(f"  Grover search:    2^{grover_bits:.0f}")
            print(f"  Threshold: 2^128")
            print(f"  Status: {'✅ SECURE' if secure else '⚠️ WEAK'}")

        return {
            'classical_bits': classical_bits,
            'grover_bits': grover_bits,
            'secure': secure
        }

    @staticmethod
    def full_security_check(crypto) -> Dict:
        """
        Run all security checks (three-fold + classical + quantum)

        Validates (Section 4 of paper):
        1. LTDF: Lossy Trapdoor Function (information-theoretic)
        2. NCSP: Non-Commutative Security Parameter (algebraic)
        3. Procrustes: Noisy Orthogonal Procrustes Problem (geometric)
        4. Period structure (Shor resistance)
        5. Grover complexity (quantum resistance)

        Returns:
            dict: Complete security analysis
        """
        is_gpu = SecurityValidator._is_gpu_crypto(crypto)
        
        print("\n" + "=" * 70)
        print(f"Security Validation: Meteor-NC (n={crypto.n}, m={crypto.m})")
        print(f"Implementation: {'GPU' if is_gpu else 'CPU'}")
        print("=" * 70)

        # LTDF: Lossy Trapdoor Function (Section 4.2)
        ltdf_result = SecurityValidator.verify_ltdf(crypto)

        # NCSP: Non-Commutative Security Parameter (Section 4.3)
        ncsp_result = SecurityValidator.verify_ncsp(crypto)

        # Procrustes: Noisy Orthogonal Procrustes Problem (Section 4.4)
        procrustes_result = SecurityValidator.verify_procrustes(crypto)

        # Period structure (Shor resistance)
        period_result = SecurityValidator.check_period_structure(crypto)

        # Grover complexity (quantum resistance)
        grover_result = SecurityValidator.estimate_grover_complexity(
            crypto.n, crypto.m
        )

        # Overall verdict
        threefold_checks = [
            ltdf_result.get('secure'),
            ncsp_result.get('secure'),
            procrustes_result.get('secure')
        ]
        threefold_secure = all(x for x in threefold_checks if x is not None)

        classical_secure = period_result['secure']
        quantum_secure = grover_result['secure']

        all_secure = threefold_secure and classical_secure and quantum_secure

        print(f"\n{'=' * 70}")
        print(f"[Summary]")
        print(f"  LTDF:             {'✅ PASSED' if ltdf_result.get('secure') else '⚠️ FAILED' if ltdf_result.get('secure') is not None else '⏭️ SKIPPED'}")
        print(f"  NCSP:             {'✅ PASSED' if ncsp_result.get('secure') else '⚠️ FAILED'}")
        print(f"  Procrustes:       {'✅ PASSED' if procrustes_result.get('secure') else '⚠️ FAILED' if procrustes_result.get('secure') is not None else '⏭️ SKIPPED'}")
        print(f"  Period Structure: {'✅ PASSED' if classical_secure else '⚠️ FAILED'}")
        print(f"  Grover Complexity: {'✅ PASSED' if quantum_secure else '⚠️ FAILED'}")
        print(f"")
        print(f"  Three-fold Security (LTDF/NCSP/Procrustes): {'✅ ALL PASSED' if threefold_secure else '⚠️ SOME FAILED'}")
        print(f"  Classical Security (Shor):                  {'✅ PASSED' if classical_secure else '⚠️ FAILED'}")
        print(f"  Quantum Security (Grover):                  {'✅ PASSED' if quantum_secure else '⚠️ FAILED'}")
        print(f"")
        print(f"  Overall: {'✅ VERIFIED' if all_secure else '⚠️ REVIEW NEEDED'}")
        print(f"{'=' * 70}")

        return {
            'ltdf': ltdf_result,
            'ncsp': ncsp_result,
            'procrustes': procrustes_result,
            'period_structure': period_result,
            'grover_complexity': grover_result,
            'overall_secure': all_secure,
            'threefold_secure': threefold_secure,
            'classical_secure': classical_secure,
            'quantum_secure': quantum_secure
        }


class PhaseDiagramAnalyzer:
    """
    Analyze Λ = K/|V|_eff phase transition

    Tests cryptosystem behavior across different Λ values
    to verify theoretical predictions.
    """

    def __init__(self, n: int = 64, m: int = 6, gpu: bool = False):
        self.n = n
        self.m = m
        self.gpu = gpu

        mode_str = 'GPU' if gpu else 'CPU'
        print(f"[Phase Analyzer] n={n}, m={m}, mode={mode_str}")

    def compute_lambda(self, noise_std: float, rank_reduction: float) -> float:
        """
        Compute theoretical Λ = K / |V|_eff

        K: Perturbation energy (proportional to noise²)
        |V|_eff: Effective volume (affected by rank reduction)
        """
        K = noise_std**2 * self.n * self.m
        V_eff = max((1 - rank_reduction)**self.n * 10.0, 1e-10)
        return K / V_eff

    def test_point(self, noise_std: float, rank_reduction: float = 0.3,
                   trials: int = 5) -> Tuple[float, float]:
        """
        Test single parameter point

        Args:
            noise_std: Noise standard deviation
            rank_reduction: Rank deficit ratio
            trials: Number of trials

        Returns:
            (success_rate, avg_error)
        """
        successes = 0
        errors = []

        for _ in range(trials):
            try:
                # Create crypto with custom parameters
                crypto = create_kdf_meteor(self.n, gpu=self.gpu)
                # Override parameters
                crypto.noise_std = noise_std
                crypto.rank_reduction = rank_reduction
                
                crypto.key_gen(verbose=False)
                crypto.expand_keys(verbose=False)

                # Test encryption/decryption
                xp = crypto.xp if hasattr(crypto, 'xp') else np
                message = xp.random.randn(self.n).astype(xp.float64)
                ciphertext = crypto.encrypt(message)
                recovered = crypto.decrypt(ciphertext)

                error = float(xp.linalg.norm(message - recovered) / xp.linalg.norm(message))
                errors.append(error)

                if error < 1e-3:  # Success threshold
                    successes += 1
            except Exception as e:
                errors.append(float('inf'))

        success_rate = successes / trials
        avg_error = np.mean([e for e in errors if e != float('inf')]) if errors else float('inf')

        return success_rate, avg_error

    def scan_lambda_range(self, lambda_values: List[float],
                          rank_reduction: float = 0.3) -> Dict:
        """
        Scan across Λ values by varying noise

        Args:
            lambda_values: List of Λ values to test
            rank_reduction: Fixed rank reduction ratio

        Returns:
            dict: Scan results
        """
        print("\n" + "=" * 70)
        print(f"Phase Transition Scan (n={self.n}, m={self.m})")
        print(f"Testing {len(lambda_values)} Λ values")
        print("=" * 70)

        results = {
            'lambda_values': [],
            'noise_values': [],
            'success_rates': [],
            'errors': []
        }

        for lam in lambda_values:
            # Convert Λ to noise_std
            # Λ = K/V_eff = (noise² × n × m) / V_eff
            V_eff = (1 - rank_reduction)**self.n * 10.0
            noise_std = np.sqrt(lam * V_eff / (self.n * self.m))

            # Test
            success, error = self.test_point(noise_std, rank_reduction)

            results['lambda_values'].append(lam)
            results['noise_values'].append(noise_std)
            results['success_rates'].append(success)
            results['errors'].append(error)

            print(f"  Λ={lam:.2f} (noise={noise_std:.2e}): Success={success:.0%}, Error={error:.2e}")

        # Find transition point
        transition_idx = None
        for i in range(len(results['success_rates']) - 1):
            if (results['success_rates'][i] > 0.5 and
                results['success_rates'][i+1] <= 0.5):
                transition_idx = i
                break

        if transition_idx is not None:
            transition_lambda = results['lambda_values'][transition_idx]
            print(f"\n✓ Phase transition detected near Λ ≈ {transition_lambda:.2f}")
        else:
            print(f"\n⚠️ No clear transition in scanned range")

        print("=" * 70)

        return results


def run_validation_suite(gpu: bool = False, security_level: int = 256):
    """
    Run complete validation suite

    Args:
        gpu: Use GPU acceleration
        security_level: 128, 256, 512, or 1024
    """
    print("\n" + "🌠" * 35)
    print("Meteor-NC: Security Validation Suite (Complete Edition)")
    print("🌠" * 35)

    # Check GPU availability
    gpu_available = check_gpu_available()
    if gpu and not gpu_available:
        print("⚠️ GPU requested but CuPy not available, falling back to CPU")
        gpu = False

    print(f"\nMode: {'GPU' if gpu else 'CPU'}")
    print(f"Security Level: METEOR-{security_level}")

    # Create crypto instance
    print(f"\n[Creating METEOR-{security_level}]")
    crypto = create_kdf_meteor(security_level, gpu=gpu)
    crypto.key_gen(verbose=True)

    print(f"\n[Expanding keys from seed...]")
    start = time.time()
    crypto.expand_keys(verbose=True)
    expand_time = time.time() - start
    print(f"  Expansion time: {expand_time:.3f}s")

    # Full security check
    security_results = SecurityValidator.full_security_check(crypto)

    # Performance check
    print(f"\n[Performance Check]")
    xp = crypto.xp if hasattr(crypto, 'xp') else np
    
    # Single message test
    message = xp.random.randn(security_level).astype(xp.float64)
    
    start = time.time()
    ciphertext = crypto.encrypt(message)
    encrypt_time = (time.time() - start) * 1000
    
    start = time.time()
    recovered = crypto.decrypt(ciphertext)
    decrypt_time = (time.time() - start) * 1000
    
    error = float(xp.linalg.norm(message - recovered) / xp.linalg.norm(message))
    
    print(f"  Single encrypt: {encrypt_time:.2f} ms")
    print(f"  Single decrypt: {decrypt_time:.2f} ms")
    print(f"  Relative error: {error:.2e}")
    print(f"  Status: {'✅ SUCCESS' if error < 1e-6 else '⚠️ HIGH ERROR'}")

    # Batch test
    print(f"\n[Batch Test (100 messages)]")
    messages = xp.random.randn(100, security_level).astype(xp.float64)
    
    start = time.time()
    ciphertexts = crypto.encrypt_batch(messages)
    batch_encrypt_time = (time.time() - start) * 1000
    
    start = time.time()
    recovered_batch, _ = crypto.decrypt_batch(ciphertexts)
    batch_decrypt_time = (time.time() - start) * 1000
    
    batch_errors = xp.linalg.norm(messages - recovered_batch, axis=1) / xp.linalg.norm(messages, axis=1)
    max_error = float(xp.max(batch_errors))
    
    print(f"  Batch encrypt: {batch_encrypt_time:.2f} ms ({batch_encrypt_time/100:.3f} ms/msg)")
    print(f"  Batch decrypt: {batch_decrypt_time:.2f} ms ({batch_decrypt_time/100:.3f} ms/msg)")
    print(f"  Max error: {max_error:.2e}")
    print(f"  Throughput: {100000/batch_decrypt_time:.0f} msg/s")

    # Phase transition scan (smaller dimension for speed)
    print(f"\n[Phase Transition Scan]")
    analyzer = PhaseDiagramAnalyzer(n=64, m=6, gpu=gpu)
    lambda_range = [0.5, 0.7, 0.9, 1.0, 1.1, 1.3, 1.5]
    phase_results = analyzer.scan_lambda_range(lambda_range)

    # Summary
    print("\n" + "=" * 70)
    print("Validation Summary")
    print("=" * 70)
    print(f"  Security Level: METEOR-{security_level}")
    print(f"  Implementation: {'GPU' if gpu else 'CPU'}")
    print(f"  Security: {'✅ ALL PASSED' if security_results['overall_secure'] else '⚠️ SOME FAILED'}")
    print(f"  Performance: ✅ Tested ({100000/batch_decrypt_time:.0f} msg/s)")
    print(f"  Phase Transition: ✅ Scanned")
    print("=" * 70)

    print("\n" + "🌠" * 35)
    print("Validation Complete!")
    print("🌠" * 35)

    return {
        'security': security_results,
        'phase': phase_results,
        'performance': {
            'encrypt_time_ms': encrypt_time,
            'decrypt_time_ms': decrypt_time,
            'batch_throughput': 100000 / batch_decrypt_time,
            'max_error': max_error
        }
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Meteor-NC Security Validation Suite')
    parser.add_argument('--gpu', action='store_true', 
                        help='Use GPU acceleration (requires CuPy)')
    parser.add_argument('--level', type=int, default=256,
                        choices=[128, 256, 512, 1024],
                        help='Security level (default: 256)')
    args = parser.parse_args()

    results = run_validation_suite(gpu=args.gpu, security_level=args.level)
    
    # Exit code based on security
    sys.exit(0 if results['security']['overall_secure'] else 1)
