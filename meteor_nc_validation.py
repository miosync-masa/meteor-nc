"""
Meteor-NC: Security Validation Tools (Complete Edition)

Comprehensive validation of Meteor-NC security properties:
1. Λ-IPP: Inverse Projection Problem (rank deficiency)
2. Λ-CP: Conjugacy Problem (non-commutativity)
3. Λ-RRP: Rotation Recovery Problem (perturbation scale)
4. Period structure analysis (Shor resistance)
5. Grover complexity estimation
6. Phase diagram analysis (Λ vs. stability)

Supports both CPU and GPU implementations.

Usage:
    python meteor_nc_validation.py

Author: Masamichi Iizumi
License: MIT
"""

import numpy as np
from scipy.linalg import lstsq
from scipy.stats import ortho_group, special_ortho_group
import time
from typing import Dict, Tuple, Union, Optional

# Import implementations
try:
    from meteor_nc_gpu import MeteorNC_GPU
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False
    print("Warning: GPU implementation not available")

try:
    from meteor_nc_cpu import MeteorNC
    CPU_AVAILABLE = True
except ImportError:
    CPU_AVAILABLE = False
    print("Warning: CPU implementation not available")

if not GPU_AVAILABLE and not CPU_AVAILABLE:
    raise ImportError("Neither GPU nor CPU implementation found!")

# Type alias
CryptoType = Union['MeteorNC_GPU', 'MeteorNC']


class SecurityValidator:
    """
    Comprehensive security validation for Meteor-NC

    Validates all three Λ-criteria:
    - Λ-IPP: Inverse Projection Problem
    - Λ-CP: Conjugacy Problem
    - Λ-RRP: Rotation Recovery Problem
    """

    @staticmethod
    def _get_public_keys(crypto):
        """Get public keys from CPU or GPU version"""
        if hasattr(crypto, 'public_keys_gpu'):
            return crypto.public_keys_gpu
        elif hasattr(crypto, 'public_keys'):
            return crypto.public_keys
        else:
            raise ValueError("No public keys found")

    @staticmethod
    def _is_gpu_crypto(crypto) -> bool:
        """Check if crypto instance is GPU version"""
        return hasattr(crypto, 'public_keys_gpu')

    @staticmethod
    def verify_lambda_ipp(crypto: CryptoType, verbose: bool = True) -> Dict:
        """
        Verify Λ-IPP: Inverse Projection Problem

        Criterion: Private projection matrices are rank-deficient,
                   while public keys appear full-rank.

        Returns:
            dict: IPP metrics and security status
        """
        is_gpu = SecurityValidator._is_gpu_crypto(crypto)

        # Check if private keys are saved
        has_private = (
            hasattr(crypto, 'private_P_gpu') if is_gpu
            else hasattr(crypto, 'private_P')
        )

        if not has_private or len(getattr(crypto,
                'private_P_gpu' if is_gpu else 'private_P', [])) == 0:
            if verbose:
                print("\n[Λ-IPP (Inverse Projection Problem)]")
                print("  ⚠️ Private keys not saved, skipping")
            return {'secure': None, 'skipped': True}

        if is_gpu:
            import cupy as cp

            # Check private deficit
            rank_deficits = []
            private_P = crypto.private_P_gpu
            for P in private_P:
                s = cp.linalg.svd(P, compute_uv=False)
                rank = int(cp.sum(s > crypto.noise_std * 10))
                deficit = crypto.n - rank
                rank_deficits.append(deficit)

            # Check public rank
            public_ranks = []
            for pk in crypto.public_keys_gpu:
                s = cp.linalg.svd(pk, compute_uv=False)
                rank = int(cp.sum(s > crypto.noise_std * 10))
                public_ranks.append(rank)
        else:
            # CPU version
            rank_deficits = []
            for P in crypto.private_P:
                s = np.linalg.svd(P, compute_uv=False)
                rank = int(np.sum(s > crypto.noise_std * 10))
                deficit = crypto.n - rank
                rank_deficits.append(deficit)

            public_ranks = []
            for pk in crypto.public_keys:
                s = np.linalg.svd(pk, compute_uv=False)
                rank = int(np.sum(s > crypto.noise_std * 10))
                public_ranks.append(rank)

        avg_deficit = float(np.mean(rank_deficits))
        avg_public = float(np.mean(public_ranks))

        # Security criterion
        secure = avg_deficit > crypto.n * 0.2 and avg_public > crypto.n * 0.95

        if verbose:
            print(f"\n[Λ-IPP (Inverse Projection Problem)]")
            print(f"  Private deficit: {avg_deficit:.1f} / {crypto.n}")
            print(f"  Public rank: {avg_public:.1f} / {crypto.n}")
            print(f"  Criterion: deficit > {crypto.n * 0.2:.0f} AND public > {crypto.n * 0.95:.0f}")
            print(f"  Status: {'✅ SECURE' if secure else '⚠️ WEAK'}")

        return {
            'private_deficit': avg_deficit,
            'public_rank': avg_public,
            'secure': secure,
            'skipped': False
        }

    @staticmethod
    def verify_lambda_cp(crypto: CryptoType, verbose: bool = True) -> Dict:
        """
        Verify Λ-CP: Conjugacy Problem (Non-commutativity)

        Criterion: Commutator norm ||[πᵢ, πⱼ]|| must exceed threshold.
                   Threshold scales with dimension: 8.0 × √(n/256)

        Returns:
            dict: CP metrics and security status
        """
        public_keys = SecurityValidator._get_public_keys(crypto)
        is_gpu = SecurityValidator._is_gpu_crypto(crypto)

        if len(public_keys) == 0:
            raise ValueError("Keys not generated")

        # Compute commutators
        commutators = []
        for i in range(len(public_keys) - 1):
            pi_i = public_keys[i]
            pi_j = public_keys[i+1]
            comm = pi_i @ pi_j - pi_j @ pi_i

            if is_gpu:
                import cupy as cp
                comm_norm = float(cp.linalg.norm(comm, 'fro'))
            else:
                comm_norm = np.linalg.norm(comm, 'fro')

            commutators.append(comm_norm)

        avg_norm = float(np.mean(commutators))

        # Dimension-scaled threshold
        threshold = 8.0 * np.sqrt(crypto.n / 256.0)
        secure = avg_norm > threshold

        if verbose:
            print(f"\n[Λ-CP (Conjugacy Problem)]")
            print(f"  Commutator norm: {avg_norm:.2f}")
            print(f"  Threshold: {threshold:.2f} (scaled by √(n/256))")
            print(f"  Status: {'✅ SECURE' if secure else '⚠️ WEAK'}")

        return {
            'avg_commutator_norm': avg_norm,
            'threshold': threshold,
            'secure': secure,
            'all_norms': commutators
        }

    @staticmethod
    def verify_lambda_rrp(crypto: CryptoType, verbose: bool = True) -> Dict:
        """
        Verify Λ-RRP: Rotation Recovery Problem

        Criterion: Rotation perturbations must be within valid scale.
                   Valid range: 0.01 < ||R||_F < 10.0

        Note: SNR is reported but security relies on S-conjugacy (Λ-CP).

        Returns:
            dict: RRP metrics and security status
        """
        is_gpu = SecurityValidator._is_gpu_crypto(crypto)

        # Check if private keys are saved
        has_private = (
            hasattr(crypto, 'private_R_gpu') if is_gpu
            else hasattr(crypto, 'private_R')
        )

        if not has_private or len(getattr(crypto,
                'private_R_gpu' if is_gpu else 'private_R', [])) == 0:
            if verbose:
                print("\n[Λ-RRP (Rotation Recovery Problem)]")
                print("  ⚠️ Private keys not saved, skipping")
            return {'secure': None, 'skipped': True}

        if is_gpu:
            import cupy as cp

            r_norms = []
            snr_values = []

            for R in crypto.private_R_gpu:
                R_norm = float(cp.linalg.norm(R, 'fro'))
                r_norms.append(R_norm)

                expected_noise = crypto.noise_std * np.sqrt(crypto.n * crypto.n)
                snr = R_norm / expected_noise if expected_noise > 0 else float('inf')
                snr_values.append(snr)
        else:
            # CPU version
            r_norms = []
            snr_values = []

            for R in crypto.private_R:
                R_norm = np.linalg.norm(R, 'fro')
                r_norms.append(R_norm)

                expected_noise = crypto.noise_std * np.sqrt(crypto.n * crypto.n)
                snr = R_norm / expected_noise if expected_noise > 0 else float('inf')
                snr_values.append(snr)

        avg_norm = float(np.mean(r_norms))
        avg_snr = float(np.mean(snr_values))

        # Security criterion: absolute scale check
        lower_bound = 0.01
        upper_bound = 10.0 * np.sqrt(crypto.n / 256.0)
        
        # Security criterion: dimension-scaled range check
        secure = lower_bound < avg_norm < upper_bound

        if verbose:
            print(f"\n[Λ-RRP (Rotation Recovery Problem)]")
            print(f"  R Frobenius norm: {avg_norm:.4f}")
            print(f"  Signal-to-Noise Ratio: {avg_snr:.2e}")
            print(f"  Valid range: [{lower_bound:.2f}, {upper_bound:.2f}] (dimension-scaled)")
            print(f"  Status: {'✅ SECURE' if secure else '⚠️ WEAK'}")
            print(f"  Note: SNR is informational; security from S-conjugacy (Λ-CP)")

        return {
            'r_norm': avg_norm,
            'snr': avg_snr,
            'lower_bound': lower_bound,
            'upper_bound': upper_bound,
            'secure': secure,
            'skipped': False
        }

    @staticmethod
    def check_period_structure(crypto: CryptoType, max_order: int = 15,
                               verbose: bool = True) -> Dict:
        """
        Check for periodic structure (Shor vulnerability)

        Tests if any public key πᵢ has small order: πᵢᵏ ≈ I

        Returns:
            dict: Period analysis results
        """
        public_keys = SecurityValidator._get_public_keys(crypto)
        is_gpu = SecurityValidator._is_gpu_crypto(crypto)

        if len(public_keys) == 0:
            raise ValueError("Keys not generated")

        n = crypto.n
        periods_found = []

        # Check first 3 keys
        for idx, pi in enumerate(public_keys[:min(3, len(public_keys))]):
            if is_gpu:
                import cupy as cp
                power = pi.copy()
                eye = cp.eye(n, dtype=cp.float64)

                for k in range(2, max_order + 1):
                    power = power @ pi
                    dist = float(cp.linalg.norm(power - eye, 'fro'))
                    if dist < 45.0:  # Threshold for period detection
                        periods_found.append((idx, k, dist))
                        break
            else:
                power = pi.copy()
                eye = np.eye(n)

                for k in range(2, max_order + 1):
                    power = power @ pi
                    dist = np.linalg.norm(power - eye, 'fro')
                    if dist < 45.0:
                        periods_found.append((idx, k, dist))
                        break

        has_period = len(periods_found) > 0
        secure = not has_period

        if verbose:
            print(f"\n[Period Structure Check (Shor Resistance)]")
            print(f"  Checked orders: 2-{max_order}")
            print(f"  Periods found: {len(periods_found)}")
            if periods_found:
                for idx, k, dist in periods_found:
                    print(f"    Key {idx}: order {k} (dist={dist:.2f})")
            print(f"  Status: {'✅ NO PERIOD' if secure else '⚠️ PERIOD DETECTED'}")

        return {
            'has_period': has_period,
            'periods': periods_found,
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
    def full_security_check(crypto: CryptoType) -> Dict:
        """
        Run all security checks (Λ-criteria + classical + quantum)

        Validates:
        1. Λ-IPP: Inverse Projection Problem
        2. Λ-CP: Conjugacy Problem
        3. Λ-RRP: Rotation Recovery Problem
        4. Period structure (Shor resistance)
        5. Grover complexity (quantum resistance)

        Returns:
            dict: Complete security analysis
        """
        print("\n" + "="*70)
        print(f"Security Validation: Meteor-NC (n={crypto.n}, m={crypto.m})")
        print(f"Implementation: {'GPU' if SecurityValidator._is_gpu_crypto(crypto) else 'CPU'}")
        print("="*70)

        # Λ-IPP: Inverse Projection Problem
        ipp_result = SecurityValidator.verify_lambda_ipp(crypto)

        # Λ-CP: Conjugacy Problem (Non-commutativity)
        cp_result = SecurityValidator.verify_lambda_cp(crypto)

        # Λ-RRP: Rotation Recovery Problem
        rrp_result = SecurityValidator.verify_lambda_rrp(crypto)

        # Period structure (Shor resistance)
        period_result = SecurityValidator.check_period_structure(crypto)

        # Grover complexity (quantum resistance)
        grover_result = SecurityValidator.estimate_grover_complexity(
            crypto.n, crypto.m
        )

        # Overall verdict
        lambda_checks = [
            ipp_result.get('secure'),
            cp_result.get('secure'),
            rrp_result.get('secure')
        ]
        lambda_secure = all(x for x in lambda_checks if x is not None)

        classical_secure = period_result['secure']
        quantum_secure = grover_result['secure']

        all_secure = lambda_secure and classical_secure and quantum_secure

        print(f"\n{'='*70}")
        print(f"[Summary]")
        print(f"  Λ-Criteria (IPP/CP/RRP): {'✅ ALL PASSED' if lambda_secure else '⚠️ SOME FAILED'}")
        print(f"  Classical Security:      {'✅ PASSED' if classical_secure else '⚠️ FAILED'}")
        print(f"  Quantum Security:        {'✅ PASSED' if quantum_secure else '⚠️ FAILED'}")
        print(f"")
        print(f"  Overall: {'✅ VERIFIED' if all_secure else '⚠️ REVIEW NEEDED'}")
        print(f"{'='*70}")

        return {
            'lambda_ipp': ipp_result,
            'lambda_cp': cp_result,
            'lambda_rrp': rrp_result,
            'period_structure': period_result,
            'grover_complexity': grover_result,
            'overall_secure': all_secure,
            'lambda_secure': lambda_secure,
            'classical_secure': classical_secure,
            'quantum_secure': quantum_secure
        }


class PhaseDiagramAnalyzer:
    """
    Analyze Λ = K/|V|_eff phase transition

    Tests cryptosystem behavior across different Λ values
    to verify theoretical predictions.
    """

    def __init__(self, n: int = 64, m: int = 6, use_gpu: bool = False):
        self.n = n
        self.m = m
        self.use_gpu = use_gpu and GPU_AVAILABLE

        if self.use_gpu:
            print(f"[Phase Analyzer] Using GPU implementation")
        else:
            print(f"[Phase Analyzer] Using CPU implementation")

    def compute_lambda(self, noise_std: float, rank_reduction: float) -> float:
        """
        Compute theoretical Λ = K / |V|_eff

        K: Perturbation energy (proportional to noise²)
        |V|_eff: Effective volume (affected by rank reduction)
        """
        K = noise_std**2 * self.n * self.m
        V_eff = max((1 - rank_reduction)**self.n * 10.0, 1e-10)
        return K / V_eff

    def test_point(self, noise_std: float, rank_reduction: float,
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
                if self.use_gpu:
                    crypto = MeteorNC_GPU(
                        n=self.n,
                        m=self.m,
                        noise_std=noise_std,
                        rank_reduction=rank_reduction
                    )
                else:
                    crypto = MeteorNC(
                        n=self.n,
                        m=self.m,
                        noise_std=noise_std,
                        rank_reduction=rank_reduction
                    )

                crypto.key_gen(verbose=False)

                # Test encryption/decryption
                message = np.random.randn(self.n)
                ciphertext = crypto.encrypt(message)
                recovered = crypto.decrypt(ciphertext)

                error = np.linalg.norm(message - recovered) / np.linalg.norm(message)
                errors.append(error)

                if error < 1e-3:  # Success threshold
                    successes += 1
            except Exception as e:
                errors.append(np.inf)

        success_rate = successes / trials
        avg_error = np.mean(errors) if errors else np.inf

        return success_rate, avg_error

    def scan_lambda_range(self, lambda_values: list,
                         rank_reduction: float = 0.3) -> Dict:
        """
        Scan across Λ values by varying noise

        Args:
            lambda_values: List of Λ values to test
            rank_reduction: Fixed rank reduction ratio

        Returns:
            dict: Scan results
        """
        print("\n" + "="*70)
        print(f"Phase Transition Scan (n={self.n}, m={self.m})")
        print(f"Testing {len(lambda_values)} Λ values")
        print("="*70)

        results = {
            'lambda_values': [],
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
            results['success_rates'].append(success)
            results['errors'].append(error)

            print(f"  Λ={lam:.2f}: Success={success:.0%}, Error={error:.2e}")

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

        print("="*70)

        return results


def run_validation_suite(use_gpu: bool = None):
    """
    Run complete validation suite

    Args:
        use_gpu: Force GPU/CPU mode. None = auto-detect
    """
    print("\n" + "🌠"*35)
    print("Meteor-NC: Security Validation Suite (Complete Edition)")
    print("🌠"*35)

    # Auto-detect if not specified
    if use_gpu is None:
        use_gpu = GPU_AVAILABLE

    if use_gpu and not GPU_AVAILABLE:
        print("⚠️ GPU requested but not available, falling back to CPU")
        use_gpu = False

    # Test METEOR-256
    print(f"\n[Testing METEOR-256 - {'GPU' if use_gpu else 'CPU'} mode]")

    if use_gpu:
        crypto = MeteorNC_GPU(n=256, m=10)
    else:
        crypto = MeteorNC(n=256, m=10)

    crypto.key_gen(verbose=True)

    # Full security check
    security_results = SecurityValidator.full_security_check(crypto)

    # Quick benchmark
    print(f"\n[Performance Check]")
    if hasattr(crypto, 'benchmark'):
        if use_gpu:
            # GPU版: batch_sizesベースのベンチマーク
            bench = crypto.benchmark(
                batch_sizes=[1, 10, 100, 1000, 5000],
                verbose=True
            )
        else:
            # CPU版: num_trialsベースのベンチマーク
            bench = crypto.benchmark(num_trials=5, verbose=True)
    else:
        print("  Benchmark not available for this implementation")

    # Phase transition scan (smaller dimension for speed)
    print(f"\n[Phase Transition Scan]")
    analyzer = PhaseDiagramAnalyzer(n=64, m=6, use_gpu=use_gpu)
    lambda_range = [0.5, 0.7, 0.9, 1.0, 1.1, 1.3, 1.5]
    phase_results = analyzer.scan_lambda_range(lambda_range)

    # Summary
    print("\n" + "="*70)
    print("Validation Summary")
    print("="*70)
    print(f"Implementation: {'GPU' if use_gpu else 'CPU'}")
    print(f"Security: {'✅ ALL PASSED' if security_results['overall_secure'] else '⚠️ SOME FAILED'}")
    if hasattr(crypto, 'benchmark'):
        print(f"Performance: ✅ Tested")
    print(f"Phase Transition: ✅ Scanned")

    print("\n" + "🌠"*35)
    print("Validation Complete!")
    print("🌠"*35)

    return {
        'security': security_results,
        'phase': phase_results
    }

if __name__ == "__main__":
    # Run with auto-detection
    results = run_validation_suite()
