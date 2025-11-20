"""
Meteor-NC: Security Validation Tools

Tools for validating Meteor-NC security properties:
1. Phase diagram analysis (Λ vs. stability)
2. Shor resistance verification
3. Non-commutativity checks

Usage:
    python meteor_nc_validation.py
"""

import numpy as np
from scipy.linalg import lstsq
from scipy.stats import ortho_group, special_ortho_group
import time
from typing import Dict, Tuple

# Import base implementation
try:
    from meteor_nc_cpu import MeteorNC
except ImportError:
    print("Error: meteor_nc_cpu.py not found. Place it in the same directory.")
    exit(1)


class SecurityValidator:
    """
    Comprehensive security validation for Meteor-NC
    """
    
    @staticmethod
    def verify_non_commutativity(crypto: MeteorNC, verbose: bool = True) -> Dict:
        """
        Verify non-commutativity (Shor resistance)
        
        Returns:
            dict: Non-commutativity metrics
        """
        if len(crypto.public_keys) == 0:
            raise ValueError("Keys not generated")
        
        # Compute commutators
        commutators = []
        for i in range(len(crypto.public_keys) - 1):
            comm = (crypto.public_keys[i] @ crypto.public_keys[i+1] - 
                   crypto.public_keys[i+1] @ crypto.public_keys[i])
            commutators.append(np.linalg.norm(comm, 'fro'))
        
        avg_norm = np.mean(commutators)
        secure = avg_norm > 8.0  # Paper threshold
        
        if verbose:
            print(f"\n[Non-Commutativity Check]")
            print(f"  Average ||[πᵢ,πⱼ]||: {avg_norm:.2f}")
            print(f"  Threshold: 8.0")
            print(f"  Status: {'✅ SECURE' if secure else '⚠️ WEAK'}")
        
        return {
            'avg_commutator_norm': avg_norm,
            'secure': secure,
            'all_norms': commutators
        }
    
    @staticmethod
    def check_period_structure(crypto: MeteorNC, max_order: int = 15, 
                               verbose: bool = True) -> Dict:
        """
        Check for periodic structure (Shor vulnerability)
        
        Returns:
            dict: Period analysis results
        """
        if len(crypto.public_keys) == 0:
            raise ValueError("Keys not generated")
        
        n = crypto.n
        periods_found = []
        
        # Check first 3 keys
        for idx, pi in enumerate(crypto.public_keys[:min(3, len(crypto.public_keys))]):
            power = pi.copy()
            for k in range(2, max_order + 1):
                power = power @ pi
                dist = np.linalg.norm(power - np.eye(n), 'fro')
                if dist < 45.0:  # Paper threshold
                    periods_found.append((idx, k, dist))
                    break
        
        has_period = len(periods_found) > 0
        secure = not has_period
        
        if verbose:
            print(f"\n[Period Structure Check]")
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
        
        Returns:
            dict: Complexity estimates
        """
        # Search space
        q = 2**31 - 1
        classical_bits = n**2 * np.log2(q) - np.log2(m * 3)
        grover_bits = classical_bits / 2
        
        secure = grover_bits > 128  # 128-bit quantum security
        
        if verbose:
            print(f"\n[Grover Complexity]")
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
    def full_security_check(crypto: MeteorNC) -> Dict:
        """
        Run all security checks
        
        Returns:
            dict: Complete security analysis
        """
        print("\n" + "="*70)
        print(f"Security Validation: Meteor-NC (n={crypto.n}, m={crypto.m})")
        print("="*70)
        
        # Non-commutativity
        nc_result = SecurityValidator.verify_non_commutativity(crypto)
        
        # Period structure
        period_result = SecurityValidator.check_period_structure(crypto)
        
        # Grover complexity
        grover_result = SecurityValidator.estimate_grover_complexity(
            crypto.n, crypto.m
        )
        
        # Overall verdict
        all_secure = (
            nc_result['secure'] and 
            period_result['secure'] and 
            grover_result['secure']
        )
        
        print(f"\n{'='*70}")
        print(f"Overall Security: {'✅ VERIFIED' if all_secure else '⚠️ REVIEW NEEDED'}")
        print(f"{'='*70}")
        
        return {
            'non_commutativity': nc_result,
            'period_structure': period_result,
            'grover_complexity': grover_result,
            'overall_secure': all_secure
        }


class PhaseDiagramAnalyzer:
    """
    Analyze Λ = K/|V|_eff phase transition
    """
    
    def __init__(self, n: int = 64, m: int = 6):
        self.n = n
        self.m = m
    
    def compute_lambda(self, noise_std: float, rank_reduction: float) -> float:
        """Compute theoretical Λ"""
        K = noise_std**2 * self.n * self.m
        V_eff = max((1 - rank_reduction)**self.n * 10.0, 1e-10)
        return K / V_eff
    
    def test_point(self, noise_std: float, rank_reduction: float, 
                   trials: int = 3) -> Tuple[float, float]:
        """
        Test single parameter point
        
        Returns:
            (success_rate, avg_error)
        """
        successes = 0
        errors = []
        
        for _ in range(trials):
            try:
                crypto = MeteorNC(
                    n=self.n,
                    m=self.m,
                    noise_std=noise_std,
                    rank_reduction=rank_reduction
                )
                crypto.key_gen(verbose=False)
                
                # Test
                message = np.random.randn(self.n)
                ciphertext = crypto.encrypt(message)
                recovered = crypto.decrypt(ciphertext)
                
                error = np.linalg.norm(message - recovered) / np.linalg.norm(message)
                errors.append(error)
                
                if error < 1e-3:
                    successes += 1
            except:
                errors.append(np.inf)
        
        success_rate = successes / trials
        avg_error = np.mean(errors) if errors else np.inf
        
        return success_rate, avg_error
    
    def scan_lambda_range(self, lambda_values: list, 
                         rank_reduction: float = 0.3) -> Dict:
        """
        Scan across Λ values by varying noise
        
        Returns:
            dict: Scan results
        """
        print("\n" + "="*70)
        print(f"Phase Transition Scan (n={self.n}, m={self.m})")
        print("="*70)
        
        results = {
            'lambda_values': [],
            'success_rates': [],
            'errors': []
        }
        
        print(f"\nScanning {len(lambda_values)} Λ values...")
        
        for lam in lambda_values:
            # Convert Λ to noise_std
            # Λ = K/V_eff = (noise^2 * n * m) / V_eff
            V_eff = (1 - rank_reduction)**self.n * 10.0
            noise_std = np.sqrt(lam * V_eff / (self.n * self.m))
            
            # Test
            success, error = self.test_point(noise_std, rank_reduction)
            
            results['lambda_values'].append(lam)
            results['success_rates'].append(success)
            results['errors'].append(error)
            
            print(f"  Λ={lam:.2f}: Success={success:.0%}, Error={error:.2e}")
        
        # Find transition
        transition_idx = None
        for i in range(len(results['success_rates']) - 1):
            if results['success_rates'][i] > 0.5 and results['success_rates'][i+1] <= 0.5:
                transition_idx = i
                break
        
        if transition_idx:
            transition_lambda = results['lambda_values'][transition_idx]
            print(f"\n✓ Phase transition detected near Λ ≈ {transition_lambda:.2f}")
        else:
            print(f"\n⚠️ No clear transition in scanned range")
        
        print("="*70)
        
        return results


def run_validation_suite():
    """
    Run complete validation suite
    """
    print("\n" + "🌠"*35)
    print("Meteor-NC: Security Validation Suite")
    print("🌠"*35)
    
    # Test METEOR-256
    print("\n[Testing METEOR-256]")
    crypto = MeteorNC(n=256, m=10)
    crypto.key_gen(verbose=True)
    
    # Full security check
    security_results = SecurityValidator.full_security_check(crypto)
    
    # Quick benchmark
    print(f"\n[Performance Check]")
    bench = crypto.benchmark(num_trials=5, verbose=True)
    
    # Phase transition scan
    print(f"\n[Phase Transition Scan]")
    analyzer = PhaseDiagramAnalyzer(n=64, m=6)
    lambda_range = [0.5, 0.7, 0.9, 1.0, 1.1, 1.3, 1.5]
    phase_results = analyzer.scan_lambda_range(lambda_range)
    
    # Summary
    print("\n" + "="*70)
    print("Validation Summary")
    print("="*70)
    print(f"Security: {'✅ PASSED' if security_results['overall_secure'] else '⚠️ FAILED'}")
    print(f"Performance: ✅ {bench['decrypt_time_ms']:.1f}ms decryption")
    print(f"Phase Transition: ✅ Scanned")
    
    print("\n" + "🌠"*35)
    print("Validation Complete!")
    print("🌠"*35)


if __name__ == "__main__":
    run_validation_suite()
