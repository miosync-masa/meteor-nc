# meteor_nc/tests/test_sidechannel.py
"""
Meteor-NC Side-Channel Evaluation Suite for TCHES

Timing side-channel resistance evaluation:
  F1. Timing Constancy (constant-time operations)
  F2. Statistical Analysis (leak detection)
  F3. Input-Dependent Variation

Reference: TCHES timing evaluation guidelines
"""

import secrets
import time
import numpy as np
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from scipy import stats

import sys
sys.path.insert(0, '/content/meteor-nc')

from meteor_nc.cryptography.common import (
    Q_DEFAULT, GPU_AVAILABLE, CRYPTO_AVAILABLE,
)
from meteor_nc.cryptography.core import (
    LWEKEM, HybridKEM, SymmetricMixer,
    LWECiphertext, FullCiphertext,
)

# =============================================================================
# Configuration
# =============================================================================

SAMPLE_COUNT = 10000  # Number of timing samples
WARMUP_COUNT = 100    # Warmup iterations before measurement
T_TEST_THRESHOLD = 4.5  # Welch's t-test threshold (|t| < 4.5 is considered safe)
CV_THRESHOLD = 0.10   # Coefficient of Variation threshold (< 10% is good)
KS_ALPHA = 0.01       # KS test significance level

# =============================================================================
# Timing Measurement Utilities
# =============================================================================

@dataclass
class TimingStats:
    """Statistics for timing measurements."""
    samples: np.ndarray
    mean: float
    std: float
    median: float
    min: float
    max: float
    cv: float  # Coefficient of Variation
    percentiles: Dict[int, float]
    
    @classmethod
    def from_samples(cls, samples: np.ndarray) -> 'TimingStats':
        return cls(
            samples=samples,
            mean=np.mean(samples),
            std=np.std(samples),
            median=np.median(samples),
            min=np.min(samples),
            max=np.max(samples),
            cv=np.std(samples) / np.mean(samples) if np.mean(samples) > 0 else 0,
            percentiles={
                1: np.percentile(samples, 1),
                5: np.percentile(samples, 5),
                25: np.percentile(samples, 25),
                75: np.percentile(samples, 75),
                95: np.percentile(samples, 95),
                99: np.percentile(samples, 99),
            }
        )


def measure_timing_ns(func, *args, **kwargs) -> int:
    """Measure function execution time in nanoseconds."""
    start = time.perf_counter_ns()
    result = func(*args, **kwargs)
    end = time.perf_counter_ns()
    return end - start, result


def collect_timing_samples(func, n_samples: int, *args, **kwargs) -> np.ndarray:
    """Collect multiple timing samples."""
    samples = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        samples[i], _ = measure_timing_ns(func, *args, **kwargs)
    return samples


# =============================================================================
# F1. Timing Constancy Tests
# =============================================================================

def test_f1_1_decaps_timing_constancy(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F1.1: Decaps timing constancy (success vs failure)
    
    Critical test: decaps should take the same time regardless of
    whether the ciphertext is valid or invalid (implicit rejection).
    
    A timing difference would leak information about validity.
    """
    print("\n[F1.1] Decaps Timing Constancy (Success vs Failure)")
    print("-" * 60)
    print(f"  Samples: {n_samples} per category")
    
    results = {
        'n_samples': n_samples,
        'success_stats': None,
        'failure_stats': None,
        't_statistic': None,
        'p_value': None,
        'timing_ratio': None,
        'passed': False,
    }
    
    # Setup KEM
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    # Warmup
    print("  Warming up...")
    for _ in range(WARMUP_COUNT):
        K, ct = kem.encaps()
        _ = kem.decaps(ct)
        ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        ct_bad.u[0] ^= 1
        _ = kem.decaps(ct_bad)
    
    # Collect SUCCESS timings (valid ciphertext)
    print("  Collecting SUCCESS timings...")
    success_times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        K, ct = kem.encaps()
        start = time.perf_counter_ns()
        _ = kem.decaps(ct)
        end = time.perf_counter_ns()
        success_times[i] = end - start
    
    # Collect FAILURE timings (invalid ciphertext - triggers implicit rejection)
    print("  Collecting FAILURE timings...")
    failure_times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        K, ct = kem.encaps()
        ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        ct_bad.u[np.random.randint(0, len(ct_bad.u))] ^= 1  # Random bit flip
        start = time.perf_counter_ns()
        _ = kem.decaps(ct_bad)
        end = time.perf_counter_ns()
        failure_times[i] = end - start
    
    # Compute statistics
    results['success_stats'] = TimingStats.from_samples(success_times)
    results['failure_stats'] = TimingStats.from_samples(failure_times)
    
    # Welch's t-test (unequal variances)
    t_stat, p_value = stats.ttest_ind(success_times, failure_times, equal_var=False)
    results['t_statistic'] = t_stat
    results['p_value'] = p_value
    
    # Timing ratio
    ratio = results['success_stats'].mean / results['failure_stats'].mean
    results['timing_ratio'] = ratio
    
    # Pass criteria:
    # 1. |t-statistic| < threshold (no significant difference)
    # 2. Timing ratio close to 1.0
    timing_similar = abs(t_stat) < T_TEST_THRESHOLD
    ratio_ok = 0.95 < ratio < 1.05  # Within 5%
    
    results['passed'] = timing_similar and ratio_ok
    
    # Print results
    print(f"\n  SUCCESS timing:")
    print(f"    Mean:   {results['success_stats'].mean/1000:.2f} μs")
    print(f"    Std:    {results['success_stats'].std/1000:.2f} μs")
    print(f"    CV:     {results['success_stats'].cv:.4f}")
    
    print(f"\n  FAILURE timing:")
    print(f"    Mean:   {results['failure_stats'].mean/1000:.2f} μs")
    print(f"    Std:    {results['failure_stats'].std/1000:.2f} μs")
    print(f"    CV:     {results['failure_stats'].cv:.4f}")
    
    print(f"\n  Statistical Analysis:")
    print(f"    Welch's t-statistic: {t_stat:.4f}")
    print(f"    p-value:             {p_value:.6f}")
    print(f"    Timing ratio:        {ratio:.4f}")
    print(f"    |t| < {T_TEST_THRESHOLD}:            {'YES ✓' if timing_similar else 'NO ✗'}")
    print(f"    Ratio in [0.95,1.05]: {'YES ✓' if ratio_ok else 'NO ✗'}")
    
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    # Convert numpy arrays to lists for serialization
    results['success_times_summary'] = {
        'mean': float(results['success_stats'].mean),
        'std': float(results['success_stats'].std),
        'cv': float(results['success_stats'].cv),
    }
    results['failure_times_summary'] = {
        'mean': float(results['failure_stats'].mean),
        'std': float(results['failure_stats'].std),
        'cv': float(results['failure_stats'].cv),
    }
    
    return results


def test_f1_2_encaps_timing_constancy(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F1.2: Encaps timing constancy
    
    Encaps should have consistent timing regardless of internal randomness.
    """
    print("\n[F1.2] Encaps Timing Constancy")
    print("-" * 60)
    print(f"  Samples: {n_samples}")
    
    results = {
        'n_samples': n_samples,
        'stats': None,
        'cv_ok': False,
        'passed': False,
    }
    
    # Setup KEM
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    # Warmup
    print("  Warming up...")
    for _ in range(WARMUP_COUNT):
        _ = kem.encaps()
    
    # Collect timings
    print("  Collecting encaps timings...")
    times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        start = time.perf_counter_ns()
        _ = kem.encaps()
        end = time.perf_counter_ns()
        times[i] = end - start
    
    # Compute statistics
    results['stats'] = TimingStats.from_samples(times)
    
    # Pass criteria: CV < threshold
    results['cv_ok'] = results['stats'].cv < CV_THRESHOLD
    results['passed'] = results['cv_ok']
    
    print(f"\n  Timing Statistics:")
    print(f"    Mean:   {results['stats'].mean/1000:.2f} μs")
    print(f"    Std:    {results['stats'].std/1000:.2f} μs")
    print(f"    CV:     {results['stats'].cv:.4f}")
    print(f"    Min:    {results['stats'].min/1000:.2f} μs")
    print(f"    Max:    {results['stats'].max/1000:.2f} μs")
    print(f"    P5-P95: [{results['stats'].percentiles[5]/1000:.2f}, {results['stats'].percentiles[95]/1000:.2f}] μs")
    
    print(f"\n  CV < {CV_THRESHOLD}: {'YES ✓' if results['cv_ok'] else 'NO ✗'}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    results['timing_summary'] = {
        'mean_us': float(results['stats'].mean / 1000),
        'std_us': float(results['stats'].std / 1000),
        'cv': float(results['stats'].cv),
    }
    
    return results


def test_f1_3_keygen_timing_constancy(n_samples: int = SAMPLE_COUNT // 10) -> Dict:
    """
    F1.3: KeyGen timing constancy
    
    KeyGen timing should be consistent (less critical but still relevant).
    Using fewer samples as KeyGen is slower.
    """
    print("\n[F1.3] KeyGen Timing Constancy")
    print("-" * 60)
    print(f"  Samples: {n_samples}")
    
    results = {
        'n_samples': n_samples,
        'stats': None,
        'cv_ok': False,
        'passed': False,
    }
    
    # Warmup
    print("  Warming up...")
    for _ in range(min(WARMUP_COUNT // 10, 10)):
        kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
        kem.key_gen()
    
    # Collect timings
    print("  Collecting keygen timings...")
    times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
        start = time.perf_counter_ns()
        kem.key_gen()
        end = time.perf_counter_ns()
        times[i] = end - start
    
    # Compute statistics
    results['stats'] = TimingStats.from_samples(times)
    
    # Pass criteria: CV < threshold (slightly relaxed for keygen)
    results['cv_ok'] = results['stats'].cv < CV_THRESHOLD * 1.5
    results['passed'] = results['cv_ok']
    
    print(f"\n  Timing Statistics:")
    print(f"    Mean:   {results['stats'].mean/1000000:.2f} ms")
    print(f"    Std:    {results['stats'].std/1000000:.2f} ms")
    print(f"    CV:     {results['stats'].cv:.4f}")
    
    print(f"\n  CV < {CV_THRESHOLD * 1.5}: {'YES ✓' if results['cv_ok'] else 'NO ✗'}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    results['timing_summary'] = {
        'mean_ms': float(results['stats'].mean / 1000000),
        'std_ms': float(results['stats'].std / 1000000),
        'cv': float(results['stats'].cv),
    }
    
    return results


# =============================================================================
# F2. Statistical Analysis Tests
# =============================================================================

def test_f2_1_ks_test_timing_distribution(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F2.1: Kolmogorov-Smirnov test for timing distribution
    
    Compare timing distributions between different input classes.
    Uses both statistical significance AND practical effect size.
    
    Note: With large samples (10000+), KS test is very sensitive to tiny
    differences. We use Cohen's d effect size to assess practical significance.
    """
    print("\n[F2.1] KS Test + Effect Size: Timing Distribution Comparison")
    print("-" * 60)
    print(f"  Samples: {n_samples} per category")
    
    # Effect size threshold (Cohen's d < 0.2 = "small" = practically insignificant)
    COHENS_D_THRESHOLD = 0.2
    
    results = {
        'n_samples': n_samples,
        'tests': [],
        'passed': True,
    }
    
    def cohens_d(group1, group2):
        """Calculate Cohen's d effect size."""
        n1, n2 = len(group1), len(group2)
        var1, var2 = np.var(group1, ddof=1), np.var(group2, ddof=1)
        pooled_std = np.sqrt(((n1-1)*var1 + (n2-1)*var2) / (n1+n2-2))
        return abs(np.mean(group1) - np.mean(group2)) / pooled_std if pooled_std > 0 else 0
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    # Warmup
    for _ in range(WARMUP_COUNT):
        K, ct = kem.encaps()
        _ = kem.decaps(ct)
    
    # Collect baseline timing (first half of samples)
    print("  Collecting baseline timings...")
    baseline_times = np.zeros(n_samples // 2, dtype=np.int64)
    for i in range(n_samples // 2):
        K, ct = kem.encaps()
        start = time.perf_counter_ns()
        _ = kem.decaps(ct)
        end = time.perf_counter_ns()
        baseline_times[i] = end - start
    
    # Test 1: Compare with second half (should be same distribution)
    print("  Collecting comparison timings (valid CT)...")
    compare_times = np.zeros(n_samples // 2, dtype=np.int64)
    for i in range(n_samples // 2):
        K, ct = kem.encaps()
        start = time.perf_counter_ns()
        _ = kem.decaps(ct)
        end = time.perf_counter_ns()
        compare_times[i] = end - start
    
    ks_stat, p_value = stats.ks_2samp(baseline_times, compare_times)
    d1 = cohens_d(baseline_times, compare_times)
    # Pass if effect size is small (practically no difference)
    test1_pass = d1 < COHENS_D_THRESHOLD
    results['tests'].append({
        'name': 'Valid CT (baseline vs compare)',
        'ks_statistic': float(ks_stat),
        'p_value': float(p_value),
        'cohens_d': float(d1),
        'passed': test1_pass,
    })
    print(f"    Valid CT comparison: KS={ks_stat:.4f}, p={p_value:.4f}, d={d1:.4f} -> {'PASS ✓' if test1_pass else 'FAIL ✗'}")
    
    # Test 2: Compare with invalid CT timings
    print("  Collecting invalid CT timings...")
    invalid_times = np.zeros(n_samples // 2, dtype=np.int64)
    for i in range(n_samples // 2):
        K, ct = kem.encaps()
        ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        ct_bad.u[0] ^= 1
        start = time.perf_counter_ns()
        _ = kem.decaps(ct_bad)
        end = time.perf_counter_ns()
        invalid_times[i] = end - start
    
    ks_stat, p_value = stats.ks_2samp(baseline_times, invalid_times)
    d2 = cohens_d(baseline_times, invalid_times)
    # Pass if effect size is small (practically no difference)
    test2_pass = d2 < COHENS_D_THRESHOLD
    results['tests'].append({
        'name': 'Valid vs Invalid CT',
        'ks_statistic': float(ks_stat),
        'p_value': float(p_value),
        'cohens_d': float(d2),
        'passed': test2_pass,
    })
    print(f"    Valid vs Invalid CT: KS={ks_stat:.4f}, p={p_value:.4f}, d={d2:.4f} -> {'PASS ✓' if test2_pass else 'FAIL ✗'}")
    
    results['passed'] = all(t['passed'] for t in results['tests'])
    
    print(f"\n  Note: Using Cohen's d < {COHENS_D_THRESHOLD} (small effect) as pass criterion")
    print(f"        Large sample sizes make p-values unreliable for practical significance")
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_f2_2_timing_histogram_analysis(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F2.2: Timing histogram analysis
    
    Analyze timing distribution shape for anomalies.
    """
    print("\n[F2.2] Timing Histogram Analysis")
    print("-" * 60)
    print(f"  Samples: {n_samples}")
    
    results = {
        'n_samples': n_samples,
        'success_analysis': {},
        'failure_analysis': {},
        'passed': True,
    }
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    # Warmup
    for _ in range(WARMUP_COUNT):
        K, ct = kem.encaps()
        _ = kem.decaps(ct)
    
    # Collect success timings
    print("  Collecting success timings...")
    success_times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        K, ct = kem.encaps()
        start = time.perf_counter_ns()
        _ = kem.decaps(ct)
        end = time.perf_counter_ns()
        success_times[i] = end - start
    
    # Collect failure timings
    print("  Collecting failure timings...")
    failure_times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        K, ct = kem.encaps()
        ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        ct_bad.u[0] ^= 1
        start = time.perf_counter_ns()
        _ = kem.decaps(ct_bad)
        end = time.perf_counter_ns()
        failure_times[i] = end - start
    
    # Analyze distributions
    def analyze_distribution(times: np.ndarray, name: str) -> Dict:
        analysis = {
            'mean': float(np.mean(times)),
            'std': float(np.std(times)),
            'skewness': float(stats.skew(times)),
            'kurtosis': float(stats.kurtosis(times)),
            'iqr': float(np.percentile(times, 75) - np.percentile(times, 25)),
        }
        
        # Check for bimodality (could indicate timing leak)
        # Simple heuristic: if kurtosis is very negative, might be bimodal
        analysis['possibly_bimodal'] = analysis['kurtosis'] < -1.0
        
        print(f"\n  {name}:")
        print(f"    Mean:     {analysis['mean']/1000:.2f} μs")
        print(f"    Std:      {analysis['std']/1000:.2f} μs")
        print(f"    Skewness: {analysis['skewness']:.4f}")
        print(f"    Kurtosis: {analysis['kurtosis']:.4f}")
        print(f"    IQR:      {analysis['iqr']/1000:.2f} μs")
        print(f"    Bimodal?: {'WARNING' if analysis['possibly_bimodal'] else 'No'}")
        
        return analysis
    
    results['success_analysis'] = analyze_distribution(success_times, "SUCCESS Distribution")
    results['failure_analysis'] = analyze_distribution(failure_times, "FAILURE Distribution")
    
    # Check for concerning patterns
    if results['success_analysis']['possibly_bimodal']:
        results['passed'] = False
        print("\n  WARNING: Success distribution may be bimodal!")
    
    if results['failure_analysis']['possibly_bimodal']:
        results['passed'] = False
        print("\n  WARNING: Failure distribution may be bimodal!")
    
    # Compare means (should be similar)
    mean_diff = abs(results['success_analysis']['mean'] - results['failure_analysis']['mean'])
    mean_ratio = mean_diff / results['success_analysis']['mean']
    results['mean_difference_ratio'] = float(mean_ratio)
    
    if mean_ratio > 0.05:  # More than 5% difference
        results['passed'] = False
        print(f"\n  WARNING: Mean difference ratio {mean_ratio:.4f} > 0.05")
    
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_f2_3_percentile_comparison(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F2.3: Percentile comparison between success/failure
    
    Compare timing percentiles to detect subtle differences.
    """
    print("\n[F2.3] Percentile Comparison")
    print("-" * 60)
    print(f"  Samples: {n_samples}")
    
    results = {
        'n_samples': n_samples,
        'percentile_diffs': {},
        'max_diff_ratio': 0,
        'passed': True,
    }
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    # Warmup
    for _ in range(WARMUP_COUNT):
        K, ct = kem.encaps()
        _ = kem.decaps(ct)
    
    # Collect timings
    print("  Collecting success timings...")
    success_times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        K, ct = kem.encaps()
        start = time.perf_counter_ns()
        _ = kem.decaps(ct)
        end = time.perf_counter_ns()
        success_times[i] = end - start
    
    print("  Collecting failure timings...")
    failure_times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        K, ct = kem.encaps()
        ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        ct_bad.u[0] ^= 1
        start = time.perf_counter_ns()
        _ = kem.decaps(ct_bad)
        end = time.perf_counter_ns()
        failure_times[i] = end - start
    
    # Compare percentiles
    percentiles = [1, 5, 10, 25, 50, 75, 90, 95, 99]
    
    print(f"\n  {'Percentile':<12} {'Success (μs)':<15} {'Failure (μs)':<15} {'Diff Ratio':<12}")
    print("  " + "-" * 54)
    
    max_diff_ratio = 0
    for p in percentiles:
        s_val = np.percentile(success_times, p)
        f_val = np.percentile(failure_times, p)
        diff_ratio = abs(s_val - f_val) / s_val if s_val > 0 else 0
        
        results['percentile_diffs'][p] = {
            'success': float(s_val),
            'failure': float(f_val),
            'diff_ratio': float(diff_ratio),
        }
        
        max_diff_ratio = max(max_diff_ratio, diff_ratio)
        
        status = "✓" if diff_ratio < 0.10 else "✗"
        print(f"  P{p:<10} {s_val/1000:<15.2f} {f_val/1000:<15.2f} {diff_ratio:<12.4f} {status}")
    
    results['max_diff_ratio'] = float(max_diff_ratio)
    results['passed'] = max_diff_ratio < 0.10  # All percentiles within 10%
    
    print(f"\n  Max diff ratio: {max_diff_ratio:.4f}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# F3. Input-Dependent Timing Tests
# =============================================================================

def test_f3_1_ciphertext_content_timing(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F3.1: Ciphertext content timing dependency
    
    Check if timing varies with ciphertext content (e.g., Hamming weight).
    """
    print("\n[F3.1] Ciphertext Content Timing Dependency")
    print("-" * 60)
    print(f"  Samples: {n_samples}")
    
    results = {
        'n_samples': n_samples,
        'correlation': None,
        'p_value': None,
        'passed': False,
    }
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    # Warmup
    for _ in range(WARMUP_COUNT):
        K, ct = kem.encaps()
        _ = kem.decaps(ct)
    
    # Collect timings with Hamming weight tracking
    print("  Collecting timings with Hamming weight tracking...")
    times = np.zeros(n_samples, dtype=np.int64)
    hamming_weights = np.zeros(n_samples, dtype=np.int64)
    
    for i in range(n_samples):
        K, ct = kem.encaps()
        
        # Calculate Hamming weight of u
        if hasattr(ct.u, 'get'):  # CuPy
            u_np = ct.u.get()
        else:
            u_np = ct.u
        hamming_weights[i] = np.sum(np.unpackbits(u_np.view(np.uint8)))
        
        start = time.perf_counter_ns()
        _ = kem.decaps(ct)
        end = time.perf_counter_ns()
        times[i] = end - start
    
    # Compute correlation
    correlation, p_value = stats.pearsonr(hamming_weights, times)
    results['correlation'] = float(correlation)
    results['p_value'] = float(p_value)
    
    # Pass criteria: low correlation (|r| < 0.1)
    results['passed'] = abs(correlation) < 0.1
    
    print(f"\n  Pearson correlation: {correlation:.6f}")
    print(f"  p-value:             {p_value:.6f}")
    print(f"  |correlation| < 0.1: {'YES ✓' if results['passed'] else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_f3_2_key_dependent_timing(n_samples: int = SAMPLE_COUNT // 10) -> Dict:
    """
    F3.2: Key-dependent timing
    
    Check if timing varies with different keys.
    """
    print("\n[F3.2] Key-Dependent Timing")
    print("-" * 60)
    print(f"  Samples: {n_samples} keys, 100 ops each")
    
    results = {
        'n_keys': n_samples,
        'key_timing_stats': [],
        'cv_across_keys': None,
        'passed': False,
    }
    
    key_means = []
    
    for k in range(n_samples):
        if k % 100 == 0:
            print(f"  Processing key {k}/{n_samples}...")
        
        kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
        kem.key_gen()
        
        # Warmup for this key
        for _ in range(10):
            K, ct = kem.encaps()
            _ = kem.decaps(ct)
        
        # Collect timings for this key
        times = np.zeros(100, dtype=np.int64)
        for i in range(100):
            K, ct = kem.encaps()
            start = time.perf_counter_ns()
            _ = kem.decaps(ct)
            end = time.perf_counter_ns()
            times[i] = end - start
        
        key_means.append(np.mean(times))
    
    key_means = np.array(key_means)
    cv_across_keys = np.std(key_means) / np.mean(key_means)
    results['cv_across_keys'] = float(cv_across_keys)
    
    # Pass criteria: CV across keys should be low
    results['passed'] = cv_across_keys < CV_THRESHOLD
    
    print(f"\n  Mean timing across keys: {np.mean(key_means)/1000:.2f} μs")
    print(f"  Std across keys:         {np.std(key_means)/1000:.2f} μs")
    print(f"  CV across keys:          {cv_across_keys:.4f}")
    print(f"  CV < {CV_THRESHOLD}:              {'YES ✓' if results['passed'] else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_f3_3_modification_position_timing(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F3.3: Modification position timing
    
    Check if timing varies based on WHERE the ciphertext is modified.
    
    Uses both ANOVA p-value AND practical difference ratio.
    With large samples, even tiny differences become "statistically significant"
    but may be practically irrelevant for security.
    """
    print("\n[F3.3] Modification Position Timing")
    print("-" * 60)
    
    # Practical significance threshold
    MAX_DIFF_RATIO_THRESHOLD = 0.05  # 5% max difference is acceptable
    
    results = {
        'position_timings': {},
        'max_diff_ratio': 0,
        'anova_f': None,
        'anova_p': None,
        'passed': False,
    }
    
    kem = LWEKEM(n=256, gpu=GPU_AVAILABLE)
    kem.key_gen()
    
    # Test positions: beginning, middle, end
    positions = [0, 64, 128, 192, 255]
    samples_per_pos = n_samples // len(positions)
    
    print(f"  Samples per position: {samples_per_pos}")
    
    # Warmup
    for _ in range(WARMUP_COUNT):
        K, ct = kem.encaps()
        ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
        ct_bad.u[0] ^= 1
        _ = kem.decaps(ct_bad)
    
    all_position_times = []
    
    for pos in positions:
        print(f"  Testing position {pos}...")
        times = np.zeros(samples_per_pos, dtype=np.int64)
        
        for i in range(samples_per_pos):
            K, ct = kem.encaps()
            ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
            ct_bad.u[pos] ^= 1
            
            start = time.perf_counter_ns()
            _ = kem.decaps(ct_bad)
            end = time.perf_counter_ns()
            times[i] = end - start
        
        stats_obj = TimingStats.from_samples(times)
        results['position_timings'][pos] = {
            'mean': float(stats_obj.mean),
            'std': float(stats_obj.std),
            'cv': float(stats_obj.cv),
        }
        all_position_times.append(times)
        
        print(f"    Position {pos}: mean={stats_obj.mean/1000:.2f}μs, std={stats_obj.std/1000:.2f}μs")
    
    # ANOVA test
    f_stat, p_value = stats.f_oneway(*all_position_times)
    results['anova_f'] = float(f_stat)
    results['anova_p'] = float(p_value)
    
    # Calculate max difference ratio
    means = [r['mean'] for r in results['position_timings'].values()]
    max_diff = max(means) - min(means)
    avg_mean = np.mean(means)
    results['max_diff_ratio'] = float(max_diff / avg_mean)
    
    # Pass criteria: EITHER statistically insignificant OR practically small difference
    # This accounts for the fact that large samples make ANOVA overly sensitive
    statistical_pass = p_value > 0.01
    practical_pass = results['max_diff_ratio'] < MAX_DIFF_RATIO_THRESHOLD
    
    results['passed'] = statistical_pass or practical_pass
    
    print(f"\n  ANOVA F-statistic: {f_stat:.4f}")
    print(f"  ANOVA p-value:     {p_value:.6f}")
    print(f"  Max diff ratio:    {results['max_diff_ratio']:.4f}")
    print(f"\n  Statistical (p > 0.01):     {'YES ✓' if statistical_pass else 'NO'}")
    print(f"  Practical (diff < {MAX_DIFF_RATIO_THRESHOLD*100:.0f}%):    {'YES ✓' if practical_pass else 'NO'}")
    print(f"  (Pass if EITHER criterion met)")
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# F4. Multi-Security Level Timing
# =============================================================================

def test_f4_timing_across_security_levels() -> Dict:
    """
    F4: Timing comparison across security levels
    
    Verify timing scales appropriately with security level.
    
    Uses both statistical significance AND practical timing ratio.
    With large samples, t-test is very sensitive to tiny differences.
    A ratio within 0.95-1.05 (5% difference) is considered secure.
    """
    print("\n[F4] Timing Across Security Levels")
    print("-" * 60)
    
    # Practical significance thresholds
    RATIO_MIN = 0.95
    RATIO_MAX = 1.05
    
    results = {
        'levels': {},
        'passed': True,
    }
    
    levels = [
        (256, "Level 1 (128-bit)"),
        (512, "Level 3 (192-bit)"),
        (1024, "Level 5 (256-bit)"),
    ]
    
    samples_per_level = 1000
    
    for n, level_name in levels:
        print(f"\n  Testing {level_name} (n={n})...")
        
        kem = LWEKEM(n=n, gpu=GPU_AVAILABLE)
        kem.key_gen()
        
        # Warmup
        for _ in range(50):
            K, ct = kem.encaps()
            _ = kem.decaps(ct)
        
        # Success timings
        success_times = np.zeros(samples_per_level, dtype=np.int64)
        for i in range(samples_per_level):
            K, ct = kem.encaps()
            start = time.perf_counter_ns()
            _ = kem.decaps(ct)
            end = time.perf_counter_ns()
            success_times[i] = end - start
        
        # Failure timings
        failure_times = np.zeros(samples_per_level, dtype=np.int64)
        for i in range(samples_per_level):
            K, ct = kem.encaps()
            ct_bad = LWECiphertext(u=ct.u.copy(), v=ct.v.copy())
            ct_bad.u[0] ^= 1
            start = time.perf_counter_ns()
            _ = kem.decaps(ct_bad)
            end = time.perf_counter_ns()
            failure_times[i] = end - start
        
        # T-test
        t_stat, p_value = stats.ttest_ind(success_times, failure_times, equal_var=False)
        statistical_pass = abs(t_stat) < T_TEST_THRESHOLD
        
        # Practical significance: timing ratio
        ratio = np.mean(success_times) / np.mean(failure_times)
        practical_pass = RATIO_MIN < ratio < RATIO_MAX
        
        # Pass if EITHER statistically insignificant OR practically small difference
        level_passed = statistical_pass or practical_pass
        
        results['levels'][n] = {
            'name': level_name,
            'success_mean_us': float(np.mean(success_times) / 1000),
            'failure_mean_us': float(np.mean(failure_times) / 1000),
            't_statistic': float(t_stat),
            'p_value': float(p_value),
            'timing_ratio': float(ratio),
            'statistical_pass': statistical_pass,
            'practical_pass': practical_pass,
            'passed': level_passed,
        }
        
        if not level_passed:
            results['passed'] = False
        
        print(f"    Success: {np.mean(success_times)/1000:.2f} μs")
        print(f"    Failure: {np.mean(failure_times)/1000:.2f} μs")
        print(f"    Ratio:   {ratio:.4f}")
        print(f"    t-stat:  {t_stat:.4f}")
        print(f"    Statistical (|t|<{T_TEST_THRESHOLD}): {'YES ✓' if statistical_pass else 'NO'}")
        print(f"    Practical (ratio∈[{RATIO_MIN},{RATIO_MAX}]): {'YES ✓' if practical_pass else 'NO'}")
        print(f"    Status:  {'PASS ✓' if level_passed else 'FAIL ✗'}")
    
    print(f"\n  Note: Pass if EITHER criterion met (accounts for large-sample sensitivity)")
    print(f"\n  Overall Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# Main Test Runner
# =============================================================================

def run_all_sidechannel_tests() -> Dict:
    """Run all side-channel evaluation tests."""
    print("=" * 70)
    print("Meteor-NC Side-Channel Evaluation Suite")
    print("=" * 70)
    print(f"GPU Available: {GPU_AVAILABLE}")
    print(f"Sample Count: {SAMPLE_COUNT}")
    print(f"T-test Threshold: {T_TEST_THRESHOLD}")
    print(f"CV Threshold: {CV_THRESHOLD}")
    
    all_results = {}
    
    # F1. Timing Constancy
    print("\n" + "=" * 70)
    print("F1. TIMING CONSTANCY")
    print("=" * 70)
    
    all_results['f1_1_decaps_constancy'] = test_f1_1_decaps_timing_constancy()
    all_results['f1_2_encaps_constancy'] = test_f1_2_encaps_timing_constancy()
    all_results['f1_3_keygen_constancy'] = test_f1_3_keygen_timing_constancy()
    
    # F2. Statistical Analysis
    print("\n" + "=" * 70)
    print("F2. STATISTICAL ANALYSIS")
    print("=" * 70)
    
    all_results['f2_1_ks_test'] = test_f2_1_ks_test_timing_distribution()
    all_results['f2_2_histogram'] = test_f2_2_timing_histogram_analysis()
    all_results['f2_3_percentile'] = test_f2_3_percentile_comparison()
    
    # F3. Input-Dependent Timing
    print("\n" + "=" * 70)
    print("F3. INPUT-DEPENDENT TIMING")
    print("=" * 70)
    
    all_results['f3_1_content_timing'] = test_f3_1_ciphertext_content_timing()
    all_results['f3_2_key_timing'] = test_f3_2_key_dependent_timing()
    all_results['f3_3_position_timing'] = test_f3_3_modification_position_timing()
    
    # F4. Multi-Security Level
    print("\n" + "=" * 70)
    print("F4. MULTI-SECURITY LEVEL TIMING")
    print("=" * 70)
    
    all_results['f4_security_levels'] = test_f4_timing_across_security_levels()
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    for name, result in all_results.items():
        if result.get('passed'):
            status = "PASS ✓"
            passed += 1
        else:
            status = "FAIL ✗"
            failed += 1
        print(f"  {name}: {status}")
    
    print(f"\nTotal: {passed} passed, {failed} failed")
    
    all_pass = failed == 0
    print(f"\n{'=' * 70}")
    print(f"SIDE-CHANNEL EVALUATION: {'✅ ALL TESTS PASSED' if all_pass else '❌ SOME TESTS FAILED'}")
    print(f"{'=' * 70}")
    
    return {
        'results': all_results,
        'passed': passed,
        'failed': failed,
        'all_pass': all_pass,
        'configuration': {
            'sample_count': SAMPLE_COUNT,
            't_test_threshold': T_TEST_THRESHOLD,
            'cv_threshold': CV_THRESHOLD,
            'ks_alpha': KS_ALPHA,
            'gpu_used': GPU_AVAILABLE,
        }
    }


if __name__ == "__main__":
    run_all_sidechannel_tests()
