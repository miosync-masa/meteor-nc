# meteor_nc/tests/test_batch_sidechannel.py
"""
Meteor-NC Batch KEM Side-Channel Evaluation Suite for TCHES

Timing side-channel resistance evaluation for GPU batch operations:
  F1. Batch Timing Constancy (constant-time batch operations)
  F2. Statistical Analysis (leak detection in batch mode)
  F3. Input-Dependent Variation (batch-specific patterns)
  F4. Scaling Linearity (timing vs batch size)

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

# =============================================================================
# Configuration
# =============================================================================

SAMPLE_COUNT = 10000  # Number of timing samples
WARMUP_COUNT = 100    # Warmup iterations before measurement
T_TEST_THRESHOLD = 4.5  # Welch's t-test threshold
CV_THRESHOLD = 0.10   # Coefficient of Variation threshold
KS_ALPHA = 0.01       # KS test significance level
LINEARITY_R2_THRESHOLD = 0.95  # R² threshold for linear scaling

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
    cv: float
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


def gpu_sync():
    """Synchronize GPU operations for accurate timing."""
    if GPU_AVAILABLE:
        import cupy as cp
        cp.cuda.Stream.null.synchronize()


# =============================================================================
# F1. Batch Timing Constancy Tests
# =============================================================================

def test_f1_1_batch_decaps_valid_vs_invalid(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F1.1: Batch decaps timing constancy (all valid vs all invalid)
    
    Critical test: batch decaps should take the same time regardless of
    whether all ciphertexts are valid or all are invalid.
    """
    print("\n[F1.1] Batch Decaps: All Valid vs All Invalid")
    print("-" * 60)
    print(f"  Samples: {n_samples} per category")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'n_samples': n_samples,
        'valid_stats': None,
        'invalid_stats': None,
        't_statistic': None,
        'p_value': None,
        'passed': False,
    }
    
    batch_size = 1000
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    # Warmup
    print("  Warming up...")
    for _ in range(WARMUP_COUNT // 10):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        _ = kem.decaps_batch(U, V)
        gpu_sync()
    
    # Collect VALID timings (all ciphertexts valid)
    print("  Collecting VALID batch timings...")
    valid_times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        gpu_sync()
        
        start = time.perf_counter_ns()
        _ = kem.decaps_batch(U, V)
        gpu_sync()
        end = time.perf_counter_ns()
        
        valid_times[i] = end - start
    
    # Collect INVALID timings (all ciphertexts tampered)
    print("  Collecting INVALID batch timings...")
    invalid_times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        
        # Tamper ALL ciphertexts
        U_bad = U.copy()
        U_bad[:, 0] ^= 1  # Flip first element of every CT
        gpu_sync()
        
        start = time.perf_counter_ns()
        _ = kem.decaps_batch(U_bad, V)
        gpu_sync()
        end = time.perf_counter_ns()
        
        invalid_times[i] = end - start
    
    # Compute statistics
    results['valid_stats'] = TimingStats.from_samples(valid_times)
    results['invalid_stats'] = TimingStats.from_samples(invalid_times)
    
    # Welch's t-test
    t_stat, p_value = stats.ttest_ind(valid_times, invalid_times, equal_var=False)
    results['t_statistic'] = float(t_stat)
    results['p_value'] = float(p_value)
    
    # Timing ratio
    ratio = results['valid_stats'].mean / results['invalid_stats'].mean
    results['timing_ratio'] = float(ratio)
    
    # Pass criteria
    timing_similar = abs(t_stat) < T_TEST_THRESHOLD
    ratio_ok = 0.95 < ratio < 1.05
    results['passed'] = timing_similar and ratio_ok
    
    # Print results
    print(f"\n  VALID batch timing (batch_size={batch_size}):")
    print(f"    Mean:   {results['valid_stats'].mean/1000000:.3f} ms")
    print(f"    Std:    {results['valid_stats'].std/1000000:.3f} ms")
    print(f"    CV:     {results['valid_stats'].cv:.4f}")
    
    print(f"\n  INVALID batch timing:")
    print(f"    Mean:   {results['invalid_stats'].mean/1000000:.3f} ms")
    print(f"    Std:    {results['invalid_stats'].std/1000000:.3f} ms")
    print(f"    CV:     {results['invalid_stats'].cv:.4f}")
    
    print(f"\n  Statistical Analysis:")
    print(f"    Welch's t-statistic: {t_stat:.4f}")
    print(f"    p-value:             {p_value:.6f}")
    print(f"    Timing ratio:        {ratio:.4f}")
    print(f"    |t| < {T_TEST_THRESHOLD}:            {'YES ✓' if timing_similar else 'NO ✗'}")
    print(f"    Ratio in [0.95,1.05]: {'YES ✓' if ratio_ok else 'NO ✗'}")
    
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_f1_2_mixed_valid_invalid_batch(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F1.2: Mixed batch timing (varying ratio of valid/invalid)
    
    Check if timing varies based on HOW MANY ciphertexts are invalid.
    """
    print("\n[F1.2] Mixed Batch: Varying Invalid Ratio")
    print("-" * 60)
    print(f"  Samples: {n_samples // 5} per ratio")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'ratios': {},
        'anova_f': None,
        'anova_p': None,
        'passed': False,
    }
    
    batch_size = 1000
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    # Warmup
    for _ in range(WARMUP_COUNT // 10):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        _ = kem.decaps_batch(U, V)
        gpu_sync()
    
    # Test different invalid ratios: 0%, 25%, 50%, 75%, 100%
    invalid_ratios = [0.0, 0.25, 0.50, 0.75, 1.0]
    samples_per_ratio = n_samples // len(invalid_ratios)
    
    all_timing_groups = []
    
    for ratio in invalid_ratios:
        print(f"  Testing {ratio*100:.0f}% invalid...")
        
        times = np.zeros(samples_per_ratio, dtype=np.int64)
        n_invalid = int(batch_size * ratio)
        
        for i in range(samples_per_ratio):
            K, U, V = kem.encaps_batch(batch_size, return_ct=True)
            
            # Tamper first n_invalid elements
            if n_invalid > 0:
                U_mixed = U.copy()
                U_mixed[:n_invalid, 0] ^= 1
            else:
                U_mixed = U
            gpu_sync()
            
            start = time.perf_counter_ns()
            _ = kem.decaps_batch(U_mixed, V)
            gpu_sync()
            end = time.perf_counter_ns()
            
            times[i] = end - start
        
        stats_obj = TimingStats.from_samples(times)
        results['ratios'][ratio] = {
            'mean_ms': float(stats_obj.mean / 1000000),
            'std_ms': float(stats_obj.std / 1000000),
            'cv': float(stats_obj.cv),
        }
        all_timing_groups.append(times)
        
        print(f"    {ratio*100:.0f}% invalid: mean={stats_obj.mean/1000000:.3f}ms, cv={stats_obj.cv:.4f}")
    
    # ANOVA test (all groups should have same mean)
    f_stat, p_value = stats.f_oneway(*all_timing_groups)
    results['anova_f'] = float(f_stat)
    results['anova_p'] = float(p_value)
    
    # Pass criteria: high p-value (no significant difference)
    results['passed'] = p_value > 0.01
    
    print(f"\n  ANOVA F-statistic: {f_stat:.4f}")
    print(f"  ANOVA p-value:     {p_value:.6f}")
    print(f"  p-value > 0.01:    {'YES ✓' if results['passed'] else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_f1_3_batch_encaps_constancy(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F1.3: Batch encaps timing constancy
    """
    print("\n[F1.3] Batch Encaps Timing Constancy")
    print("-" * 60)
    print(f"  Samples: {n_samples}")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'n_samples': n_samples,
        'stats': None,
        'cv_ok': False,
        'passed': False,
    }
    
    batch_size = 1000
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    # Warmup
    print("  Warming up...")
    for _ in range(WARMUP_COUNT // 10):
        _ = kem.encaps_batch(batch_size, return_ct=False)
        gpu_sync()
    
    # Collect timings
    print("  Collecting batch encaps timings...")
    times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        gpu_sync()
        start = time.perf_counter_ns()
        _ = kem.encaps_batch(batch_size, return_ct=False)
        gpu_sync()
        end = time.perf_counter_ns()
        times[i] = end - start
    
    # Compute statistics
    results['stats'] = TimingStats.from_samples(times)
    
    # Pass criteria
    results['cv_ok'] = results['stats'].cv < CV_THRESHOLD
    results['passed'] = results['cv_ok']
    
    print(f"\n  Timing Statistics (batch_size={batch_size}):")
    print(f"    Mean:   {results['stats'].mean/1000000:.3f} ms")
    print(f"    Std:    {results['stats'].std/1000000:.3f} ms")
    print(f"    CV:     {results['stats'].cv:.4f}")
    print(f"    Min:    {results['stats'].min/1000000:.3f} ms")
    print(f"    Max:    {results['stats'].max/1000000:.3f} ms")
    
    print(f"\n  CV < {CV_THRESHOLD}: {'YES ✓' if results['cv_ok'] else 'NO ✗'}")
    print(f"  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# F2. Statistical Analysis Tests
# =============================================================================

def test_f2_1_ks_test_batch_timing(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F2.1: KS test for batch timing distribution
    """
    print("\n[F2.1] KS Test: Batch Timing Distribution")
    print("-" * 60)
    print(f"  Samples: {n_samples // 2} per category")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'tests': [],
        'passed': True,
    }
    
    batch_size = 1000
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    # Warmup
    for _ in range(WARMUP_COUNT // 10):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        _ = kem.decaps_batch(U, V)
        gpu_sync()
    
    half_samples = n_samples // 2
    
    # Baseline: all valid
    print("  Collecting baseline (all valid)...")
    baseline_times = np.zeros(half_samples, dtype=np.int64)
    for i in range(half_samples):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        gpu_sync()
        start = time.perf_counter_ns()
        _ = kem.decaps_batch(U, V)
        gpu_sync()
        end = time.perf_counter_ns()
        baseline_times[i] = end - start
    
    # Test 1: Compare with another valid batch
    print("  Collecting comparison (all valid)...")
    compare_times = np.zeros(half_samples, dtype=np.int64)
    for i in range(half_samples):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        gpu_sync()
        start = time.perf_counter_ns()
        _ = kem.decaps_batch(U, V)
        gpu_sync()
        end = time.perf_counter_ns()
        compare_times[i] = end - start
    
    ks_stat, p_value = stats.ks_2samp(baseline_times, compare_times)
    test1_pass = p_value > KS_ALPHA
    results['tests'].append({
        'name': 'Valid vs Valid (baseline)',
        'ks_statistic': float(ks_stat),
        'p_value': float(p_value),
        'passed': test1_pass,
    })
    print(f"    Valid vs Valid: KS={ks_stat:.4f}, p={p_value:.4f} -> {'PASS ✓' if test1_pass else 'FAIL ✗'}")
    
    # Test 2: Compare with all invalid
    print("  Collecting invalid batch timings...")
    invalid_times = np.zeros(half_samples, dtype=np.int64)
    for i in range(half_samples):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        U_bad = U.copy()
        U_bad[:, 0] ^= 1
        gpu_sync()
        start = time.perf_counter_ns()
        _ = kem.decaps_batch(U_bad, V)
        gpu_sync()
        end = time.perf_counter_ns()
        invalid_times[i] = end - start
    
    ks_stat, p_value = stats.ks_2samp(baseline_times, invalid_times)
    test2_pass = p_value > KS_ALPHA
    results['tests'].append({
        'name': 'Valid vs Invalid',
        'ks_statistic': float(ks_stat),
        'p_value': float(p_value),
        'passed': test2_pass,
    })
    print(f"    Valid vs Invalid: KS={ks_stat:.4f}, p={p_value:.4f} -> {'PASS ✓' if test2_pass else 'FAIL ✗'}")
    
    results['passed'] = all(t['passed'] for t in results['tests'])
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_f2_2_batch_histogram_analysis(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F2.2: Batch timing histogram analysis
    """
    print("\n[F2.2] Batch Timing Histogram Analysis")
    print("-" * 60)
    print(f"  Samples: {n_samples}")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'valid_analysis': {},
        'invalid_analysis': {},
        'passed': True,
    }
    
    batch_size = 1000
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    # Warmup
    for _ in range(WARMUP_COUNT // 10):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        _ = kem.decaps_batch(U, V)
        gpu_sync()
    
    # Collect valid timings
    print("  Collecting valid batch timings...")
    valid_times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        gpu_sync()
        start = time.perf_counter_ns()
        _ = kem.decaps_batch(U, V)
        gpu_sync()
        end = time.perf_counter_ns()
        valid_times[i] = end - start
    
    # Collect invalid timings
    print("  Collecting invalid batch timings...")
    invalid_times = np.zeros(n_samples, dtype=np.int64)
    for i in range(n_samples):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        U_bad = U.copy()
        U_bad[:, 0] ^= 1
        gpu_sync()
        start = time.perf_counter_ns()
        _ = kem.decaps_batch(U_bad, V)
        gpu_sync()
        end = time.perf_counter_ns()
        invalid_times[i] = end - start
    
    def analyze_distribution(times: np.ndarray, name: str) -> Dict:
        analysis = {
            'mean_ms': float(np.mean(times) / 1000000),
            'std_ms': float(np.std(times) / 1000000),
            'skewness': float(stats.skew(times)),
            'kurtosis': float(stats.kurtosis(times)),
            'iqr_ms': float((np.percentile(times, 75) - np.percentile(times, 25)) / 1000000),
            'possibly_bimodal': float(stats.kurtosis(times)) < -1.0,
        }
        
        print(f"\n  {name}:")
        print(f"    Mean:     {analysis['mean_ms']:.3f} ms")
        print(f"    Std:      {analysis['std_ms']:.3f} ms")
        print(f"    Skewness: {analysis['skewness']:.4f}")
        print(f"    Kurtosis: {analysis['kurtosis']:.4f}")
        print(f"    IQR:      {analysis['iqr_ms']:.3f} ms")
        print(f"    Bimodal?: {'WARNING' if analysis['possibly_bimodal'] else 'No'}")
        
        return analysis
    
    results['valid_analysis'] = analyze_distribution(valid_times, "VALID Distribution")
    results['invalid_analysis'] = analyze_distribution(invalid_times, "INVALID Distribution")
    
    # Check for concerning patterns
    if results['valid_analysis']['possibly_bimodal']:
        results['passed'] = False
    if results['invalid_analysis']['possibly_bimodal']:
        results['passed'] = False
    
    # Compare means
    mean_diff = abs(results['valid_analysis']['mean_ms'] - results['invalid_analysis']['mean_ms'])
    mean_ratio = mean_diff / results['valid_analysis']['mean_ms']
    results['mean_difference_ratio'] = float(mean_ratio)
    
    if mean_ratio > 0.05:
        results['passed'] = False
        print(f"\n  WARNING: Mean difference ratio {mean_ratio:.4f} > 0.05")
    
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# F3. Input-Dependent Variation Tests
# =============================================================================

def test_f3_1_tamper_position_timing(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F3.1: Tamper position timing (which element in batch is tampered)
    
    Check if timing varies based on WHERE in the batch the tampering occurs.
    """
    print("\n[F3.1] Tamper Position in Batch")
    print("-" * 60)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'position_timings': {},
        'anova_f': None,
        'anova_p': None,
        'passed': False,
    }
    
    batch_size = 1000
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    # Test positions: beginning, middle, end of batch
    positions = [0, 250, 500, 750, 999]
    samples_per_pos = n_samples // len(positions)
    
    print(f"  Samples per position: {samples_per_pos}")
    
    # Warmup
    for _ in range(WARMUP_COUNT // 10):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        _ = kem.decaps_batch(U, V)
        gpu_sync()
    
    all_position_times = []
    
    for pos in positions:
        print(f"  Testing tamper at batch index {pos}...")
        times = np.zeros(samples_per_pos, dtype=np.int64)
        
        for i in range(samples_per_pos):
            K, U, V = kem.encaps_batch(batch_size, return_ct=True)
            
            # Tamper only element at position 'pos'
            U_bad = U.copy()
            U_bad[pos, 0] ^= 1
            gpu_sync()
            
            start = time.perf_counter_ns()
            _ = kem.decaps_batch(U_bad, V)
            gpu_sync()
            end = time.perf_counter_ns()
            
            times[i] = end - start
        
        stats_obj = TimingStats.from_samples(times)
        results['position_timings'][pos] = {
            'mean_ms': float(stats_obj.mean / 1000000),
            'std_ms': float(stats_obj.std / 1000000),
            'cv': float(stats_obj.cv),
        }
        all_position_times.append(times)
        
        print(f"    Position {pos}: mean={stats_obj.mean/1000000:.3f}ms")
    
    # ANOVA test
    f_stat, p_value = stats.f_oneway(*all_position_times)
    results['anova_f'] = float(f_stat)
    results['anova_p'] = float(p_value)
    
    # Pass criteria
    results['passed'] = p_value > 0.01
    
    print(f"\n  ANOVA F-statistic: {f_stat:.4f}")
    print(f"  ANOVA p-value:     {p_value:.6f}")
    print(f"  p-value > 0.01:    {'YES ✓' if results['passed'] else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_f3_2_tamper_count_timing(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F3.2: Tamper count timing (how many elements are tampered)
    
    Check if timing correlates with NUMBER of tampered elements.
    """
    print("\n[F3.2] Tamper Count Correlation")
    print("-" * 60)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'correlation': None,
        'p_value': None,
        'passed': False,
    }
    
    batch_size = 1000
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    # Warmup
    for _ in range(WARMUP_COUNT // 10):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        _ = kem.decaps_batch(U, V)
        gpu_sync()
    
    print(f"  Collecting timings with varying tamper counts...")
    
    times = np.zeros(n_samples, dtype=np.int64)
    tamper_counts = np.zeros(n_samples, dtype=np.int64)
    
    for i in range(n_samples):
        K, U, V = kem.encaps_batch(batch_size, return_ct=True)
        
        # Random number of tampered elements (0 to batch_size)
        n_tamper = np.random.randint(0, batch_size + 1)
        tamper_counts[i] = n_tamper
        
        U_bad = U.copy()
        if n_tamper > 0:
            tamper_indices = np.random.choice(batch_size, n_tamper, replace=False)
            U_bad[tamper_indices, 0] ^= 1
        gpu_sync()
        
        start = time.perf_counter_ns()
        _ = kem.decaps_batch(U_bad, V)
        gpu_sync()
        end = time.perf_counter_ns()
        
        times[i] = end - start
    
    # Compute correlation
    correlation, p_value = stats.pearsonr(tamper_counts, times)
    results['correlation'] = float(correlation)
    results['p_value'] = float(p_value)
    
    # Pass criteria: low correlation
    results['passed'] = abs(correlation) < 0.1
    
    print(f"\n  Pearson correlation: {correlation:.6f}")
    print(f"  p-value:             {p_value:.6f}")
    print(f"  |correlation| < 0.1: {'YES ✓' if results['passed'] else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_f3_3_key_dependent_batch_timing(n_samples: int = SAMPLE_COUNT // 10) -> Dict:
    """
    F3.3: Key-dependent batch timing
    """
    print("\n[F3.3] Key-Dependent Batch Timing")
    print("-" * 60)
    print(f"  Samples: {n_samples} keys, 100 ops each")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'n_keys': n_samples,
        'cv_across_keys': None,
        'passed': False,
    }
    
    batch_size = 1000
    key_means = []
    
    for k in range(n_samples):
        if k % 100 == 0:
            print(f"  Processing key {k}/{n_samples}...")
        
        kem = BatchLWEKEM(n=256, device_id=0)
        kem.key_gen()
        
        # Warmup for this key
        for _ in range(5):
            K, U, V = kem.encaps_batch(batch_size, return_ct=True)
            _ = kem.decaps_batch(U, V)
            gpu_sync()
        
        # Collect timings for this key
        times = np.zeros(100, dtype=np.int64)
        for i in range(100):
            K, U, V = kem.encaps_batch(batch_size, return_ct=True)
            gpu_sync()
            start = time.perf_counter_ns()
            _ = kem.decaps_batch(U, V)
            gpu_sync()
            end = time.perf_counter_ns()
            times[i] = end - start
        
        key_means.append(np.mean(times))
    
    key_means = np.array(key_means)
    cv_across_keys = np.std(key_means) / np.mean(key_means)
    results['cv_across_keys'] = float(cv_across_keys)
    
    # Pass criteria
    results['passed'] = cv_across_keys < CV_THRESHOLD
    
    print(f"\n  Mean timing across keys: {np.mean(key_means)/1000000:.3f} ms")
    print(f"  Std across keys:         {np.std(key_means)/1000000:.3f} ms")
    print(f"  CV across keys:          {cv_across_keys:.4f}")
    print(f"  CV < {CV_THRESHOLD}:              {'YES ✓' if results['passed'] else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# F4. Scaling Linearity Tests
# =============================================================================

def test_f4_1_scaling_linearity(n_samples: int = 100) -> Dict:
    """
    F4.1: Batch size scaling linearity
    
    Timing should scale linearly with batch size (no data-dependent branches).
    """
    print("\n[F4.1] Batch Size Scaling Linearity")
    print("-" * 60)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'batch_sizes': [],
        'mean_times': [],
        'r_squared': None,
        'passed': False,
    }
    
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    # Test batch sizes
    batch_sizes = [100, 500, 1000, 2000, 5000, 10000]
    mean_times = []
    
    for bs in batch_sizes:
        print(f"  Testing batch_size={bs}...")
        
        # Warmup
        for _ in range(10):
            K, U, V = kem.encaps_batch(bs, return_ct=True)
            _ = kem.decaps_batch(U, V)
            gpu_sync()
        
        # Collect timings
        times = np.zeros(n_samples, dtype=np.int64)
        for i in range(n_samples):
            K, U, V = kem.encaps_batch(bs, return_ct=True)
            gpu_sync()
            start = time.perf_counter_ns()
            _ = kem.decaps_batch(U, V)
            gpu_sync()
            end = time.perf_counter_ns()
            times[i] = end - start
        
        mean_time = np.mean(times)
        mean_times.append(mean_time)
        print(f"    batch_size={bs}: {mean_time/1000000:.3f} ms")
    
    results['batch_sizes'] = batch_sizes
    results['mean_times'] = [float(t) for t in mean_times]
    
    # Linear regression
    slope, intercept, r_value, p_value, std_err = stats.linregress(batch_sizes, mean_times)
    r_squared = r_value ** 2
    results['r_squared'] = float(r_squared)
    results['slope'] = float(slope)
    results['intercept'] = float(intercept)
    
    # Pass criteria: R² > threshold (good linear fit)
    results['passed'] = r_squared > LINEARITY_R2_THRESHOLD
    
    print(f"\n  Linear Regression:")
    print(f"    R²:        {r_squared:.6f}")
    print(f"    Slope:     {slope/1000:.3f} μs/element")
    print(f"    Intercept: {intercept/1000000:.3f} ms")
    print(f"    R² > {LINEARITY_R2_THRESHOLD}:   {'YES ✓' if results['passed'] else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


def test_f4_2_per_element_timing(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F4.2: Per-element timing consistency across batch sizes
    
    Per-element timing should be constant regardless of batch size.
    """
    print("\n[F4.2] Per-Element Timing Consistency")
    print("-" * 60)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'per_element_times': {},
        'cv_across_sizes': None,
        'passed': False,
    }
    
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    batch_sizes = [100, 500, 1000, 5000, 10000]
    samples_per_size = n_samples // len(batch_sizes)
    
    per_element_means = []
    
    for bs in batch_sizes:
        print(f"  Testing batch_size={bs}...")
        
        # Warmup
        for _ in range(10):
            K, U, V = kem.encaps_batch(bs, return_ct=True)
            _ = kem.decaps_batch(U, V)
            gpu_sync()
        
        # Collect timings
        times = np.zeros(samples_per_size, dtype=np.int64)
        for i in range(samples_per_size):
            K, U, V = kem.encaps_batch(bs, return_ct=True)
            gpu_sync()
            start = time.perf_counter_ns()
            _ = kem.decaps_batch(U, V)
            gpu_sync()
            end = time.perf_counter_ns()
            times[i] = end - start
        
        # Per-element timing
        per_element_time = np.mean(times) / bs
        per_element_means.append(per_element_time)
        
        results['per_element_times'][bs] = {
            'per_element_us': float(per_element_time / 1000),
            'total_ms': float(np.mean(times) / 1000000),
        }
        
        print(f"    batch_size={bs}: {per_element_time/1000:.3f} μs/element")
    
    # CV across different batch sizes
    cv_across_sizes = np.std(per_element_means) / np.mean(per_element_means)
    results['cv_across_sizes'] = float(cv_across_sizes)
    
    # Pass criteria: low CV (consistent per-element timing)
    results['passed'] = cv_across_sizes < CV_THRESHOLD * 2  # Slightly relaxed
    
    print(f"\n  Per-element timing CV: {cv_across_sizes:.4f}")
    print(f"  CV < {CV_THRESHOLD * 2}: {'YES ✓' if results['passed'] else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# F5. Multi-Security Level Timing
# =============================================================================

def test_f5_timing_across_security_levels() -> Dict:
    """
    F5: Batch timing comparison across security levels
    """
    print("\n[F5] Batch Timing Across Security Levels")
    print("-" * 60)
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    results = {
        'levels': {},
        'passed': True,
    }
    
    levels = [
        (256, "Level 1 (128-bit)"),
        (512, "Level 3 (192-bit)"),
        (1024, "Level 5 (256-bit)"),
    ]
    
    # Adjust batch size for memory constraints
    batch_sizes = {256: 1000, 512: 500, 1024: 200}
    samples_per_level = 1000
    
    for n, level_name in levels:
        print(f"\n  Testing {level_name} (n={n})...")
        
        batch_size = batch_sizes[n]
        
        try:
            kem = BatchLWEKEM(n=n, device_id=0)
            kem.key_gen()
            
            # Warmup
            for _ in range(10):
                K, U, V = kem.encaps_batch(batch_size, return_ct=True)
                _ = kem.decaps_batch(U, V)
                gpu_sync()
            
            # Valid timings
            valid_times = np.zeros(samples_per_level, dtype=np.int64)
            for i in range(samples_per_level):
                K, U, V = kem.encaps_batch(batch_size, return_ct=True)
                gpu_sync()
                start = time.perf_counter_ns()
                _ = kem.decaps_batch(U, V)
                gpu_sync()
                end = time.perf_counter_ns()
                valid_times[i] = end - start
            
            # Invalid timings
            invalid_times = np.zeros(samples_per_level, dtype=np.int64)
            for i in range(samples_per_level):
                K, U, V = kem.encaps_batch(batch_size, return_ct=True)
                U_bad = U.copy()
                U_bad[:, 0] ^= 1
                gpu_sync()
                start = time.perf_counter_ns()
                _ = kem.decaps_batch(U_bad, V)
                gpu_sync()
                end = time.perf_counter_ns()
                invalid_times[i] = end - start
            
            # T-test
            t_stat, p_value = stats.ttest_ind(valid_times, invalid_times, equal_var=False)
            timing_similar = abs(t_stat) < T_TEST_THRESHOLD
            
            results['levels'][n] = {
                'name': level_name,
                'batch_size': batch_size,
                'valid_mean_ms': float(np.mean(valid_times) / 1000000),
                'invalid_mean_ms': float(np.mean(invalid_times) / 1000000),
                't_statistic': float(t_stat),
                'p_value': float(p_value),
                'passed': timing_similar,
            }
            
            if not timing_similar:
                results['passed'] = False
            
            ratio = np.mean(valid_times) / np.mean(invalid_times)
            print(f"    Valid:   {np.mean(valid_times)/1000000:.3f} ms (batch={batch_size})")
            print(f"    Invalid: {np.mean(invalid_times)/1000000:.3f} ms")
            print(f"    Ratio:   {ratio:.4f}")
            print(f"    t-stat:  {t_stat:.4f}")
            print(f"    Status:  {'PASS ✓' if timing_similar else 'FAIL ✗'}")
            
        except Exception as e:
            print(f"    ERROR: {e}")
            results['levels'][n] = {'error': str(e), 'passed': False}
            results['passed'] = False
    
    print(f"\n  Overall Result: {'PASS ✓' if results['passed'] else 'FAIL ✗'}")
    
    return results


# =============================================================================
# Main Test Runner
# =============================================================================

def run_all_batch_sidechannel_tests() -> Dict:
    """Run all batch side-channel evaluation tests."""
    print("=" * 70)
    print("Meteor-NC Batch KEM Side-Channel Evaluation Suite")
    print("=" * 70)
    print(f"GPU Available: {GPU_AVAILABLE}")
    print(f"Sample Count: {SAMPLE_COUNT}")
    print(f"T-test Threshold: {T_TEST_THRESHOLD}")
    print(f"CV Threshold: {CV_THRESHOLD}")
    print(f"Linearity R² Threshold: {LINEARITY_R2_THRESHOLD}")
    
    if not GPU_AVAILABLE:
        print("\nWARNING: GPU not available. All batch tests will be skipped.")
        return {'all_pass': True, 'skipped': True}
    
    all_results = {}
    
    # F1. Batch Timing Constancy
    print("\n" + "=" * 70)
    print("F1. BATCH TIMING CONSTANCY")
    print("=" * 70)
    
    all_results['f1_1_valid_vs_invalid'] = test_f1_1_batch_decaps_valid_vs_invalid()
    all_results['f1_2_mixed_batch'] = test_f1_2_mixed_valid_invalid_batch()
    all_results['f1_3_encaps_constancy'] = test_f1_3_batch_encaps_constancy()
    
    # F2. Statistical Analysis
    print("\n" + "=" * 70)
    print("F2. STATISTICAL ANALYSIS")
    print("=" * 70)
    
    all_results['f2_1_ks_test'] = test_f2_1_ks_test_batch_timing()
    all_results['f2_2_histogram'] = test_f2_2_batch_histogram_analysis()
    
    # F3. Input-Dependent Variation
    print("\n" + "=" * 70)
    print("F3. INPUT-DEPENDENT VARIATION")
    print("=" * 70)
    
    all_results['f3_1_tamper_position'] = test_f3_1_tamper_position_timing()
    all_results['f3_2_tamper_count'] = test_f3_2_tamper_count_timing()
    all_results['f3_3_key_dependent'] = test_f3_3_key_dependent_batch_timing()
    
    # F4. Scaling Linearity
    print("\n" + "=" * 70)
    print("F4. SCALING LINEARITY")
    print("=" * 70)
    
    all_results['f4_1_scaling_linearity'] = test_f4_1_scaling_linearity()
    all_results['f4_2_per_element'] = test_f4_2_per_element_timing()
    
    # F5. Multi-Security Level
    print("\n" + "=" * 70)
    print("F5. MULTI-SECURITY LEVEL")
    print("=" * 70)
    
    all_results['f5_security_levels'] = test_f5_timing_across_security_levels()
    
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
            status = "PASS ✓"
            passed += 1
        else:
            status = "FAIL ✗"
            failed += 1
        print(f"  {name}: {status}")
    
    print(f"\nTotal: {passed} passed, {failed} failed, {skipped} skipped")
    
    all_pass = failed == 0
    print(f"\n{'=' * 70}")
    print(f"BATCH SIDE-CHANNEL EVALUATION: {'✅ ALL TESTS PASSED' if all_pass else '❌ SOME TESTS FAILED'}")
    print(f"{'=' * 70}")
    
    return {
        'results': all_results,
        'passed': passed,
        'failed': failed,
        'skipped': skipped,
        'all_pass': all_pass,
        'configuration': {
            'sample_count': SAMPLE_COUNT,
            't_test_threshold': T_TEST_THRESHOLD,
            'cv_threshold': CV_THRESHOLD,
            'linearity_r2_threshold': LINEARITY_R2_THRESHOLD,
            'ks_alpha': KS_ALPHA,
            'gpu_used': GPU_AVAILABLE,
        }
    }


if __name__ == "__main__":
    run_all_batch_sidechannel_tests()
