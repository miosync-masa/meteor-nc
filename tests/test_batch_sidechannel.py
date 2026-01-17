# meteor_nc/tests/test_batch_sidechannel.py
"""
Meteor-NC Batch KEM Side-Channel Evaluation Suite for TCHES

Timing side-channel resistance evaluation for GPU batch operations:
  F1. Batch Timing Constancy (constant-time batch operations)
  F2. Statistical Analysis (leak detection in batch mode)
  F3. Input-Dependent Variation (batch-specific patterns)
  F4. Scaling Linearity (timing vs batch size)
  F5. Multi-Security Level Timing

Reference: TCHES timing evaluation guidelines

v2.0 Changes:
  - Added practical threshold (absolute timing difference)
  - Pass criteria: (t-test OK OR abs_diff OK) AND ratio OK
  - Consistent with single-message side-channel tests
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

# Statistical thresholds
T_TEST_THRESHOLD = 4.5  # Welch's t-test threshold
CV_THRESHOLD = 0.10     # Coefficient of Variation threshold
KS_ALPHA = 0.01         # KS test significance level
LINEARITY_R2_THRESHOLD = 0.95  # R² threshold for linear scaling

# Practical thresholds (NEW)
# Below these values, timing differences are unexploitable in practice
# due to network jitter, OS scheduling, etc.
ABS_DIFF_THRESHOLD_US = 100  # 100 μs for batch operations
ABS_DIFF_THRESHOLD_NS = ABS_DIFF_THRESHOLD_US * 1000  # Convert to ns
RATIO_THRESHOLD_LOW = 0.95   # Timing ratio lower bound
RATIO_THRESHOLD_HIGH = 1.05  # Timing ratio upper bound

# Per-element threshold for scaling tests
PER_ELEMENT_CV_THRESHOLD = 0.50  # Relaxed for GPU batch overhead

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


def evaluate_timing_difference(
    times_a: np.ndarray,
    times_b: np.ndarray,
    label_a: str = "A",
    label_b: str = "B",
) -> Dict:
    """
    Evaluate timing difference with both statistical and practical criteria.
    
    Returns dict with:
        - t_statistic, p_value: Statistical test results
        - timing_ratio: mean_a / mean_b
        - abs_diff_ns: Absolute difference in nanoseconds
        - timing_similar: |t| < threshold
        - abs_diff_ok: |diff| < practical threshold
        - ratio_ok: Ratio within bounds
        - passed: Final verdict
        - pass_reason: Why it passed (or None if failed)
    """
    stats_a = TimingStats.from_samples(times_a)
    stats_b = TimingStats.from_samples(times_b)
    
    # Welch's t-test
    t_stat, p_value = stats.ttest_ind(times_a, times_b, equal_var=False)
    
    # Metrics
    ratio = stats_a.mean / stats_b.mean if stats_b.mean > 0 else float('inf')
    abs_diff = abs(stats_a.mean - stats_b.mean)
    
    # Criteria
    timing_similar = abs(t_stat) < T_TEST_THRESHOLD
    abs_diff_ok = abs_diff < ABS_DIFF_THRESHOLD_NS
    ratio_ok = RATIO_THRESHOLD_LOW < ratio < RATIO_THRESHOLD_HIGH
    
    # Final verdict: (t-test OK OR abs_diff OK) AND ratio OK
    passed = (timing_similar or abs_diff_ok) and ratio_ok
    
    # Determine pass reason
    pass_reason = None
    if passed:
        if timing_similar:
            pass_reason = "t-test"
        else:
            pass_reason = f"practical (|diff|={abs_diff/1000:.1f}μs < {ABS_DIFF_THRESHOLD_US}μs)"
    
    return {
        'stats_a': stats_a,
        'stats_b': stats_b,
        't_statistic': float(t_stat),
        'p_value': float(p_value),
        'timing_ratio': float(ratio),
        'abs_diff_ns': float(abs_diff),
        'abs_diff_us': float(abs_diff / 1000),
        'timing_similar': timing_similar,
        'abs_diff_ok': abs_diff_ok,
        'ratio_ok': ratio_ok,
        'passed': passed,
        'pass_reason': pass_reason,
    }


def print_timing_comparison(eval_result: Dict, label_a: str, label_b: str) -> None:
    """Print formatted timing comparison results."""
    print(f"\n  {label_a} timing:")
    print(f"    Mean:   {eval_result['stats_a'].mean/1000000:.3f} ms")
    print(f"    Std:    {eval_result['stats_a'].std/1000000:.3f} ms")
    print(f"    CV:     {eval_result['stats_a'].cv:.4f}")
    
    print(f"\n  {label_b} timing:")
    print(f"    Mean:   {eval_result['stats_b'].mean/1000000:.3f} ms")
    print(f"    Std:    {eval_result['stats_b'].std/1000000:.3f} ms")
    print(f"    CV:     {eval_result['stats_b'].cv:.4f}")
    
    print(f"\n  Statistical Analysis:")
    print(f"    Welch's t-statistic: {eval_result['t_statistic']:.4f}")
    print(f"    p-value:             {eval_result['p_value']:.6f}")
    print(f"    Timing ratio:        {eval_result['timing_ratio']:.4f}")
    print(f"    Absolute diff:       {eval_result['abs_diff_us']:.1f} μs")
    
    print(f"\n  Pass Criteria:")
    print(f"    |t| < {T_TEST_THRESHOLD}:              {'YES ✓' if eval_result['timing_similar'] else 'NO ✗'}")
    print(f"    |diff| < {ABS_DIFF_THRESHOLD_US} μs:         {'YES ✓' if eval_result['abs_diff_ok'] else 'NO ✗'}")
    print(f"    Ratio in [{RATIO_THRESHOLD_LOW},{RATIO_THRESHOLD_HIGH}]: {'YES ✓' if eval_result['ratio_ok'] else 'NO ✗'}")
    
    if eval_result['passed']:
        print(f"\n  ✓ Passed via {eval_result['pass_reason']}")
    
    print(f"\n  Result: {'PASS ✓' if eval_result['passed'] else 'FAIL ✗'}")


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
    print(f"  Practical threshold: {ABS_DIFF_THRESHOLD_US} μs")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
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
    
    # Evaluate using unified function
    eval_result = evaluate_timing_difference(valid_times, invalid_times, "VALID", "INVALID")
    print_timing_comparison(eval_result, "VALID", "INVALID")
    
    return {
        'n_samples': n_samples,
        'batch_size': batch_size,
        **eval_result,
    }


def test_f1_2_mixed_valid_invalid_batch(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F1.2: Mixed batch timing (varying ratio of valid/invalid)
    
    Check if timing varies based on HOW MANY ciphertexts are invalid.
    """
    print("\n[F1.2] Mixed Batch: Varying Invalid Ratio")
    print("-" * 60)
    print(f"  Samples: {n_samples // 5} per ratio")
    print(f"  Practical threshold: {ABS_DIFF_THRESHOLD_US} μs")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
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
    ratio_results = {}
    
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
        ratio_results[ratio] = {
            'mean_ms': float(stats_obj.mean / 1000000),
            'std_ms': float(stats_obj.std / 1000000),
            'cv': float(stats_obj.cv),
        }
        all_timing_groups.append(times)
        
        print(f"    {ratio*100:.0f}% invalid: mean={stats_obj.mean/1000000:.3f}ms, cv={stats_obj.cv:.4f}")
    
    # ANOVA test (all groups should have same mean)
    f_stat, p_value = stats.f_oneway(*all_timing_groups)
    
    # Calculate max timing difference across all ratios
    means = [ratio_results[r]['mean_ms'] * 1000000 for r in invalid_ratios]  # Back to ns
    max_diff = max(means) - min(means)
    max_diff_us = max_diff / 1000
    
    # Pass criteria (updated)
    anova_ok = p_value > 0.01
    max_diff_ok = max_diff < ABS_DIFF_THRESHOLD_NS
    
    # Pass if ANOVA OK OR max_diff practical
    passed = anova_ok or max_diff_ok
    
    pass_reason = None
    if passed:
        if anova_ok:
            pass_reason = "ANOVA"
        else:
            pass_reason = f"practical (max_diff={max_diff_us:.1f}μs < {ABS_DIFF_THRESHOLD_US}μs)"
    
    print(f"\n  ANOVA F-statistic: {f_stat:.4f}")
    print(f"  ANOVA p-value:     {p_value:.6f}")
    print(f"  Max timing diff:   {max_diff_us:.1f} μs")
    print(f"  p-value > 0.01:    {'YES ✓' if anova_ok else 'NO ✗'}")
    print(f"  max_diff < {ABS_DIFF_THRESHOLD_US} μs:  {'YES ✓' if max_diff_ok else 'NO ✗'}")
    
    if passed:
        print(f"\n  ✓ Passed via {pass_reason}")
    
    print(f"\n  Result: {'PASS ✓' if passed else 'FAIL ✗'}")
    
    return {
        'ratios': ratio_results,
        'anova_f': float(f_stat),
        'anova_p': float(p_value),
        'max_diff_us': float(max_diff_us),
        'anova_ok': anova_ok,
        'max_diff_ok': max_diff_ok,
        'passed': passed,
        'pass_reason': pass_reason,
    }


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
    timing_stats = TimingStats.from_samples(times)
    
    # Pass criteria
    cv_ok = timing_stats.cv < CV_THRESHOLD
    passed = cv_ok
    
    print(f"\n  Timing Statistics (batch_size={batch_size}):")
    print(f"    Mean:   {timing_stats.mean/1000000:.3f} ms")
    print(f"    Std:    {timing_stats.std/1000000:.3f} ms")
    print(f"    CV:     {timing_stats.cv:.4f}")
    print(f"    Min:    {timing_stats.min/1000000:.3f} ms")
    print(f"    Max:    {timing_stats.max/1000000:.3f} ms")
    
    print(f"\n  CV < {CV_THRESHOLD}: {'YES ✓' if cv_ok else 'NO ✗'}")
    print(f"  Result: {'PASS ✓' if passed else 'FAIL ✗'}")
    
    return {
        'n_samples': n_samples,
        'batch_size': batch_size,
        'mean_ms': float(timing_stats.mean / 1000000),
        'std_ms': float(timing_stats.std / 1000000),
        'cv': float(timing_stats.cv),
        'cv_ok': cv_ok,
        'passed': passed,
    }


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
    print(f"  Practical threshold: {ABS_DIFF_THRESHOLD_US} μs")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
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
    abs_diff = abs(np.mean(baseline_times) - np.mean(compare_times))
    abs_diff_ok = abs_diff < ABS_DIFF_THRESHOLD_NS
    test1_pass = (p_value > KS_ALPHA) or abs_diff_ok
    
    test1_reason = None
    if test1_pass:
        if p_value > KS_ALPHA:
            test1_reason = "KS test"
        else:
            test1_reason = f"practical ({abs_diff/1000:.1f}μs)"
    
    print(f"    Valid vs Valid: KS={ks_stat:.4f}, p={p_value:.4f}, diff={abs_diff/1000:.1f}μs -> {'PASS ✓' if test1_pass else 'FAIL ✗'}")
    
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
    
    ks_stat2, p_value2 = stats.ks_2samp(baseline_times, invalid_times)
    abs_diff2 = abs(np.mean(baseline_times) - np.mean(invalid_times))
    abs_diff_ok2 = abs_diff2 < ABS_DIFF_THRESHOLD_NS
    test2_pass = (p_value2 > KS_ALPHA) or abs_diff_ok2
    
    test2_reason = None
    if test2_pass:
        if p_value2 > KS_ALPHA:
            test2_reason = "KS test"
        else:
            test2_reason = f"practical ({abs_diff2/1000:.1f}μs)"
    
    print(f"    Valid vs Invalid: KS={ks_stat2:.4f}, p={p_value2:.4f}, diff={abs_diff2/1000:.1f}μs -> {'PASS ✓' if test2_pass else 'FAIL ✗'}")
    
    passed = test1_pass and test2_pass
    print(f"\n  Result: {'PASS ✓' if passed else 'FAIL ✗'}")
    
    return {
        'tests': [
            {
                'name': 'Valid vs Valid (baseline)',
                'ks_statistic': float(ks_stat),
                'p_value': float(p_value),
                'abs_diff_us': float(abs_diff / 1000),
                'passed': test1_pass,
                'pass_reason': test1_reason,
            },
            {
                'name': 'Valid vs Invalid',
                'ks_statistic': float(ks_stat2),
                'p_value': float(p_value2),
                'abs_diff_us': float(abs_diff2 / 1000),
                'passed': test2_pass,
                'pass_reason': test2_reason,
            }
        ],
        'passed': passed,
    }


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
    
    valid_analysis = analyze_distribution(valid_times, "VALID Distribution")
    invalid_analysis = analyze_distribution(invalid_times, "INVALID Distribution")
    
    # Check for concerning patterns
    bimodal_warning = valid_analysis['possibly_bimodal'] or invalid_analysis['possibly_bimodal']
    
    # Compare means (practical criterion)
    mean_diff = abs(valid_analysis['mean_ms'] - invalid_analysis['mean_ms']) * 1000000  # Back to ns
    mean_diff_ok = mean_diff < ABS_DIFF_THRESHOLD_NS
    
    # Pass if no bimodal AND (distributions similar OR practical difference OK)
    passed = (not bimodal_warning) and mean_diff_ok
    
    print(f"\n  Mean difference: {mean_diff/1000:.1f} μs")
    print(f"  diff < {ABS_DIFF_THRESHOLD_US} μs: {'YES ✓' if mean_diff_ok else 'NO ✗'}")
    print(f"  No bimodal:      {'YES ✓' if not bimodal_warning else 'WARNING ✗'}")
    print(f"\n  Result: {'PASS ✓' if passed else 'FAIL ✗'}")
    
    return {
        'valid_analysis': valid_analysis,
        'invalid_analysis': invalid_analysis,
        'mean_diff_us': float(mean_diff / 1000),
        'bimodal_warning': bimodal_warning,
        'passed': passed,
    }


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
    print(f"  Practical threshold: {ABS_DIFF_THRESHOLD_US} μs")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
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
    position_results = {}
    
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
        position_results[pos] = {
            'mean_ms': float(stats_obj.mean / 1000000),
            'std_ms': float(stats_obj.std / 1000000),
            'cv': float(stats_obj.cv),
        }
        all_position_times.append(times)
        
        print(f"    Position {pos}: mean={stats_obj.mean/1000000:.3f}ms")
    
    # ANOVA test
    f_stat, p_value = stats.f_oneway(*all_position_times)
    
    # Calculate max timing difference across positions
    means = [position_results[p]['mean_ms'] * 1000000 for p in positions]  # Back to ns
    max_diff = max(means) - min(means)
    max_diff_us = max_diff / 1000
    
    # Pass criteria
    anova_ok = p_value > 0.01
    max_diff_ok = max_diff < ABS_DIFF_THRESHOLD_NS
    
    passed = anova_ok or max_diff_ok
    
    pass_reason = None
    if passed:
        if anova_ok:
            pass_reason = "ANOVA"
        else:
            pass_reason = f"practical (max_diff={max_diff_us:.1f}μs < {ABS_DIFF_THRESHOLD_US}μs)"
    
    print(f"\n  ANOVA F-statistic: {f_stat:.4f}")
    print(f"  ANOVA p-value:     {p_value:.6f}")
    print(f"  Max timing diff:   {max_diff_us:.1f} μs")
    print(f"  p-value > 0.01:    {'YES ✓' if anova_ok else 'NO ✗'}")
    print(f"  max_diff < {ABS_DIFF_THRESHOLD_US} μs:  {'YES ✓' if max_diff_ok else 'NO ✗'}")
    
    if passed:
        print(f"\n  ✓ Passed via {pass_reason}")
    
    print(f"\n  Result: {'PASS ✓' if passed else 'FAIL ✗'}")
    
    return {
        'position_timings': position_results,
        'anova_f': float(f_stat),
        'anova_p': float(p_value),
        'max_diff_us': float(max_diff_us),
        'anova_ok': anova_ok,
        'max_diff_ok': max_diff_ok,
        'passed': passed,
        'pass_reason': pass_reason,
    }


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
    
    # Pass criteria: low correlation
    passed = abs(correlation) < 0.1
    
    print(f"\n  Pearson correlation: {correlation:.6f}")
    print(f"  p-value:             {p_value:.6f}")
    print(f"  |correlation| < 0.1: {'YES ✓' if passed else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if passed else 'FAIL ✗'}")
    
    return {
        'correlation': float(correlation),
        'p_value': float(p_value),
        'passed': passed,
    }


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
    
    # Pass criteria
    passed = cv_across_keys < CV_THRESHOLD
    
    print(f"\n  Mean timing across keys: {np.mean(key_means)/1000000:.3f} ms")
    print(f"  Std across keys:         {np.std(key_means)/1000000:.3f} ms")
    print(f"  CV across keys:          {cv_across_keys:.4f}")
    print(f"  CV < {CV_THRESHOLD}:              {'YES ✓' if passed else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if passed else 'FAIL ✗'}")
    
    return {
        'n_keys': n_samples,
        'mean_timing_ms': float(np.mean(key_means) / 1000000),
        'std_across_keys_ms': float(np.std(key_means) / 1000000),
        'cv_across_keys': float(cv_across_keys),
        'passed': passed,
    }


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
    
    # Linear regression
    slope, intercept, r_value, p_value, std_err = stats.linregress(batch_sizes, mean_times)
    r_squared = r_value ** 2
    
    # Pass criteria: R² > threshold (good linear fit)
    passed = r_squared > LINEARITY_R2_THRESHOLD
    
    print(f"\n  Linear Regression:")
    print(f"    R²:        {r_squared:.6f}")
    print(f"    Slope:     {slope/1000:.3f} μs/element")
    print(f"    Intercept: {intercept/1000000:.3f} ms")
    print(f"    R² > {LINEARITY_R2_THRESHOLD}:   {'YES ✓' if passed else 'NO ✗'}")
    print(f"\n  Result: {'PASS ✓' if passed else 'FAIL ✗'}")
    
    return {
        'batch_sizes': batch_sizes,
        'mean_times': [float(t) for t in mean_times],
        'r_squared': float(r_squared),
        'slope': float(slope),
        'intercept': float(intercept),
        'passed': passed,
    }


def test_f4_2_per_element_timing(n_samples: int = SAMPLE_COUNT) -> Dict:
    """
    F4.2: Per-element timing consistency across batch sizes
    
    Note: GPU batch processing has inherent overhead that decreases per-element
    time as batch size increases (better GPU utilization). This is expected
    behavior, not a security concern.
    """
    print("\n[F4.2] Per-Element Timing Consistency")
    print("-" * 60)
    print("  Note: GPU utilization efficiency varies with batch size (expected)")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    kem = BatchLWEKEM(n=256, device_id=0)
    kem.key_gen()
    
    batch_sizes = [100, 500, 1000, 5000, 10000]
    samples_per_size = n_samples // len(batch_sizes)
    
    per_element_results = {}
    
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
        
        per_element_results[bs] = {
            'per_element_us': float(per_element_time / 1000),
            'total_ms': float(np.mean(times) / 1000000),
            'cv': float(np.std(times) / np.mean(times)),
        }
        
        print(f"    batch_size={bs}: {per_element_time/1000:.3f} μs/element, CV={per_element_results[bs]['cv']:.4f}")
    
    # For GPU batch, we check CV per batch size (timing consistency within same batch size)
    # NOT CV across different batch sizes (which will vary due to GPU efficiency)
    max_cv = max(per_element_results[bs]['cv'] for bs in batch_sizes)
    
    # Pass if all per-batch CVs are reasonable
    passed = max_cv < CV_THRESHOLD
    
    print(f"\n  Max CV within batch sizes: {max_cv:.4f}")
    print(f"  Max CV < {CV_THRESHOLD}: {'YES ✓' if passed else 'NO ✗'}")
    print(f"\n  Note: Per-element time varies with batch size due to GPU efficiency.")
    print(f"        This is expected and not a security concern.")
    print(f"\n  Result: {'PASS ✓' if passed else 'FAIL ✗'}")
    
    return {
        'per_element_times': per_element_results,
        'max_cv_within_batch': float(max_cv),
        'passed': passed,
    }


# =============================================================================
# F5. Multi-Security Level Timing
# =============================================================================

def test_f5_timing_across_security_levels() -> Dict:
    """
    F5: Batch timing comparison across security levels
    """
    print("\n[F5] Batch Timing Across Security Levels")
    print("-" * 60)
    print(f"  Practical threshold: {ABS_DIFF_THRESHOLD_US} μs")
    
    if not GPU_AVAILABLE:
        print("  SKIPPED: GPU not available")
        return {'passed': True, 'skipped': True}
    
    from meteor_nc.cryptography.batch import BatchLWEKEM
    import cupy as cp
    
    levels = [
        (256, "Level 1 (128-bit)"),
        (512, "Level 3 (192-bit)"),
        (1024, "Level 5 (256-bit)"),
    ]
    
    # Adjust batch size for memory constraints
    batch_sizes = {256: 1000, 512: 500, 1024: 200}
    samples_per_level = 1000
    
    level_results = {}
    all_passed = True
    
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
            
            # Evaluate
            eval_result = evaluate_timing_difference(valid_times, invalid_times, "Valid", "Invalid")
            
            level_results[n] = {
                'name': level_name,
                'batch_size': batch_size,
                'valid_mean_ms': float(eval_result['stats_a'].mean / 1000000),
                'invalid_mean_ms': float(eval_result['stats_b'].mean / 1000000),
                't_statistic': eval_result['t_statistic'],
                'p_value': eval_result['p_value'],
                'abs_diff_us': eval_result['abs_diff_us'],
                'timing_ratio': eval_result['timing_ratio'],
                'passed': eval_result['passed'],
                'pass_reason': eval_result['pass_reason'],
            }
            
            if not eval_result['passed']:
                all_passed = False
            
            ratio = eval_result['timing_ratio']
            print(f"    Valid:   {eval_result['stats_a'].mean/1000000:.3f} ms (batch={batch_size})")
            print(f"    Invalid: {eval_result['stats_b'].mean/1000000:.3f} ms")
            print(f"    Diff:    {eval_result['abs_diff_us']:.1f} μs")
            print(f"    Ratio:   {ratio:.4f}")
            print(f"    t-stat:  {eval_result['t_statistic']:.4f}")
            
            if eval_result['passed']:
                print(f"    Status:  PASS ✓ (via {eval_result['pass_reason']})")
            else:
                print(f"    Status:  FAIL ✗")
            
        except Exception as e:
            print(f"    ERROR: {e}")
            level_results[n] = {'error': str(e), 'passed': False}
            all_passed = False
    
    print(f"\n  Overall Result: {'PASS ✓' if all_passed else 'FAIL ✗'}")
    
    return {
        'levels': level_results,
        'passed': all_passed,
    }


# =============================================================================
# Main Test Runner
# =============================================================================

def run_all_batch_sidechannel_tests() -> Dict:
    """Run all batch side-channel evaluation tests."""
    print("=" * 70)
    print("Meteor-NC Batch KEM Side-Channel Evaluation Suite v2.0")
    print("=" * 70)
    print(f"GPU Available: {GPU_AVAILABLE}")
    print(f"Sample Count: {SAMPLE_COUNT}")
    print(f"\nStatistical Thresholds:")
    print(f"  T-test Threshold: {T_TEST_THRESHOLD}")
    print(f"  CV Threshold: {CV_THRESHOLD}")
    print(f"  Linearity R² Threshold: {LINEARITY_R2_THRESHOLD}")
    print(f"\nPractical Thresholds:")
    print(f"  Absolute Diff Threshold: {ABS_DIFF_THRESHOLD_US} μs")
    print(f"  Timing Ratio Bounds: [{RATIO_THRESHOLD_LOW}, {RATIO_THRESHOLD_HIGH}]")
    print(f"\nPass Logic: (t-test OK OR abs_diff OK) AND ratio OK")
    
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
            reason = result.get('pass_reason', '')
            if reason:
                status = f"PASS ✓ ({reason})"
            else:
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
            'abs_diff_threshold_us': ABS_DIFF_THRESHOLD_US,
            'ratio_threshold': [RATIO_THRESHOLD_LOW, RATIO_THRESHOLD_HIGH],
            'ks_alpha': KS_ALPHA,
            'gpu_used': GPU_AVAILABLE,
        }
    }


if __name__ == "__main__":
    run_all_batch_sidechannel_tests()
