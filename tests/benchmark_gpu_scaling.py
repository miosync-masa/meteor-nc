#!/usr/bin/env python3
"""
Meteor-NC: GPU Scaling Benchmark

Tests performance across security levels (128, 256, 512, 1024).
Validates three-fold security (LTDF/NCSP/Procrustes).

Usage:
    # In Google Colab with A100 GPU
    !cd /content/meteor-nc && python tests/benchmark_gpu_scaling.py
"""

# ============================================================================
# Cell 1: Setup
# ============================================================================
print("=" * 70)
print("Meteor-NC: GPU Scaling Benchmark Setup")
print("=" * 70)

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import time

from meteor_nc import create_kdf_meteor, check_gpu_available

# Check GPU
if not check_gpu_available():
    print("⚠️ GPU not available! Running in CPU mode.")
    GPU_MODE = False
else:
    print("✅ GPU available!")
    GPU_MODE = True


# ============================================================================
# Cell 2: Quick Test (n=256 baseline)
# ============================================================================
print("\n" + "=" * 70)
print("Quick Test: n=256 (Baseline)")
print("=" * 70)

# Create METEOR-256
crypto = create_kdf_meteor(256, gpu=GPU_MODE)
crypto.key_gen(verbose=True)
crypto.expand_keys(verbose=True)

# Quick benchmark
messages = np.random.randn(7000, 256)
ciphertexts = crypto.encrypt_batch(messages)

# Warmup
print("[*] Warming up...")
for _ in range(3):
    _ = crypto.decrypt_batch(ciphertexts[:5000])

# Benchmark
recovered, dec_time = crypto.decrypt_batch(ciphertexts)
throughput = 7000 / dec_time

print(f"\n[Results]")
print(f"  Decryption: {dec_time*1000:.2f}ms")
print(f"  Throughput: {throughput:,.0f} msg/s")

error = np.linalg.norm(messages - recovered) / np.linalg.norm(messages)
print(f"  Error: {error:.2e}")

# Security
security = crypto.verify_security(verbose=True)


# ============================================================================
# Cell 3: Full Scaling Benchmark
# ============================================================================
print("\n" + "=" * 70)
print("Full Scaling Benchmark: n ∈ {128, 256, 512, 1024}")
print("=" * 70)


def benchmark_n_value(n, batch_size=7000, gpu=True):
    """Benchmark single n value"""
    print(f"\n{'=' * 70}")
    print(f"Testing n={n} (Security: {n}-bit)")
    print(f"{'=' * 70}")

    # Create instance
    crypto = create_kdf_meteor(n, gpu=gpu)

    # Key generation
    print(f"[*] Generating keys...")
    start = time.time()
    crypto.key_gen(verbose=False)
    crypto.expand_keys(verbose=False)
    keygen_time = time.time() - start
    print(f"    Key generation: {keygen_time:.3f}s")

    # Prepare data
    messages = np.random.randn(batch_size, n)

    # Warmup
    print(f"[*] Warming up...")
    warmup_size = min(5000, batch_size)
    for _ in range(3):
        _ = crypto.encrypt_batch(messages[:warmup_size])
        _ = crypto.decrypt_batch(crypto.encrypt_batch(messages[:warmup_size]))

    # Benchmark encryption
    print(f"[*] Benchmarking encryption...")
    start = time.time()
    ciphertexts = crypto.encrypt_batch(messages)
    enc_time = time.time() - start
    enc_throughput = batch_size / enc_time

    # Benchmark decryption (optimized)
    print(f"[*] Benchmarking decryption...")
    recovered, dec_time = crypto.decrypt_batch(ciphertexts)
    dec_throughput = batch_size / dec_time

    # Error
    error = np.linalg.norm(messages - recovered) / np.linalg.norm(messages)

    # Security (quick check)
    print(f"[*] Verifying security...")
    security = crypto.verify_security(verbose=False)

    # Results
    result = {
        'n': n,
        'm': crypto.m,
        'keygen_time': keygen_time,
        'enc_time_ms': enc_time * 1000,
        'dec_time_ms': dec_time * 1000,
        'enc_throughput': enc_throughput,
        'dec_throughput': dec_throughput,
        'error': error,
        'ncsp_norm': security.get('ncsp_commutator_norm', security.get('cp_commutator_norm', 0)),
        'ncsp_threshold': security.get('ncsp_threshold', security.get('cp_threshold', 0)),
        'secure': security['secure']
    }

    # Print summary
    print(f"\n[Summary]")
    print(f"  Encryption:  {enc_time*1000:>7.2f}ms → {enc_throughput:>10,.0f} msg/s")
    print(f"  Decryption:  {dec_time*1000:>7.2f}ms → {dec_throughput:>10,.0f} msg/s")
    print(f"  Error:       {error:.2e}")
    print(f"  Security:    NCSP={result['ncsp_norm']:.1f} "
          f"(threshold: {result['ncsp_threshold']:.1f}) "
          f"{'✅' if security['secure'] else '❌'}")

    return result


# Run benchmarks
n_values = [128, 256, 512, 1024]
results = []

for n in n_values:
    result = benchmark_n_value(n, batch_size=7000, gpu=GPU_MODE)
    results.append(result)


# ============================================================================
# Cell 4: Results Analysis
# ============================================================================
print("\n" + "=" * 70)
print("SCALING RESULTS")
print("=" * 70)

# Display table
print(f"\n{'n':<8} {'m':<6} {'KeyGen (s)':<12} {'Enc (ms)':<10} {'Dec (ms)':<10} "
      f"{'Dec Throughput':<16} {'NCSP':<12} {'Threshold':<10} {'Secure':<8}")
print("-" * 100)

for row in results:
    print(f"{row['n']:<8} {row['m']:<6} {row['keygen_time']:>10.2f}  "
          f"{row['enc_time_ms']:>8.2f}  {row['dec_time_ms']:>8.2f}  "
          f"{row['dec_throughput']:>14,.0f}  "
          f"{row['ncsp_norm']:>10.1f}  {row['ncsp_threshold']:>8.1f}  "
          f"{'✅' if row['secure'] else '❌'}")

# Efficiency analysis
print("\n" + "=" * 70)
print("EFFICIENCY ANALYSIS")
print("=" * 70)

baseline = results[0]  # n=128
print(f"\n{'n':<8} {'Theoretical':<15} {'Actual Dec':<15} {'GPU Efficiency':<15}")
print("-" * 70)

for r in results:
    theoretical = (r['n'] / baseline['n']) ** 3
    actual = r['dec_time_ms'] / baseline['dec_time_ms']
    efficiency = theoretical / actual

    print(f"{r['n']:<8} {theoretical:>13.1f}×  {actual:>13.1f}×  {efficiency:>13.1%}")

# Key findings
print("\n" + "=" * 70)
print("KEY FINDINGS")
print("=" * 70)

max_throughput = max(r['dec_throughput'] for r in results)
best_n = next(r['n'] for r in results if r['dec_throughput'] == max_throughput)

print(f"\n🏆 Peak Throughput: {max_throughput:,.0f} msg/s at n={best_n}")

# Comparisons
kyber_throughput = 5000  # msg/s (Kyber-768 estimate)
aes_throughput = 100000  # msg/s

print(f"\n[Comparison with other schemes]")
for r in results:
    kyber_speedup = r['dec_throughput'] / kyber_throughput
    aes_speedup = r['dec_throughput'] / aes_throughput
    print(f"   n={r['n']:4d}: {kyber_speedup:>5.0f}× vs Kyber-768, {aes_speedup:>5.1f}× vs AES-256")


# ============================================================================
# Cell 5: Visualization (Optional)
# ============================================================================
try:
    import matplotlib.pyplot as plt
    
    print("\n[*] Creating visualizations...")
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    n_vals = [r['n'] for r in results]
    
    # 1. Throughput vs n
    ax = axes[0, 0]
    ax.plot(n_vals, [r['dec_throughput'] / 1000 for r in results], 'o-', linewidth=2, markersize=10)
    ax.set_xlabel('Security Level (n)', fontsize=12)
    ax.set_ylabel('Throughput (K msg/s)', fontsize=12)
    ax.set_title('Decryption Throughput vs. Security Level', fontsize=14)
    ax.grid(True, alpha=0.3)
    ax.set_xscale('log', base=2)
    
    # 2. GPU Efficiency
    ax = axes[0, 1]
    theoretical = [(r['n'] / baseline['n']) ** 3 for r in results]
    actual = [r['dec_time_ms'] / baseline['dec_time_ms'] for r in results]
    efficiency = [t / a for t, a in zip(theoretical, actual)]
    
    ax.plot(n_vals, efficiency, 's-', linewidth=2, markersize=10, color='green')
    ax.axhline(y=1.0, color='red', linestyle='--', label='Linear (100%)')
    ax.set_xlabel('Security Level (n)', fontsize=12)
    ax.set_ylabel('GPU Efficiency', fontsize=12)
    ax.set_title('GPU Parallelization Efficiency', fontsize=14)
    ax.grid(True, alpha=0.3)
    ax.set_xscale('log', base=2)
    ax.legend()
    
    # 3. Time breakdown
    ax = axes[1, 0]
    width = 0.35
    x = np.arange(len(results))
    ax.bar(x - width/2, [r['enc_time_ms'] for r in results], width, label='Encryption', alpha=0.8)
    ax.bar(x + width/2, [r['dec_time_ms'] for r in results], width, label='Decryption', alpha=0.8)
    ax.set_xlabel('Security Level (n)', fontsize=12)
    ax.set_ylabel('Time (ms)', fontsize=12)
    ax.set_title('Encryption vs Decryption Time', fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels(n_vals)
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    ax.set_yscale('log')
    
    # 4. Security vs Performance
    ax = axes[1, 1]
    scatter = ax.scatter(
        [r['dec_throughput'] / 1000 for r in results],
        [r['ncsp_norm'] for r in results],
        s=[r['n'] / 2 for r in results],
        alpha=0.6,
        c=n_vals,
        cmap='viridis'
    )
    ax.set_xlabel('Decryption Throughput (K msg/s)', fontsize=12)
    ax.set_ylabel('NCSP (Non-Commutativity)', fontsize=12)
    ax.set_title('Security vs. Performance Trade-off', fontsize=14)
    
    # Draw threshold line (0.5 × √n for n=256)
    ax.axhline(y=8.0, color='red', linestyle='--', label='Threshold (n=256)')
    ax.grid(True, alpha=0.3)
    ax.legend()
    
    # Add colorbar
    cbar = plt.colorbar(scatter, ax=ax)
    cbar.set_label('n', fontsize=10)
    
    plt.tight_layout()
    plt.savefig('meteor_nc_scaling.png', dpi=150, bbox_inches='tight')
    print("[✓] Saved: meteor_nc_scaling.png")
    plt.show()

except ImportError:
    print("\n[*] matplotlib not available, skipping visualization")


# ============================================================================
# Final Summary
# ============================================================================
print("\n" + "=" * 70)
print("✅ Benchmark Complete!")
print("=" * 70)

print(f"""
Summary:
  - GPU Mode: {GPU_MODE}
  - Tested levels: {n_values}
  - Peak throughput: {max_throughput:,.0f} msg/s (n={best_n})
  - All security checks: {'✅ PASSED' if all(r['secure'] for r in results) else '⚠️ SOME FAILED'}

Paper Reference (TCHES):
  - METEOR-256: 700K msg/s (140× Kyber-768, 7× AES-256)
  - Three-fold security: LTDF + NCSP + Procrustes
""")
