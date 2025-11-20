# ============================================================================
# Meteor-NC: GPU Scaling Benchmark
# Run this in Google Colab with A100 GPU
# ============================================================================

# Cell 1: Setup
# ============================================================================
print("="*70)
print("Meteor-NC: GPU Scaling Benchmark Setup")
print("="*70)

# Check GPU
!nvidia-smi

# Install dependencies
print("\n[*] Installing dependencies...")
!pip install cupy-cuda12x -q

# Clone repository
print("\n[*] Cloning Meteor-NC repository...")
!git clone https://github.com/miosync-masa/meteor-nc.git
%cd meteor-nc

print("\n✅ Setup complete!")

# Cell 2: Quick Test (n=256 baseline)
# ============================================================================
print("\n" + "="*70)
print("Quick Test: n=256 (Baseline)")
print("="*70)

from meteor_nc_gpu2 import MeteorNC_GPU, check_gpu_available
import numpy as np

# Check GPU
if not check_gpu_available():
    raise RuntimeError("GPU not available!")

# Test n=256
crypto = MeteorNC_GPU(n=256, m=10)
crypto.key_gen(verbose=True)

# Quick benchmark
messages = np.random.randn(5000, 256)
ciphertexts = crypto.encrypt_batch(messages)

# Warmup
for _ in range(3):
    _ = crypto.decrypt_batch(ciphertexts[:100])

# Benchmark
recovered, dec_time = crypto.decrypt_batch(ciphertexts)
throughput = 5000 / dec_time

print(f"\n[Results]")
print(f"Decryption: {dec_time*1000:.2f}ms")
print(f"Throughput: {throughput:,.0f} msg/s")

error = np.linalg.norm(messages - recovered) / np.linalg.norm(messages)
print(f"Error: {error:.2e}")

# Security
security = crypto.verify_security(verbose=True)

crypto.cleanup()

# Cell 3: Full Scaling Benchmark
# ============================================================================
print("\n" + "="*70)
print("Full Scaling Benchmark: n ∈ {128, 256, 512, 1024}")
print("="*70)

import time
from meteor_nc_gpu2 import MeteorNC_GPU
import numpy as np

def benchmark_n_value(n, batch_size=1000):
    """Benchmark single n value"""
    print(f"\n{'='*70}")
    print(f"Testing n={n} (Security: {n}-bit)")
    print(f"{'='*70}")
    
    # Adjust m
    m = max(8, n // 32 + 2)
    
    # Create instance
    crypto = MeteorNC_GPU(n=n, m=m)
    
    # Key generation
    print(f"[*] Generating keys...")
    keygen_time = crypto.key_gen(verbose=False)
    print(f"    Key generation: {keygen_time:.3f}s")
    
    # Prepare data
    messages = np.random.randn(batch_size, n)
    
    # Warmup
    print(f"[*] Warming up...")
    for _ in range(3):
        _ = crypto.encrypt_batch(messages[:min(100, batch_size)])
        _ = crypto.decrypt_batch(crypto.encrypt_batch(messages[:min(100, batch_size)]))
    
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
        'm': m,
        'keygen_time': keygen_time,
        'enc_time_ms': enc_time * 1000,
        'dec_time_ms': dec_time * 1000,
        'enc_throughput': enc_throughput,
        'dec_throughput': dec_throughput,
        'error': error,
        'cp_norm': security['cp_commutator_norm'],
        'secure': security['secure']
    }
    
    # Print summary
    print(f"\n[Summary]")
    print(f"  Encryption:  {enc_time*1000:>7.2f}ms → {enc_throughput:>10,.0f} msg/s")
    print(f"  Decryption:  {dec_time*1000:>7.2f}ms → {dec_throughput:>10,.0f} msg/s")
    print(f"  Error:       {error:.2e}")
    print(f"  Security:    Λ-CP={security['cp_commutator_norm']:.1f} {'✅' if security['secure'] else '❌'}")
    
    # Cleanup
    crypto.cleanup()
    
    return result

# Run benchmarks
n_values = [128, 256, 512, 1024]
results = []

for n in n_values:
    result = benchmark_n_value(n, batch_size=1000)
    results.append(result)

# Cell 4: Results Analysis
# ============================================================================
print("\n" + "="*70)
print("SCALING RESULTS")
print("="*70)

import pandas as pd

# Create DataFrame
df = pd.DataFrame(results)

# Display table
print(f"\n{'n':<8} {'m':<6} {'KeyGen (s)':<12} {'Enc (ms)':<10} {'Dec (ms)':<10} "
      f"{'Dec Throughput':<16} {'Λ-CP':<8} {'Secure':<8}")
print("-"*70)

for _, row in df.iterrows():
    print(f"{row['n']:<8} {row['m']:<6} {row['keygen_time']:>10.2f}  "
          f"{row['enc_time_ms']:>8.2f}  {row['dec_time_ms']:>8.2f}  "
          f"{row['dec_throughput']:>14,.0f}  "
          f"{row['cp_norm']:>6.1f}  {'✅' if row['secure'] else '❌'}")

# Efficiency analysis
print("\n" + "="*70)
print("EFFICIENCY ANALYSIS")
print("="*70)

baseline = results[0]  # n=128
print(f"\n{'n':<8} {'Theoretical':<15} {'Actual Dec':<15} {'GPU Efficiency':<15}")
print("-"*70)

for r in results:
    theoretical = (r['n'] / baseline['n']) ** 3
    actual = r['dec_time_ms'] / baseline['dec_time_ms']
    efficiency = theoretical / actual
    
    print(f"{r['n']:<8} {theoretical:>13.1f}×  {actual:>13.1f}×  {efficiency:>13.1%}")

# Speedup visualization
print("\n" + "="*70)
print("KEY FINDINGS")
print("="*70)

max_throughput = max(r['dec_throughput'] for r in results)
best_n = next(r['n'] for r in results if r['dec_throughput'] == max_throughput)

print(f"\n🏆 Peak Throughput: {max_throughput:,.0f} msg/s at n={best_n}")

# AES comparison
aes_throughput = 100000  # msg/s
for r in results:
    speedup = r['dec_throughput'] / aes_throughput
    print(f"   n={r['n']:4d}: {speedup:>5.1f}× faster than AES-256")

# Cell 5: Optional - Visualization
# ============================================================================
print("\n[*] Creating visualizations...")

import matplotlib.pyplot as plt

fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# 1. Throughput vs n
ax = axes[0, 0]
ax.plot(df['n'], df['dec_throughput'] / 1000, 'o-', linewidth=2, markersize=10)
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

ax.plot(df['n'], efficiency, 's-', linewidth=2, markersize=10, color='green')
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
ax.bar(x - width/2, df['enc_time_ms'], width, label='Encryption', alpha=0.8)
ax.bar(x + width/2, df['dec_time_ms'], width, label='Decryption', alpha=0.8)
ax.set_xlabel('Security Level (n)', fontsize=12)
ax.set_ylabel('Time (ms)', fontsize=12)
ax.set_title('Encryption vs Decryption Time', fontsize=14)
ax.set_xticks(x)
ax.set_xticklabels([r['n'] for r in results])
ax.legend()
ax.grid(True, alpha=0.3, axis='y')
ax.set_yscale('log')

# 4. Security vs Performance
ax = axes[1, 1]
scatter = ax.scatter(df['dec_throughput'] / 1000, df['cp_norm'], 
                     s=df['n']/2, alpha=0.6, c=df['n'], cmap='viridis')
ax.set_xlabel('Decryption Throughput (K msg/s)', fontsize=12)
ax.set_ylabel('Non-commutativity (Λ-CP)', fontsize=12)
ax.set_title('Security vs. Performance Trade-off', fontsize=14)
ax.axhline(y=8.0, color='red', linestyle='--', label='Security Threshold')
ax.grid(True, alpha=0.3)
ax.legend()

# Add colorbar
cbar = plt.colorbar(scatter, ax=ax)
cbar.set_label('n', fontsize=10)

plt.tight_layout()
plt.savefig('meteor_nc_scaling.png', dpi=150, bbox_inches='tight')
print("[✓] Saved: meteor_nc_scaling.png")
plt.show()

print("\n" + "="*70)
print("✅ Benchmark Complete!")
print("="*70)
