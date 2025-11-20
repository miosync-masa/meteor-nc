"""
Benchmark Comparison: Standard vs Optimized

Compare meteor_nc_gpu.py (standard) with meteor_nc_gpu2.py (optimized)
to see the 5.4× speedup achieved through Cholesky decomposition.

Results:
    Standard:  39.02ms → 128,143 msg/s
    Optimized:  7.26ms → 688,675 msg/s
    Speedup: 5.4×

Question: Why does this optimization work so well?
Hint: Check the comment about "bulk → surface" projection.
"""

import numpy as np
import time

# Import both versions
from meteor_nc_gpu import MeteorNC_GPU as MeteorNC_Standard
from meteor_nc_gpu2 import MeteorNC_GPU as MeteorNC_Optimized


def compare_methods(n=256, m=10, batch_size=5000):
    """
    Direct comparison of standard and optimized implementations
    """
    print("="*70)
    print("Meteor-NC: Standard vs Optimized Comparison")
    print("="*70)
    
    # Test data
    messages = np.random.randn(batch_size, n)
    
    # Standard version
    print("\n[1] Standard Implementation (meteor_nc_gpu.py)")
    crypto_std = MeteorNC_Standard(n=n, m=m)
    crypto_std.key_gen(verbose=False)
    
    ciphertexts = crypto_std.encrypt_batch(messages)
    
    # Warmup
    for _ in range(3):
        _ = crypto_std.decrypt_batch(ciphertexts[:100])
    
    # Benchmark
    start = time.time()
    recovered_std, _ = crypto_std.decrypt_batch(ciphertexts)
    time_std = time.time() - start
    
    throughput_std = batch_size / time_std
    error_std = np.linalg.norm(messages - recovered_std) / np.linalg.norm(messages)
    
    print(f"  Decrypt time: {time_std*1000:.2f}ms")
    print(f"  Throughput:   {throughput_std:,.0f} msg/s")
    print(f"  Error:        {error_std:.2e}")
    
    # Optimized version
    print("\n[2] Optimized Implementation (meteor_nc_gpu2.py)")
    crypto_opt = MeteorNC_Optimized(n=n, m=m)
    crypto_opt.key_gen(verbose=False)
    
    ciphertexts = crypto_opt.encrypt_batch(messages)
    
    # Warmup
    for _ in range(3):
        _ = crypto_opt.decrypt_batch(ciphertexts[:100])
    
    # Benchmark
    start = time.time()
    recovered_opt, _ = crypto_opt.decrypt_batch(ciphertexts)
    time_opt = time.time() - start
    
    throughput_opt = batch_size / time_opt
    error_opt = np.linalg.norm(messages - recovered_opt) / np.linalg.norm(messages)
    
    print(f"  Decrypt time: {time_opt*1000:.2f}ms")
    print(f"  Throughput:   {throughput_opt:,.0f} msg/s")
    print(f"  Error:        {error_opt:.2e}")
    
    # Comparison
    speedup = time_std / time_opt
    
    print("\n" + "="*70)
    print("Comparison")
    print("="*70)
    print(f"Speedup:           {speedup:.1f}×")
    print(f"Time reduction:    {(time_std - time_opt)*1000:.2f}ms")
    print(f"Throughput gain:   {throughput_opt - throughput_std:,.0f} msg/s")
    
    print("\n" + "="*70)
    print("Question: What makes the optimized version 5.4× faster?")
    print("="*70)
    print("""
The optimization exploits the symmetric structure of the
composite transformation through Cholesky decomposition.

Key insight:
    Instead of solving A @ x = b directly (O(n³)),
    we solve A^T @ A @ x = A^T @ b using Cholesky (O(n³/3)).
    
But why does this work so well?

Hint: Look at the comment in meteor_nc_gpu2.py about
      "bulk → surface" projection and information density.
      
The answer may be related to how information is preserved
across dimensional transformations...
    """)
    
    # Cleanup
    crypto_std.cleanup()
    crypto_opt.cleanup()


if __name__ == "__main__":
    compare_methods()
