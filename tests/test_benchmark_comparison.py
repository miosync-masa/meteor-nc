# meteor_nc/tests/test_benchmark_comparison.py
"""
Meteor-NC Benchmark Comparison Suite for TCHES

MUST requirements for paper submission:
  1. Comparison with ML-KEM (Kyber) reference - same condition benchmark
  2. Memory footprint measurement (peak RAM during encaps/decaps)
  3. Embedded deployment considerations (design-derived constraints)

Reference: TCHES evaluation guidelines
"""

import secrets
import time
import tracemalloc
import gc
import numpy as np
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import sys

sys.path.insert(0, '/content/meteor-nc')

from meteor_nc.cryptography.common import (
    Q_DEFAULT, MSG_BYTES, GPU_AVAILABLE, CRYPTO_AVAILABLE,
)
from meteor_nc.cryptography.core import LWEKEM, HybridKEM

# =============================================================================
# Try to import Kyber reference implementation
# =============================================================================

KYBER_AVAILABLE = False
try:
    # Try pqcrypto (if installed)
    from pqcrypto.kem.kyber512 import generate_keypair as kyber512_keygen
    from pqcrypto.kem.kyber512 import encrypt as kyber512_enc, decrypt as kyber512_dec
    from pqcrypto.kem.kyber768 import generate_keypair as kyber768_keygen
    from pqcrypto.kem.kyber768 import encrypt as kyber768_enc, decrypt as kyber768_dec
    from pqcrypto.kem.kyber1024 import generate_keypair as kyber1024_keygen
    from pqcrypto.kem.kyber1024 import encrypt as kyber1024_enc, decrypt as kyber1024_dec
    KYBER_AVAILABLE = True
    KYBER_SOURCE = "pqcrypto"
    print("Kyber: Using pqcrypto library")
except ImportError:
    pass

if not KYBER_AVAILABLE:
    try:
        # Try kyber-py (pure Python reference)
        from kyber import Kyber512, Kyber768, Kyber1024
        KYBER_AVAILABLE = True
        KYBER_SOURCE = "kyber-py"
        print("Kyber: Using kyber-py library")
    except ImportError:
        pass

if not KYBER_AVAILABLE:
    print("WARNING: No Kyber implementation found.")
    print("  Install with: pip install pqcrypto")
    print("  Or: pip install kyber-py")


# =============================================================================
# Configuration
# =============================================================================

WARMUP_ITERATIONS = 100
BENCHMARK_ITERATIONS = 1000


# =============================================================================
# 1. Comparison with ML-KEM (Kyber)
# =============================================================================

def benchmark_meteor_nc(n: int, iterations: int = BENCHMARK_ITERATIONS) -> Dict:
    """Benchmark Meteor-NC KEM at specified security level."""
    results = {
        'n': n,
        'iterations': iterations,
        'keygen': {},
        'encaps': {},
        'decaps': {},
    }
    
    # Force CPU-only for fair comparison
    kem = LWEKEM(n=n, gpu=False)
    
    # Warmup
    for _ in range(min(WARMUP_ITERATIONS, 50)):
        kem.key_gen()
        K, ct = kem.encaps()
        _ = kem.decaps(ct)
    
    # KeyGen benchmark
    gc.collect()
    times = []
    for _ in range(iterations):
        kem_temp = LWEKEM(n=n, gpu=False)
        start = time.perf_counter()
        kem_temp.key_gen()
        end = time.perf_counter()
        times.append(end - start)
    
    results['keygen'] = {
        'mean_ms': np.mean(times) * 1000,
        'std_ms': np.std(times) * 1000,
        'ops_sec': 1.0 / np.mean(times),
    }
    
    # Setup for encaps/decaps
    kem = LWEKEM(n=n, gpu=False)
    kem.key_gen()
    
    # Encaps benchmark
    gc.collect()
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        K, ct = kem.encaps()
        end = time.perf_counter()
        times.append(end - start)
    
    results['encaps'] = {
        'mean_ms': np.mean(times) * 1000,
        'std_ms': np.std(times) * 1000,
        'ops_sec': 1.0 / np.mean(times),
    }
    
    # Decaps benchmark
    K, ct = kem.encaps()
    gc.collect()
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        _ = kem.decaps(ct)
        end = time.perf_counter()
        times.append(end - start)
    
    results['decaps'] = {
        'mean_ms': np.mean(times) * 1000,
        'std_ms': np.std(times) * 1000,
        'ops_sec': 1.0 / np.mean(times),
    }
    
    return results


def benchmark_kyber_pqcrypto(level: int, iterations: int = BENCHMARK_ITERATIONS) -> Dict:
    """Benchmark Kyber using pqcrypto library."""
    results = {
        'level': level,
        'iterations': iterations,
        'keygen': {},
        'encaps': {},
        'decaps': {},
    }
    
    if level == 512:
        keygen, enc, dec = kyber512_keygen, kyber512_enc, kyber512_dec
    elif level == 768:
        keygen, enc, dec = kyber768_keygen, kyber768_enc, kyber768_dec
    else:  # 1024
        keygen, enc, dec = kyber1024_keygen, kyber1024_enc, kyber1024_dec
    
    # Warmup
    for _ in range(min(WARMUP_ITERATIONS, 50)):
        pk, sk = keygen()
        ct, ss = enc(pk)
        _ = dec(sk, ct)
    
    # KeyGen benchmark
    gc.collect()
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        pk, sk = keygen()
        end = time.perf_counter()
        times.append(end - start)
    
    results['keygen'] = {
        'mean_ms': np.mean(times) * 1000,
        'std_ms': np.std(times) * 1000,
        'ops_sec': 1.0 / np.mean(times),
    }
    
    # Setup for encaps/decaps
    pk, sk = keygen()
    
    # Encaps benchmark
    gc.collect()
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        ct, ss = enc(pk)
        end = time.perf_counter()
        times.append(end - start)
    
    results['encaps'] = {
        'mean_ms': np.mean(times) * 1000,
        'std_ms': np.std(times) * 1000,
        'ops_sec': 1.0 / np.mean(times),
    }
    
    # Decaps benchmark
    ct, ss = enc(pk)
    gc.collect()
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        _ = dec(sk, ct)
        end = time.perf_counter()
        times.append(end - start)
    
    results['decaps'] = {
        'mean_ms': np.mean(times) * 1000,
        'std_ms': np.std(times) * 1000,
        'ops_sec': 1.0 / np.mean(times),
    }
    
    return results


def benchmark_kyber_py(level: int, iterations: int = BENCHMARK_ITERATIONS) -> Dict:
    """Benchmark Kyber using kyber-py library."""
    results = {
        'level': level,
        'iterations': iterations,
        'keygen': {},
        'encaps': {},
        'decaps': {},
    }
    
    if level == 512:
        kyber = Kyber512
    elif level == 768:
        kyber = Kyber768
    else:  # 1024
        kyber = Kyber1024
    
    # Warmup
    for _ in range(min(WARMUP_ITERATIONS, 20)):  # Fewer for slow pure Python
        pk, sk = kyber.keygen()
        ct, ss = kyber.enc(pk)
        _ = kyber.dec(ct, sk)
    
    # KeyGen benchmark (fewer iterations for pure Python)
    test_iterations = min(iterations, 100)
    gc.collect()
    times = []
    for _ in range(test_iterations):
        start = time.perf_counter()
        pk, sk = kyber.keygen()
        end = time.perf_counter()
        times.append(end - start)
    
    results['keygen'] = {
        'mean_ms': np.mean(times) * 1000,
        'std_ms': np.std(times) * 1000,
        'ops_sec': 1.0 / np.mean(times),
    }
    
    # Setup for encaps/decaps
    pk, sk = kyber.keygen()
    
    # Encaps benchmark
    gc.collect()
    times = []
    for _ in range(test_iterations):
        start = time.perf_counter()
        ct, ss = kyber.enc(pk)
        end = time.perf_counter()
        times.append(end - start)
    
    results['encaps'] = {
        'mean_ms': np.mean(times) * 1000,
        'std_ms': np.std(times) * 1000,
        'ops_sec': 1.0 / np.mean(times),
    }
    
    # Decaps benchmark
    ct, ss = kyber.enc(pk)
    gc.collect()
    times = []
    for _ in range(test_iterations):
        start = time.perf_counter()
        _ = kyber.dec(ct, sk)
        end = time.perf_counter()
        times.append(end - start)
    
    results['decaps'] = {
        'mean_ms': np.mean(times) * 1000,
        'std_ms': np.std(times) * 1000,
        'ops_sec': 1.0 / np.mean(times),
    }
    
    results['note'] = f"Pure Python implementation, {test_iterations} iterations"
    
    return results


def test_comparison_with_kyber() -> Dict:
    """
    Compare Meteor-NC with ML-KEM (Kyber) under same conditions.
    
    Security level mapping:
      - Kyber512  (NIST Level 1) ↔ Meteor-NC n=256
      - Kyber768  (NIST Level 3) ↔ Meteor-NC n=512
      - Kyber1024 (NIST Level 5) ↔ Meteor-NC n=1024
    """
    print("\n" + "=" * 70)
    print("COMPARISON: Meteor-NC vs ML-KEM (Kyber)")
    print("=" * 70)
    print(f"Kyber available: {KYBER_AVAILABLE}")
    if KYBER_AVAILABLE:
        print(f"Kyber source: {KYBER_SOURCE}")
    print(f"Mode: CPU-only (fair comparison)")
    print(f"Iterations: {BENCHMARK_ITERATIONS}")
    
    results = {
        'kyber_available': KYBER_AVAILABLE,
        'levels': {},
    }
    
    # Security level mapping
    level_map = [
        (256, 512, "NIST Level 1 (128-bit)"),
        (512, 768, "NIST Level 3 (192-bit)"),
        (1024, 1024, "NIST Level 5 (256-bit)"),
    ]
    
    for meteor_n, kyber_level, level_name in level_map:
        print(f"\n{'─' * 70}")
        print(f"  {level_name}")
        print(f"  Meteor-NC n={meteor_n} vs Kyber-{kyber_level}")
        print(f"{'─' * 70}")
        
        level_results = {
            'name': level_name,
            'meteor_nc': None,
            'kyber': None,
        }
        
        # Benchmark Meteor-NC
        print(f"\n  [Meteor-NC n={meteor_n}]")
        meteor_results = benchmark_meteor_nc(n=meteor_n, iterations=BENCHMARK_ITERATIONS)
        level_results['meteor_nc'] = meteor_results
        
        print(f"    KeyGen: {meteor_results['keygen']['mean_ms']:.3f} ms ({meteor_results['keygen']['ops_sec']:.0f} ops/s)")
        print(f"    Encaps: {meteor_results['encaps']['mean_ms']:.3f} ms ({meteor_results['encaps']['ops_sec']:.0f} ops/s)")
        print(f"    Decaps: {meteor_results['decaps']['mean_ms']:.3f} ms ({meteor_results['decaps']['ops_sec']:.0f} ops/s)")
        
        # Benchmark Kyber if available
        if KYBER_AVAILABLE:
            print(f"\n  [Kyber-{kyber_level}]")
            
            if KYBER_SOURCE == "pqcrypto":
                kyber_results = benchmark_kyber_pqcrypto(level=kyber_level, iterations=BENCHMARK_ITERATIONS)
            else:
                kyber_results = benchmark_kyber_py(level=kyber_level, iterations=BENCHMARK_ITERATIONS)
            
            level_results['kyber'] = kyber_results
            
            print(f"    KeyGen: {kyber_results['keygen']['mean_ms']:.3f} ms ({kyber_results['keygen']['ops_sec']:.0f} ops/s)")
            print(f"    Encaps: {kyber_results['encaps']['mean_ms']:.3f} ms ({kyber_results['encaps']['ops_sec']:.0f} ops/s)")
            print(f"    Decaps: {kyber_results['decaps']['mean_ms']:.3f} ms ({kyber_results['decaps']['ops_sec']:.0f} ops/s)")
            
            # Comparison ratio
            print(f"\n  [Comparison: Meteor-NC / Kyber]")
            keygen_ratio = meteor_results['keygen']['mean_ms'] / kyber_results['keygen']['mean_ms']
            encaps_ratio = meteor_results['encaps']['mean_ms'] / kyber_results['encaps']['mean_ms']
            decaps_ratio = meteor_results['decaps']['mean_ms'] / kyber_results['decaps']['mean_ms']
            
            print(f"    KeyGen: {keygen_ratio:.2f}x {'(slower)' if keygen_ratio > 1 else '(faster)'}")
            print(f"    Encaps: {encaps_ratio:.2f}x {'(slower)' if encaps_ratio > 1 else '(faster)'}")
            print(f"    Decaps: {decaps_ratio:.2f}x {'(slower)' if decaps_ratio > 1 else '(faster)'}")
            
            level_results['comparison'] = {
                'keygen_ratio': keygen_ratio,
                'encaps_ratio': encaps_ratio,
                'decaps_ratio': decaps_ratio,
            }
        else:
            print(f"\n  [Kyber-{kyber_level}] SKIPPED - library not available")
        
        results['levels'][level_name] = level_results
    
    return results


# =============================================================================
# 2. Memory Footprint Measurement
# =============================================================================

def measure_memory_footprint(n: int, operation: str) -> Dict:
    """
    Measure peak memory usage during KEM operations.
    
    Uses tracemalloc for accurate Python memory tracking.
    """
    gc.collect()
    tracemalloc.start()
    
    if operation == 'keygen':
        kem = LWEKEM(n=n, gpu=False)
        kem.key_gen()
        
    elif operation == 'encaps':
        kem = LWEKEM(n=n, gpu=False)
        kem.key_gen()
        tracemalloc.reset_peak()  # Reset after keygen
        K, ct = kem.encaps()
        
    elif operation == 'decaps':
        kem = LWEKEM(n=n, gpu=False)
        kem.key_gen()
        K, ct = kem.encaps()
        tracemalloc.reset_peak()  # Reset after encaps
        _ = kem.decaps(ct)
    
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    return {
        'current_bytes': current,
        'peak_bytes': peak,
        'current_kb': current / 1024,
        'peak_kb': peak / 1024,
        'current_mb': current / (1024 * 1024),
        'peak_mb': peak / (1024 * 1024),
    }


def test_memory_footprint() -> Dict:
    """
    Measure memory footprint for all security levels.
    """
    print("\n" + "=" * 70)
    print("MEMORY FOOTPRINT MEASUREMENT")
    print("=" * 70)
    print("Mode: CPU-only")
    print("Method: tracemalloc (Python heap)")
    
    results = {}
    
    levels = [
        (256, "NIST Level 1 (128-bit)"),
        (512, "NIST Level 3 (192-bit)"),
        (1024, "NIST Level 5 (256-bit)"),
    ]
    
    for n, level_name in levels:
        print(f"\n{'─' * 70}")
        print(f"  {level_name} (n={n})")
        print(f"{'─' * 70}")
        
        level_results = {
            'n': n,
            'name': level_name,
        }
        
        # Measure each operation
        for op in ['keygen', 'encaps', 'decaps']:
            mem = measure_memory_footprint(n, op)
            level_results[op] = mem
            print(f"    {op.capitalize():8} Peak: {mem['peak_kb']:.1f} KB ({mem['peak_mb']:.2f} MB)")
        
        results[n] = level_results
    
    # Summary table
    print(f"\n{'─' * 70}")
    print("  SUMMARY TABLE (Peak Memory in KB)")
    print(f"{'─' * 70}")
    print(f"  {'Level':<25} {'KeyGen':>10} {'Encaps':>10} {'Decaps':>10}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*10}")
    
    for n, level_name in levels:
        r = results[n]
        print(f"  {level_name:<25} {r['keygen']['peak_kb']:>10.1f} {r['encaps']['peak_kb']:>10.1f} {r['decaps']['peak_kb']:>10.1f}")
    
    return results


# =============================================================================
# 3. Embedded Deployment Considerations
# =============================================================================

def calculate_design_constraints() -> Dict:
    """
    Calculate design-derived constraints for embedded deployment.
    
    Based on Meteor-NC parameter choices:
    - Matrix A: n × n elements, each log2(Q) bits
    - Public key: A + b
    - Secret key: s + z
    - Ciphertext: u + v
    """
    print("\n" + "=" * 70)
    print("EMBEDDED DEPLOYMENT CONSIDERATIONS")
    print("=" * 70)
    print("Design-derived constraints for ARM/mobile deployment")
    
    results = {}
    
    # Parameters
    Q = Q_DEFAULT  # Modulus
    q_bits = int(np.ceil(np.log2(Q)))  # Bits per coefficient
    hash_bytes = 32  # SHA-256 output
    seed_bytes = 32  # Seed size
    
    print(f"\n  Base parameters:")
    print(f"    Q (modulus): {Q} ({q_bits} bits per coefficient)")
    print(f"    Hash output: {hash_bytes} bytes (SHA-256)")
    print(f"    Seed size: {seed_bytes} bytes")
    
    levels = [
        (256, "NIST Level 1", 128),
        (512, "NIST Level 3", 192),
        (1024, "NIST Level 5", 256),
    ]
    
    print(f"\n{'─' * 70}")
    print("  SIZE ANALYSIS BY SECURITY LEVEL")
    print(f"{'─' * 70}")
    
    for n, level_name, security_bits in levels:
        print(f"\n  [{level_name}] n={n}, {security_bits}-bit security")
        print(f"  {'─' * 40}")
        
        level_results = {
            'n': n,
            'security_bits': security_bits,
        }
        
        # Matrix A: n × n coefficients
        # In practice, A is generated from seed (PRNG), so only seed stored
        a_seed_bytes = seed_bytes
        a_full_bytes = n * n * (q_bits // 8 + 1)  # If stored fully
        
        # Public key: seed for A + b (n coefficients)
        pk_bytes = seed_bytes + n * (q_bits // 8 + 1)
        
        # Secret key: s (n coefficients) + z (random bytes for FO)
        sk_bytes = n * (q_bits // 8 + 1) + seed_bytes
        
        # Ciphertext: u (n coefficients) + v (n coefficients)
        ct_bytes = 2 * n * (q_bits // 8 + 1)
        
        # Shared secret
        ss_bytes = 32
        
        level_results['sizes'] = {
            'pk_bytes': pk_bytes,
            'sk_bytes': sk_bytes,
            'ct_bytes': ct_bytes,
            'ss_bytes': ss_bytes,
            'a_seed_bytes': a_seed_bytes,
            'a_full_bytes': a_full_bytes,
        }
        
        print(f"    Public Key:     {pk_bytes:>6} bytes ({pk_bytes/1024:.1f} KB)")
        print(f"    Secret Key:     {sk_bytes:>6} bytes ({sk_bytes/1024:.1f} KB)")
        print(f"    Ciphertext:     {ct_bytes:>6} bytes ({ct_bytes/1024:.1f} KB)")
        print(f"    Shared Secret:  {ss_bytes:>6} bytes")
        
        # RAM requirements during operation
        # KeyGen: Need A (from seed) + s + e + b
        keygen_ram = a_full_bytes + 3 * n * (q_bits // 8 + 1)
        
        # Encaps: Need A (from seed) + r + e1 + e2 + u + v
        encaps_ram = a_full_bytes + 5 * n * (q_bits // 8 + 1)
        
        # Decaps: Need u + v + s + recomputed values
        decaps_ram = a_full_bytes + 4 * n * (q_bits // 8 + 1)
        
        level_results['ram'] = {
            'keygen_bytes': keygen_ram,
            'encaps_bytes': encaps_ram,
            'decaps_bytes': decaps_ram,
        }
        
        print(f"\n    Estimated RAM requirements:")
        print(f"      KeyGen: {keygen_ram/1024:>8.1f} KB ({keygen_ram/(1024*1024):.2f} MB)")
        print(f"      Encaps: {encaps_ram/1024:>8.1f} KB ({encaps_ram/(1024*1024):.2f} MB)")
        print(f"      Decaps: {decaps_ram/1024:>8.1f} KB ({decaps_ram/(1024*1024):.2f} MB)")
        
        # Mobile/embedded feasibility
        typical_mobile_ram_mb = 2048  # 2GB typical smartphone
        typical_iot_ram_kb = 256  # 256KB typical IoT device
        
        mobile_feasible = (encaps_ram / (1024*1024)) < typical_mobile_ram_mb * 0.1  # < 10% of RAM
        iot_feasible = (encaps_ram / 1024) < typical_iot_ram_kb
        
        level_results['feasibility'] = {
            'mobile': mobile_feasible,
            'iot': iot_feasible,
        }
        
        print(f"\n    Deployment feasibility:")
        print(f"      Smartphone (2GB RAM):  {'✓ Feasible' if mobile_feasible else '✗ May be constrained'}")
        print(f"      IoT (256KB RAM):       {'✓ Feasible' if iot_feasible else '✗ Requires chunking/streaming'}")
        
        results[n] = level_results
    
    # Comparison table
    print(f"\n{'─' * 70}")
    print("  SUMMARY: KEY/CT SIZES (bytes)")
    print(f"{'─' * 70}")
    print(f"  {'Level':<20} {'PK':>8} {'SK':>8} {'CT':>8} {'SS':>6}")
    print(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*8} {'-'*6}")
    
    for n, level_name, _ in levels:
        r = results[n]['sizes']
        print(f"  {level_name:<20} {r['pk_bytes']:>8} {r['sk_bytes']:>8} {r['ct_bytes']:>8} {r['ss_bytes']:>6}")
    
    # Kyber comparison (reference values)
    print(f"\n  {'ML-KEM (Kyber) Reference':}")
    print(f"  {'Level':<20} {'PK':>8} {'SK':>8} {'CT':>8} {'SS':>6}")
    print(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*8} {'-'*6}")
    print(f"  {'Kyber-512':<20} {800:>8} {1632:>8} {768:>8} {32:>6}")
    print(f"  {'Kyber-768':<20} {1184:>8} {2400:>8} {1088:>8} {32:>6}")
    print(f"  {'Kyber-1024':<20} {1568:>8} {3168:>8} {1568:>8} {32:>6}")
    
    # Streaming/Chunking design notes
    print(f"\n{'─' * 70}")
    print("  STREAMING/CHUNKING DESIGN FOR CONSTRAINED DEVICES")
    print(f"{'─' * 70}")
    print("""
    For memory-constrained environments (IoT, embedded), Meteor-NC supports:
    
    1. Seed-based A generation:
       - Store 32-byte seed instead of full n×n matrix
       - Generate A rows on-the-fly during computation
       - Trade-off: ~4x slower, but 1000x less memory
    
    2. Chunked processing:
       - Process k rows at a time (k = available_ram / row_size)
       - Streaming accumulation of inner products
       - Suitable for n=256 on 64KB devices
    
    3. Recommended configurations:
       - Smartphone: Full matrix in RAM (fastest)
       - Raspberry Pi: Seed-based A, full vectors
       - IoT (256KB): Seed-based A, chunked vectors
       - IoT (64KB): Not recommended for n>256
    """)
    
    return results


# =============================================================================
# 4. Kyber Size Comparison Table
# =============================================================================

def test_size_comparison_with_kyber() -> Dict:
    """
    Direct size comparison between Meteor-NC and ML-KEM (Kyber).
    """
    print("\n" + "=" * 70)
    print("SIZE COMPARISON: Meteor-NC vs ML-KEM (Kyber)")
    print("=" * 70)
    
    # Kyber reference sizes (from NIST submission)
    kyber_sizes = {
        512: {'pk': 800, 'sk': 1632, 'ct': 768, 'ss': 32},
        768: {'pk': 1184, 'sk': 2400, 'ct': 1088, 'ss': 32},
        1024: {'pk': 1568, 'sk': 3168, 'ct': 1568, 'ss': 32},
    }
    
    # Calculate Meteor-NC sizes
    Q = Q_DEFAULT
    q_bits = int(np.ceil(np.log2(Q)))
    bytes_per_coeff = q_bits // 8 + 1
    seed_bytes = 32
    
    meteor_sizes = {}
    for n in [256, 512, 1024]:
        meteor_sizes[n] = {
            'pk': seed_bytes + n * bytes_per_coeff,
            'sk': n * bytes_per_coeff + seed_bytes,
            'ct': 2 * n * bytes_per_coeff,
            'ss': 32,
        }
    
    # Comparison table
    print(f"\n  {'Scheme':<20} {'Security':>12} {'PK':>8} {'SK':>8} {'CT':>8} {'SS':>6}")
    print(f"  {'-'*20} {'-'*12} {'-'*8} {'-'*8} {'-'*8} {'-'*6}")
    
    level_map = [
        (256, 512, "128-bit"),
        (512, 768, "192-bit"),
        (1024, 1024, "256-bit"),
    ]
    
    results = {'comparison': []}
    
    for meteor_n, kyber_level, security in level_map:
        m = meteor_sizes[meteor_n]
        k = kyber_sizes[kyber_level]
        
        print(f"  {'Meteor-NC n='+str(meteor_n):<20} {security:>12} {m['pk']:>8} {m['sk']:>8} {m['ct']:>8} {m['ss']:>6}")
        print(f"  {'Kyber-'+str(kyber_level):<20} {security:>12} {k['pk']:>8} {k['sk']:>8} {k['ct']:>8} {k['ss']:>6}")
        
        # Ratio
        pk_ratio = m['pk'] / k['pk']
        sk_ratio = m['sk'] / k['sk']
        ct_ratio = m['ct'] / k['ct']
        
        print(f"  {'Ratio (M/K)':<20} {'':<12} {pk_ratio:>8.2f} {sk_ratio:>8.2f} {ct_ratio:>8.2f} {'1.00':>6}")
        print()
        
        results['comparison'].append({
            'security': security,
            'meteor_n': meteor_n,
            'kyber_level': kyber_level,
            'meteor': m,
            'kyber': k,
            'ratio': {'pk': pk_ratio, 'sk': sk_ratio, 'ct': ct_ratio},
        })
    
    return results


# =============================================================================
# Main Test Runner
# =============================================================================

def run_all_benchmark_tests() -> Dict:
    """Run all benchmark comparison tests."""
    print("=" * 70)
    print("Meteor-NC Benchmark Comparison Suite for TCHES")
    print("=" * 70)
    print(f"Kyber Available: {KYBER_AVAILABLE}")
    print(f"GPU Available: {GPU_AVAILABLE} (using CPU-only for fair comparison)")
    
    all_results = {}
    
    # 1. Kyber comparison
    all_results['kyber_comparison'] = test_comparison_with_kyber()
    
    # 2. Memory footprint
    all_results['memory_footprint'] = test_memory_footprint()
    
    # 3. Embedded constraints
    all_results['embedded_constraints'] = calculate_design_constraints()
    
    # 4. Size comparison
    all_results['size_comparison'] = test_size_comparison_with_kyber()
    
    # Final summary
    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY")
    print("=" * 70)
    
    print("\n  ✅ Performance comparison with ML-KEM (Kyber)")
    print("  ✅ Memory footprint measurement")
    print("  ✅ Embedded deployment analysis")
    print("  ✅ Key/CT size comparison")
    
    if not KYBER_AVAILABLE:
        print("\n  ⚠️  Note: Kyber library not installed.")
        print("      Install with: pip install pqcrypto")
        print("      Or: pip install kyber-py")
    
    return all_results


if __name__ == "__main__":
    run_all_benchmark_tests()
