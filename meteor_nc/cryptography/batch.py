# meteor_nc/cryptography/batch.py
"""
Meteor-NC Batch KEM

GPU-parallel batch encapsulation/decapsulation for high-throughput servers.
Requires CuPy + CUDA.

Features:
- GPU-native CBD sampling (splitmix64)
- GPU-accelerated BLAKE3 hashing (no Python loops)
- Implicit rejection with branchless selection
"""

from __future__ import annotations

import os
import secrets
from typing import Optional, Tuple

import numpy as np

from .common import (
    HKDF,
    Q_DEFAULT,
    MSG_BYTES,
    MSG_BITS,
    GPU_AVAILABLE,
    _sha256,
)

if not GPU_AVAILABLE:
    raise ImportError("BatchKEM requires CuPy + CUDA")

import cupy as cp

from .kernels.blake3_kernel import GPUBlake3


# =============================================================================
# GPU-Native CBD Kernel (splitmix64)
# =============================================================================

_CBD_KERNEL = cp.RawKernel(r'''
extern "C" __global__
void cbd_from_seeds(
    const unsigned long long* __restrict__ seeds,
    long long* __restrict__ out,
    const int dim,
    const int batch,
    const int eta,
    const unsigned long long stride_seed
) {
    int tid = (int)(blockDim.x * blockIdx.x + threadIdx.x);
    int total = dim * batch;
    if (tid >= total) return;

    int i = tid % dim;
    int b = tid / dim;

    // splitmix64 (statistically excellent)
    unsigned long long x = seeds[b] + (unsigned long long)i * stride_seed;
    x += 0x9e3779b97f4a7c15ULL;
    unsigned long long z = x;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    z = z ^ (z >> 31);

    int a = 0, c = 0;
    for (int t = 0; t < eta; t++) {
        a += (int)((z >> t) & 1ULL);
        c += (int)((z >> (t + eta)) & 1ULL);
    }
    out[tid] = (long long)(a - c);
}
''', 'cbd_from_seeds')

_STRIDE_SEED = np.uint64(0xD1B54A32D192ED03)


def _cbd_from_seeds(seeds: cp.ndarray, dim: int, eta: int) -> cp.ndarray:
    """
    Generate CBD samples on GPU.
    
    Args:
        seeds: (batch,) uint64
        dim: output dimension
        eta: CBD parameter
        
    Returns:
        (dim, batch) int64
    """
    batch = int(seeds.size)
    total = dim * batch
    out = cp.empty(total, dtype=cp.int64)
    
    threads = 256
    blocks = (total + threads - 1) // threads
    
    _CBD_KERNEL(
        (blocks,), (threads,),
        (seeds, out, dim, batch, eta, _STRIDE_SEED)
    )
    
    return out.reshape((batch, dim)).T  # (dim, batch)


# =============================================================================
# Batch LWE-KEM with GPU BLAKE3
# =============================================================================

class BatchLWEKEM:
    """
    GPU-parallel batch KEM with Fujisaki-Okamoto transform.
    
    All hash operations run on GPU via BLAKE3.
    No Python loops in hot path.
    
    Target: 1M+ ops/sec
    """
    
    def __init__(
        self,
        n: int = 256,
        k: Optional[int] = None,
        q: int = Q_DEFAULT,
        eta: int = 2,
        device_id: int = 0,
    ):
        cp.cuda.Device(device_id).use()
        
        self.n = int(n)
        self.k = int(k if k is not None else n)
        self.q = int(q)
        self.eta = int(eta)
        self.device_id = device_id
        
        self.delta = q // 2
        
        # GPU BLAKE3 hasher
        self._blake3 = GPUBlake3(device_id=device_id)
        
        # Keys (initialized by key_gen)
        self.A: Optional[cp.ndarray] = None
        self.b: Optional[cp.ndarray] = None
        self.s: Optional[cp.ndarray] = None
        self.z: Optional[bytes] = None
        self.pk_hash: Optional[bytes] = None
        self.pk_hash_gpu: Optional[cp.ndarray] = None
    
    def key_gen(self, seed: Optional[bytes] = None) -> None:
        """Generate LWE key pair."""
        seed = seed or secrets.token_bytes(32)
        hkdf = HKDF(salt=_sha256(b"batch-kem-v2"))
        prk = hkdf.extract(seed)
        
        # Public matrix A
        seed_A = int.from_bytes(hkdf.expand(prk, b"A", 8), "big")
        cp.random.seed(seed_A & 0xFFFFFFFF)
        self.A = cp.random.randint(0, self.q, (self.k, self.n), dtype=cp.int64)
        
        # Secret vector s (CBD via GPU)
        seed_s = np.array([int.from_bytes(hkdf.expand(prk, b"s", 8), "big")], dtype=np.uint64)
        seed_s_gpu = cp.asarray(seed_s, dtype=cp.uint64)
        self.s = _cbd_from_seeds(seed_s_gpu, self.n, self.eta).flatten()
        
        # Error vector e (CBD via GPU)
        seed_e = np.array([int.from_bytes(hkdf.expand(prk, b"e", 8), "big")], dtype=np.uint64)
        seed_e_gpu = cp.asarray(seed_e, dtype=cp.uint64)
        e = _cbd_from_seeds(seed_e_gpu, self.k, self.eta).flatten()
        
        # Public key b = As + e mod q
        self.b = (self.A @ self.s + e) % self.q
        
        # FO transform helpers
        pk_bytes = cp.asnumpy(self.A).tobytes() + cp.asnumpy(self.b).tobytes()
        self.pk_hash = _sha256(b"pk", pk_bytes)
        self.pk_hash_gpu = cp.asarray(np.frombuffer(self.pk_hash, dtype=np.uint8))
        
        # Implicit rejection seed
        self.z = hkdf.expand(prk, b"z", 32)
    
    def encaps_batch(self, batch: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Batch KEM encapsulation.
        
        All operations GPU-accelerated. No Python loops.
        
        Args:
            batch: Number of encapsulations
            
        Returns:
            K: (batch, 32) shared secrets
            U: (batch, n) ciphertext component
            V: (batch, MSG_BITS) ciphertext component
        """
        if self.A is None:
            raise ValueError("Keys not initialized. Call key_gen() first.")
        
        # 1. Generate random messages (CPU, cryptographically secure)
        M_bytes = os.urandom(MSG_BYTES * batch)
        M_gpu = cp.asarray(
            np.frombuffer(M_bytes, dtype=np.uint8).reshape(batch, MSG_BYTES)
        )
        
        # 2. Derive FO seeds via GPU BLAKE3 (NO PYTHON LOOP!)
        seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(
            M_gpu, self.pk_hash
        )
        
        # 3. CBD samples (GPU parallel)
        R = _cbd_from_seeds(seeds_r, self.k, self.eta)        # (k, batch)
        E1 = _cbd_from_seeds(seeds_e1, self.n, self.eta)      # (n, batch)
        E2 = _cbd_from_seeds(seeds_e2, MSG_BITS, self.eta)    # (MSG_BITS, batch)
        
        # 4. Encode messages
        M_np = np.frombuffer(M_bytes, dtype=np.uint8).reshape(batch, MSG_BYTES)
        M_bits_np = np.unpackbits(M_np, axis=1)  # (batch, MSG_BITS) on CPU
        M_bits = cp.asarray(M_bits_np, dtype=cp.int64)
        M_encoded = M_bits * self.delta
        
        # 5. GPU matrix operations
        U = (self.A.T @ R + E1) % self.q                      # (n, batch)
        B_dot_R = self.b @ R                                   # (batch,)
        V = (B_dot_R[None, :] + E2 + M_encoded.T) % self.q    # (MSG_BITS, batch)
        
        # 6. Compute ciphertext hashes for key derivation (GPU)
        U_t = U.T  # (batch, n)
        V_t = V.T  # (batch, MSG_BITS)
        
        # Hash U||V for each ciphertext
        # We need to compute H(U||V) for key derivation
        # For now, use first 32 bytes of U as proxy (simplified)
        # TODO: Full ct_hash if needed
        ct_hash_proxy = cp.ascontiguousarray(U_t[:, :32].astype(cp.uint8))
        
        # 7. Derive shared keys via GPU BLAKE3 (NO PYTHON LOOP!)
        # For encaps, all are "good" keys
        ok_mask = cp.ones(batch, dtype=cp.uint8)
        K_gpu = self._blake3.derive_keys_batch(
            M_gpu,
            ct_hash_proxy,
            self.z,
            ok_mask,
        )
        
        # 8. Transfer results to CPU
        K = cp.asnumpy(K_gpu)
        U_np = cp.asnumpy(U_t).astype(np.int64)
        V_np = cp.asnumpy(V_t).astype(np.int64)
        
        return K, U_np, V_np
    
    def decaps_batch(
        self,
        U: np.ndarray,
        V: np.ndarray,
    ) -> np.ndarray:
        """
        Batch KEM decapsulation with implicit rejection.
        
        All operations GPU-accelerated. No Python loops.
        
        Args:
            U: (batch, n) ciphertext component
            V: (batch, MSG_BITS) ciphertext component
            
        Returns:
            K: (batch, 32) shared secrets
        """
        if self.A is None or self.s is None:
            raise ValueError("Keys not initialized. Call key_gen() first.")
        
        batch = U.shape[0]
        
        # 1. Transfer to GPU
        U_gpu = cp.asarray(U, dtype=cp.int64)  # (batch, n)
        V_gpu = cp.asarray(V, dtype=cp.int64)  # (batch, MSG_BITS)
        
        # 2. Decrypt: v - s·u mod q
        S_dot_U = U_gpu @ self.s              # (batch,)
        V_dec = (V_gpu - S_dot_U[:, None]) % self.q  # (batch, MSG_BITS)
        
        # 3. Decode message bits
        half_q = self.q // 2
        V_centered = cp.where(V_dec > half_q, V_dec - self.q, V_dec)
        threshold = self.q // 4
        M_bits = (cp.abs(V_centered) > threshold).astype(cp.uint8)  # (batch, MSG_BITS)
        
        # Pack bits to bytes
        M_bits_np = cp.asnumpy(M_bits).astype(np.uint8)
        M_recovered_np = np.packbits(M_bits_np, axis=1)  # (batch, MSG_BYTES) on CPU
        M_recovered = cp.asarray(M_recovered_np)
        
        # 4. Re-derive FO seeds via GPU BLAKE3
        seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(
            M_recovered, self.pk_hash
        )
        
        # 5. Re-encrypt (GPU parallel)
        R2 = _cbd_from_seeds(seeds_r, self.k, self.eta)
        E1_2 = _cbd_from_seeds(seeds_e1, self.n, self.eta)
        E2_2 = _cbd_from_seeds(seeds_e2, MSG_BITS, self.eta)
        
        M_encoded = M_bits.astype(cp.int64) * self.delta
        
        U2 = (self.A.T @ R2 + E1_2) % self.q
        B_dot_R2 = self.b @ R2
        V2 = (B_dot_R2[None, :] + E2_2 + M_encoded.T) % self.q
        
        # 6. FO verification (GPU, branchless)
        U_match = cp.all(U_gpu == U2.T, axis=1)
        V_match = cp.all(V_gpu == V2.T, axis=1)
        ok_mask = (U_match & V_match).astype(cp.uint8)
        
        # 7. Compute ciphertext hash proxy
        ct_hash_proxy = cp.ascontiguousarray(U_gpu[:, :32].astype(cp.uint8))
        
        # 8. Derive keys with implicit rejection (GPU BLAKE3)
        K_gpu = self._blake3.derive_keys_batch(
            M_recovered,
            ct_hash_proxy,
            self.z,
            ok_mask,
        )
        
        return cp.asnumpy(K_gpu)


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute batch KEM tests with GPU BLAKE3."""
    print("=" * 70)
    print("Meteor-NC Batch KEM Test Suite (GPU BLAKE3)")
    print("=" * 70)
    
    import time
    
    results = {}
    
    # Test 1: Basic functionality
    print("\n[Test 1] Batch Encaps/Decaps")
    print("-" * 40)
    
    kem = BatchLWEKEM(n=256)
    kem.key_gen()
    
    batch_sizes = [1, 10, 100, 1000]
    
    for bs in batch_sizes:
        K_enc, U, V = kem.encaps_batch(bs)
        K_dec = kem.decaps_batch(U, V)
        
        match = np.all(K_enc == K_dec)
        print(f"  Batch {bs:4d}: {'PASS' if match else 'FAIL'}")
        results[f"batch_{bs}"] = match
    
    # Test 2: Implicit rejection
    print("\n[Test 2] Implicit Rejection")
    print("-" * 40)
    
    K_enc, U, V = kem.encaps_batch(10)
    
    U_bad = U.copy()
    U_bad[0, 0] ^= 1  # Corrupt first ciphertext
    
    K_dec_bad = kem.decaps_batch(U_bad, V)
    
    first_differs = not np.array_equal(K_enc[0], K_dec_bad[0])
    rest_match = np.all(K_enc[1:] == K_dec_bad[1:])
    
    rejection_ok = first_differs and rest_match
    results["rejection"] = rejection_ok
    print(f"  Corrupted ciphertext rejected: {'PASS' if rejection_ok else 'FAIL'}")
    
    # Test 3: Determinism
    print("\n[Test 3] Seed Determinism")
    print("-" * 40)
    
    seed = secrets.token_bytes(32)
    kem1 = BatchLWEKEM(n=256)
    kem1.key_gen(seed=seed)
    kem2 = BatchLWEKEM(n=256)
    kem2.key_gen(seed=seed)
    
    A_match = cp.array_equal(kem1.A, kem2.A)
    results["determinism"] = bool(A_match)
    print(f"  Deterministic keygen: {'PASS' if A_match else 'FAIL'}")
    
    # Test 4: Throughput benchmark
    print("\n[Test 4] Throughput Benchmark (GPU BLAKE3)")
    print("-" * 40)
    
    kem = BatchLWEKEM(n=256)
    kem.key_gen()
    
    # Warmup
    _ = kem.encaps_batch(100)
    cp.cuda.Stream.null.synchronize()
    
    # Benchmark different batch sizes
    for batch in [1000, 10000, 100000]:
        # Encaps
        start = time.perf_counter()
        K, U, V = kem.encaps_batch(batch)
        cp.cuda.Stream.null.synchronize()
        enc_time = time.perf_counter() - start
        
        # Decaps
        start = time.perf_counter()
        _ = kem.decaps_batch(U, V)
        cp.cuda.Stream.null.synchronize()
        dec_time = time.perf_counter() - start
        
        enc_rate = batch / enc_time
        dec_rate = batch / dec_time
        
        print(f"  Batch {batch:>6,}:")
        print(f"    Encaps: {enc_rate:>10,.0f} ops/sec ({enc_time*1000:>6.1f} ms)")
        print(f"    Decaps: {dec_rate:>10,.0f} ops/sec ({dec_time*1000:>6.1f} ms)")
    
    # Test 5: Million ops target
    print("\n[Test 5] Million Ops Target")
    print("-" * 40)
    
    batch = 1000000
    print(f"  Testing {batch:,} encapsulations...")
    
    start = time.perf_counter()
    K, U, V = kem.encaps_batch(batch)
    cp.cuda.Stream.null.synchronize()
    enc_time = time.perf_counter() - start
    
    enc_rate = batch / enc_time
    target_met = enc_rate >= 1_000_000
    results["million_target"] = target_met
    
    print(f"  Rate: {enc_rate:,.0f} ops/sec")
    print(f"  Target (1M ops/sec): {'ACHIEVED!' if target_met else 'Not yet'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
