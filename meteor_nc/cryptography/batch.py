# meteor_nc/cryptography/batch.py
"""
Meteor-NC Batch KEM (v2 - Optimized)

GPU-parallel batch KEM with:
- q = 2^32 (uint32 overflow = mod)
- n = k = 256 fixed (128-bit security)
- Custom CUDA kernels for GEMM
- GPU BLAKE3 for ct_hash = H(U||V)
- FO transform + implicit rejection
"""

from __future__ import annotations

import os
import secrets
from typing import Optional, Tuple

import numpy as np

from .common import (
    HKDF,
    MSG_BYTES,
    MSG_BITS,
    GPU_AVAILABLE,
    _sha256,
)

if not GPU_AVAILABLE:
    raise ImportError("BatchKEM requires CuPy + CUDA")

import cupy as cp

from .kernels.blake3_kernel import GPUBlake3
from .kernels.batch_kernels import (
    cbd_i32,
    matmul_AT_R,
    bdot_R,
    b_from_As,
    sdot_U,
    unpack_to_encoded,
    pack_bits_gpu,
)

# =============================================================================
# Constants
# =============================================================================

Q_BATCH = 2**32  # uint32 overflow = mod 2^32
N_FIXED = 256    # 128-bit security
K_FIXED = 256
ETA_DEFAULT = 2


# =============================================================================
# Batch LWE-KEM (Optimized)
# =============================================================================

class BatchLWEKEM:
    """
    GPU-parallel batch KEM.
    
    Optimized for:
    - q = 2^32 (no mod operations, uint32 wrap)
    - n = k = 256 (128-bit security, fixed for kernel optimization)
    - All hot paths in custom CUDA kernels
    
    Target: 1M+ ops/sec
    """
    
    def __init__(
        self,
        n: int = N_FIXED,
        k: int = K_FIXED,
        eta: int = ETA_DEFAULT,
        device_id: int = 0,
    ):
        if n != N_FIXED or k != K_FIXED:
            raise ValueError(f"BatchKEM optimized for n=k={N_FIXED} only")
        
        cp.cuda.Device(device_id).use()
        
        self.n = N_FIXED
        self.k = K_FIXED
        self.q = Q_BATCH
        self.eta = eta
        self.device_id = device_id
        
        self.delta = 2**31  # q // 2 for encoding
        
        # GPU BLAKE3
        self._blake3 = GPUBlake3(device_id=device_id)
        
        # Keys (initialized by key_gen)
        self.A: Optional[cp.ndarray] = None   # (k, n) uint32
        self.b: Optional[cp.ndarray] = None   # (k,) uint32
        self.s: Optional[cp.ndarray] = None   # (n,) int32
        self.z: Optional[bytes] = None
        self.pk_hash: Optional[bytes] = None
    
    def key_gen(self, seed: Optional[bytes] = None) -> None:
        """Generate LWE key pair."""
        seed = seed or secrets.token_bytes(32)
        hkdf = HKDF(salt=_sha256(b"batch-kem-v2-u32"))
        prk = hkdf.extract(seed)
        
        # Public matrix A: (k, n) uint32
        seed_A = int.from_bytes(hkdf.expand(prk, b"A", 8), "big")
        cp.random.seed(seed_A & 0xFFFFFFFF)
        self.A = cp.random.randint(0, 2**32, (self.k, self.n), dtype=cp.uint32)
        
        # Secret vector s: (n,) int32 via CBD
        seed_s = np.array([int.from_bytes(hkdf.expand(prk, b"s", 8), "big")], dtype=np.uint64)
        self.s = cbd_i32(cp.asarray(seed_s), self.n, self.eta).flatten()
        
        # Error vector e: (k,) int32 via CBD
        seed_e = np.array([int.from_bytes(hkdf.expand(prk, b"e", 8), "big")], dtype=np.uint64)
        e = cbd_i32(cp.asarray(seed_e), self.k, self.eta).flatten()
        
        # Public key b = A @ s + e (mod 2^32) via custom kernel
        self.b = b_from_As(self.A, self.s, e)
        
        # FO helpers
        pk_bytes = cp.asnumpy(self.A).tobytes() + cp.asnumpy(self.b).tobytes()
        self.pk_hash = _sha256(b"pk", pk_bytes)
        self.z = hkdf.expand(prk, b"z", 32)
    
    def encaps_batch(self, batch: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Batch KEM encapsulation.
        
        Returns:
            K: (batch, 32) shared secrets
            U: (batch, n) uint32 ciphertext
            V: (batch, MSG_BITS) uint32 ciphertext
        """
        if self.A is None:
            raise ValueError("Keys not initialized")
        
        # 1. Random messages (CPU, cryptographically secure)
        M_bytes = os.urandom(MSG_BYTES * batch)
        M_np = np.frombuffer(M_bytes, dtype=np.uint8).reshape(batch, MSG_BYTES)
        M_gpu = cp.asarray(M_np)
        
        # 2. Derive FO seeds via GPU BLAKE3
        seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(M_gpu, self.pk_hash)
        
        # 3. CBD samples (int32) via custom kernel
        R = cbd_i32(seeds_r, self.k, self.eta)       # (k, batch) int32
        E1 = cbd_i32(seeds_e1, self.n, self.eta)     # (n, batch) int32
        E2 = cbd_i32(seeds_e2, MSG_BITS, self.eta)   # (MSG_BITS, batch) int32
        
        # 4. Encode message: M_bits * delta
        M_encoded = unpack_to_encoded(M_gpu, self.delta) 
        
        # 5. U = A.T @ R + E1 (mod 2^32) via custom kernel
        U = matmul_AT_R(self.A, R, E1)  # (n, batch) uint32
        
        # 6. B_dot_R = b @ R (mod 2^32) via custom kernel
        B_dot_R = bdot_R(self.b, R)  # (batch,) uint32
        
        # 7. V = B_dot_R + E2 + M_encoded (mod 2^32)
        E2_u32 = E2.astype(cp.uint32)  # (MSG_BITS, batch)
        V = B_dot_R[None, :] + E2_u32 + M_encoded # auto wrap uint32
        
        # 8. Transpose for output
        U_t = cp.ascontiguousarray(U.T)  # (batch, n) uint32
        V_t = cp.ascontiguousarray(V.T)  # (batch, MSG_BITS) uint32
        
        # 9. ct_hash = BLAKE3(U||V) via GPU
        ct_hash = self._blake3.hash_u32_concat_batch(U_t, V_t)  # (batch, 32) uint8
        
        # 10. Derive shared keys via GPU BLAKE3
        ok_mask = cp.ones(batch, dtype=cp.uint8)
        K_gpu = self._blake3.derive_keys_batch(M_gpu, ct_hash, self.z, ok_mask)
        
        # 11. Transfer to CPU
        K = cp.asnumpy(K_gpu)
        U_np = cp.asnumpy(U_t)
        V_np = cp.asnumpy(V_t)
        
        return K, U_np, V_np
    
    def decaps_batch(
        self,
        U: np.ndarray,
        V: np.ndarray,
    ) -> np.ndarray:
        """
        Batch KEM decapsulation with implicit rejection.
        
        Args:
            U: (batch, n) uint32
            V: (batch, MSG_BITS) uint32
            
        Returns:
            K: (batch, 32) shared secrets
        """
        if self.A is None or self.s is None:
            raise ValueError("Keys not initialized")
        
        batch = U.shape[0]
        
        # 1. Transfer to GPU
        U_gpu = cp.asarray(U, dtype=cp.uint32)  # (batch, n)
        V_gpu = cp.asarray(V, dtype=cp.uint32)  # (batch, MSG_BITS)
        
        # 2. S_dot_U = s @ U.T (mod 2^32) via custom kernel
        S_dot_U = sdot_U(self.s, U_gpu)  # (batch,) uint32
        
        # 3. V_dec = V - S_dot_U (mod 2^32)
        V_dec = V_gpu - S_dot_U[:, None]  # auto wrap uint32
        
        # 4. Decode message bits
        V_signed = V_dec.view(cp.int32)
        threshold = np.int32(1 << 30)
        M_bits = ((V_signed > threshold) | (V_signed < -threshold)).astype(cp.uint8)
        
        # 5. Pack bits to bytes (CPU side)
        M_recovered = pack_bits_gpu(M_bits) 
        
        # 6. Re-derive FO seeds
        seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(M_recovered, self.pk_hash)
        
        # 7. Re-encrypt
        R2 = cbd_i32(seeds_r, self.k, self.eta)
        E1_2 = cbd_i32(seeds_e1, self.n, self.eta)
        E2_2 = cbd_i32(seeds_e2, MSG_BITS, self.eta)
        
        M_bits_u32 = M_bits.astype(cp.uint32)
        M_encoded = M_bits_u32 * np.uint32(self.delta)
        
        U2 = matmul_AT_R(self.A, R2, E1_2)
        B_dot_R2 = bdot_R(self.b, R2)
        V2 = B_dot_R2[None, :] + E2_2.astype(cp.uint32) + M_encoded.T
        
        # 8. FO verification (GPU)
        U2_t = cp.ascontiguousarray(U2.T)
        V2_t = cp.ascontiguousarray(V2.T)
        
        U_match = cp.all(U_gpu == U2_t, axis=1)
        V_match = cp.all(V_gpu == V2_t, axis=1)
        ok_mask = (U_match & V_match).astype(cp.uint8)
        
        # 9. ct_hash = BLAKE3(U||V) via GPU (from INPUT ciphertext)
        ct_hash = self._blake3.hash_u32_concat_batch(U_gpu, V_gpu)
        
        # 10. Derive keys with implicit rejection
        K_gpu = self._blake3.derive_keys_batch(M_recovered, ct_hash, self.z, ok_mask)
        
        return cp.asnumpy(K_gpu)


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute batch KEM tests."""
    print("=" * 70)
    print("Meteor-NC Batch KEM v2 (uint32 optimized)")
    print("=" * 70)
    
    import time
    
    results = {}
    
    # Test 1: Basic functionality
    print("\n[Test 1] Batch Encaps/Decaps")
    print("-" * 40)
    
    kem = BatchLWEKEM()
    kem.key_gen()
    
    for bs in [1, 10, 100, 1000]:
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
    U_bad[0, 0] ^= 1
    K_dec_bad = kem.decaps_batch(U_bad, V)
    
    first_differs = not np.array_equal(K_enc[0], K_dec_bad[0])
    rest_match = np.all(K_enc[1:] == K_dec_bad[1:])
    rejection_ok = first_differs and rest_match
    results["rejection"] = rejection_ok
    print(f"  Corrupted rejected: {'PASS' if rejection_ok else 'FAIL'}")
    
    # Test 3: Determinism
    print("\n[Test 3] Seed Determinism")
    print("-" * 40)
    
    seed = secrets.token_bytes(32)
    kem1 = BatchLWEKEM()
    kem1.key_gen(seed=seed)
    kem2 = BatchLWEKEM()
    kem2.key_gen(seed=seed)
    A_match = cp.array_equal(kem1.A, kem2.A)
    results["determinism"] = bool(A_match)
    print(f"  Deterministic keygen: {'PASS' if A_match else 'FAIL'}")
    
    # Test 4: Throughput
    print("\n[Test 4] Throughput Benchmark")
    print("-" * 40)
    
    # Warmup
    _ = kem.encaps_batch(100)
    cp.cuda.Stream.null.synchronize()
    
    for batch in [1000, 10000, 100000]:
        start = time.perf_counter()
        K, U, V = kem.encaps_batch(batch)
        cp.cuda.Stream.null.synchronize()
        enc_time = time.perf_counter() - start
        
        start = time.perf_counter()
        _ = kem.decaps_batch(U, V)
        cp.cuda.Stream.null.synchronize()
        dec_time = time.perf_counter() - start
        
        print(f"  Batch {batch:>6,}:")
        print(f"    Encaps: {batch/enc_time:>10,.0f} ops/sec ({enc_time*1000:>6.1f} ms)")
        print(f"    Decaps: {batch/dec_time:>10,.0f} ops/sec ({dec_time*1000:>6.1f} ms)")
    
    # Test 5: Million target
    print("\n[Test 5] Million Ops Target")
    print("-" * 40)
    
    batch = 1_000_000
    print(f"  Testing {batch:,} encapsulations...")
    
    start = time.perf_counter()
    K, U, V = kem.encaps_batch(batch)
    cp.cuda.Stream.null.synchronize()
    enc_time = time.perf_counter() - start
    
    rate = batch / enc_time
    target_met = rate >= 1_000_000
    results["million"] = target_met
    
    print(f"  Rate: {rate:,.0f} ops/sec")
    print(f"  Target (1M): {'ACHIEVED!' if target_met else 'Not yet'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
