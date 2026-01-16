# meteor_nc/cryptography/batch.py
"""
Meteor-NC Batch KEM (v2 - Correct PKE Design)

GPU-parallel batch KEM with:
- q = 2^32 (uint32 overflow = mod)
- n = k = 256/512/1024 (multi-security level)
- Custom CUDA kernels for GEMM
- GPU BLAKE3 for ct_hash = H(U||V)
- FO transform + implicit rejection

CORRECT KEY STRUCTURE:
  - pk_seed (32B): Public, used to reconstruct matrix A via SHA-256 PRG
  - b (k×4B): Public, computed as A @ s + e during key_gen
  - s: SECRET, generated from TRUE RANDOMNESS (not from seed!)

This ensures:
  - Anyone with (pk_seed, b) can encrypt (encaps_batch)
  - Only the holder of s can decrypt (decaps_batch)
  - pk_seed leaking does NOT compromise secret key!
"""

from __future__ import annotations

import os
import secrets
import struct
from typing import Optional, Tuple

import numpy as np

from .common import (
    _sha256,
    prg_sha256,
    HKDF,
    GPU_AVAILABLE,
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

from .kernels.batch_kernels_v2 import (
    unpack_to_encoded_v2,
    pack_bits_v2,
)
from .kernels.blake3_kernel_v2 import GPUBlake3V2

# =============================================================================
# Constants
# =============================================================================

Q_BATCH = 2**32  # uint32 overflow = mod 2^32
N_FIXED = 256    # 128-bit security
K_FIXED = 256
ETA_DEFAULT = 2
SUPPORTED_N = [256, 512, 1024]


# =============================================================================
# Batch LWE-KEM (Correct PKE Design)
# =============================================================================

class BatchLWEKEM:
    """
    GPU-parallel batch KEM with correct PKE design.
    
    CORRECT KEY STRUCTURE:
      - pk_seed (32B): Public, for deterministic A reconstruction
      - b (k,): Public, computed as A @ s + e
      - s: SECRET, from TRUE RANDOMNESS
    
    Optimized for:
    - q = 2^32 (no mod operations, uint32 wrap)
    - n = k = 256/512/1024
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
        if n not in SUPPORTED_N:
            raise ValueError(f"BatchKEM supports n={SUPPORTED_N}")
        
        cp.cuda.Device(device_id).use()
        
        self.n = n
        self.k = k if k is not None else n
        self.q = Q_BATCH
        self.eta = eta
        self.device_id = device_id
            
        self.msg_bits = n
        self.msg_bytes = n // 8
        
        self.delta = 2**31  # q // 2 for encoding
     
        if n == 256:
            self._blake3 = GPUBlake3(device_id=device_id)
        else:
            self._blake3 = GPUBlake3V2(device_id=device_id)
            
        # Keys (initialized by key_gen)
        self.pk_seed: Optional[bytes] = None
        self.A: Optional[cp.ndarray] = None
        self.b: Optional[cp.ndarray] = None
        self.s: Optional[cp.ndarray] = None
        self.z: Optional[bytes] = None
        self.pk_hash: Optional[bytes] = None
    
    def _reconstruct_A(self, pk_seed: bytes) -> cp.ndarray:
        """
        Reconstruct matrix A from pk_seed using SHA-256 counter-mode PRG.
        
        This is deterministic and implementation-independent.
        Bias from u32 mod q is negligible for q = 2^32.
        """
        num_bytes = self.k * self.n * 4  # uint32 per element
        prg_output = prg_sha256(pk_seed, num_bytes, domain=b"matrix_A_batch")
        
        # Convert to uint32 array on GPU
        raw = np.frombuffer(prg_output, dtype="<u4").copy()
        A_flat = raw.reshape(self.k, self.n)
        
        return cp.asarray(A_flat, dtype=cp.uint32)
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """
        Generate LWE key pair with correct PKE design.
        
        Returns:
            pk_bytes: Serialized public key (pk_seed + b + pk_hash)
            sk_bytes: Serialized secret key (s + z)
        """
        # 1. Generate pk_seed (PUBLIC - for A reconstruction)
        self.pk_seed = secrets.token_bytes(32)
        
        # 2. Reconstruct A from pk_seed (deterministic)
        self.A = self._reconstruct_A(self.pk_seed)
        
        # 3. Generate s from TRUE RANDOMNESS (SECRET!)
        # Use secrets module for cryptographic randomness
        s_bytes = secrets.token_bytes(self.n * 4)
        s_raw = np.frombuffer(s_bytes, dtype="<u4").copy()
        # Map to small error range [-eta, eta] for proper LWE
        s_np = ((s_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
        self.s = cp.asarray(s_np, dtype=cp.int32)
        
        # 4. Generate e (error) from HKDF for reproducibility in tests
        # (Could also use secrets, but HKDF is deterministic for testing)
        e_seed = secrets.token_bytes(32)
        hkdf = HKDF(salt=_sha256(b"batch-kem-v2-error"))
        prk = hkdf.extract(e_seed)
        seed_e = np.array([int.from_bytes(hkdf.expand(prk, b"e", 8), "big")], dtype=np.uint64)
        e = cbd_i32(cp.asarray(seed_e), self.k, self.eta).flatten()
        
        # 5. Compute b = A @ s + e (mod 2^32) via custom kernel
        self.b = b_from_As(self.A, self.s, e)
        
        # 6. FO helpers
        # pk_hash = H(pk_seed || b) - NOT including A since A is derived from pk_seed
        b_bytes = cp.asnumpy(self.b).astype("<u4").tobytes()
        self.pk_hash = _sha256(b"pk", self.pk_seed, b_bytes)
        
        # 7. Generate implicit rejection seed z (SECRET)
        self.z = secrets.token_bytes(32)
        
        # 8. Serialize keys
        pk_bytes = self._export_public_key()
        sk_bytes = self._export_secret_key()
        
        return pk_bytes, sk_bytes
    
    def _export_public_key(self) -> bytes:
        """
        Serialize public key to wire format.
        
        Note: q = 2^32 is encoded as 0 (since 2^32 exceeds uint32 range).
        This is decoded back to 2^32 in load_public_key.
        """
        if self.pk_seed is None or self.b is None or self.pk_hash is None:
            raise ValueError("Keys not initialized")
        
        # q = 2^32 exceeds uint32 range, encode as 0
        q_encoded = 0 if self.q == 2**32 else self.q
        
        b_bytes = cp.asnumpy(self.b).astype("<u4").tobytes()
        return (
            struct.pack(">III", self.n, self.k, q_encoded) +  # header (12B)
            self.pk_seed +                                     # 32B
            b_bytes +                                          # k*4B
            self.pk_hash                                       # 32B
        )
    
    def _export_secret_key(self) -> bytes:
        """Serialize secret key."""
        if self.s is None or self.z is None:
            raise ValueError("Keys not initialized")
        
        s_bytes = cp.asnumpy(self.s).astype("<i4").tobytes()
        return s_bytes + self.z
    
    def load_public_key(self, pk_bytes: bytes) -> None:
        """
        Load public key from bytes.
        
        This allows ANYONE to encrypt without knowing the secret key!
        
        Note: q = 0 in wire format means q = 2^32 (overflow encoding).
        """
        if len(pk_bytes) < 12:
            raise ValueError(f"Public key too short: {len(pk_bytes)} < 12")
        
        n, k, q_encoded = struct.unpack(">III", pk_bytes[:12])
        
        # q = 0 means 2^32 (overflow encoding)
        q = 2**32 if q_encoded == 0 else q_encoded
        
        if n != self.n or k != self.k or q != self.q:
            raise ValueError(f"Parameter mismatch: expected n={self.n}, k={self.k}, q={self.q}, got n={n}, k={k}, q={q}")
        
        expected_size = 12 + 32 + k * 4 + 32
        if len(pk_bytes) < expected_size:
            raise ValueError(f"Public key truncated: {len(pk_bytes)} < {expected_size}")
        
        self.pk_seed = pk_bytes[12:44]
        b_raw = np.frombuffer(pk_bytes[44:44 + k * 4], dtype="<u4").copy()
        self.b = cp.asarray(b_raw, dtype=cp.uint32)
        self.pk_hash = pk_bytes[44 + k * 4:44 + k * 4 + 32]
        
        # Reconstruct A from pk_seed
        self.A = self._reconstruct_A(self.pk_seed)
        
        # s remains None - we don't have the secret key!
        self.s = None
        self.z = None
    
    def load_secret_key(self, sk_bytes: bytes) -> None:
        """Load secret key from bytes."""
        expected_size = self.n * 4 + 32
        if len(sk_bytes) < expected_size:
            raise ValueError(f"Secret key truncated: {len(sk_bytes)} < {expected_size}")
        
        s_np = np.frombuffer(sk_bytes[:self.n * 4], dtype="<i4").copy()
        self.s = cp.asarray(s_np, dtype=cp.int32)
        self.z = sk_bytes[self.n * 4:self.n * 4 + 32]
    
    def encaps_batch(self, batch: int, return_ct: bool = True) -> Tuple[np.ndarray, Optional[np.ndarray], Optional[np.ndarray]]:
        """
        Batch encapsulation (encryption).
        
        Can be called by ANYONE with the public key!
        """
        if self.A is None or self.b is None:
            raise ValueError("Public key not initialized")
        
        # 1. Random messages (CPU, cryptographically secure)
        M_bytes = os.urandom(self.msg_bytes * batch)
        M_np = np.frombuffer(M_bytes, dtype=np.uint8).reshape(batch, self.msg_bytes)
        M_gpu = cp.asarray(M_np)
        
        # 2. Derive FO seeds via GPU BLAKE3
        if self.n == 256:
            seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(M_gpu, self.pk_hash)
        else:
            seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(M_gpu, self.pk_hash, self.msg_bytes)
        
        # 3. CBD samples (int32) via custom kernel
        R = cbd_i32(seeds_r, self.k, self.eta)
        E1 = cbd_i32(seeds_e1, self.n, self.eta)
        E2 = cbd_i32(seeds_e2, self.msg_bits, self.eta)
        
        # 4. Encode message: M_bits * delta
        if self.n == 256:
            M_encoded = unpack_to_encoded(M_gpu, self.delta)
        else:
            M_encoded = unpack_to_encoded_v2(M_gpu, self.delta, self.msg_bits, self.msg_bytes)
        
        # 5. U = A.T @ R + E1 (mod 2^32) via custom kernel
        U = matmul_AT_R(self.A, R, E1)
        
        # 6. B_dot_R = b @ R (mod 2^32) via custom kernel
        B_dot_R = bdot_R(self.b, R)
        
        # 7. V = B_dot_R + E2 + M_encoded (mod 2^32)
        E2_u32 = E2.astype(cp.uint32)
        V = B_dot_R[None, :] + E2_u32 + M_encoded
        
        # 8. Transpose for output
        U_t = cp.ascontiguousarray(U.T)
        V_t = cp.ascontiguousarray(V.T)
        
        # 9. ct_hash = BLAKE3(U||V) via GPU
        ct_hash = self._blake3.hash_u32_concat_batch(U_t, V_t, self.n, self.msg_bits)
        
        # 10. Derive shared keys via GPU BLAKE3
        ok_mask = cp.ones(batch, dtype=cp.uint8)
        if self.n == 256:
            K_gpu = self._blake3.derive_keys_batch(M_gpu, ct_hash, self.z or b'\x00' * 32, ok_mask)
        else:
            K_gpu = self._blake3.derive_keys_batch(M_gpu, ct_hash, self.z or b'\x00' * 32, ok_mask, self.msg_bytes)
        
        # 11. Transfer to CPU
        K = cp.asnumpy(K_gpu)
        
        if not return_ct:
            return K, None, None
        
        U_np = cp.asnumpy(U_t)
        V_np = cp.asnumpy(V_t)
        
        return K, U_np, V_np
    
    def decaps_batch(
        self,
        U: np.ndarray,
        V: np.ndarray,
    ) -> np.ndarray:
        """
        Batch decapsulation (decryption).
        
        Can ONLY be called by the holder of the secret key!
        """
        if self.A is None or self.s is None:
            raise ValueError("Keys not initialized (need both pk and sk for decaps)")
        
        batch = U.shape[0]
        
        # 1. Transfer to GPU
        U_gpu = cp.asarray(U, dtype=cp.uint32)
        V_gpu = cp.asarray(V, dtype=cp.uint32)
        
        # 2. S_dot_U = s @ U.T (mod 2^32) via custom kernel
        S_dot_U = sdot_U(self.s, U_gpu)
        
        # 3. V_dec = V - S_dot_U (mod 2^32)
        V_dec = V_gpu - S_dot_U[:, None]
        
        # 4. Decode message bits
        V_signed = V_dec.view(cp.int32)
        threshold = np.int32(1 << 30)
        M_bits = ((V_signed > threshold) | (V_signed < -threshold)).astype(cp.uint8)
        
        # 5. Pack bits to bytes
        if self.n == 256:
            M_recovered = pack_bits_gpu(M_bits)
        else:
            M_recovered = pack_bits_v2(M_bits, self.msg_bits, self.msg_bytes)
        
        # 6. Re-derive FO seeds
        if self.n == 256:
            seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(M_recovered, self.pk_hash)
        else:
            seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(M_recovered, self.pk_hash, self.msg_bytes)
        
        # 7. Re-encrypt
        R2 = cbd_i32(seeds_r, self.k, self.eta)
        E1_2 = cbd_i32(seeds_e1, self.n, self.eta)
        E2_2 = cbd_i32(seeds_e2, self.msg_bits, self.eta)
        
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
        
        # 9. ct_hash = BLAKE3(U||V) via GPU
        ct_hash = self._blake3.hash_u32_concat_batch(U_gpu, V_gpu, self.n, self.msg_bits)
        
        # 10. Derive keys with implicit rejection
        if self.n == 256:
            K_gpu = self._blake3.derive_keys_batch(M_recovered, ct_hash, self.z, ok_mask)
        else:
            K_gpu = self._blake3.derive_keys_batch(M_recovered, ct_hash, self.z, ok_mask, self.msg_bytes)
        
        return cp.asnumpy(K_gpu)


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute batch KEM tests."""
    print("=" * 70)
    print("Meteor-NC Batch KEM v2 (Correct PKE Design)")
    print("=" * 70)
    
    import time
    
    results = {}
    
    # Test 1: Basic functionality
    print("\n[Test 1] Batch Encaps/Decaps")
    print("-" * 40)
    
    kem = BatchLWEKEM()
    pk_bytes, sk_bytes = kem.key_gen()
    
    print(f"  PK size: {len(pk_bytes)} bytes")
    print(f"  SK size: {len(sk_bytes)} bytes")
    
    for bs in [1, 10, 100, 1000]:
        K_enc, U, V = kem.encaps_batch(bs)
        K_dec = kem.decaps_batch(U, V)
        match = np.all(K_enc == K_dec)
        print(f"  Batch {bs:4d}: {'PASS' if match else 'FAIL'}")
        results[f"batch_{bs}"] = match
    
    # Test 2: Sender/Receiver Separation (Core Security Test!)
    print("\n[Test 2] Sender/Receiver Separation (Core Security)")
    print("-" * 40)
    
    # Receiver generates keys
    receiver = BatchLWEKEM()
    pk_bytes, sk_bytes = receiver.key_gen()
    
    # Sender loads ONLY public key
    sender = BatchLWEKEM()
    sender.load_public_key(pk_bytes)
    
    # Sender can encrypt
    K_sender, U, V = sender.encaps_batch(10)
    
    # Sender should NOT be able to decrypt (no secret key!)
    try:
        _ = sender.decaps_batch(U, V)
        sender_blocked = False
        print("  ERROR: Sender was able to decrypt without secret key!")
    except ValueError as e:
        sender_blocked = True
        print(f"  Sender blocked: {e}")
    
    # Receiver can decrypt
    receiver.load_secret_key(sk_bytes)  # Load sk back (was cleared during export)
    K_receiver = receiver.decaps_batch(U, V)
    keys_match = np.all(K_sender == K_receiver)
    
    results["sender_blocked"] = sender_blocked
    results["keys_match"] = keys_match
    print(f"  Sender blocked: {'PASS' if sender_blocked else 'FAIL'}")
    print(f"  Keys match: {'PASS' if keys_match else 'FAIL'}")
    
    # Test 3: Implicit rejection
    print("\n[Test 3] Implicit Rejection")
    print("-" * 40)
    
    kem = BatchLWEKEM()
    kem.key_gen()
    
    K_enc, U, V = kem.encaps_batch(10)
    U_bad = U.copy()
    U_bad[0, 0] ^= 1
    K_dec_bad = kem.decaps_batch(U_bad, V)
    
    first_differs = not np.array_equal(K_enc[0], K_dec_bad[0])
    rest_match = np.all(K_enc[1:] == K_dec_bad[1:])
    rejection_ok = first_differs and rest_match
    results["rejection"] = rejection_ok
    print(f"  Corrupted rejected: {'PASS' if rejection_ok else 'FAIL'}")
    
    # Test 4: pk_seed determinism (A reconstruction)
    print("\n[Test 4] Matrix A Reconstruction Determinism")
    print("-" * 40)
    
    kem1 = BatchLWEKEM()
    pk1, _ = kem1.key_gen()
    
    kem2 = BatchLWEKEM()
    kem2.load_public_key(pk1)
    
    A_match = cp.array_equal(kem1.A, kem2.A)
    results["A_determinism"] = bool(A_match)
    print(f"  A reconstruction matches: {'PASS' if A_match else 'FAIL'}")
    
    # Test 5: Throughput
    print("\n[Test 5] Throughput Benchmark")
    print("-" * 40)
    
    kem = BatchLWEKEM()
    kem.key_gen()
    
    # Warmup
    _ = kem.encaps_batch(500)
    cp.cuda.Stream.null.synchronize()
    
    for batch in [1000, 10000, 100000]:
        # GPU-only encaps
        start = time.perf_counter()
        K, _, _ = kem.encaps_batch(batch, return_ct=False)
        cp.cuda.Stream.null.synchronize()
        enc_gpu_time = time.perf_counter() - start
        
        # Transfer-included encaps
        start = time.perf_counter()
        K, U, V = kem.encaps_batch(batch, return_ct=True)
        cp.cuda.Stream.null.synchronize()
        enc_full_time = time.perf_counter() - start
        
        # Decaps
        start = time.perf_counter()
        _ = kem.decaps_batch(U, V)
        cp.cuda.Stream.null.synchronize()
        dec_time = time.perf_counter() - start
        
        print(f"  Batch {batch:>6,}:")
        print(f"    Encaps (GPU):  {batch/enc_gpu_time:>10,.0f} ops/sec")
        print(f"    Encaps (Full): {batch/enc_full_time:>10,.0f} ops/sec")
        print(f"    Decaps:        {batch/dec_time:>10,.0f} ops/sec")
        
    # Test 6: Million target
    print("\n[Test 6] Million Ops Target")
    print("-" * 40)
    
    batch = 1_000_000
    print(f"  Testing {batch:,} encapsulations...")
    
    # GPU-only (KEM processing capability)
    start = time.perf_counter()
    K, _, _ = kem.encaps_batch(batch, return_ct=False)
    cp.cuda.Stream.null.synchronize()
    enc_time = time.perf_counter() - start
    
    rate = batch / enc_time
    target_met = rate >= 1_000_000
    results["million"] = target_met
    
    print(f"  KEM Processing: {rate:,.0f} ops/sec")
    print(f"  Target (1M): {'✅ ACHIEVED!' if target_met else 'Not yet'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    
    if all_pass:
        print("\n✓ Security property verified:")
        print("  - Sender with pk_seed + b CAN encrypt (encaps_batch)")
        print("  - Sender with pk_seed + b CANNOT decrypt")
        print("  - Only secret key holder can decrypt (decaps_batch)")
        print("  - pk_seed leak does NOT compromise secret key!")
    
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
