# meteor_nc/cryptography/batch.py
"""
Meteor-NC Batch Hybrid KEM (GPU-Accelerated) v2.0

GPU-parallel hybrid encryption combining:
- BatchLWEKEM: GPU-accelerated LWE key encapsulation
- GPUChaCha20Poly1305: GPU-accelerated authenticated encryption
- Coefficient Compression: Kyber-style bandwidth reduction (v2.0) ★NEW

Features:
- q = 2^32 (uint32 overflow = mod)
- n = k = 256/512/1024 (multi-security level)
- Custom CUDA kernels for all hot paths
- Wire-based FO transform with compression ★NEW
- core.py compatible interface

Target: 1M+ ops/sec on modern GPUs

Key Generation Security:
- seed=None (default): TRUE RANDOMNESS for s (standard PKE)
- seed=bytes: Deterministic derivation (for auth/reproducibility)

v2.0 Changes:
- Wire-based FO transform (compressed form is canonical)
- Ciphertext sizes: 518B (n=256), 1094B (n=512), 2310B (n=1024)
- ~75% bandwidth reduction
"""

from __future__ import annotations

import os
import secrets
import struct
from dataclasses import dataclass
from typing import Optional, Tuple, List, Union

import numpy as np

from .common import (
    _sha256,
    prg_sha256,
    HKDF,
    GPU_AVAILABLE,
    Q_DEFAULT,
)

# =============================================================================
# Compression Import (v2.0)
# =============================================================================

try:
    from .compression import (
        compress_ciphertext,
        decompress_ciphertext,
        compressed_size,
        get_compression_params,
        COMPRESSION_PARAMS,
    )
    COMPRESSION_AVAILABLE = True
except ImportError:
    COMPRESSION_AVAILABLE = False

if not GPU_AVAILABLE:
    raise ImportError("BatchKEM requires CuPy + CUDA")

import cupy as cp

from .kernels.blake3_kernel import GPUBlake3
from .kernels.blake3_kernel_v2 import GPUBlake3V2
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
from .kernels.chacha_poly_kernel import GPUChaCha20Poly1305


# =============================================================================
# Constants
# =============================================================================

Q_BATCH = 2**32
N_FIXED = 256
K_FIXED = 256
ETA_DEFAULT = 2
SUPPORTED_N = [256, 512, 1024]


# =============================================================================
# Data Classes (core.py compatible)
# =============================================================================

@dataclass
class BatchCiphertext:
    """
    Hybrid ciphertext for batch operations.
    
    v2.0: Wire-based design with kem_wire as canonical form.
    
    Wire format (compressed, v2.0):
        | header (16B) | kem_wire | nonce (24B) | ct | tag (16B) |
        
    CRITICAL: kem_wire is the canonical form for:
      - FO transform verification (wire == recomputed_wire)
      - AAD computation (AAD = H(kem_wire))
      - Storage/transmission
    
    U/V are derived from kem_wire via decompression (for internal use only).
    """
    U: np.ndarray           # (n,) uint32 - KEM ciphertext part 1 (derived from kem_wire)
    V: np.ndarray           # (msg_bits,) uint32 - KEM ciphertext part 2 (derived from kem_wire)
    nonce: bytes            # 24 bytes - DEM nonce
    ciphertext: bytes       # Variable - DEM ciphertext
    tag: bytes              # 16 bytes - DEM auth tag
    n: int = 256
    msg_bits: int = 256
    kem_wire: Optional[bytes] = None  # v2.0: Canonical KEM ciphertext (compressed)
    q: int = Q_BATCH                   # v2.0: Modulus for compression
    
    def get_kem_wire(self) -> bytes:
        """
        Get canonical KEM wire format.
        
        If kem_wire is already set, return it.
        Otherwise, compress U/V to create it.
        """
        if self.kem_wire is not None:
            return self.kem_wire
        
        if not COMPRESSION_AVAILABLE:
            raise ImportError("Compression module not available")
        
        self.kem_wire = compress_ciphertext(self.U, self.V, self.q)
        return self.kem_wire
    
    def get_aad(self) -> bytes:
        """
        Get AAD for DEM encryption/decryption.
        
        CRITICAL: AAD must be derived from kem_wire (canonical form),
        NOT from raw U/V coefficients!
        """
        return _sha256(b"batch-hybrid-aad", self.get_kem_wire())
    
    def to_bytes(self) -> bytes:
        """Serialize to wire format (uncompressed, legacy)."""
        u_bytes = self.U.astype('<u4').tobytes()
        v_bytes = self.V.astype('<u4').tobytes()
        ct_len = len(self.ciphertext)
        
        return (
            struct.pack('>III', self.n, self.msg_bits, ct_len) +
            u_bytes +
            v_bytes +
            self.nonce +
            self.ciphertext +
            self.tag
        )
    
    def to_bytes_compressed(self) -> bytes:
        """
        Serialize to wire format (compressed, v2.0).
        
        This uses kem_wire as the canonical KEM ciphertext.
        """
        kem_wire = self.get_kem_wire()
        ct_len = len(self.ciphertext)
        
        return (
            struct.pack('>IIII', self.n, self.msg_bits, ct_len, len(kem_wire)) +
            kem_wire +
            self.nonce +
            self.ciphertext +
            self.tag
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'BatchCiphertext':
        """Deserialize from wire format (uncompressed, legacy)."""
        if len(data) < 12:
            raise ValueError("Ciphertext too short")
        
        n, msg_bits, ct_len = struct.unpack('>III', data[:12])
        
        offset = 12
        u_size = n * 4
        v_size = msg_bits * 4
        
        expected_len = 12 + u_size + v_size + 24 + ct_len + 16
        if len(data) < expected_len:
            raise ValueError(f"Ciphertext truncated: {len(data)} < {expected_len}")
        
        U = np.frombuffer(data[offset:offset + u_size], dtype='<u4').copy()
        offset += u_size
        
        V = np.frombuffer(data[offset:offset + v_size], dtype='<u4').copy()
        offset += v_size
        
        nonce = data[offset:offset + 24]
        offset += 24
        
        ciphertext = data[offset:offset + ct_len]
        offset += ct_len
        
        tag = data[offset:offset + 16]
        
        return cls(
            U=U, V=V, nonce=nonce,
            ciphertext=ciphertext, tag=tag,
            n=n, msg_bits=msg_bits,
            kem_wire=None,  # Will be computed on demand
            q=Q_BATCH,
        )
    
    @classmethod
    def from_bytes_compressed(cls, data: bytes, q: int = Q_BATCH) -> 'BatchCiphertext':
        """
        Deserialize from wire format (compressed, v2.0).
        
        CRITICAL: Preserves kem_wire as canonical form!
        """
        if not COMPRESSION_AVAILABLE:
            raise ImportError("Compression module not available")
        
        if len(data) < 16:
            raise ValueError("Ciphertext too short")
        
        n, msg_bits, ct_len, kem_wire_len = struct.unpack('>IIII', data[:16])
        
        offset = 16
        kem_wire = data[offset:offset + kem_wire_len]
        offset += kem_wire_len
        
        # Decompress to get U/V (for internal computation)
        U, V = decompress_ciphertext(kem_wire, q)
        
        nonce = data[offset:offset + 24]
        offset += 24
        
        ciphertext = data[offset:offset + ct_len]
        offset += ct_len
        
        tag = data[offset:offset + 16]
        
        return cls(
            U=U, V=V, nonce=nonce,
            ciphertext=ciphertext, tag=tag,
            n=n, msg_bits=msg_bits,
            kem_wire=kem_wire,  # Preserve canonical form!
            q=q,
        )
    
    def wire_size(self) -> int:
        """Get uncompressed wire format size in bytes."""
        return 12 + self.n * 4 + self.msg_bits * 4 + 24 + len(self.ciphertext) + 16
    
    def wire_size_compressed(self) -> int:
        """Get compressed wire format size in bytes."""
        if not COMPRESSION_AVAILABLE:
            raise ImportError("Compression module not available")
        kem_size = compressed_size(self.n, self.msg_bits)
        return 16 + kem_size + 24 + len(self.ciphertext) + 16


# =============================================================================
# Batch LWE-KEM (GPU-Accelerated)
# =============================================================================

class BatchLWEKEM:
    """
    GPU-parallel batch KEM with correct PKE design.
    
    CORRECT KEY STRUCTURE:
      - pk_seed (32B): Public, used to reconstruct matrix A
      - b (k×4B): Public, computed as A @ s + e mod q during key_gen
      - s: SECRET, generated from TRUE RANDOMNESS (not from pk_seed!)
    
    v2.0: Wire-based FO transform with compression support.
    
    This is the KEM-only component. For hybrid encryption,
    use BatchHybridKEM which combines this with DEM.
    """
    
    def __init__(
        self,
        n: int = N_FIXED,
        k: int = K_FIXED,
        eta: int = ETA_DEFAULT,
        device_id: int = 0,
        use_compression: bool = True,  # v2.0: Default to compressed
    ):
        if n not in SUPPORTED_N:
            raise ValueError(f"BatchKEM supports n={SUPPORTED_N}")
        
        cp.cuda.Device(device_id).use()
        
        self.n = n
        self.k = k if k is not None else n
        self.q = Q_BATCH
        self.eta = eta
        self.device_id = device_id
        self.use_compression = use_compression and COMPRESSION_AVAILABLE
        
        self.msg_bits = n
        self.msg_bytes = n // 8
        self.delta = 2**31
        
        if n == 256:
            self._blake3 = GPUBlake3(device_id=device_id)
        else:
            self._blake3 = GPUBlake3V2(device_id=device_id)
        
        # Keys
        self.pk_seed: Optional[bytes] = None
        self.A: Optional[cp.ndarray] = None
        self.b: Optional[cp.ndarray] = None
        self.s: Optional[cp.ndarray] = None
        self.z: Optional[bytes] = None
        self.pk_hash: Optional[bytes] = None
    
    def _reconstruct_A(self, pk_seed: bytes) -> cp.ndarray:
        """Reconstruct matrix A from pk_seed."""
        num_bytes = self.k * self.n * 4
        prg_output = prg_sha256(pk_seed, num_bytes, domain=b"matrix_A_batch")
        raw = np.frombuffer(prg_output, dtype="<u4").copy()
        A_flat = raw.reshape(self.k, self.n)
        return cp.asarray(A_flat, dtype=cp.uint32)
    
    def key_gen(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Generate LWE key pair.
        
        Args:
            seed: Optional master seed for deterministic key generation.
                  - None (default): Use TRUE RANDOMNESS for s (standard PKE)
                  - bytes: Derive all key material from seed (for auth/reproducibility)
        
        Returns:
            Tuple of (public_key_bytes, secret_key_bytes)
        """
        if seed is not None:
            # Deterministic key generation from master seed
            hkdf = HKDF(salt=_sha256(b"batch-kem-v2-auth"))
            prk = hkdf.extract(seed)
            
            self.pk_seed = hkdf.expand(prk, b"pk_seed", 32)
            
            s_bytes = hkdf.expand(prk, b"secret_s", self.n * 4)
            s_raw = np.frombuffer(s_bytes, dtype="<u4").copy()
            s_np = ((s_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
            self.s = cp.asarray(s_np, dtype=cp.int32)
            
            e_seed = hkdf.expand(prk, b"error_seed", 32)
            self.z = hkdf.expand(prk, b"implicit_z", 32)
        else:
            # Standard PKE: TRUE RANDOMNESS
            self.pk_seed = secrets.token_bytes(32)
            
            s_bytes = secrets.token_bytes(self.n * 4)
            s_raw = np.frombuffer(s_bytes, dtype="<u4").copy()
            s_np = ((s_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
            self.s = cp.asarray(s_np, dtype=cp.int32)
            
            e_seed = secrets.token_bytes(32)
            self.z = secrets.token_bytes(32)
        
        self.A = self._reconstruct_A(self.pk_seed)
        
        hkdf_e = HKDF(salt=_sha256(b"batch-kem-v2-error"))
        prk_e = hkdf_e.extract(e_seed)
        seed_e = np.array([int.from_bytes(hkdf_e.expand(prk_e, b"e", 8), "big")], dtype=np.uint64)
        e = cbd_i32(cp.asarray(seed_e), self.k, self.eta).flatten()
        
        self.b = b_from_As(self.A, self.s, e)
        
        b_bytes = cp.asnumpy(self.b).astype("<u4").tobytes()
        self.pk_hash = _sha256(b"pk", self.pk_seed, b_bytes)
        
        pk_bytes = self._export_public_key()
        sk_bytes = self._export_secret_key()
        
        return pk_bytes, sk_bytes
    
    def _export_public_key(self) -> bytes:
        """Serialize public key."""
        if self.pk_seed is None or self.b is None or self.pk_hash is None:
            raise ValueError("Keys not initialized")
        
        q_encoded = 0 if self.q == 2**32 else self.q
        b_bytes = cp.asnumpy(self.b).astype("<u4").tobytes()
        
        return (
            struct.pack(">III", self.n, self.k, q_encoded) +
            self.pk_seed +
            b_bytes +
            self.pk_hash
        )
    
    def _export_secret_key(self) -> bytes:
        """Serialize secret key."""
        if self.s is None or self.z is None:
            raise ValueError("Keys not initialized")
        
        s_bytes = cp.asnumpy(self.s).astype("<i4").tobytes()
        return s_bytes + self.z
    
    def load_public_key(self, pk_bytes: bytes) -> None:
        """Load public key from bytes."""
        if len(pk_bytes) < 12:
            raise ValueError(f"Public key too short: {len(pk_bytes)} < 12")
        
        n, k, q_encoded = struct.unpack(">III", pk_bytes[:12])
        q = 2**32 if q_encoded == 0 else q_encoded
        
        if n != self.n or k != self.k or q != self.q:
            raise ValueError(f"Parameter mismatch")
        
        expected_size = 12 + 32 + k * 4 + 32
        if len(pk_bytes) < expected_size:
            raise ValueError(f"Public key truncated")
        
        self.pk_seed = pk_bytes[12:44]
        b_raw = np.frombuffer(pk_bytes[44:44 + k * 4], dtype="<u4").copy()
        self.b = cp.asarray(b_raw, dtype=cp.uint32)
        self.pk_hash = pk_bytes[44 + k * 4:44 + k * 4 + 32]
        
        self.A = self._reconstruct_A(self.pk_seed)
        self.s = None
        self.z = None
    
    def load_secret_key(self, sk_bytes: bytes) -> None:
        """Load secret key from bytes."""
        expected_size = self.n * 4 + 32
        if len(sk_bytes) < expected_size:
            raise ValueError(f"Secret key truncated")
        
        s_np = np.frombuffer(sk_bytes[:self.n * 4], dtype="<i4").copy()
        self.s = cp.asarray(s_np, dtype=cp.int32)
        self.z = sk_bytes[self.n * 4:self.n * 4 + 32]
    
    # =========================================================================
    # v2.0: Wire-Based Encapsulation (Single Message)
    # =========================================================================
    
    def encaps(self) -> Tuple[bytes, bytes]:
        """
        Single-message encapsulation with wire-based FO (v2.0).
        
        CRITICAL: K is derived from wire (canonical form), NOT raw coefficients!
        
        Returns:
            K: 32-byte shared secret (wire-based KDF)
            wire: Compressed KEM ciphertext bytes (canonical form)
        """
        # Get (U, V, m) from batch encaps
        # NOTE: We discard K from encaps_batch because it uses raw-coefficient KDF
        _, U_batch, V_batch, M_np = self.encaps_batch(1, return_ct=True, return_msg=True)
        
        U = U_batch[0]
        V = V_batch[0]
        m = M_np[0].tobytes()
        
        # v2.0: Compress to wire format (canonical form)
        if self.use_compression:
            wire = compress_ciphertext(U, V, self.q)
        else:
            wire = (
                struct.pack('>II', len(U), len(V)) +
                U.astype('<u4').tobytes() +
                V.astype('<u4').tobytes()
            )
        
        # v2.0: Wire-based KDF (MUST match decaps_single_wire!)
        ct_hash = _sha256(b"ct_hash", wire)
        K = _sha256(b"shared_key", m, ct_hash)
        
        return K, wire
    
    def decaps(self, wire: bytes) -> bytes:
        """
        Single-message decapsulation with wire-based FO (v2.0).
        
        CRITICAL: FO verification uses wire comparison, not coefficient comparison!
        
        Args:
            wire: Compressed KEM ciphertext bytes (canonical form)
            
        Returns:
            K: 32-byte shared secret
        """
        # Decompress using self.q
        if self.use_compression:
            U, V = decompress_ciphertext(wire, self.q)
        else:
            u_len, v_len = struct.unpack('>II', wire[:8])
            offset = 8
            U = np.frombuffer(wire[offset:offset + u_len * 4], dtype='<u4').copy()
            offset += u_len * 4
            V = np.frombuffer(wire[offset:offset + v_len * 4], dtype='<u4').copy()
        
        # Decaps with wire-based FO verification
        K = self.decaps_single_wire(U, V, wire)
        
        return K
    
    def decaps_single_wire(self, U: np.ndarray, V: np.ndarray, wire: bytes) -> bytes:
        """
        Single-message decapsulation with wire-based FO verification.
        
        Args:
            U, V: Decompressed coefficients (for LWE decryption)
            wire: Original compressed wire (for FO comparison)
            
        Returns:
            K: 32-byte shared secret
        """
        if self.A is None or self.s is None:
            raise ValueError("Keys not initialized (need both pk and sk)")
        
        # Transfer to GPU
        U_gpu = cp.asarray(U.reshape(1, -1), dtype=cp.uint32)
        V_gpu = cp.asarray(V.reshape(1, -1), dtype=cp.uint32)
        
        # Decrypt: V - s^T U
        S_dot_U = sdot_U(self.s, U_gpu)
        V_dec = V_gpu - S_dot_U[:, None]
        
        # Decode message bits
        V_signed = V_dec.view(cp.int32)
        threshold = np.int32(1 << 30)
        M_bits = ((V_signed > threshold) | (V_signed < -threshold)).astype(cp.uint8)
        
        # Pack bits to message
        if self.n == 256:
            M_recovered = pack_bits_gpu(M_bits)
        else:
            M_recovered = pack_bits_v2(M_bits, self.msg_bits, self.msg_bytes)
        
        M_np = cp.asnumpy(M_recovered)[0]
        
        # Re-derive FO seeds from recovered message
        if self.n == 256:
            seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(M_recovered, self.pk_hash)
        else:
            seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(M_recovered, self.pk_hash, self.msg_bytes)
        
        # Re-encrypt to get (U2, V2)
        R2 = cbd_i32(seeds_r, self.k, self.eta)
        E1_2 = cbd_i32(seeds_e1, self.n, self.eta)
        E2_2 = cbd_i32(seeds_e2, self.msg_bits, self.eta)
        
        M_bits_u32 = M_bits.astype(cp.uint32)
        M_encoded = M_bits_u32 * np.uint32(self.delta)
        
        U2 = matmul_AT_R(self.A, R2, E1_2)
        B_dot_R2 = bdot_R(self.b, R2)
        V2 = B_dot_R2[None, :] + E2_2.astype(cp.uint32) + M_encoded.T
        
        U2_np = cp.asnumpy(U2.T)[0]
        V2_np = cp.asnumpy(V2.T)[0]
        
        # v2.0: FO verification using WIRE COMPARISON (not coefficient comparison!)
        if self.use_compression:
            wire2 = compress_ciphertext(U2_np, V2_np, self.q)
            ok = (wire == wire2)
        else:
            wire2 = (
                struct.pack('>II', len(U2_np), len(V2_np)) +
                U2_np.astype('<u4').tobytes() +
                V2_np.astype('<u4').tobytes()
            )
            ok = (wire == wire2)
        
        # ct_hash from original wire (canonical form)
        ct_hash = _sha256(b"ct_hash", wire)
        
        # Derive key with implicit rejection
        if ok:
            K = _sha256(b"shared_key", M_np.tobytes(), ct_hash)
        else:
            K = _sha256(b"reject_key", self.z, ct_hash)
        
        return K
    
    # =========================================================================
    # Batch Operations (Internal Format for GPU Efficiency)
    # =========================================================================
    
    def encaps_batch(
        self,
        batch: int,
        return_ct: bool = True,
        return_msg: bool = False,  # v2.0: Return message for wire-based KDF
    ):
        """
        Batch encapsulation (encryption) - returns shared keys.
        
        For GPU efficiency, returns raw (U, V) arrays instead of wire format.
        Use encaps() for single-message wire-based operation.
        
        Args:
            batch: Number of messages to encapsulate
            return_ct: Return (U, V) arrays
            return_msg: Return message bytes (for wire-based KDF)
        
        Returns:
            If return_msg=False (default, backward compatible):
                K: (batch, 32) shared keys
                U: (batch, n) or None
                V: (batch, msg_bits) or None
            If return_msg=True:
                K, U, V, M: where M is (batch, msg_bytes)
            
            WARNING: K is raw-coefficient based. Use encaps() for wire-based K.
        """
        if self.A is None or self.b is None:
            raise ValueError("Public key not initialized")
        
        # 1. Random messages
        M_bytes = os.urandom(self.msg_bytes * batch)
        M_np = np.frombuffer(M_bytes, dtype=np.uint8).reshape(batch, self.msg_bytes)
        M_gpu = cp.asarray(M_np)
        
        # 2. Derive FO seeds
        if self.n == 256:
            seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(M_gpu, self.pk_hash)
        else:
            seeds_r, seeds_e1, seeds_e2 = self._blake3.derive_seeds_batch(M_gpu, self.pk_hash, self.msg_bytes)
        
        # 3. CBD samples
        R = cbd_i32(seeds_r, self.k, self.eta)
        E1 = cbd_i32(seeds_e1, self.n, self.eta)
        E2 = cbd_i32(seeds_e2, self.msg_bits, self.eta)
        
        # 4. Encode message
        if self.n == 256:
            M_encoded = unpack_to_encoded(M_gpu, self.delta)
        else:
            M_encoded = unpack_to_encoded_v2(M_gpu, self.delta, self.msg_bits, self.msg_bytes)
        
        # 5. U = A.T @ R + E1
        U = matmul_AT_R(self.A, R, E1)
        
        # 6. B_dot_R = b @ R
        B_dot_R = bdot_R(self.b, R)
        
        # 7. V = B_dot_R + E2 + M_encoded
        E2_u32 = E2.astype(cp.uint32)
        V = B_dot_R[None, :] + E2_u32 + M_encoded
        
        # 8. Transpose
        U_t = cp.ascontiguousarray(U.T)
        V_t = cp.ascontiguousarray(V.T)
        
        # 9. ct_hash (raw coefficient based - for backward compat only)
        ct_hash = self._blake3.hash_u32_concat_batch(U_t, V_t, self.n, self.msg_bits)
        
        # 10. Derive shared keys (WARNING: raw-coefficient based!)
        ok_mask = cp.ones(batch, dtype=cp.uint8)
        if self.n == 256:
            K_gpu = self._blake3.derive_keys_batch(M_gpu, ct_hash, self.z or b'\x00' * 32, ok_mask)
        else:
            K_gpu = self._blake3.derive_keys_batch(M_gpu, ct_hash, self.z or b'\x00' * 32, ok_mask, self.msg_bytes)
        
        K = cp.asnumpy(K_gpu)
        
        # Return with backward compatibility
        if not return_ct:
            if return_msg:
                return K, None, None, M_np
            return K, None, None  # 3 values (backward compat)
        
        U_out = cp.asnumpy(U_t)
        V_out = cp.asnumpy(V_t)
        
        if return_msg:
            return K, U_out, V_out, M_np  # 4 values (v2.0)
        return K, U_out, V_out  # 3 values (backward compat)
    
    def decaps_batch(self, U: np.ndarray, V: np.ndarray) -> np.ndarray:
        """
        Batch decapsulation (decryption) - returns shared keys.
        
        For GPU efficiency, takes raw (U, V) arrays.
        Use decaps() for single-message wire-based operation.
        
        Args:
            U: (batch, n) ciphertext part 1
            V: (batch, msg_bits) ciphertext part 2
            
        Returns:
            K: (batch, 32) shared keys
        """
        if self.A is None or self.s is None:
            raise ValueError("Keys not initialized (need both pk and sk)")
        
        batch = U.shape[0]
        
        # 1. Transfer to GPU
        U_gpu = cp.asarray(U, dtype=cp.uint32)
        V_gpu = cp.asarray(V, dtype=cp.uint32)
        
        # 2. S_dot_U
        S_dot_U = sdot_U(self.s, U_gpu)
        
        # 3. V_dec
        V_dec = V_gpu - S_dot_U[:, None]
        
        # 4. Decode bits
        V_signed = V_dec.view(cp.int32)
        threshold = np.int32(1 << 30)
        M_bits = ((V_signed > threshold) | (V_signed < -threshold)).astype(cp.uint8)
        
        # 5. Pack bits
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
        
        # 8. FO verification
        U2_t = cp.ascontiguousarray(U2.T)
        V2_t = cp.ascontiguousarray(V2.T)
        
        U_match = cp.all(U_gpu == U2_t, axis=1)
        V_match = cp.all(V_gpu == V2_t, axis=1)
        ok_mask = (U_match & V_match).astype(cp.uint8)
        
        # 9. ct_hash
        ct_hash = self._blake3.hash_u32_concat_batch(U_gpu, V_gpu, self.n, self.msg_bits)
        
        # 10. Derive keys with implicit rejection
        if self.n == 256:
            K_gpu = self._blake3.derive_keys_batch(M_recovered, ct_hash, self.z, ok_mask)
        else:
            K_gpu = self._blake3.derive_keys_batch(M_recovered, ct_hash, self.z, ok_mask, self.msg_bytes)
        
        return cp.asnumpy(K_gpu)


# =============================================================================
# Batch Hybrid KEM (KEM + DEM Integration)
# =============================================================================

class BatchHybridKEM:
    """
    GPU-accelerated Hybrid KEM combining:
    - BatchLWEKEM for key encapsulation
    - GPUChaCha20Poly1305 for data encryption
    
    v2.0: Wire-based ciphertext with compression support.
    """
    
    def __init__(
        self,
        n: int = N_FIXED,
        eta: int = ETA_DEFAULT,
        device_id: int = 0,
        use_compression: bool = True,  # v2.0: Default to compressed
    ):
        self.n = n
        self.device_id = device_id
        self.use_compression = use_compression and COMPRESSION_AVAILABLE
        
        self.kem = BatchLWEKEM(
            n=n, k=n, eta=eta, device_id=device_id,
            use_compression=use_compression
        )
        
        self._dem: Optional[GPUChaCha20Poly1305] = None
    
    def key_gen(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Generate key pair."""
        return self.kem.key_gen(seed=seed)
    
    def load_public_key(self, pk_bytes: bytes) -> None:
        """Load public key (for encryption only)."""
        self.kem.load_public_key(pk_bytes)
    
    def load_secret_key(self, sk_bytes: bytes) -> None:
        """Load secret key (for decryption)."""
        self.kem.load_secret_key(sk_bytes)
    
    def load_keys(self, pk_bytes: bytes, sk_bytes: bytes) -> None:
        """Load both public and secret keys."""
        self.load_public_key(pk_bytes)
        self.load_secret_key(sk_bytes)
    
    # =========================================================================
    # Single Message Interface (v2.0: Wire-Based with Correct KDF)
    # =========================================================================
    
    def encrypt(self, plaintext: bytes) -> BatchCiphertext:
        """
        Encrypt a single message.
        
        v2.0: Uses wire-based KDF for K (matches decrypt side!)
        
        Returns:
            BatchCiphertext (use to_bytes_compressed() for transmission)
        """
        # 1. KEM encaps with wire-based KDF
        K, kem_wire = self.kem.encaps()
        
        # 2. Decompress to get U/V for storage
        if self.use_compression:
            U, V = decompress_ciphertext(kem_wire, self.kem.q)
        else:
            u_len, v_len = struct.unpack('>II', kem_wire[:8])
            off = 8
            U = np.frombuffer(kem_wire[off:off + u_len * 4], dtype='<u4').copy()
            off += u_len * 4
            V = np.frombuffer(kem_wire[off:off + v_len * 4], dtype='<u4').copy()
        
        # 3. AAD from kem_wire (canonical form)
        aad = _sha256(b"batch-hybrid-aad", kem_wire)
        
        # 4. DEM: Encrypt with ChaCha20-Poly1305
        dem = GPUChaCha20Poly1305(K, device_id=self.device_id)
        nonce = secrets.token_bytes(24)
        
        ciphertext, tag = dem.encrypt(plaintext, nonce, aad)
        
        return BatchCiphertext(
            U=U, V=V,
            nonce=nonce, ciphertext=ciphertext, tag=tag,
            n=self.kem.n, msg_bits=self.kem.msg_bits,
            kem_wire=kem_wire,  # v2.0: Store canonical form
            q=self.kem.q,
        )
    
    def decrypt(self, ct: Union[BatchCiphertext, bytes]) -> bytes:
        """
        Decrypt a single message.
        
        v2.0: AAD is derived from kem_wire (canonical form)!
        
        Args:
            ct: BatchCiphertext or serialized bytes
        """
        if isinstance(ct, bytes):
            # Auto-detect format by header size
            if len(ct) >= 16:
                # Try compressed format first (16-byte header)
                try:
                    ct = BatchCiphertext.from_bytes_compressed(ct, self.kem.q)
                except:
                    ct = BatchCiphertext.from_bytes(ct)
            else:
                ct = BatchCiphertext.from_bytes(ct)
        
        # 1. Get kem_wire (canonical form)
        kem_wire = ct.get_kem_wire()
        
        # 2. KEM decaps with wire-based FO
        K = self.kem.decaps_single_wire(ct.U, ct.V, kem_wire)
        
        # 3. AAD from kem_wire (MUST match encrypt side!)
        aad = _sha256(b"batch-hybrid-aad", kem_wire)
        
        # 4. DEM: Decrypt
        dem = GPUChaCha20Poly1305(K, device_id=self.device_id)
        
        return dem.decrypt(ct.ciphertext, ct.tag, ct.nonce, aad)
    
    # =========================================================================
    # Batch Interface (High Throughput)
    # =========================================================================
    
    def encrypt_batch(self, plaintexts: List[bytes]) -> List[BatchCiphertext]:
        """
        Encrypt multiple messages in parallel.
        
        v2.0: Uses wire-based KDF for each message.
        """
        batch = len(plaintexts)
        
        # Get (U, V, M) - we'll recompute K with wire-based KDF
        _, U, V, M_np = self.kem.encaps_batch(batch, return_ct=True, return_msg=True)
        
        results = []
        for i in range(batch):
            # Create kem_wire (canonical form)
            if self.use_compression:
                kem_wire = compress_ciphertext(U[i], V[i], self.kem.q)
            else:
                kem_wire = (
                    struct.pack('>II', len(U[i]), len(V[i])) +
                    U[i].astype('<u4').tobytes() +
                    V[i].astype('<u4').tobytes()
                )
            
            # Wire-based KDF (MUST match decrypt side!)
            ct_hash = _sha256(b"ct_hash", kem_wire)
            K = _sha256(b"shared_key", M_np[i].tobytes(), ct_hash)
            
            # AAD from kem_wire
            aad = _sha256(b"batch-hybrid-aad", kem_wire)
            
            dem = GPUChaCha20Poly1305(K, device_id=self.device_id)
            nonce = secrets.token_bytes(24)
            
            ciphertext, tag = dem.encrypt(plaintexts[i], nonce, aad)
            
            results.append(BatchCiphertext(
                U=U[i], V=V[i],
                nonce=nonce, ciphertext=ciphertext, tag=tag,
                n=self.kem.n, msg_bits=self.kem.msg_bits,
                kem_wire=kem_wire,
                q=self.kem.q,
            ))
        
        return results
    
    def decrypt_batch(self, ciphertexts: List[Union[BatchCiphertext, bytes]]) -> List[bytes]:
        """
        Decrypt multiple messages in parallel.
        
        v2.0: Uses wire-based FO and kem_wire-derived AAD.
        """
        cts = []
        for ct in ciphertexts:
            if isinstance(ct, bytes):
                try:
                    cts.append(BatchCiphertext.from_bytes_compressed(ct, self.kem.q))
                except:
                    cts.append(BatchCiphertext.from_bytes(ct))
            else:
                cts.append(ct)
        
        batch = len(cts)
        
        # Decrypt each message with wire-based FO
        results = []
        for i in range(batch):
            ct = cts[i]
            kem_wire = ct.get_kem_wire()
            
            # Decaps with wire-based FO
            K = self.kem.decaps_single_wire(ct.U, ct.V, kem_wire)
            
            # AAD from kem_wire
            aad = _sha256(b"batch-hybrid-aad", kem_wire)
            
            dem = GPUChaCha20Poly1305(K, device_id=self.device_id)
            plaintext = dem.decrypt(ct.ciphertext, ct.tag, ct.nonce, aad)
            results.append(plaintext)
        
        return results
    
    # =========================================================================
    # KEM-only Interface
    # =========================================================================
    
    def encaps_batch(self, batch: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """KEM-only batch encapsulation."""
        return self.kem.encaps_batch(batch, return_ct=True)
    
    def decaps_batch(self, U: np.ndarray, V: np.ndarray) -> np.ndarray:
        """KEM-only batch decapsulation."""
        return self.kem.decaps_batch(U, V)


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute batch hybrid KEM tests."""
    import time
    
    print("=" * 70)
    print("Meteor-NC Batch Hybrid KEM v2.0 (Compression Support)")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Basic Hybrid Encryption
    print("\n[Test 1] Single Message Encrypt/Decrypt")
    print("-" * 40)
    
    hybrid = BatchHybridKEM(use_compression=True)
    pk, sk = hybrid.key_gen()
    hybrid.load_secret_key(sk)
    
    print(f"  PK size: {len(pk)} bytes")
    print(f"  SK size: {len(sk)} bytes")
    
    plaintext = b"Hello, Meteor-NC Batch Hybrid KEM v2.0!"
    ct = hybrid.encrypt(plaintext)
    recovered = hybrid.decrypt(ct)
    
    single_ok = (plaintext == recovered)
    results["single"] = single_ok
    print(f"  Single message: {'PASS' if single_ok else 'FAIL'}")
    
    # Test 2: Compressed Serialization
    print("\n[Test 2] Compressed Ciphertext Serialization")
    print("-" * 40)
    
    ct_compressed = ct.to_bytes_compressed()
    ct_uncompressed = ct.to_bytes()
    
    print(f"  Uncompressed: {len(ct_uncompressed)} bytes")
    print(f"  Compressed:   {len(ct_compressed)} bytes")
    print(f"  Reduction:    {100 * (1 - len(ct_compressed) / len(ct_uncompressed)):.1f}%")
    
    ct_recovered = BatchCiphertext.from_bytes_compressed(ct_compressed)
    recovered2 = hybrid.decrypt(ct_recovered)
    
    serial_ok = (plaintext == recovered2)
    results["serialization"] = serial_ok
    print(f"  Serialization roundtrip: {'PASS' if serial_ok else 'FAIL'}")
    
    # Test 3: Wire-Based KEM (Single)
    print("\n[Test 3] Wire-Based KEM (Single Message)")
    print("-" * 40)
    
    kem = BatchLWEKEM(use_compression=True)
    kem.key_gen()
    
    K1, wire = kem.encaps()
    K2 = kem.decaps(wire)
    
    wire_size = len(wire)
    expected_size = compressed_size(kem.n, kem.msg_bits)
    
    wire_ok = (K1 == K2) and (wire_size == expected_size)
    results["wire_kem"] = wire_ok
    print(f"  Wire size: {wire_size} bytes (expected {expected_size})")
    print(f"  Key match: {'PASS' if K1 == K2 else 'FAIL'}")
    
    # Test 4: Sender/Receiver Separation
    print("\n[Test 4] Sender/Receiver Separation")
    print("-" * 40)
    
    receiver = BatchHybridKEM()
    pk, sk = receiver.key_gen()
    
    sender = BatchHybridKEM()
    sender.load_public_key(pk)
    
    ct = sender.encrypt(b"Secret message")
    
    try:
        _ = sender.decrypt(ct)
        sender_blocked = False
    except (ValueError, Exception):
        sender_blocked = True
    
    receiver.load_secret_key(sk)
    recovered = receiver.decrypt(ct)
    
    sep_ok = sender_blocked and (recovered == b"Secret message")
    results["separation"] = sep_ok
    print(f"  Sender blocked: {'PASS' if sender_blocked else 'FAIL'}")
    print(f"  Receiver decrypts: {'PASS' if recovered == b'Secret message' else 'FAIL'}")
    
    # Test 5: Batch Encryption
    print("\n[Test 5] Batch Encrypt/Decrypt")
    print("-" * 40)
    
    messages = [f"Message {i}: " + secrets.token_hex(16) for i in range(100)]
    messages_bytes = [m.encode() for m in messages]
    
    cts = hybrid.encrypt_batch(messages_bytes)
    recovered_batch = hybrid.decrypt_batch(cts)
    
    batch_ok = all(m == r for m, r in zip(messages_bytes, recovered_batch))
    results["batch"] = batch_ok
    print(f"  Batch 100: {'PASS' if batch_ok else 'FAIL'}")
    
    # Test 6: Tamper Detection
    print("\n[Test 6] Tamper Detection")
    print("-" * 40)
    
    ct = hybrid.encrypt(b"Authentic message")
    
    ct_tampered = BatchCiphertext(
        U=ct.U, V=ct.V,
        nonce=ct.nonce,
        ciphertext=bytes([ct.ciphertext[0] ^ 1]) + ct.ciphertext[1:],
        tag=ct.tag,
        n=ct.n, msg_bits=ct.msg_bits
    )
    
    try:
        _ = hybrid.decrypt(ct_tampered)
        tamper_detected = False
    except ValueError:
        tamper_detected = True
    
    results["tamper"] = tamper_detected
    print(f"  Tamper detected: {'PASS' if tamper_detected else 'FAIL'}")
    
    # Test 7: KEM Throughput
    print("\n[Test 7] KEM Throughput (GPU)")
    print("-" * 40)
    
    kem = BatchLWEKEM()
    kem.key_gen()
    
    # Warmup
    _ = kem.encaps_batch(1000)
    cp.cuda.Stream.null.synchronize()
    
    for batch in [10000, 100000, 1000000]:
        start = time.perf_counter()
        K, U, V = kem.encaps_batch(batch)
        cp.cuda.Stream.null.synchronize()
        enc_time = time.perf_counter() - start
        
        start = time.perf_counter()
        _ = kem.decaps_batch(U, V)
        cp.cuda.Stream.null.synchronize()
        dec_time = time.perf_counter() - start
        
        print(f"  Batch {batch:>7,}:")
        print(f"    Encaps: {batch/enc_time:>12,.0f} ops/sec")
        print(f"    Decaps: {batch/dec_time:>12,.0f} ops/sec")
    
    # Test 8: Multi-Level Size Check
    print("\n[Test 8] Multi-Level Compression Sizes")
    print("-" * 40)
    
    for n in [256, 512, 1024]:
        kem = BatchLWEKEM(n=n, use_compression=True)
        kem.key_gen()
        
        K, wire = kem.encaps()
        expected = compressed_size(n, n)
        
        print(f"  n={n}: {len(wire)}B (expected {expected}B) {'✓' if len(wire) == expected else '✗'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
