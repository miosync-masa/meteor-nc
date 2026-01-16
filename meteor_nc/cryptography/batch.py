# meteor_nc/cryptography/batch.py
"""
Meteor-NC Batch Hybrid KEM (GPU-Accelerated)

GPU-parallel hybrid encryption combining:
- BatchLWEKEM: GPU-accelerated LWE key encapsulation
- GPUChaCha20Poly1305: GPU-accelerated authenticated encryption

Features:
- q = 2^32 (uint32 overflow = mod)
- n = k = 256/512/1024 (multi-security level)
- Custom CUDA kernels for all hot paths
- core.py compatible interface

Target: 1M+ ops/sec on modern GPUs
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
)

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
    
    Wire format:
        | header (12B) | U (n*4B) | V (msg_bits*4B) | nonce (24B) | ct | tag (16B) |
    """
    U: np.ndarray           # (n,) uint32 - KEM ciphertext part 1
    V: np.ndarray           # (msg_bits,) uint32 - KEM ciphertext part 2
    nonce: bytes            # 24 bytes - DEM nonce
    ciphertext: bytes       # Variable - DEM ciphertext
    tag: bytes              # 16 bytes - DEM auth tag
    n: int = 256
    msg_bits: int = 256
    
    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        u_bytes = self.U.astype('<u4').tobytes()
        v_bytes = self.V.astype('<u4').tobytes()
        ct_len = len(self.ciphertext)
        
        return (
            struct.pack('>III', self.n, self.msg_bits, ct_len) +  # header (12B)
            u_bytes +                                              # n*4 bytes
            v_bytes +                                              # msg_bits*4 bytes
            self.nonce +                                           # 24 bytes
            self.ciphertext +                                      # variable
            self.tag                                               # 16 bytes
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'BatchCiphertext':
        """Deserialize from wire format."""
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
            n=n, msg_bits=msg_bits
        )


# =============================================================================
# Batch LWE-KEM (GPU-Accelerated)
# =============================================================================

class BatchLWEKEM:
    """
    GPU-parallel batch KEM with correct PKE design.
    
    This is the KEM-only component. For hybrid encryption,
    use BatchHybridKEM which combines this with DEM.
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
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """Generate LWE key pair."""
        # 1. pk_seed (PUBLIC)
        self.pk_seed = secrets.token_bytes(32)
        
        # 2. Reconstruct A
        self.A = self._reconstruct_A(self.pk_seed)
        
        # 3. s from TRUE RANDOMNESS (SECRET)
        s_bytes = secrets.token_bytes(self.n * 4)
        s_raw = np.frombuffer(s_bytes, dtype="<u4").copy()
        s_np = ((s_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
        self.s = cp.asarray(s_np, dtype=cp.int32)
        
        # 4. e (error)
        e_seed = secrets.token_bytes(32)
        hkdf = HKDF(salt=_sha256(b"batch-kem-v2-error"))
        prk = hkdf.extract(e_seed)
        seed_e = np.array([int.from_bytes(hkdf.expand(prk, b"e", 8), "big")], dtype=np.uint64)
        e = cbd_i32(cp.asarray(seed_e), self.k, self.eta).flatten()
        
        # 5. b = A @ s + e
        self.b = b_from_As(self.A, self.s, e)
        
        # 6. pk_hash
        b_bytes = cp.asnumpy(self.b).astype("<u4").tobytes()
        self.pk_hash = _sha256(b"pk", self.pk_seed, b_bytes)
        
        # 7. z (implicit rejection seed)
        self.z = secrets.token_bytes(32)
        
        # 8. Serialize
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
    
    def encaps_batch(
        self,
        batch: int,
        return_ct: bool = True
    ) -> Tuple[np.ndarray, Optional[np.ndarray], Optional[np.ndarray]]:
        """Batch encapsulation (encryption) - returns shared keys."""
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
        
        # 9. ct_hash
        ct_hash = self._blake3.hash_u32_concat_batch(U_t, V_t, self.n, self.msg_bits)
        
        # 10. Derive shared keys
        ok_mask = cp.ones(batch, dtype=cp.uint8)
        if self.n == 256:
            K_gpu = self._blake3.derive_keys_batch(M_gpu, ct_hash, self.z or b'\x00' * 32, ok_mask)
        else:
            K_gpu = self._blake3.derive_keys_batch(M_gpu, ct_hash, self.z or b'\x00' * 32, ok_mask, self.msg_bytes)
        
        K = cp.asnumpy(K_gpu)
        
        if not return_ct:
            return K, None, None
        
        return K, cp.asnumpy(U_t), cp.asnumpy(V_t)
    
    def decaps_batch(self, U: np.ndarray, V: np.ndarray) -> np.ndarray:
        """Batch decapsulation (decryption) - returns shared keys."""
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
    
    Provides core.py compatible interface plus batch operations.
    """
    
    def __init__(
        self,
        n: int = N_FIXED,
        eta: int = ETA_DEFAULT,
        device_id: int = 0,
    ):
        self.n = n
        self.device_id = device_id
        
        # Initialize KEM
        self.kem = BatchLWEKEM(n=n, k=n, eta=eta, device_id=device_id)
        
        # DEM will be initialized per-key
        self._dem: Optional[GPUChaCha20Poly1305] = None
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """Generate key pair."""
        return self.kem.key_gen()
    
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
    # Single Message Interface (core.py compatible)
    # =========================================================================
    
    def encrypt(self, plaintext: bytes) -> BatchCiphertext:
        """
        Encrypt a single message.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            BatchCiphertext containing KEM ciphertext + DEM ciphertext
        """
        # 1. KEM: Get shared key
        K, U, V = self.kem.encaps_batch(1, return_ct=True)
        shared_key = K[0]
        
        # 2. DEM: Encrypt with ChaCha20-Poly1305
        dem = GPUChaCha20Poly1305(shared_key, device_id=self.device_id)
        nonce = secrets.token_bytes(24)
        
        # AAD includes KEM ciphertext hash for binding
        aad = _sha256(b"batch-hybrid-aad", U[0].tobytes(), V[0].tobytes())
        
        ciphertext, tag = dem.encrypt(plaintext, nonce, aad)
        
        return BatchCiphertext(
            U=U[0], V=V[0],
            nonce=nonce, ciphertext=ciphertext, tag=tag,
            n=self.kem.n, msg_bits=self.kem.msg_bits
        )
    
    def decrypt(self, ct: Union[BatchCiphertext, bytes]) -> bytes:
        """
        Decrypt a single message.
        
        Args:
            ct: BatchCiphertext or serialized bytes
            
        Returns:
            Decrypted plaintext
        """
        if isinstance(ct, bytes):
            ct = BatchCiphertext.from_bytes(ct)
        
        # 1. KEM: Recover shared key
        U_batch = ct.U.reshape(1, -1)
        V_batch = ct.V.reshape(1, -1)
        K = self.kem.decaps_batch(U_batch, V_batch)
        shared_key = K[0]
        
        # 2. DEM: Decrypt
        dem = GPUChaCha20Poly1305(shared_key, device_id=self.device_id)
        
        aad = _sha256(b"batch-hybrid-aad", ct.U.tobytes(), ct.V.tobytes())
        
        return dem.decrypt(ct.ciphertext, ct.tag, ct.nonce, aad)
    
    # =========================================================================
    # Batch Interface (High Throughput)
    # =========================================================================
    
    def encrypt_batch(
        self,
        plaintexts: List[bytes],
    ) -> List[BatchCiphertext]:
        """
        Encrypt multiple messages in parallel.
        
        Args:
            plaintexts: List of messages to encrypt
            
        Returns:
            List of BatchCiphertext
        """
        batch = len(plaintexts)
        
        # 1. KEM: Get shared keys for all messages
        K, U, V = self.kem.encaps_batch(batch, return_ct=True)
        
        # 2. DEM: Encrypt each message
        # TODO: Batch DEM encryption with GPU kernel
        results = []
        for i in range(batch):
            dem = GPUChaCha20Poly1305(K[i], device_id=self.device_id)
            nonce = secrets.token_bytes(24)
            aad = _sha256(b"batch-hybrid-aad", U[i].tobytes(), V[i].tobytes())
            
            ciphertext, tag = dem.encrypt(plaintexts[i], nonce, aad)
            
            results.append(BatchCiphertext(
                U=U[i], V=V[i],
                nonce=nonce, ciphertext=ciphertext, tag=tag,
                n=self.kem.n, msg_bits=self.kem.msg_bits
            ))
        
        return results
    
    def decrypt_batch(
        self,
        ciphertexts: List[Union[BatchCiphertext, bytes]],
    ) -> List[bytes]:
        """
        Decrypt multiple messages in parallel.
        
        Args:
            ciphertexts: List of BatchCiphertext or serialized bytes
            
        Returns:
            List of decrypted plaintexts
        """
        # Parse ciphertexts
        cts = []
        for ct in ciphertexts:
            if isinstance(ct, bytes):
                cts.append(BatchCiphertext.from_bytes(ct))
            else:
                cts.append(ct)
        
        batch = len(cts)
        
        # 1. KEM: Recover shared keys
        U_batch = np.stack([ct.U for ct in cts])
        V_batch = np.stack([ct.V for ct in cts])
        K = self.kem.decaps_batch(U_batch, V_batch)
        
        # 2. DEM: Decrypt each message
        # TODO: Batch DEM decryption with GPU kernel
        results = []
        for i in range(batch):
            dem = GPUChaCha20Poly1305(K[i], device_id=self.device_id)
            aad = _sha256(b"batch-hybrid-aad", cts[i].U.tobytes(), cts[i].V.tobytes())
            
            plaintext = dem.decrypt(cts[i].ciphertext, cts[i].tag, cts[i].nonce, aad)
            results.append(plaintext)
        
        return results
    
    # =========================================================================
    # KEM-only Interface (for advanced usage)
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
    print("Meteor-NC Batch Hybrid KEM (GPU-Accelerated)")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Basic Hybrid Encryption
    print("\n[Test 1] Single Message Encrypt/Decrypt")
    print("-" * 40)
    
    hybrid = BatchHybridKEM()
    pk, sk = hybrid.key_gen()
    hybrid.load_secret_key(sk)
    
    print(f"  PK size: {len(pk)} bytes")
    print(f"  SK size: {len(sk)} bytes")
    
    plaintext = b"Hello, Meteor-NC Batch Hybrid KEM!"
    ct = hybrid.encrypt(plaintext)
    recovered = hybrid.decrypt(ct)
    
    single_ok = (plaintext == recovered)
    results["single"] = single_ok
    print(f"  Single message: {'PASS' if single_ok else 'FAIL'}")
    
    # Test 2: Serialization
    print("\n[Test 2] Ciphertext Serialization")
    print("-" * 40)
    
    ct_bytes = ct.to_bytes()
    ct_recovered = BatchCiphertext.from_bytes(ct_bytes)
    recovered2 = hybrid.decrypt(ct_recovered)
    
    serial_ok = (plaintext == recovered2)
    results["serialization"] = serial_ok
    print(f"  Serialization roundtrip: {'PASS' if serial_ok else 'FAIL'}")
    print(f"  Ciphertext size: {len(ct_bytes)} bytes")
    
    # Test 3: Batch Encryption
    print("\n[Test 3] Batch Encrypt/Decrypt")
    print("-" * 40)
    
    messages = [f"Message {i}: " + secrets.token_hex(16) for i in range(100)]
    messages_bytes = [m.encode() for m in messages]
    
    cts = hybrid.encrypt_batch(messages_bytes)
    recovered_batch = hybrid.decrypt_batch(cts)
    
    batch_ok = all(m == r for m, r in zip(messages_bytes, recovered_batch))
    results["batch"] = batch_ok
    print(f"  Batch 100: {'PASS' if batch_ok else 'FAIL'}")
    
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
    
    # Test 5: Tamper Detection
    print("\n[Test 5] Tamper Detection")
    print("-" * 40)
    
    hybrid = BatchHybridKEM()
    pk, sk = hybrid.key_gen()
    hybrid.load_secret_key(sk)
    
    ct = hybrid.encrypt(b"Authentic message")
    
    # Tamper with ciphertext
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
    
    # Test 6: KEM Throughput
    print("\n[Test 6] KEM Throughput (GPU)")
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
    
    # Test 7: Million Target
    print("\n[Test 7] Million Ops Target")
    print("-" * 40)
    
    batch = 1_000_000
    
    start = time.perf_counter()
    K, _, _ = kem.encaps_batch(batch, return_ct=False)
    cp.cuda.Stream.null.synchronize()
    enc_time = time.perf_counter() - start
    
    rate = batch / enc_time
    million_ok = rate >= 1_000_000
    results["million"] = million_ok
    
    print(f"  KEM Processing: {rate:,.0f} ops/sec")
    print(f"  Target (1M): {'✅ ACHIEVED!' if million_ok else 'Not yet'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
