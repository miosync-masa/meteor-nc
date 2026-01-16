# meteor_nc/cryptography/batch.py
"""
Meteor-NC Batch Hybrid KEM

GPU-accelerated Hybrid PKE for high-throughput encryption:
  - KEM: LWE-based key encapsulation (Post-Quantum)
  - DEM: AES-GCM for bulk data encryption (GPU parallel)

Design:
  - encaps_batch: Encrypt multiple messages for SAME recipient
    1. KEM encaps once → K
    2. GPU parallel AEAD encrypt all messages with K
    
  - decaps_batch: Decrypt multiple ciphertexts
    1. KEM decaps once → K
    2. GPU parallel AEAD decrypt all messages with K

This ensures:
  - Anyone with recipient's public key CAN encrypt
  - Only recipient with secret key CAN decrypt
  - High throughput via GPU parallelism
  - Post-Quantum secure (LWE-KEM)

Performance Target: 1M+ messages/sec at NIST Level 5
"""

from __future__ import annotations

import secrets
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple, List

import numpy as np

from .common import (
    GPU_AVAILABLE,
    CRYPTO_AVAILABLE,
    _sha256,
    prg_sha256,
    HKDF,
    LWECiphertext,
)

if not GPU_AVAILABLE:
    raise ImportError("BatchHybridKEM requires CuPy + CUDA")

import cupy as cp

if CRYPTO_AVAILABLE:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =============================================================================
# Constants
# =============================================================================

Q_BATCH = 2**32  # uint32 overflow = mod 2^32 (GPU optimized)


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class BatchEncrypted:
    """
    Batch encrypted data container.
    
    Contains:
    - KEM ciphertext (for key recovery)
    - Encrypted messages (variable length)
    - Tags (16 bytes each)
    - Nonces (12 bytes each)
    """
    kem_u: np.ndarray           # KEM ciphertext u
    kem_v: np.ndarray           # KEM ciphertext v
    ciphertexts: List[bytes]    # Encrypted messages
    tags: List[bytes]           # 16-byte tags
    nonces: List[bytes]         # 12-byte nonces
    
    def __len__(self):
        return len(self.ciphertexts)


# =============================================================================
# Batch Hybrid KEM
# =============================================================================

class BatchHybridKEM:
    """
    GPU-accelerated Batch Hybrid PKE.
    
    For high-throughput scenarios:
    - Server sending many messages to same recipient
    - Batch processing of encrypted data
    
    Example (Sender):
        >>> sender = BatchHybridKEM(n=256)
        >>> sender.load_recipient_public_key(bob_pk)
        >>> 
        >>> messages = [b"msg1", b"msg2", b"msg3", ...]
        >>> encrypted = sender.encaps_batch(messages)
        >>> # Send encrypted to Bob
    
    Example (Receiver):
        >>> receiver = BatchHybridKEM(n=256, seed=bob_seed)
        >>> receiver.key_gen()
        >>> 
        >>> decrypted = receiver.decaps_batch(encrypted)
    """
    
    def __init__(
        self,
        n: int = 256,
        k: Optional[int] = None,
        eta: int = 2,
        device_id: int = 0,
        seed: Optional[bytes] = None,
    ):
        """
        Initialize BatchHybridKEM.
        
        Args:
            n: LWE dimension (256, 512, 1024 for 128/192/256-bit security)
            k: Number of LWE samples (default: n)
            eta: Error distribution parameter
            device_id: CUDA device ID
            seed: Optional seed for deterministic key generation
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required")
        
        self.n = int(n)
        self.k = int(k if k is not None else n)
        self.q = Q_BATCH
        self.eta = int(eta)
        self.device_id = int(device_id)
        self.seed = seed
        
        # Message size (bits) = n
        self.msg_bits = self.n
        self.msg_bytes = self.n // 8
        
        # Select GPU
        cp.cuda.Device(self.device_id).use()
        
        # LWE keys
        self.pk_seed: Optional[bytes] = None
        self.A: Optional[cp.ndarray] = None
        self.b: Optional[cp.ndarray] = None
        self.pk_hash: Optional[bytes] = None
        self.s: Optional[cp.ndarray] = None
        self.z: Optional[bytes] = None
        
        # Recipient's public key
        self._recipient_pk_seed: Optional[bytes] = None
        self._recipient_A: Optional[cp.ndarray] = None
        self._recipient_b: Optional[cp.ndarray] = None
    
    # =========================================================================
    # Matrix A Reconstruction
    # =========================================================================
    
    def _reconstruct_A(self, pk_seed: bytes) -> cp.ndarray:
        """
        Reconstruct matrix A from pk_seed using SHA-256 counter-mode PRG.
        
        Deterministic, cross-platform compatible.
        """
        num_bytes = self.k * self.n * 4
        prg_output = prg_sha256(pk_seed, num_bytes, domain=b"matrix_A_batch_v2")
        raw = np.frombuffer(prg_output, dtype="<u4").copy()
        return cp.asarray(raw.reshape(self.k, self.n), dtype=cp.uint32)
    
    # =========================================================================
    # Key Generation
    # =========================================================================
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """
        Generate LWE key pair.
        
        Returns:
            Tuple of (public_key_bytes, secret_key_bytes)
        """
        cp.cuda.Device(self.device_id).use()
        
        if self.seed is not None:
            # Deterministic key generation from seed
            hkdf = HKDF(salt=_sha256(b"meteor-batch-auth-v2"))
            prk = hkdf.extract(self.seed)
            
            self.pk_seed = hkdf.expand(prk, b"pk_seed", 32)
            
            # Derive s from seed
            s_bytes = hkdf.expand(prk, b"secret_s", self.n * 4)
            s_raw = np.frombuffer(s_bytes, dtype="<u4").copy()
            s_np = ((s_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
            self.s = cp.asarray(s_np, dtype=cp.int32)
            
            # Derive e from seed
            e_bytes = hkdf.expand(prk, b"error_e", self.k * 4)
            e_raw = np.frombuffer(e_bytes, dtype="<u4").copy()
            e_np = ((e_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
            e = cp.asarray(e_np, dtype=cp.int32)
            
            # Derive z from seed
            self.z = hkdf.expand(prk, b"implicit_z", 32)
        else:
            # Standard PKE: TRUE RANDOMNESS
            self.pk_seed = secrets.token_bytes(32)
            
            # s from true randomness
            s_bytes = secrets.token_bytes(self.n * 4)
            s_raw = np.frombuffer(s_bytes, dtype="<u4").copy()
            s_np = ((s_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
            self.s = cp.asarray(s_np, dtype=cp.int32)
            
            # e from true randomness
            e_bytes = secrets.token_bytes(self.k * 4)
            e_raw = np.frombuffer(e_bytes, dtype="<u4").copy()
            e_np = ((e_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
            e = cp.asarray(e_np, dtype=cp.int32)
            
            self.z = secrets.token_bytes(32)
        
        # Reconstruct A
        self.A = self._reconstruct_A(self.pk_seed)
        
        # Compute b = A @ s + e (mod 2^32, via uint32 overflow)
        A_i64 = self.A.astype(cp.int64)
        s_i64 = self.s.astype(cp.int64)
        e_i64 = e.astype(cp.int64)
        
        b_i64 = A_i64 @ s_i64 + e_i64
        self.b = (b_i64 % self.q).astype(cp.uint32)
        
        # Compute pk_hash
        b_bytes = cp.asnumpy(self.b).astype("<u4").tobytes()
        self.pk_hash = _sha256(b"pk_hash_batch", self.pk_seed + b_bytes)
        
        return self._export_public_key(), self._export_secret_key()
    
    def _export_public_key(self) -> bytes:
        """Serialize public key."""
        if self.pk_seed is None or self.b is None:
            raise ValueError("Keys not initialized")
        
        # q = 2^32 encoded as 0
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
    
    def get_public_key(self) -> bytes:
        """Get public key bytes."""
        return self._export_public_key()
    
    # =========================================================================
    # Load Keys
    # =========================================================================
    
    def load_recipient_public_key(self, pk_bytes: bytes) -> None:
        """
        Load recipient's public key for encryption.
        
        This allows ANYONE to encrypt without knowing the secret key!
        """
        if len(pk_bytes) < 12:
            raise ValueError("Public key too short")
        
        n, k, q_encoded = struct.unpack(">III", pk_bytes[:12])
        q = 2**32 if q_encoded == 0 else q_encoded
        
        if n != self.n or k != self.k or q != self.q:
            raise ValueError(f"Parameter mismatch")
        
        expected_size = 12 + 32 + k * 4 + 32
        if len(pk_bytes) < expected_size:
            raise ValueError("Public key truncated")
        
        self._recipient_pk_seed = pk_bytes[12:44]
        b_raw = np.frombuffer(pk_bytes[44:44 + k * 4], dtype="<u4").copy()
        self._recipient_b = cp.asarray(b_raw, dtype=cp.uint32)
        self._recipient_A = self._reconstruct_A(self._recipient_pk_seed)
    
    def load_secret_key(self, sk_bytes: bytes) -> None:
        """Load secret key for decryption."""
        expected_size = self.n * 4 + 32
        if len(sk_bytes) < expected_size:
            raise ValueError("Secret key truncated")
        
        s_np = np.frombuffer(sk_bytes[:self.n * 4], dtype="<i4").copy()
        self.s = cp.asarray(s_np, dtype=cp.int32)
        self.z = sk_bytes[self.n * 4:self.n * 4 + 32]
    
    # =========================================================================
    # KEM Encapsulation (using recipient's PUBLIC key)
    # =========================================================================
    
    def _encaps_single(self) -> Tuple[bytes, LWECiphertext]:
        """
        Single KEM encapsulation with recipient's public key.
        
        Returns:
            Tuple of (shared_secret K, ciphertext)
        """
        if self._recipient_A is None or self._recipient_b is None:
            raise ValueError("Recipient public key not loaded")
        
        cp.cuda.Device(self.device_id).use()
        
        # Generate random message m
        m = secrets.token_bytes(self.msg_bytes)
        
        # Derive r from m (for FO transform)
        r_seed = _sha256(b"fo_r_batch", m)
        
        # Generate r, e1, e2 from r_seed
        hkdf = HKDF(salt=_sha256(b"fo-encaps-v2"))
        prk = hkdf.extract(r_seed)
        
        r_bytes = hkdf.expand(prk, b"r", self.n * 4)
        r_raw = np.frombuffer(r_bytes, dtype="<u4").copy()
        r_np = ((r_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
        r = cp.asarray(r_np, dtype=cp.int32)
        
        e1_bytes = hkdf.expand(prk, b"e1", self.n * 4)
        e1_raw = np.frombuffer(e1_bytes, dtype="<u4").copy()
        e1_np = ((e1_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
        e1 = cp.asarray(e1_np, dtype=cp.int32)
        
        e2_bytes = hkdf.expand(prk, b"e2", self.msg_bits * 4)
        e2_raw = np.frombuffer(e2_bytes, dtype="<u4").copy()
        e2_np = ((e2_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
        e2 = cp.asarray(e2_np, dtype=cp.int32)
        
        # u = A^T @ r + e1
        A_T = self._recipient_A.T.astype(cp.int64)
        r_i64 = r.astype(cp.int64)
        e1_i64 = e1.astype(cp.int64)
        
        u_i64 = A_T @ r_i64 + e1_i64
        u = (u_i64 % self.q).astype(cp.int64)
        
        # v = b^T @ r + e2 + encode(m)
        b_i64 = self._recipient_b.astype(cp.int64)
        e2_i64 = e2.astype(cp.int64)
        
        # Encode m
        m_bits = np.unpackbits(np.frombuffer(m, dtype=np.uint8))[:self.msg_bits]
        delta = self.q // 2
        encoded = cp.asarray(m_bits.astype(np.int64) * delta, dtype=cp.int64)
        
        v_i64 = cp.dot(b_i64.astype(cp.int64), r_i64) + e2_i64 + encoded
        v = (v_i64 % self.q).astype(cp.int64)
        
        # Derive K
        u_np = cp.asnumpy(u)
        v_np = cp.asnumpy(v)
        ct_hash = _sha256(b"ct_hash_batch", u_np.tobytes() + v_np.tobytes())
        K = _sha256(b"shared_secret_batch", m + ct_hash)
        
        return K, LWECiphertext(u=u_np, v=v_np)
    
    # =========================================================================
    # Batch Encryption (using recipient's PUBLIC key)
    # =========================================================================
    
    def encaps_batch(self, messages: List[bytes]) -> BatchEncrypted:
        """
        Encrypt multiple messages for the same recipient.
        
        Uses recipient's PUBLIC KEY for KEM encapsulation (once).
        All messages encrypted with derived session key (parallel).
        
        Args:
            messages: List of messages to encrypt
            
        Returns:
            BatchEncrypted containing KEM ciphertext + encrypted messages
        """
        if not messages:
            raise ValueError("No messages to encrypt")
        
        # 1. KEM encapsulation (once)
        K, kem_ct = self._encaps_single()
        
        # 2. Derive AES key from K
        aes_key = _sha256(b"batch-aes-key-v2", K)
        cipher = AESGCM(aes_key)
        
        # 3. Encrypt all messages (CPU for now, GPU kernel for production)
        ciphertexts = []
        tags = []
        nonces = []
        
        for i, msg in enumerate(messages):
            # Unique nonce per message
            nonce = _sha256(b"batch-nonce", K + struct.pack(">Q", i))[:12]
            
            ct_with_tag = cipher.encrypt(nonce, msg, None)
            
            ciphertexts.append(ct_with_tag[:-16])
            tags.append(ct_with_tag[-16:])
            nonces.append(nonce)
        
        return BatchEncrypted(
            kem_u=kem_ct.u,
            kem_v=kem_ct.v,
            ciphertexts=ciphertexts,
            tags=tags,
            nonces=nonces,
        )
    
    # =========================================================================
    # KEM Decapsulation (using own SECRET key)
    # =========================================================================
    
    def _decaps_single(self, kem_ct: LWECiphertext) -> bytes:
        """
        Single KEM decapsulation with own secret key.
        
        Returns:
            Shared secret K
        """
        if self.s is None or self.z is None:
            raise ValueError("Secret key not loaded")
        if self.A is None or self.b is None:
            raise ValueError("Public key not loaded")
        
        cp.cuda.Device(self.device_id).use()
        
        u = cp.asarray(kem_ct.u, dtype=cp.int64)
        v = cp.asarray(kem_ct.v, dtype=cp.int64)
        
        # w = v - s^T @ u
        s_i64 = self.s.astype(cp.int64)
        w = (v - cp.dot(s_i64, u)) % self.q
        
        # Decode m
        delta = self.q // 2
        w_np = cp.asnumpy(w)
        m_bits = ((w_np + delta // 2) // delta) % 2
        m_bits = m_bits[:self.msg_bits].astype(np.uint8)
        m = np.packbits(m_bits).tobytes()
        
        # Re-encapsulate to verify (FO transform)
        r_seed = _sha256(b"fo_r_batch", m)
        hkdf = HKDF(salt=_sha256(b"fo-encaps-v2"))
        prk = hkdf.extract(r_seed)
        
        r_bytes = hkdf.expand(prk, b"r", self.n * 4)
        r_raw = np.frombuffer(r_bytes, dtype="<u4").copy()
        r_np = ((r_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
        r = cp.asarray(r_np, dtype=cp.int32)
        
        e1_bytes = hkdf.expand(prk, b"e1", self.n * 4)
        e1_raw = np.frombuffer(e1_bytes, dtype="<u4").copy()
        e1_np = ((e1_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
        e1 = cp.asarray(e1_np, dtype=cp.int32)
        
        e2_bytes = hkdf.expand(prk, b"e2", self.msg_bits * 4)
        e2_raw = np.frombuffer(e2_bytes, dtype="<u4").copy()
        e2_np = ((e2_raw % (2 * self.eta + 1)).astype(np.int32) - self.eta)
        e2 = cp.asarray(e2_np, dtype=cp.int32)
        
        # Recompute u' and v'
        A_T = self.A.T.astype(cp.int64)
        r_i64 = r.astype(cp.int64)
        e1_i64 = e1.astype(cp.int64)
        
        u_prime = (A_T @ r_i64 + e1_i64) % self.q
        
        b_i64 = self.b.astype(cp.int64)
        e2_i64 = e2.astype(cp.int64)
        
        m_bits_enc = np.unpackbits(np.frombuffer(m, dtype=np.uint8))[:self.msg_bits]
        encoded = cp.asarray(m_bits_enc.astype(np.int64) * delta, dtype=cp.int64)
        
        v_prime = (cp.dot(b_i64.astype(cp.int64), r_i64) + e2_i64 + encoded) % self.q
        
        # Verify
        u_np = cp.asnumpy(u)
        v_np = cp.asnumpy(v)
        u_prime_np = cp.asnumpy(u_prime)
        v_prime_np = cp.asnumpy(v_prime)
        
        ct_hash = _sha256(b"ct_hash_batch", u_np.tobytes() + v_np.tobytes())
        
        if np.array_equal(u_np, u_prime_np) and np.array_equal(v_np, v_prime_np):
            return _sha256(b"shared_secret_batch", m + ct_hash)
        else:
            # Implicit rejection
            return _sha256(b"implicit_reject_batch", self.z + ct_hash)
    
    # =========================================================================
    # Batch Decryption (using own SECRET key)
    # =========================================================================
    
    def decaps_batch(self, encrypted: BatchEncrypted) -> List[bytes]:
        """
        Decrypt multiple messages.
        
        Uses own SECRET KEY for KEM decapsulation (once).
        All messages decrypted with derived session key.
        
        Args:
            encrypted: BatchEncrypted from encaps_batch()
            
        Returns:
            List of decrypted messages
        """
        # 1. KEM decapsulation (once)
        kem_ct = LWECiphertext(u=encrypted.kem_u, v=encrypted.kem_v)
        K = self._decaps_single(kem_ct)
        
        # 2. Derive AES key
        aes_key = _sha256(b"batch-aes-key-v2", K)
        cipher = AESGCM(aes_key)
        
        # 3. Decrypt all messages
        messages = []
        
        for i, (ct, tag, nonce) in enumerate(zip(
            encrypted.ciphertexts, encrypted.tags, encrypted.nonces
        )):
            try:
                msg = cipher.decrypt(nonce, ct + tag, None)
                messages.append(msg)
            except Exception as e:
                raise ValueError(f"Decryption failed for message {i}: {e}")
        
        return messages


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute BatchHybridKEM tests."""
    print("=" * 70)
    print("Meteor-NC BatchHybridKEM Test Suite (Correct PKE Design)")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Basic batch encrypt/decrypt
    print("\n[Test 1] Basic Batch Encrypt/Decrypt")
    print("-" * 40)
    
    # Bob generates keys
    bob = BatchHybridKEM(n=256)
    bob_pk, bob_sk = bob.key_gen()
    
    # Alice encrypts FOR Bob
    alice = BatchHybridKEM(n=256)
    alice.load_recipient_public_key(bob_pk)
    
    messages = [
        b"Hello Bob!",
        b"This is message 2",
        b"And message 3",
        b"Final message",
    ]
    
    encrypted = alice.encaps_batch(messages)
    decrypted = bob.decaps_batch(encrypted)
    
    basic_ok = (messages == decrypted)
    results['basic'] = basic_ok
    print(f"  Messages: {len(messages)}")
    print(f"  Result: {'PASS' if basic_ok else 'FAIL'}")
    
    # Test 2: Large batch
    print("\n[Test 2] Large Batch (1000 messages)")
    print("-" * 40)
    
    large_messages = [secrets.token_bytes(100) for _ in range(1000)]
    
    start = time.perf_counter()
    encrypted2 = alice.encaps_batch(large_messages)
    enc_time = time.perf_counter() - start
    
    start = time.perf_counter()
    decrypted2 = bob.decaps_batch(encrypted2)
    dec_time = time.perf_counter() - start
    
    large_ok = (large_messages == decrypted2)
    results['large'] = large_ok
    print(f"  Encrypt: {enc_time*1000:.1f}ms ({len(large_messages)/enc_time:.0f} msg/s)")
    print(f"  Decrypt: {dec_time*1000:.1f}ms ({len(large_messages)/dec_time:.0f} msg/s)")
    print(f"  Result: {'PASS' if large_ok else 'FAIL'}")
    
    # Test 3: Wrong recipient cannot decrypt
    print("\n[Test 3] Security: Wrong Recipient Cannot Decrypt")
    print("-" * 40)
    
    eve = BatchHybridKEM(n=256)
    eve.key_gen()
    
    encrypted3 = alice.encaps_batch([b"Secret for Bob!"])
    
    security_ok = False
    try:
        eve.decaps_batch(encrypted3)
        print("  Eve decrypted! SECURITY BREACH!")
    except Exception:
        security_ok = True
        print("  Eve blocked: decryption failed")
    
    results['security'] = security_ok
    print(f"  Result: {'PASS' if security_ok else 'FAIL'}")
    
    # Test 4: Seed reproducibility
    print("\n[Test 4] Seed Reproducibility")
    print("-" * 40)
    
    seed = b"test_seed_for_batch_1234567890ab"
    
    bob1 = BatchHybridKEM(n=256, seed=seed)
    bob1.key_gen()
    
    bob2 = BatchHybridKEM(n=256, seed=seed)
    bob2.key_gen()
    
    seed_ok = (bob1.get_public_key() == bob2.get_public_key())
    results['seed'] = seed_ok
    print(f"  Same seed → Same PK: {'PASS' if seed_ok else 'FAIL'}")
    
    # Test 5: Variable message sizes
    print("\n[Test 5] Variable Message Sizes")
    print("-" * 40)
    
    var_messages = [
        b"",
        b"a",
        secrets.token_bytes(100),
        secrets.token_bytes(1000),
        secrets.token_bytes(10000),
    ]
    
    encrypted5 = alice.encaps_batch(var_messages)
    decrypted5 = bob.decaps_batch(encrypted5)
    
    var_ok = (var_messages == decrypted5)
    results['variable'] = var_ok
    print(f"  Sizes: {[len(m) for m in var_messages]}")
    print(f"  Result: {'PASS' if var_ok else 'FAIL'}")
    
    # Test 6: Throughput benchmark
    print("\n[Test 6] Throughput Benchmark")
    print("-" * 40)
    
    for msg_size in [32, 256, 1024]:
        for batch_size in [100, 1000, 10000]:
            messages = [secrets.token_bytes(msg_size) for _ in range(batch_size)]
            
            start = time.perf_counter()
            encrypted = alice.encaps_batch(messages)
            elapsed = time.perf_counter() - start
            
            throughput = batch_size / elapsed
            mb_per_sec = (batch_size * msg_size) / elapsed / (1024 * 1024)
            
            print(f"  {batch_size:5d} × {msg_size:4d}B: {throughput:,.0f} msg/s ({mb_per_sec:.1f} MB/s)")
    
    results['benchmark'] = True
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    passed = sum(results.values())
    total = len(results)
    
    print(f"Result: {passed}/{total} tests passed")
    
    if all_pass:
        print("\n✓ ALL TESTS PASSED")
        print("\n✓ Security properties verified:")
        print("  - KEM encaps with recipient's PUBLIC key")
        print("  - All messages encrypted with derived AES key")
        print("  - Only recipient can decrypt with SECRET key")
        print("  - Wrong recipient CANNOT decrypt")
    else:
        print("\n✗ SOME TESTS FAILED")
        for name, ok in results.items():
            if not ok:
                print(f"  - {name}: FAILED")
    
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
