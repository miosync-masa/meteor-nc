# meteor_nc/cryptography/core.py
"""
Meteor-NC Core Components

Single-message LWE-KEM with Fujisaki-Okamoto transform and hybrid encryption.
CPU-friendly implementation (GPU optional for acceleration).

Supports multiple security levels:
  - 128-bit (n=256)
  - 192-bit (n=512)
  - 256-bit (n=1024)
"""

from __future__ import annotations

import secrets
import struct
from typing import Any, Callable, Dict, Optional, Tuple

import numpy as np

from .common import (
    HKDF,
    CenteredBinomial,
    Q_DEFAULT,
    MSG_BYTES,
    MSG_BITS,
    SECURITY_PARAMS,
    GPU_AVAILABLE,
    CRYPTO_AVAILABLE,
    _sha256,
    _ct_eq,
    _words_from_bytes_le,
    _bytes_from_words_le,
    LWEPublicKey,
    LWESecretKey,
    LWECiphertext,
    FullCiphertext,
    prg_sha256,
    small_error_from_seed,
)

if GPU_AVAILABLE:
    import cupy as cp

if CRYPTO_AVAILABLE:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =============================================================================
# HKDF-based Key Derivation (RFC 5869 Compliant)
# =============================================================================

# Domain-separated salt for Meteor-NC
_METEOR_SALT = _sha256(b"meteor-nc-v1-hkdf-salt")
_HKDF_INSTANCE = HKDF(salt=_METEOR_SALT)


def _derive_key(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """
    HKDF-based key derivation with proper domain separation.
    
    Compliant with RFC 5869 and NIST SP 800-56C.
    
    Args:
        ikm: Input keying material
        info: Context/application-specific info string
        length: Desired output length in bytes
    
    Returns:
        Derived key material
    """
    return _HKDF_INSTANCE.derive(ikm, info, length)


# =============================================================================
# Symmetric Mixer (Feistel Network)
# =============================================================================

class SymmetricMixer:
    """
    Feistel network-based reversible mixer.
    
    Provides fast symmetric diffusion for the DEM layer.
    Security is provided by AEAD; this adds diffusion.
    """
    
    def __init__(
        self,
        key: bytes,
        rounds: int = 8,
        gpu: bool = True,
        device_id: int = 0,
    ):
        if len(key) < 32:
            raise ValueError("Key must be at least 32 bytes")
        
        self.rounds = int(rounds)
        self.gpu = bool(gpu and GPU_AVAILABLE)
        self.device_id = int(device_id)
        
        if self.gpu:
            cp.cuda.Device(self.device_id).use()
            self.xp = cp
        else:
            self.xp = np
        
        self._round_keys = self._expand_round_keys(key, self.rounds)
    
    @staticmethod
    def _expand_round_keys(key: bytes, rounds: int) -> list:
        """Derive round constants deterministically from key."""
        out = []
        seed = _sha256(b"symmetric-mixer", key)
        
        for i in range(rounds):
            block = _sha256(seed, struct.pack(">I", i))
            mul = int.from_bytes(block[:4], "little") | 1
            a = (block[4] % 23) + 5
            b = (block[5] % 23) + 5
            out.append((mul, a, b))
        
        return out
    
    def _round_function(self, L: Any, round_idx: int) -> Any:
        """Feistel round function."""
        xp = self.xp
        mul, a, b = self._round_keys[round_idx]
        
        x = L.astype(xp.uint32, copy=False)
        x = (x.astype(xp.uint64) * xp.uint64(mul)) & xp.uint64(0xFFFFFFFF)
        x = x.astype(xp.uint32)
        x = x ^ ((x << xp.uint32(a)) & xp.uint32(0xFFFFFFFF))
        x = x ^ (x >> xp.uint32(b))
        
        return x
    
    def forward(self, plaintext: bytes) -> bytes:
        """Apply forward mixing transformation."""
        xp = self.xp
        orig_len = len(plaintext)
        
        words = _words_from_bytes_le(plaintext)
        nwords = words.shape[0]
        
        if nwords % 2 == 1:
            words = np.concatenate([words, np.zeros(1, dtype=np.uint32)])
            nwords += 1
        
        if self.gpu:
            state = cp.asarray(words, dtype=cp.uint32)
        else:
            state = words.astype(np.uint32)
        
        half = nwords // 2
        L = state[:half].copy()
        R = state[half:].copy()
        
        for r in range(self.rounds):
            F = self._round_function(L, r)
            R = R ^ F
            L, R = R, L
        
        state_out = xp.concatenate([L, R], axis=0)
        
        if self.gpu:
            state_out = cp.asnumpy(state_out)
        
        mixed_bytes = _bytes_from_words_le(np.asarray(state_out, dtype=np.uint32))
        
        return struct.pack(">Q", orig_len) + mixed_bytes
    
    def inverse(self, mixed_with_len: bytes) -> bytes:
        """Apply inverse mixing transformation."""
        xp = self.xp
        
        orig_len = struct.unpack(">Q", mixed_with_len[:8])[0]
        mixed = mixed_with_len[8:]
        
        words = _words_from_bytes_le(mixed)
        nwords = words.shape[0]
        
        if self.gpu:
            state = cp.asarray(words, dtype=cp.uint32)
        else:
            state = words.astype(np.uint32)
        
        half = nwords // 2
        L = state[:half].copy()
        R = state[half:].copy()
        
        for r in reversed(range(self.rounds)):
            L, R = R, L
            F = self._round_function(L, r)
            R = R ^ F
        
        state_out = xp.concatenate([L, R], axis=0)
        
        if self.gpu:
            state_out = cp.asnumpy(state_out)
        
        plaintext_padded = _bytes_from_words_le(np.asarray(state_out, dtype=np.uint32))
        
        return plaintext_padded[:orig_len]


# =============================================================================
# LWE-KEM with Fujisaki-Okamoto Transform
# =============================================================================

class LWEKEM:
    """
    LWE-based Key Encapsulation Mechanism with FO transform.
    
    Provides IND-CCA2 security assuming LWE hardness.
    Uses implicit rejection to prevent timing side-channels.
    
    Key derivation uses HKDF (RFC 5869) for proper domain separation
    and compliance with NIST SP 800-56C.
    
    Supports multiple security levels:
        - n=256:  128-bit security (NIST Level 1)
        - n=512:  192-bit security (NIST Level 3)
        - n=1024: 256-bit security (NIST Level 5)
    """
    
    def __init__(
        self,
        n: int = 256,
        k: Optional[int] = None,
        q: int = Q_DEFAULT,
        eta: int = 2,
        gpu: bool = True,
        device_id: int = 0,
        seed: Optional[bytes] = None,
    ):
        self.n = int(n)
        self.k = int(k if k is not None else n)
        self.q = int(q)
        self.eta = int(eta)
        
        # Dynamic message size based on n (supports 128/192/256-bit security)
        self.msg_bits = self.n   # 256, 512, or 1024
        self.msg_bytes = self.n // 8  # 32, 64, or 128
        
        self.gpu = bool(gpu and GPU_AVAILABLE)
        self.device_id = int(device_id)
        
        if self.gpu:
            cp.cuda.Device(self.device_id).use()
            self.xp = cp
        else:
            self.xp = np
        
        self._cbd = CenteredBinomial(eta=self.eta, xp=self.xp)
        
        self.master_seed = seed if seed is not None else secrets.token_bytes(32)
        self._hkdf = HKDF(salt=self._compute_salt())
        self._prk: Optional[bytes] = None
        
        self.pk: Optional[LWEPublicKey] = None
        self.sk: Optional[LWESecretKey] = None
        
        self.delta = self.q // 2
    
    def _compute_salt(self) -> bytes:
        """Compute domain-separated salt."""
        s = f"lwe-kem,n={self.n},k={self.k},q={self.q},eta={self.eta}"
        return _sha256(s.encode())
    
    def _get_prk(self) -> bytes:
        if self._prk is None:
            self._prk = self._hkdf.extract(self.master_seed)
        return self._prk
    
    def _derive(self, label: str, nbytes: int) -> bytes:
        return self._hkdf.expand(self._get_prk(), label.encode(), nbytes)
    
    def _seed32(self, label: str) -> int:
        return int.from_bytes(self._derive(label, 8), "big")
    
    def _mod_q(self, x: Any) -> Any:
        return x % self.q
    
    def _to_xp(self, x: Any) -> Any:
        if self.gpu:
            return cp.asarray(x, dtype=cp.int64)
        return np.asarray(x, dtype=np.int64)
    
    def _to_numpy(self, x: Any) -> np.ndarray:
        if self.gpu:
            return cp.asnumpy(x)
        return np.asarray(x)
    
    def key_gen(self) -> None:
        """Generate LWE key pair."""
        seed_A = self._seed32("matrix_A")
        if self.gpu:
            cp.random.seed(seed_A & 0xFFFFFFFF)
            A = cp.random.randint(0, self.q, (self.k, self.n), dtype=cp.int64)
        else:
            rng_A = np.random.RandomState(seed_A & 0xFFFFFFFF)
            A = rng_A.randint(0, self.q, (self.k, self.n), dtype=np.int64)
        
        seed_s = self._seed32("secret_s")
        seed_e = self._seed32("error_e")
        
        if self.gpu:
            cp.random.seed(seed_s & 0xFFFFFFFF)
            s = self._cbd.sample_vector(self.n)
            cp.random.seed(seed_e & 0xFFFFFFFF)
            e = self._cbd.sample_vector(self.k)
        else:
            cbd_cpu = CenteredBinomial(self.eta, np)
            rng_s = np.random.RandomState(seed_s & 0xFFFFFFFF)
            rng_e = np.random.RandomState(seed_e & 0xFFFFFFFF)
            s = cbd_cpu.sample_vector(self.n, rng=rng_s)
            e = cbd_cpu.sample_vector(self.k, rng=rng_e)
        
        b = self._mod_q(A @ s + e)
        
        pk_bytes = self._to_numpy(A).tobytes() + self._to_numpy(b).tobytes()
        pk_hash = _sha256(b"pk_hash", pk_bytes)
        z = self._derive("implicit_reject", 32)
        
        self.pk = LWEPublicKey(A=A, b=b, pk_hash=pk_hash)
        self.sk = LWESecretKey(s=s, z=z)
    
    @staticmethod
    def _bytes_to_bits(data: bytes) -> np.ndarray:
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        return bits.astype(np.int64)
    
    @staticmethod
    def _bits_to_bytes(bits: np.ndarray) -> bytes:
        return np.packbits(np.asarray(bits, dtype=np.uint8)).tobytes()
    
    def _encode_message(self, m: bytes) -> Any:
        """Encode message bytes to LWE-compatible vector."""
        if len(m) != self.msg_bytes:
            raise ValueError(f"Message must be {self.msg_bytes} bytes")
        bits = self._bytes_to_bits(m)
        return self._to_xp(bits) * int(self.delta)
    
    def _decode_message(self, v_dec: Any) -> bytes:
        """Decode LWE decryption result to message bytes."""
        xp = self.xp
        half_q = self.q // 2
        v_centered = xp.where(v_dec > half_q, v_dec - self.q, v_dec)
        threshold = self.q // 4
        bits = (xp.abs(v_centered) > threshold).astype(xp.int64)
        return self._bits_to_bytes(self._to_numpy(bits).astype(np.uint8))
    
    def _encrypt_internal(self, m_encoded: Any, rbytes: bytes) -> Tuple[Any, Any]:
        """Internal encryption with deterministic randomness."""
        xp = self.xp
        
        seed_r  = _sha256(b"r",  rbytes)
        seed_e1 = _sha256(b"e1", rbytes)
        seed_e2 = _sha256(b"e2", rbytes)
        
        # Get dimensions from A shape
        k = self.pk.A.shape[0]  # A is (k, n)
        n = self.pk.A.shape[1]
        
        # r is length k, e1 is length n, e2 is msg_bits
        r_np  = small_error_from_seed(seed_r,  k)
        e1_np = small_error_from_seed(seed_e1, n)
        e2_np = small_error_from_seed(seed_e2, self.msg_bits)  # Dynamic!
        
        if self.gpu:
            r  = xp.asarray(r_np)
            e1 = xp.asarray(e1_np)
            e2 = xp.asarray(e2_np)
        else:
            r, e1, e2 = r_np, e1_np, e2_np
        
        u = (self.pk.A.T @ r + e1) % self.q
        v = (self.pk.b @ r + e2 + m_encoded) % self.q
        
        return u, v
    
    def _decrypt_internal(self, u: Any, v: Any) -> Any:
        """Internal LWE decryption."""
        if self.sk is None:
            raise ValueError("Secret key not initialized")
        
        s_dot_u = self.sk.s @ u
        return self._mod_q(v - s_dot_u)
    
    def encaps(
        self,
        rng: Optional[Callable[[int], bytes]] = None,
    ) -> Tuple[bytes, LWECiphertext]:
        """
        KEM encapsulation.
        
        Uses HKDF (RFC 5869) for shared secret derivation.
        
        Args:
            rng: Optional random bytes generator (default: secrets.token_bytes)
        
        Returns:
            K: Shared secret (32 bytes)
            ct: Ciphertext
        """
        if self.pk is None:
            raise ValueError("Public key not initialized")
        
        rng = rng or secrets.token_bytes
        m = rng(self.msg_bytes)  # Dynamic message size
        r = _sha256(b"random", m, self.pk.pk_hash)
        
        m_encoded = self._encode_message(m)
        u, v = self._encrypt_internal(m_encoded, r)
        
        u_np = self._to_numpy(u).astype(np.int64)
        v_np = self._to_numpy(v).astype(np.int64)
        ct_bytes = u_np.tobytes() + v_np.tobytes()
        
        # HKDF-based shared secret derivation (RFC 5869 compliant)
        K = _derive_key(m + ct_bytes, b"meteor-nc-shared-secret")
        
        return K, LWECiphertext(u=u_np, v=v_np)
    
    def decaps(self, ct: LWECiphertext) -> bytes:
        """
        KEM decapsulation with implicit rejection.
        
        Uses HKDF (RFC 5869) for shared secret derivation.
        Implicit rejection uses separate domain to prevent oracle attacks.
        
        Returns:
            K: Shared secret (32 bytes)
        """
        if self.pk is None or self.sk is None:
            raise ValueError("Keys not initialized")
        
        u = self._to_xp(ct.u)
        v = self._to_xp(ct.v)
        
        v_dec = self._decrypt_internal(u, v)
        m_prime = self._decode_message(v_dec)
        
        r_prime = _sha256(b"random", m_prime, self.pk.pk_hash)
        
        m_prime_encoded = self._encode_message(m_prime)
        u2, v2 = self._encrypt_internal(m_prime_encoded, r_prime)
        
        u2_np = self._to_numpy(u2).astype(np.int64)
        v2_np = self._to_numpy(v2).astype(np.int64)
        
        ct_bytes = ct.u.astype(np.int64).tobytes() + ct.v.astype(np.int64).tobytes()
        ct2_bytes = u2_np.tobytes() + v2_np.tobytes()
        
        ok = _ct_eq(ct_bytes, ct2_bytes)
        
        # HKDF-based key derivation with domain separation
        K_good = _derive_key(m_prime + ct_bytes, b"meteor-nc-shared-secret")
        K_fail = _derive_key(self.sk.z + ct_bytes, b"meteor-nc-implicit-reject")
        
        return K_good if ok == 1 else K_fail
    
    def export_seed(self) -> bytes:
        """Export master seed for key recovery."""
        return self.master_seed


# =============================================================================
# Hybrid Cryptosystem
# =============================================================================

class HybridKEM:
    """
    Hybrid Key Encapsulation Mechanism.
    
    Combines LWE-KEM with symmetric encryption (mixer + AEAD).
    All key derivations use HKDF (RFC 5869) for proper domain separation.
    """
    
    def __init__(
        self,
        security_level: int = 128,
        gpu: bool = True,
        device_id: int = 0,
        seed: Optional[bytes] = None,
        mixer_rounds: int = 8,
    ):
        if security_level not in SECURITY_PARAMS:
            raise ValueError(f"Unsupported security level: {security_level}")
        
        params = SECURITY_PARAMS[security_level]
        self.security_level = int(security_level)
        self.n = int(params["n"])
        self.gpu = bool(gpu and GPU_AVAILABLE)
        self.device_id = int(device_id)
        self.mixer_rounds = int(mixer_rounds)
        
        self.master_seed = seed if seed is not None else secrets.token_bytes(32)
        
        hkdf = HKDF(salt=_sha256(b"hybrid-kem", struct.pack(">I", self.security_level)))
        prk = hkdf.extract(self.master_seed)
        kem_seed = hkdf.expand(prk, b"kem-seed", 32)
        mixer_seed = hkdf.expand(prk, b"mixer-seed", 32)
        
        self.kem = LWEKEM(
            n=params["n"],
            k=params["k"],
            q=params["q"],
            eta=params["eta"],
            gpu=self.gpu,
            device_id=self.device_id,
            seed=kem_seed,
        )
        
        self.mixer = SymmetricMixer(
            key=mixer_seed,
            rounds=self.mixer_rounds,
            gpu=self.gpu,
            device_id=self.device_id,
        )
    
    def key_gen(self) -> None:
        """Generate key pair."""
        self.kem.key_gen()
    
    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> FullCiphertext:
        """
        Encrypt plaintext with optional associated data.
        
        AEAD key is derived using HKDF for proper domain separation.
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required")
        
        K, kem_ct = self.kem.encaps()
        
        # HKDF-based AEAD key derivation (RFC 5869 compliant)
        aead_key = _derive_key(K, b"meteor-nc-aead-key")
        
        mixed = self.mixer.forward(plaintext)
        
        aesgcm = AESGCM(aead_key)
        nonce = secrets.token_bytes(12)
        ct_with_tag = aesgcm.encrypt(nonce, mixed, aad)
        
        tag = ct_with_tag[-16:]
        ct_body = ct_with_tag[:-16]
        
        return FullCiphertext(
            u=kem_ct.u,
            v=kem_ct.v,
            nonce=nonce,
            ct=ct_body,
            tag=tag,
        )
    
    def decrypt(self, ciphertext: FullCiphertext, aad: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext with optional AAD verification.
        
        AEAD key is derived using HKDF for proper domain separation.
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required")
        
        kem_ct = LWECiphertext(u=ciphertext.u, v=ciphertext.v)
        K = self.kem.decaps(kem_ct)
        
        # HKDF-based AEAD key derivation (RFC 5869 compliant)
        aead_key = _derive_key(K, b"meteor-nc-aead-key")
        
        aesgcm = AESGCM(aead_key)
        ct_with_tag = ciphertext.ct + ciphertext.tag
        mixed = aesgcm.decrypt(ciphertext.nonce, ct_with_tag, aad)
        
        plaintext = self.mixer.inverse(mixed)
        
        return plaintext
    
    def export_seed(self) -> bytes:
        """Export 32-byte master seed."""
        return self.master_seed


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute test suite."""
    print("=" * 70)
    print("Meteor-NC Core Test Suite")
    print("=" * 70)
    
    use_gpu = GPU_AVAILABLE
    print(f"\nGPU Available: {use_gpu}")
    
    results = {}
    
    # Test 1: Symmetric Mixer
    print("\n[Test 1] Symmetric Mixer")
    print("-" * 40)
    
    mixer_key = secrets.token_bytes(32)
    mixer = SymmetricMixer(key=mixer_key, rounds=8, gpu=use_gpu)
    
    test_sizes = [1, 16, 100, 1000, 10000]
    mixer_ok = True
    
    for size in test_sizes:
        msg = secrets.token_bytes(size)
        mixed = mixer.forward(msg)
        recovered = mixer.inverse(mixed)
        ok = (msg == recovered)
        mixer_ok = mixer_ok and ok
        print(f"  Size {size:5d}: {'PASS' if ok else 'FAIL'}")
    
    results["mixer"] = mixer_ok
    
    # Test 2: LWE-KEM (Multi-Security Levels)
    print("\n[Test 2] LWE-KEM (Multi-Security Levels)")
    print("-" * 40)
    
    kem_ok = True
    for n, label in [(256, "128-bit"), (512, "192-bit"), (1024, "256-bit")]:
        kem = LWEKEM(n=n, gpu=use_gpu)
        kem.key_gen()
        K1, ct = kem.encaps()
        K2 = kem.decaps(ct)
        match = (K1 == K2)
        kem_ok = kem_ok and match
        print(f"  {label} (n={n}): u={ct.u.shape}, v={ct.v.shape}, {'PASS' if match else 'FAIL'}")
    
    results["kem"] = kem_ok
    
    # Test 3: Hybrid Encryption
    if CRYPTO_AVAILABLE:
        print("\n[Test 3] Hybrid Encryption")
        print("-" * 40)
        
        crypto = HybridKEM(security_level=128, gpu=use_gpu)
        crypto.key_gen()
        
        msg = b"Test message for hybrid encryption"
        ct = crypto.encrypt(msg, aad=b"aad")
        pt = crypto.decrypt(ct, aad=b"aad")
        enc_ok = (msg == pt)
        results["encryption"] = enc_ok
        print(f"  Encrypt/Decrypt: {'PASS' if enc_ok else 'FAIL'}")
        
        try:
            _ = crypto.decrypt(ct, aad=b"wrong")
            aead_ok = False
        except Exception:
            aead_ok = True
        results["aead"] = aead_ok
        print(f"  AEAD Integrity: {'PASS' if aead_ok else 'FAIL'}")
    
    # Test 4: Seed Determinism
    print("\n[Test 4] Seed Determinism")
    print("-" * 40)
    
    seed = secrets.token_bytes(32)
    c1 = HybridKEM(security_level=128, gpu=use_gpu, seed=seed)
    c1.key_gen()
    c2 = HybridKEM(security_level=128, gpu=use_gpu, seed=seed)
    c2.key_gen()
    
    A1 = c1.kem._to_numpy(c1.kem.pk.A)
    A2 = c2.kem._to_numpy(c2.kem.pk.A)
    seed_ok = np.array_equal(A1, A2)
    results["determinism"] = seed_ok
    print(f"  Deterministic KeyGen: {'PASS' if seed_ok else 'FAIL'}")
    
    # Test 5: HKDF Key Derivation Consistency
    print("\n[Test 5] HKDF Key Derivation")
    print("-" * 40)
    
    test_ikm = b"test input keying material"
    test_info = b"test-context"
    k1 = _derive_key(test_ikm, test_info, 32)
    k2 = _derive_key(test_ikm, test_info, 32)
    k3 = _derive_key(test_ikm, b"different-context", 32)
    
    hkdf_deterministic = (k1 == k2)
    hkdf_domain_sep = (k1 != k3)
    hkdf_ok = hkdf_deterministic and hkdf_domain_sep
    results["hkdf"] = hkdf_ok
    print(f"  Deterministic: {'PASS' if hkdf_deterministic else 'FAIL'}")
    print(f"  Domain Separation: {'PASS' if hkdf_domain_sep else 'FAIL'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
