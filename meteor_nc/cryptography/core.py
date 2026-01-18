# meteor_nc/cryptography/core.py
"""
Meteor-NC Core Components

Single-message LWE-KEM with Fujisaki-Okamoto transform and hybrid encryption.
CPU-friendly implementation (GPU optional for acceleration).

v2.0 Changes:
  - Wire-based FO transform: compress → compare wire, not raw (u,v)
  - Compressed ciphertext as canonical form for transmission
  - Backward compatible: uncompressed methods still available

Key Structure:
  - Public Key: pk_seed (32B) + b (k×4B as uint32) + metadata
  - Secret Key: s (n×8B as int64, internal only)
  - Matrix A is reconstructed from pk_seed via SHA-256 counter-mode PRG

Wire Format Specification:
  - Header fields: big-endian (">I", ">II", ">III")
  - Coefficient arrays (b, u, v): little-endian uint32 ("<u4")
  
Compressed Ciphertext Sizes (v2.0):
  - n=256:  518 bytes (vs 2056 uncompressed, -75%)
  - n=512:  1094 bytes (vs 4104 uncompressed, -73%)
  - n=1024: 2310 bytes (vs 8200 uncompressed, -72%)

Supports multiple security levels:
  - 128-bit (n=256): PK ~1.1KB, CT 518B
  - 192-bit (n=512): PK ~2.1KB, CT 1094B
  - 256-bit (n=1024): PK ~4.2KB, CT 2310B

Updated: 2025-01-18
Version: 2.0 - Wire-based FO transform with compression
"""


from __future__ import annotations

import secrets
import struct
from typing import Any, Callable, Optional, Tuple

import numpy as np

# =============================================================================
# Import from common.py
# =============================================================================

from .common import (
    # Constants
    Q_DEFAULT,
    SECURITY_PARAMS,
    GPU_AVAILABLE,
    CRYPTO_AVAILABLE,
    cp,
    AESGCM,
    # Utilities
    _sha256,
    _ct_eq,
    _words_from_bytes_le,
    _bytes_from_words_le,
    prg_sha256,
    small_error_from_seed,
    _derive_key,
    # HKDF
    HKDF,
    # Data structures
    LWEPublicKey,
    LWESecretKey,
    LWECiphertext,
    FullCiphertext,
    # CBD
    CenteredBinomial,
)


# =============================================================================
# Domain-separated HKDF for Meteor-NC
# =============================================================================

_METEOR_SALT = _sha256(b"meteor-nc-v1-hkdf-salt")
_HKDF_INSTANCE = HKDF(salt=_METEOR_SALT)


def _derive_key_meteor(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-based key derivation with Meteor-NC domain separation."""
    return _HKDF_INSTANCE.derive(ikm, info, length)


# =============================================================================
# Symmetric Mixer (Feistel Network)
# =============================================================================

class SymmetricMixer:
    """Feistel network-based reversible mixer."""
    
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
# LWE-KEM with Fujisaki-Okamoto Transform (Wire-Based FO v2.0)
# =============================================================================

class LWEKEM:
    """
    LWE-based Key Encapsulation Mechanism with FO transform.
    
    v2.0: Wire-Based FO Transform
    =============================
    FO verification now uses compressed wire format as canonical form:
    
      encaps():
        1. Generate random message m
        2. Encrypt: (u, v) = Enc(m)
        3. Compress: wire = compress(u, v)  ← CANONICAL FORM
        4. Derive: K = HKDF(m || H(wire))
        5. Return: (K, wire)
      
      decaps(wire):
        1. Decompress: (u, v) = decompress(wire)
        2. Decrypt: m' = Dec(u, v)
        3. Re-encrypt: (u', v') = Enc(m')
        4. Re-compress: wire' = compress(u', v')
        5. Compare: wire == wire' ?  ← WIRE COMPARISON
        6. If match: K = HKDF(m' || H(wire))
           Else: K = HKDF(z || H(wire))  (implicit rejection)
    
    This design ensures:
      - Lossy compression doesn't break FO verification
      - Wire format is self-describing and portable
      - ~75% bandwidth reduction vs uncompressed
    
    CORRECT KEY STRUCTURE:
      - pk_seed (32B): Public, used to reconstruct matrix A via SHA-256 PRG
      - b (k×4B as uint32): Public, computed as A @ s + e mod q during key_gen
      - s: SECRET, generated from TRUE RANDOMNESS (not from seed!)
    
    Supports multiple security levels:
        - n=256:  128-bit security (NIST Level 1), CT 518B
        - n=512:  192-bit security (NIST Level 3), CT 1094B
        - n=1024: 256-bit security (NIST Level 5), CT 2310B
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
        use_compression: bool = True,  # v2.0: Enable compression by default
    ):
        """
        Initialize LWE-KEM.
        
        Args:
            n: Dimension (256, 512, or 1024)
            k: Number of samples (default: n)
            q: Modulus (default: 2^32 - 5)
            eta: Error distribution parameter
            gpu: Use GPU acceleration
            device_id: GPU device ID
            seed: Optional master seed for deterministic key generation.
            use_compression: Use compressed wire format (default: True)
        """
        self.n = int(n)
        self.k = int(k if k is not None else n)
        self.q = int(q)
        self.eta = int(eta)
        self.seed = seed
        self.use_compression = bool(use_compression)
        
        # Dynamic message size based on n
        self.msg_bits = self.n
        self.msg_bytes = self.n // 8
        
        self.gpu = bool(gpu and GPU_AVAILABLE)
        self.device_id = int(device_id)
        
        if self.gpu:
            cp.cuda.Device(self.device_id).use()
            self.xp = cp
        else:
            self.xp = np
        
        self._cbd = CenteredBinomial(eta=self.eta, xp=self.xp)
        
        self.pk: Optional[LWEPublicKey] = None
        self.sk: Optional[LWESecretKey] = None
        
        self.delta = self.q // 2
        
        # Cache for reconstructed A matrix
        self._A_cache: Optional[Any] = None
        self._A_cache_seed: Optional[bytes] = None
    
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
    
    def _reconstruct_A(self, pk_seed: bytes) -> Any:
        """Reconstruct matrix A from pk_seed using deterministic expansion."""
        if self._A_cache is not None and self._A_cache_seed == pk_seed:
            return self._A_cache
        
        num_elements = self.k * self.n
        num_bytes = num_elements * 4
        
        prg_output = prg_sha256(pk_seed, num_bytes, domain=b"matrix_A")
        
        raw = np.frombuffer(prg_output, dtype="<u4").copy()
        A_flat = (raw.astype(np.int64) % self.q)
        A = A_flat.reshape(self.k, self.n)
        
        if self.gpu:
            A = cp.asarray(A)
        
        self._A_cache = A
        self._A_cache_seed = pk_seed
        
        return A
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """
        Generate LWE key pair.
        
        Returns:
            Tuple of (public_key_bytes, secret_key_bytes) for storage
        """
        if self.seed is not None:
            hkdf = HKDF(salt=_sha256(b"meteor-nc-auth-v2"))
            prk = hkdf.extract(self.seed)
            
            pk_seed = hkdf.expand(prk, b"pk_seed", 32)
            
            s_bytes = hkdf.expand(prk, b"secret_s", self.n * 4)
            s_raw = np.frombuffer(s_bytes, dtype="<u4").copy()
            s_np = ((s_raw % (2 * self.eta + 1)).astype(np.int64) - self.eta)
            
            e_bytes = hkdf.expand(prk, b"error_e", self.k * 4)
            e_raw = np.frombuffer(e_bytes, dtype="<u4").copy()
            e_np = ((e_raw % (2 * self.eta + 1)).astype(np.int64) - self.eta)
            
            z = hkdf.expand(prk, b"implicit_z", 32)
            
            if self.gpu:
                s = cp.asarray(s_np)
                e = cp.asarray(e_np)
            else:
                s = s_np
                e = e_np
        else:
            pk_seed = secrets.token_bytes(32)
            
            if self.gpu:
                s_np = np.array([
                    secrets.randbelow(2 * self.eta + 1) - self.eta 
                    for _ in range(self.n)
                ], dtype=np.int64)
                e_np = np.array([
                    secrets.randbelow(2 * self.eta + 1) - self.eta 
                    for _ in range(self.k)
                ], dtype=np.int64)
                s = cp.asarray(s_np)
                e = cp.asarray(e_np)
            else:
                s_np = np.array([
                    secrets.randbelow(2 * self.eta + 1) - self.eta 
                    for _ in range(self.n)
                ], dtype=np.int64)
                e_np = np.array([
                    secrets.randbelow(2 * self.eta + 1) - self.eta 
                    for _ in range(self.k)
                ], dtype=np.int64)
                s = s_np
                e = e_np
            
            z = secrets.token_bytes(32)
        
        A = self._reconstruct_A(pk_seed)
        
        b = self._mod_q(A @ s + e)
        
        b_np = self._to_numpy(b)
        b_bytes_for_hash = b_np.astype("<u4").tobytes()
        pk_bytes_for_hash = pk_seed + b_bytes_for_hash
        pk_hash = _sha256(b"pk_hash", pk_bytes_for_hash)
        
        self.pk = LWEPublicKey(
            pk_seed=pk_seed,
            b=b_np,
            pk_hash=pk_hash,
            n=self.n,
            k=self.k,
            q=self.q,
        )
        self.sk = LWESecretKey(s=self._to_numpy(s), z=z)
        
        return self.pk.to_bytes(), self._export_secret_key()
    
    def _export_secret_key(self) -> bytes:
        """Serialize secret key to bytes."""
        if self.sk is None:
            raise ValueError("Secret key not initialized")
        return self.sk.s.astype(np.int64).tobytes() + self.sk.z
    
    def _import_secret_key(self, data: bytes) -> None:
        """Deserialize secret key from bytes."""
        s_bytes = data[:-32]
        z = data[-32:]
        s = np.frombuffer(s_bytes, dtype=np.int64).copy()
        self.sk = LWESecretKey(s=s, z=z)
    
    def load_public_key(self, pk_bytes: bytes) -> None:
        """Load public key from serialized bytes."""
        self.pk = LWEPublicKey.from_bytes(pk_bytes)
        self.sk = None
        
        self.n = self.pk.n
        self.k = self.pk.k
        self.q = self.pk.q
        self.msg_bits = self.n
        self.msg_bytes = self.n // 8
    
    def load_secret_key(self, sk_bytes: bytes) -> None:
        """Load secret key from serialized bytes."""
        self._import_secret_key(sk_bytes)
    
    def get_public_key_bytes(self) -> bytes:
        """Get serialized public key for transmission."""
        if self.pk is None:
            raise ValueError("Public key not initialized")
        return self.pk.to_bytes()
    
    def get_public_key_size(self) -> int:
        """Get public key size in bytes."""
        return 12 + 32 + self.k * 4 + 32
    
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
        
        seed_r = _sha256(b"r", rbytes)
        seed_e1 = _sha256(b"e1", rbytes)
        seed_e2 = _sha256(b"e2", rbytes)
        
        r_np = small_error_from_seed(seed_r, self.k)
        e1_np = small_error_from_seed(seed_e1, self.n)
        e2_np = small_error_from_seed(seed_e2, self.msg_bits)
        
        A = self._reconstruct_A(self.pk.pk_seed)
        b = self._to_xp(self.pk.b)
        
        if self.gpu:
            r = xp.asarray(r_np)
            e1 = xp.asarray(e1_np)
            e2 = xp.asarray(e2_np)
        else:
            r, e1, e2 = r_np, e1_np, e2_np
        
        u = (A.T @ r + e1) % self.q
        v = (b @ r + e2 + m_encoded) % self.q
        
        return u, v
    
    def _decrypt_internal(self, u: Any, v: Any) -> Any:
        """Internal LWE decryption."""
        if self.sk is None:
            raise ValueError("Secret key not initialized")
        
        s = self._to_xp(self.sk.s)
        s_dot_u = s @ u
        return self._mod_q(v - s_dot_u)
    
    def encaps(
        self,
        rng: Optional[Callable[[int], bytes]] = None,
    ) -> Tuple[bytes, bytes]:
        """
        KEM encapsulation (encryption).
        
        v2.0: Returns compressed wire format as canonical ciphertext.
        
        Returns:
            K: Shared secret (32 bytes)
            wire: Compressed ciphertext (canonical form for FO)
        """
        if self.pk is None:
            raise ValueError("Public key not initialized")
        
        rng = rng or secrets.token_bytes
        m = rng(self.msg_bytes)
        r = _sha256(b"random", m, self.pk.pk_hash)
        
        m_encoded = self._encode_message(m)
        u, v = self._encrypt_internal(m_encoded, r)
        
        u_np = self._to_numpy(u).astype(np.int64)
        v_np = self._to_numpy(v).astype(np.int64)
        
        ct = LWECiphertext(u=u_np, v=v_np)
        
        # v2.0: Use compressed wire as canonical form
        if self.use_compression:
            wire = ct.to_bytes_compressed(self.q)
        else:
            wire = ct.to_bytes()
        
        # KDF input uses wire hash
        wire_hash = _sha256(b"ct_hash", wire)
        K = _derive_key_meteor(m + wire_hash, b"meteor-nc-shared-secret")
        
        return K, wire
    
    def decaps(self, wire: bytes) -> bytes:
        """
        KEM decapsulation (decryption).
        
        v2.0: Wire-based FO verification.
        
        Args:
            wire: Compressed (or uncompressed) ciphertext
        
        Returns:
            K: Shared secret (32 bytes)
        """
        if self.pk is None or self.sk is None:
            raise ValueError("Keys not initialized (need both pk and sk for decaps)")
        
        # Decompress ciphertext
        if self.use_compression:
            ct = LWECiphertext.from_bytes_compressed(wire, self.q)
        else:
            ct = LWECiphertext.from_bytes(wire)
        
        u = self._to_xp(ct.u)
        v = self._to_xp(ct.v)
        
        # Decrypt
        v_dec = self._decrypt_internal(u, v)
        m_prime = self._decode_message(v_dec)
        
        # Re-encrypt
        r_prime = _sha256(b"random", m_prime, self.pk.pk_hash)
        m_prime_encoded = self._encode_message(m_prime)
        u2, v2 = self._encrypt_internal(m_prime_encoded, r_prime)
        
        u2_np = self._to_numpy(u2).astype(np.int64)
        v2_np = self._to_numpy(v2).astype(np.int64)
        ct2 = LWECiphertext(u=u2_np, v=v2_np)
        
        # v2.0: Re-compress and compare WIRE (not raw u,v)
        if self.use_compression:
            wire2 = ct2.to_bytes_compressed(self.q)
        else:
            wire2 = ct2.to_bytes()
        
        # FO verification: compare wire formats
        ok = _ct_eq(wire, wire2)
        
        # Derive shared key
        wire_hash = _sha256(b"ct_hash", wire)
        K_good = _derive_key_meteor(m_prime + wire_hash, b"meteor-nc-shared-secret")
        K_fail = _derive_key_meteor(self.sk.z + wire_hash, b"meteor-nc-implicit-reject")
        
        return K_good if ok == 1 else K_fail
    
    # --- Legacy methods for backward compatibility ---
    
    def encaps_uncompressed(
        self,
        rng: Optional[Callable[[int], bytes]] = None,
    ) -> Tuple[bytes, LWECiphertext]:
        """Legacy encaps returning LWECiphertext object."""
        if self.pk is None:
            raise ValueError("Public key not initialized")
        
        rng = rng or secrets.token_bytes
        m = rng(self.msg_bytes)
        r = _sha256(b"random", m, self.pk.pk_hash)
        
        m_encoded = self._encode_message(m)
        u, v = self._encrypt_internal(m_encoded, r)
        
        u_np = self._to_numpy(u).astype(np.int64)
        v_np = self._to_numpy(v).astype(np.int64)
        
        ct = LWECiphertext(u=u_np, v=v_np)
        
        ct_wire = ct.to_bytes()
        K = _derive_key_meteor(m + ct_wire, b"meteor-nc-shared-secret")
        
        return K, ct
    
    def decaps_uncompressed(self, ct: LWECiphertext) -> bytes:
        """Legacy decaps taking LWECiphertext object."""
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
        ct2 = LWECiphertext(u=u2_np, v=v2_np)
        
        ct_wire = ct.to_bytes()
        ct2_wire = ct2.to_bytes()
        
        ok = _ct_eq(ct_wire, ct2_wire)
        
        K_good = _derive_key_meteor(m_prime + ct_wire, b"meteor-nc-shared-secret")
        K_fail = _derive_key_meteor(self.sk.z + ct_wire, b"meteor-nc-implicit-reject")
        
        return K_good if ok == 1 else K_fail


# =============================================================================
# Hybrid Cryptosystem
# =============================================================================

class HybridKEM:
    """
    Hybrid Key Encapsulation Mechanism.
    
    Combines LWE-KEM with symmetric encryption (mixer + AEAD).
    """
    
    def __init__(
        self,
        security_level: int = 128,
        gpu: bool = True,
        device_id: int = 0,
        mixer_rounds: int = 8,
        use_compression: bool = True,
    ):
        if security_level not in SECURITY_PARAMS:
            raise ValueError(f"Unsupported security level: {security_level}")
        
        params = SECURITY_PARAMS[security_level]
        self.security_level = int(security_level)
        self.n = int(params["n"])
        self.gpu = bool(gpu and GPU_AVAILABLE)
        self.device_id = int(device_id)
        self.mixer_rounds = int(mixer_rounds)
        self.use_compression = bool(use_compression)
        
        self.kem = LWEKEM(
            n=params["n"],
            k=params["k"],
            q=params["q"],
            eta=params["eta"],
            gpu=self.gpu,
            device_id=self.device_id,
            use_compression=self.use_compression,
        )
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """Generate key pair."""
        return self.kem.key_gen()
    
    def load_public_key(self, pk_bytes: bytes) -> None:
        """Load recipient's public key for encryption."""
        self.kem.load_public_key(pk_bytes)
    
    def load_keys(self, pk_bytes: bytes, sk_bytes: bytes) -> None:
        """Load both public and secret keys for decryption."""
        self.kem.load_public_key(pk_bytes)
        self.kem.load_secret_key(sk_bytes)
    
    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        """
        Encrypt plaintext with optional associated data.
        
        Returns:
            Serialized FullCiphertext (KEM wire + DEM ciphertext)
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required")
        
        K, kem_wire = self.kem.encaps()
        aead_key = _derive_key_meteor(K, b"meteor-nc-aead-key")
        mixer_key = _derive_key_meteor(K, b"meteor-nc-mixer-key")
        
        mixer = SymmetricMixer(
            key=mixer_key,
            rounds=self.mixer_rounds,
            gpu=self.gpu,
            device_id=self.device_id,
        )
        mixed = mixer.forward(plaintext)
        
        aesgcm = AESGCM(aead_key)
        nonce = secrets.token_bytes(12)
        ct_with_tag = aesgcm.encrypt(nonce, mixed, aad)
        
        tag = ct_with_tag[-16:]
        ct_body = ct_with_tag[:-16]
        
        # Serialize: kem_wire_len (4B) + kem_wire + nonce (12B) + ct_len (4B) + ct + tag (16B)
        return (
            struct.pack(">I", len(kem_wire)) +
            kem_wire +
            nonce +
            struct.pack(">I", len(ct_body)) +
            ct_body +
            tag
        )
    
    def decrypt(self, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        """Decrypt ciphertext with optional AAD verification."""
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required")
        
        # Parse
        if len(ciphertext) < 4:
            raise ValueError("Ciphertext too short")
        
        kem_wire_len = struct.unpack(">I", ciphertext[:4])[0]
        offset = 4
        
        kem_wire = ciphertext[offset:offset + kem_wire_len]
        offset += kem_wire_len
        
        nonce = ciphertext[offset:offset + 12]
        offset += 12
        
        ct_len = struct.unpack(">I", ciphertext[offset:offset + 4])[0]
        offset += 4
        
        ct_body = ciphertext[offset:offset + ct_len]
        offset += ct_len
        
        tag = ciphertext[offset:offset + 16]
        
        # Decrypt KEM
        K = self.kem.decaps(kem_wire)
        
        aead_key = _derive_key_meteor(K, b"meteor-nc-aead-key")
        mixer_key = _derive_key_meteor(K, b"meteor-nc-mixer-key")
        
        mixer = SymmetricMixer(
            key=mixer_key,
            rounds=self.mixer_rounds,
            gpu=self.gpu,
            device_id=self.device_id,
        )
        
        aesgcm = AESGCM(aead_key)
        ct_with_tag = ct_body + tag
        mixed = aesgcm.decrypt(nonce, ct_with_tag, aad)
        
        plaintext = mixer.inverse(mixed)
        
        return plaintext
    
    def get_public_key_size(self) -> int:
        """Get public key size in bytes."""
        return self.kem.get_public_key_size()


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute test suite."""
    print("=" * 70)
    print("Meteor-NC Core v2.0 Test Suite (Wire-Based FO)")
    print("=" * 70)
    
    use_gpu = GPU_AVAILABLE
    print(f"\nGPU Available: {use_gpu}")
    
    results = {}
    
    # Test 1: Symmetric Mixer
    print("\n[Test 1] Symmetric Mixer")
    print("-" * 40)
    
    mixer_key = secrets.token_bytes(32)
    mixer = SymmetricMixer(key=mixer_key, rounds=8, gpu=use_gpu)
    
    test_sizes = [1, 16, 100, 1000]
    mixer_ok = True
    
    for size in test_sizes:
        msg = secrets.token_bytes(size)
        mixed = mixer.forward(msg)
        recovered = mixer.inverse(mixed)
        ok = (msg == recovered)
        mixer_ok = mixer_ok and ok
        print(f"  Size {size:5d}: {'PASS' if ok else 'FAIL'}")
    
    results["mixer"] = mixer_ok
    
    # Test 2: LWE-KEM with Compression (v2.0)
    print("\n[Test 2] LWE-KEM with Wire-Based FO (v2.0)")
    print("-" * 40)
    
    kem_ok = True
    for level, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit")]:
        params = SECURITY_PARAMS[level]
        kem = LWEKEM(n=params["n"], k=params["k"], eta=params["eta"], gpu=use_gpu, use_compression=True)
        pk_bytes, sk_bytes = kem.key_gen()
        
        K1, wire = kem.encaps()
        K2 = kem.decaps(wire)
        match = (K1 == K2)
        kem_ok = kem_ok and match
        
        print(f"  {label}: wire={len(wire)}B, KeyMatch={'PASS' if match else 'FAIL'}")
    
    results["kem_compressed"] = kem_ok
    
    # Test 3: Sender/Receiver Separation
    print("\n[Test 3] Sender/Receiver Separation")
    print("-" * 40)
    
    separation_ok = True
    
    for level, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit")]:
        params = SECURITY_PARAMS[level]
        
        receiver = LWEKEM(n=params["n"], k=params["k"], eta=params["eta"], gpu=use_gpu)
        pk_bytes, sk_bytes = receiver.key_gen()
        
        sender = LWEKEM(n=params["n"], k=params["k"], eta=params["eta"], gpu=use_gpu)
        sender.load_public_key(pk_bytes)
        
        K_sender, wire = sender.encaps()
        
        try:
            sender.decaps(wire)
            sender_cannot_decrypt = False
        except ValueError:
            sender_cannot_decrypt = True
        
        K_receiver = receiver.decaps(wire)
        keys_match = (K_sender == K_receiver)
        
        level_ok = sender_cannot_decrypt and keys_match
        separation_ok = separation_ok and level_ok
        
        print(f"  {label}: SenderBlocked={'PASS' if sender_cannot_decrypt else 'FAIL'}, "
              f"KeyMatch={'PASS' if keys_match else 'FAIL'}")
    
    results["separation"] = separation_ok
    
    # Test 4: Wire Size Verification
    print("\n[Test 4] Compressed Wire Size")
    print("-" * 40)
    
    expected_sizes = {256: 518, 512: 1094, 1024: 2310}
    size_ok = True
    
    for level, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit")]:
        params = SECURITY_PARAMS[level]
        n = params["n"]
        
        kem = LWEKEM(n=n, gpu=use_gpu, use_compression=True)
        kem.key_gen()
        
        _, wire = kem.encaps()
        actual = len(wire)
        expected = expected_sizes[n]
        
        ok = (actual == expected)
        size_ok = size_ok and ok
        
        print(f"  {label}: {actual}B (expected {expected}B) {'✓' if ok else '✗'}")
    
    results["wire_sizes"] = size_ok
    
    # Test 5: Hybrid Encryption
    if CRYPTO_AVAILABLE:
        print("\n[Test 5] Hybrid Encryption")
        print("-" * 40)
        
        receiver = HybridKEM(security_level=128, gpu=use_gpu)
        pk_bytes, sk_bytes = receiver.key_gen()
        
        sender = HybridKEM(security_level=128, gpu=use_gpu)
        sender.load_public_key(pk_bytes)
        
        msg = b"Test message for hybrid encryption - confidential!"
        ct = sender.encrypt(msg, aad=b"metadata")
        
        receiver_dec = HybridKEM(security_level=128, gpu=use_gpu)
        receiver_dec.load_keys(pk_bytes, sk_bytes)
        pt = receiver_dec.decrypt(ct, aad=b"metadata")
        
        enc_ok = (msg == pt)
        results["encryption"] = enc_ok
        print(f"  Encrypt/Decrypt: {'PASS' if enc_ok else 'FAIL'}")
        
        try:
            _ = receiver_dec.decrypt(ct, aad=b"wrong")
            aead_ok = False
        except Exception:
            aead_ok = True
        results["aead"] = aead_ok
        print(f"  AEAD Integrity: {'PASS' if aead_ok else 'FAIL'}")
    
    # Test 6: FO Implicit Rejection
    print("\n[Test 6] FO Implicit Rejection (Tampered Wire)")
    print("-" * 40)
    
    rejection_ok = True
    
    for level, label in [(128, "128-bit")]:
        params = SECURITY_PARAMS[level]
        
        kem = LWEKEM(n=params["n"], gpu=use_gpu)
        kem.key_gen()
        
        K_orig, wire = kem.encaps()
        
        # Tamper with wire
        wire_tampered = bytearray(wire)
        wire_tampered[10] ^= 0xFF
        wire_tampered = bytes(wire_tampered)
        
        K_tampered = kem.decaps(wire_tampered)
        
        # K should be different (implicit rejection)
        rejected = (K_orig != K_tampered)
        rejection_ok = rejection_ok and rejected
        
        print(f"  {label}: Tampered wire rejected: {'PASS' if rejected else 'FAIL'}")
    
    results["implicit_rejection"] = rejection_ok
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    
    if all_pass:
        print("\n✓ Wire-based FO verified:")
        print("  - Compressed wire is canonical form")
        print("  - FO comparison uses wire == wire'")
        print("  - Implicit rejection works correctly")
        print("  - ~75% bandwidth reduction achieved")
    
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
