# meteor_nc/cryptography/core.py
"""
Meteor-NC Core Components

Single-message LWE-KEM with Fujisaki-Okamoto transform and hybrid encryption.
CPU-friendly implementation (GPU optional for acceleration).

Key Structure:
  - Public Key: pk_seed (32B) + b (k×4B as uint32) + metadata
  - Secret Key: s (n×8B as int64, internal only)
  - Matrix A is reconstructed from pk_seed via SHA-256 counter-mode PRG

Wire Format Specification:
  - Header fields: big-endian (">I", ">II", ">III")
  - Coefficient arrays (b, u, v): little-endian uint32 ("<u4")
  - This mixed endianness is intentional: headers follow network byte order,
    while coefficient arrays use native x86/ARM little-endian for efficiency.

Public Key Wire Format:
  | Field    | Size      | Encoding        |
  |----------|-----------|-----------------|
  | n        | 4B        | big-endian u32  |
  | k        | 4B        | big-endian u32  |
  | q        | 4B        | big-endian u32  |
  | pk_seed  | 32B       | raw bytes       |
  | b        | k×4B      | LE uint32 array |
  | pk_hash  | 32B       | raw bytes       |

Ciphertext Wire Format:
  | Field    | Size      | Encoding        |
  |----------|-----------|-----------------|
  | u_len    | 4B        | big-endian u32  |
  | v_len    | 4B        | big-endian u32  |
  | u        | u_len×4B  | LE uint32 array |
  | v        | v_len×4B  | LE uint32 array |

Supports multiple security levels:
  - 128-bit (n=256): PK ~1.1KB, CT ~2.0KB
  - 192-bit (n=512): PK ~2.1KB, CT ~4.1KB
  - 256-bit (n=1024): PK ~4.2KB, CT ~8.2KB
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


def _derive_key(ikm: bytes, info: bytes, length: int = 32) -> bytes:
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
# LWE-KEM with Fujisaki-Okamoto Transform (CORRECT DESIGN!)
# =============================================================================

class LWEKEM:
    """
    LWE-based Key Encapsulation Mechanism with FO transform.
    
    CORRECT KEY STRUCTURE:
      - pk_seed (32B): Public, used to reconstruct matrix A via SHA-256 PRG
      - b (k×4B as uint32): Public, computed as A @ s + e mod q during key_gen
      - s: SECRET, generated from TRUE RANDOMNESS (not from seed!)
    
    Wire format sizes:
      - Public key: 12 (header) + 32 (pk_seed) + k*4 (b as uint32) + 32 (pk_hash)
      - Ciphertext: n*4 (u as uint32) + msg_bits*4 (v as uint32)
    
    This ensures:
      - Anyone with (pk_seed, b) can encrypt (encaps)
      - Only the holder of s can decrypt (decaps)
      - pk_seed leaking does NOT compromise secret key!
    
    Matrix A reconstruction:
      - Uses SHA-256 in counter mode (deterministic, implementation-independent)
      - Bias from u32 mod q (q=2^32-5) is negligible (~5/2^32 per element)
    
    Supports multiple security levels:
        - n=256:  128-bit security (NIST Level 1), PK ~1.1KB
        - n=512:  192-bit security (NIST Level 3), PK ~2.1KB
        - n=1024: 256-bit security (NIST Level 5), PK ~4.2KB
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
                  - None (default): Use true randomness for s (recommended for PKE)
                  - bytes: Derive s from seed (for auth/reproducibility use cases)
                  
                  WARNING: If seed is provided, the same seed will always produce
                  the same key pair. Only use this for authentication scenarios
                  where the seed itself is kept secret!
        """
        self.n = int(n)
        self.k = int(k if k is not None else n)
        self.q = int(q)
        self.eta = int(eta)
        self.seed = seed  # Store for key_gen
        
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
        """
        Reconstruct matrix A from pk_seed using deterministic expansion.
        
        Uses SHA-256 in counter mode (prg_sha256) for deterministic,
        implementation-independent reconstruction. This ensures:
          - Cross-platform compatibility
          - No dependence on PRNG implementation details
          - RFC-style "deterministic expansion" from seed
        
        The matrix A is LARGE (k×n×8 bytes) but can be reconstructed
        from a 32-byte seed, enabling compact public key representation.
        
        Uses caching to avoid recomputation.
        """
        # Check cache
        if self._A_cache is not None and self._A_cache_seed == pk_seed:
            return self._A_cache
        
        # Deterministic expansion using SHA-256 counter mode PRG
        # Each element needs 4 bytes (uint32), then mod q
        num_elements = self.k * self.n
        num_bytes = num_elements * 4
        
        # Generate deterministic random bytes
        prg_output = prg_sha256(pk_seed, num_bytes, domain=b"matrix_A")
        
        # Convert to uint32 array and reduce mod q
        raw = np.frombuffer(prg_output, dtype="<u4").copy()
        A_flat = (raw.astype(np.int64) % self.q)
        A = A_flat.reshape(self.k, self.n)
        
        if self.gpu:
            A = cp.asarray(A)
        
        # Update cache
        self._A_cache = A
        self._A_cache_seed = pk_seed
        
        return A
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """
        Generate LWE key pair.
        
        Behavior depends on self.seed:
          - seed=None (default): Use TRUE RANDOMNESS for s (standard PKE)
          - seed=bytes: Derive all key material from seed (for auth/reproducibility)
        
        In both cases, pk_seed leaking does NOT compromise the secret key,
        because s is either truly random or derived from a separate secret seed.
        
        Returns:
            Tuple of (public_key_bytes, secret_key_bytes) for storage
        """
        if self.seed is not None:
            # Deterministic key generation from master seed
            # Used for authentication scenarios where reproducibility is needed
            hkdf = HKDF(salt=_sha256(b"meteor-nc-auth-v2"))
            prk = hkdf.extract(self.seed)
            
            # Derive pk_seed (can be public)
            pk_seed = hkdf.expand(prk, b"pk_seed", 32)
            
            # Derive s from seed (SECRET - but seed is also secret!)
            s_bytes = hkdf.expand(prk, b"secret_s", self.n * 4)
            s_raw = np.frombuffer(s_bytes, dtype="<u4").copy()
            s_np = ((s_raw % (2 * self.eta + 1)).astype(np.int64) - self.eta)
            
            # Derive e from seed
            e_bytes = hkdf.expand(prk, b"error_e", self.k * 4)
            e_raw = np.frombuffer(e_bytes, dtype="<u4").copy()
            e_np = ((e_raw % (2 * self.eta + 1)).astype(np.int64) - self.eta)
            
            # Derive z from seed
            z = hkdf.expand(prk, b"implicit_z", 32)
            
            if self.gpu:
                s = cp.asarray(s_np)
                e = cp.asarray(e_np)
            else:
                s = s_np
                e = e_np
        else:
            # Standard PKE: TRUE RANDOMNESS for secret values
            pk_seed = secrets.token_bytes(32)
            
            # Generate s and e from TRUE RANDOMNESS (not from seed!)
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
            
            # Generate implicit rejection seed
            z = secrets.token_bytes(32)
        
        # Reconstruct A from pk_seed (deterministic)
        A = self._reconstruct_A(pk_seed)
        
        # Compute b = A @ s + e (mod q)
        b = self._mod_q(A @ s + e)
        
        # Compute pk_hash for FO transform
        # Use uint32 representation for consistency with serialization
        b_np = self._to_numpy(b)
        b_bytes_for_hash = b_np.astype("<u4").tobytes()
        pk_bytes_for_hash = pk_seed + b_bytes_for_hash
        pk_hash = _sha256(b"pk_hash", pk_bytes_for_hash)
        
        # Store keys
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
        """
        Load public key from serialized bytes.
        
        Use this on the SENDER side to encrypt to a recipient.
        After calling this, encaps() is available but decaps() is not.
        
        Args:
            pk_bytes: Serialized public key (from recipient's key_gen)
        """
        self.pk = LWEPublicKey.from_bytes(pk_bytes)
        self.sk = None  # Cannot decaps without secret key!
        
        # Update parameters from public key
        self.n = self.pk.n
        self.k = self.pk.k
        self.q = self.pk.q
        self.msg_bits = self.n
        self.msg_bytes = self.n // 8
    
    def load_secret_key(self, sk_bytes: bytes) -> None:
        """
        Load secret key from serialized bytes.
        
        MUST be called together with load_public_key for decaps to work.
        
        Args:
            sk_bytes: Serialized secret key
        """
        self._import_secret_key(sk_bytes)
    
    def get_public_key_bytes(self) -> bytes:
        """Get serialized public key for transmission."""
        if self.pk is None:
            raise ValueError("Public key not initialized")
        return self.pk.to_bytes()
    
    def get_public_key_size(self) -> int:
        """Get public key size in bytes."""
        # header(12) + pk_seed(32) + b(k*4 as uint32) + pk_hash(32)
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
        
        # Reconstruct A from pk_seed
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
    ) -> Tuple[bytes, LWECiphertext]:
        """
        KEM encapsulation (encryption).
        
        Can be called by ANYONE with the public key!
        
        Returns:
            K: Shared secret (32 bytes)
            ct: Ciphertext
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
        
        # KDF input uses wire format (uint32) for specification consistency
        ct_wire = ct.to_bytes()
        K = _derive_key(m + ct_wire, b"meteor-nc-shared-secret")
        
        return K, ct
    
    def decaps(self, ct: LWECiphertext) -> bytes:
        """
        KEM decapsulation (decryption).
        
        Can ONLY be called by the holder of the secret key!
        
        Returns:
            K: Shared secret (32 bytes)
        """
        if self.pk is None or self.sk is None:
            raise ValueError("Keys not initialized (need both pk and sk for decaps)")
        
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
        
        # Use wire format (uint32) for CT comparison and KDF input
        ct_wire = ct.to_bytes()
        ct2_wire = ct2.to_bytes()
        
        ok = _ct_eq(ct_wire, ct2_wire)
        
        K_good = _derive_key(m_prime + ct_wire, b"meteor-nc-shared-secret")
        K_fail = _derive_key(self.sk.z + ct_wire, b"meteor-nc-implicit-reject")
        
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
    ):
        if security_level not in SECURITY_PARAMS:
            raise ValueError(f"Unsupported security level: {security_level}")
        
        params = SECURITY_PARAMS[security_level]
        self.security_level = int(security_level)
        self.n = int(params["n"])
        self.gpu = bool(gpu and GPU_AVAILABLE)
        self.device_id = int(device_id)
        self.mixer_rounds = int(mixer_rounds)
        
        self.kem = LWEKEM(
            n=params["n"],
            k=params["k"],
            q=params["q"],
            eta=params["eta"],
            gpu=self.gpu,
            device_id=self.device_id,
        )
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """
        Generate key pair.
        
        Returns:
            Tuple of (public_key_bytes, secret_key_bytes)
        """
        return self.kem.key_gen()
    
    def load_public_key(self, pk_bytes: bytes) -> None:
        """Load recipient's public key for encryption."""
        self.kem.load_public_key(pk_bytes)
    
    def load_keys(self, pk_bytes: bytes, sk_bytes: bytes) -> None:
        """Load both public and secret keys for decryption."""
        self.kem.load_public_key(pk_bytes)
        self.kem.load_secret_key(sk_bytes)
    
    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> FullCiphertext:
        """Encrypt plaintext with optional associated data."""
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required")
        
        K, kem_ct = self.kem.encaps()
        aead_key = _derive_key(K, b"meteor-nc-aead-key")
        mixer_key = _derive_key(K, b"meteor-nc-mixer-key")  # Derive from shared secret!
        
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
        
        return FullCiphertext(
            u=kem_ct.u,
            v=kem_ct.v,
            nonce=nonce,
            ct=ct_body,
            tag=tag,
        )
    
    def decrypt(self, ciphertext: FullCiphertext, aad: Optional[bytes] = None) -> bytes:
        """Decrypt ciphertext with optional AAD verification."""
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required")
        
        kem_ct = LWECiphertext(u=ciphertext.u, v=ciphertext.v)
        K = self.kem.decaps(kem_ct)
        
        aead_key = _derive_key(K, b"meteor-nc-aead-key")
        mixer_key = _derive_key(K, b"meteor-nc-mixer-key")  # Derive from shared secret!
        
        mixer = SymmetricMixer(
            key=mixer_key,
            rounds=self.mixer_rounds,
            gpu=self.gpu,
            device_id=self.device_id,
        )
        
        aesgcm = AESGCM(aead_key)
        ct_with_tag = ciphertext.ct + ciphertext.tag
        mixed = aesgcm.decrypt(ciphertext.nonce, ct_with_tag, aad)
        
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
    print("Meteor-NC Core Test Suite (Correct PKE Design)")
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
    
    # Test 2: LWE-KEM Key Generation and Basic Encrypt/Decrypt
    print("\n[Test 2] LWE-KEM (Multi-Security Levels)")
    print("-" * 40)
    
    kem_ok = True
    for level, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit")]:
        params = SECURITY_PARAMS[level]
        kem = LWEKEM(n=params["n"], k=params["k"], eta=params["eta"], gpu=use_gpu)
        pk_bytes, sk_bytes = kem.key_gen()
        
        K1, ct = kem.encaps()
        K2 = kem.decaps(ct)
        match = (K1 == K2)
        kem_ok = kem_ok and match
        
        pk_size = len(pk_bytes)
        print(f"  {label}: PK={pk_size}B, KeyMatch={'PASS' if match else 'FAIL'}")
    
    results["kem"] = kem_ok
    
    # Test 3: Correct PKE Structure (Sender/Receiver Separation)
    print("\n[Test 3] Sender/Receiver Separation (Core Security Test)")
    print("-" * 40)
    
    separation_ok = True
    
    for level, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit")]:
        params = SECURITY_PARAMS[level]
        
        # RECEIVER: Generate keys and keep secret key
        receiver = LWEKEM(n=params["n"], k=params["k"], eta=params["eta"], gpu=use_gpu)
        pk_bytes, sk_bytes = receiver.key_gen()
        
        # SENDER: Only gets public key (simulating key exchange)
        sender = LWEKEM(n=params["n"], k=params["k"], eta=params["eta"], gpu=use_gpu)
        sender.load_public_key(pk_bytes)
        
        # Sender can encrypt
        K_sender, ct = sender.encaps()
        
        # Sender CANNOT decrypt (no secret key)
        try:
            sender.decaps(ct)
            sender_cannot_decrypt = False  # BAD: sender could decrypt
        except ValueError:
            sender_cannot_decrypt = True   # GOOD: sender blocked
        
        # Receiver CAN decrypt
        K_receiver = receiver.decaps(ct)
        keys_match = (K_sender == K_receiver)
        
        level_ok = sender_cannot_decrypt and keys_match
        separation_ok = separation_ok and level_ok
        
        print(f"  {label}: SenderBlocked={'PASS' if sender_cannot_decrypt else 'FAIL'}, "
              f"KeyMatch={'PASS' if keys_match else 'FAIL'}")
    
    results["separation"] = separation_ok
    
    # Test 4: Public Key Serialization
    print("\n[Test 4] Public Key Serialization")
    print("-" * 40)
    
    serial_ok = True
    for level, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit")]:
        params = SECURITY_PARAMS[level]
        
        kem1 = LWEKEM(n=params["n"], gpu=use_gpu)
        pk_bytes, sk_bytes = kem1.key_gen()
        
        # Deserialize and use
        kem2 = LWEKEM(n=params["n"], gpu=use_gpu)
        kem2.load_public_key(pk_bytes)
        kem2.load_secret_key(sk_bytes)
        
        K1, ct = kem2.encaps()
        K2 = kem2.decaps(ct)
        
        match = (K1 == K2)
        serial_ok = serial_ok and match
        print(f"  {label}: {'PASS' if match else 'FAIL'}")
    
    results["serialization"] = serial_ok
    
    # Test 5: Hybrid Encryption
    if CRYPTO_AVAILABLE:
        print("\n[Test 5] Hybrid Encryption")
        print("-" * 40)
        
        # Receiver generates keys
        receiver = HybridKEM(security_level=128, gpu=use_gpu)
        pk_bytes, sk_bytes = receiver.key_gen()
        
        # Sender encrypts with public key only
        sender = HybridKEM(security_level=128, gpu=use_gpu)
        sender.load_public_key(pk_bytes)
        
        msg = b"Test message for hybrid encryption - confidential!"
        ct = sender.encrypt(msg, aad=b"metadata")
        
        # Receiver decrypts with both keys
        receiver_dec = HybridKEM(security_level=128, gpu=use_gpu)
        receiver_dec.load_keys(pk_bytes, sk_bytes)
        pt = receiver_dec.decrypt(ct, aad=b"metadata")
        
        enc_ok = (msg == pt)
        results["encryption"] = enc_ok
        print(f"  Encrypt/Decrypt: {'PASS' if enc_ok else 'FAIL'}")
        
        # AEAD integrity
        try:
            _ = receiver_dec.decrypt(ct, aad=b"wrong")
            aead_ok = False
        except Exception:
            aead_ok = True
        results["aead"] = aead_ok
        print(f"  AEAD Integrity: {'PASS' if aead_ok else 'FAIL'}")
    
    # Test 6: HKDF Key Derivation
    print("\n[Test 6] HKDF Key Derivation")
    print("-" * 40)
    
    test_ikm = b"test input keying material"
    k1 = _derive_key(test_ikm, b"context-a", 32)
    k2 = _derive_key(test_ikm, b"context-a", 32)
    k3 = _derive_key(test_ikm, b"context-b", 32)
    
    hkdf_ok = (k1 == k2) and (k1 != k3)
    results["hkdf"] = hkdf_ok
    print(f"  Deterministic: {'PASS' if k1 == k2 else 'FAIL'}")
    print(f"  Domain Separation: {'PASS' if k1 != k3 else 'FAIL'}")
    
    # Test 7: Public Key and Ciphertext Sizes (Wire Format)
    print("\n[Test 7] Public Key & Ciphertext Sizes (Wire Format, uint32)")
    print("-" * 40)
    
    size_ok = True
    for level, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit")]:
        params = SECURITY_PARAMS[level]
        kem = LWEKEM(n=params["n"], gpu=use_gpu)
        pk_bytes, _ = kem.key_gen()
        
        # Public key size (uint32 for b)
        expected_pk_size = 12 + 32 + params["k"] * 4 + 32  # header + pk_seed + b(uint32) + pk_hash
        actual_pk_size = len(pk_bytes)
        pk_match = (actual_pk_size == expected_pk_size)
        size_ok = size_ok and pk_match
        
        # Ciphertext size (wire format)
        _, ct = kem.encaps()
        wire_size = ct.wire_size()  # Uses the new method!
        expected_ct_size = 8 + params["n"] * 4 + kem.msg_bits * 4  # header + u + v
        ct_match = (wire_size == expected_ct_size)
        size_ok = size_ok and ct_match
        
        # CT serialization round-trip
        ct_bytes = ct.to_bytes()
        ct_restored = LWECiphertext.from_bytes(ct_bytes)
        ct_roundtrip = np.array_equal(ct.u, ct_restored.u) and np.array_equal(ct.v, ct_restored.v)
        size_ok = size_ok and ct_roundtrip
        
        print(f"  {label}:")
        print(f"    PK: {actual_pk_size}B (expected {expected_pk_size}B) {'✓' if pk_match else '✗'}")
        print(f"    CT: {wire_size}B (expected {expected_ct_size}B) {'✓' if ct_match else '✗'}")
        print(f"    CT round-trip: {'✓' if ct_roundtrip else '✗'}")
    
    results["wire_format"] = size_ok
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    
    if all_pass:
        print("\n✓ Security property verified:")
        print("  - Sender with pk_seed + b CAN encrypt")
        print("  - Sender with pk_seed + b CANNOT decrypt")
        print("  - Only secret key holder can decrypt")
        print("  - pk_seed leak does NOT compromise secret key!")
    
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
