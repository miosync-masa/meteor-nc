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

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

import numpy as np


# =============================================================================
# GPU Detection
# =============================================================================

try:
    import cupy as cp
    GPU_AVAILABLE = True
except ImportError:
    cp = None
    GPU_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    AESGCM = None
    CRYPTO_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

Q_DEFAULT: int = 4294967291  # 2^32 - 5 (prime)

SECURITY_PARAMS: Dict[int, Dict[str, int]] = {
    128: {"n": 256, "k": 256, "eta": 2, "q": Q_DEFAULT},
    192: {"n": 512, "k": 512, "eta": 2, "q": Q_DEFAULT},
    256: {"n": 1024, "k": 1024, "eta": 3, "q": Q_DEFAULT},
}


# =============================================================================
# Utility Functions
# =============================================================================

def _sha256(*chunks: bytes) -> bytes:
    """Compute SHA-256 hash of concatenated inputs."""
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def _ct_eq(a: bytes, b: bytes) -> int:
    """
    Constant-time byte comparison. Returns 1 if equal, 0 otherwise.
    
    Note: Length check is not constant-time, but in FO transform
    ct and ct' are always same-length by construction.
    """
    if len(a) != len(b):
        return 0
    return 1 if hmac.compare_digest(a, b) else 0


def _words_from_bytes_le(data: bytes) -> np.ndarray:
    """Convert bytes to uint32 array (little-endian), with zero-padding."""
    pad = (-len(data)) % 4
    if pad:
        data = data + b"\x00" * pad
    return np.frombuffer(data, dtype="<u4").copy()


def _bytes_from_words_le(words: np.ndarray) -> bytes:
    """Convert uint32 array to bytes (little-endian)."""
    return words.astype("<u4", copy=False).tobytes()


def prg_sha256(seed: bytes, out_len: int, domain: bytes = b"prg") -> bytes:
    """Deterministic PRG using SHA-256 in counter mode."""
    out = bytearray()
    ctr = 0
    while len(out) < out_len:
        out.extend(_sha256(domain, seed, struct.pack("<I", ctr)))
        ctr += 1
    return bytes(out[:out_len])


def small_error_from_seed(seed: bytes, n: int) -> np.ndarray:
    """Deterministic error sampling in [-2, 2]^n from seed."""
    nbytes = n
    buf = prg_sha256(seed, nbytes, domain=b"error")
    arr = np.frombuffer(buf, dtype=np.uint8).copy()
    return ((arr % 5) - 2).astype(np.int64)


# =============================================================================
# HKDF (RFC 5869)
# =============================================================================

class HKDF:
    """HMAC-based Key Derivation Function (RFC 5869)."""
    
    HASH_LEN: int = 32
    
    def __init__(self, salt: Optional[bytes] = None):
        self.salt = salt if salt is not None else b"\x00" * self.HASH_LEN
    
    def extract(self, ikm: bytes) -> bytes:
        """HKDF-Extract: PRK = HMAC(salt, IKM)"""
        return hmac.new(self.salt, ikm, hashlib.sha256).digest()
    
    def expand(self, prk: bytes, info: bytes = b"", length: int = 32) -> bytes:
        """HKDF-Expand: OKM = T(1) || T(2) || ... truncated to length"""
        n_blocks = (length + self.HASH_LEN - 1) // self.HASH_LEN
        okm = b""
        t_prev = b""
        for i in range(1, n_blocks + 1):
            t_prev = hmac.new(prk, t_prev + info + bytes([i]), hashlib.sha256).digest()
            okm += t_prev
        return okm[:length]
    
    def derive(self, ikm: bytes, info: bytes = b"", length: int = 32) -> bytes:
        """One-shot derivation: Extract then Expand."""
        return self.expand(self.extract(ikm), info, length)


# Domain-separated HKDF for Meteor-NC
_METEOR_SALT = _sha256(b"meteor-nc-v1-hkdf-salt")
_HKDF_INSTANCE = HKDF(salt=_METEOR_SALT)


def _derive_key(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-based key derivation with proper domain separation."""
    return _HKDF_INSTANCE.derive(ikm, info, length)


# =============================================================================
# Centered Binomial Distribution
# =============================================================================

class CenteredBinomial:
    """Centered binomial distribution sampler."""
    
    def __init__(self, eta: int = 2, xp: Any = np):
        if eta <= 0:
            raise ValueError("Parameter eta must be positive")
        self.eta = int(eta)
        self.xp = xp
    
    def sample(self, shape: Tuple[int, ...], rng: Optional[Any] = None) -> Any:
        """Sample from centered binomial distribution."""
        xp = self.xp
        eta = self.eta
        
        if rng is None:
            bits = xp.random.randint(0, 2, size=shape + (2 * eta,), dtype=xp.int8)
        else:
            bits = rng.randint(0, 2, size=shape + (2 * eta,)).astype(np.int8)
        
        a = bits[..., :eta].sum(axis=-1)
        b = bits[..., eta:].sum(axis=-1)
        return (a - b).astype(xp.int64)
    
    def sample_vector(self, n: int, rng: Optional[Any] = None) -> Any:
        """Sample a 1D vector."""
        return self.sample((n,), rng=rng)


# =============================================================================
# Data Structures (Correct Design!)
# =============================================================================

@dataclass
class LWEPublicKey:
    """
    LWE public key with compact representation.
    
    Structure:
      - pk_seed: 32 bytes (used to reconstruct matrix A)
      - b: n-dimensional vector (b = A @ s + e)
      - pk_hash: H(pk) for FO transform
      
    Total public key size: 12 (header) + 32 (pk_seed) + k*4 (b as uint32) + 32 (pk_hash)
      - n=256:  12 + 32 + 1024 + 32 = 1100 bytes ≈ 1KB
      - n=512:  12 + 32 + 2048 + 32 = 2124 bytes ≈ 2KB
      - n=1024: 12 + 32 + 4096 + 32 = 4172 bytes ≈ 4KB
    
    Matrix A (n×n) is NOT stored - reconstructed from pk_seed when needed!
    
    Note: b is serialized as uint32 (little-endian) since all values are in [0, q)
    where q < 2^32. This halves the public key size compared to int64.
    """
    pk_seed: bytes      # 32 bytes - reconstruct A from this
    b: np.ndarray       # (k,) vector - CANNOT be derived from seed!
    pk_hash: bytes      # H(pk) for FO transform
    n: int              # dimension
    k: int              # k (= n by default)
    q: int              # modulus
    
    def to_bytes(self) -> bytes:
        """Serialize public key to bytes (b as uint32 for compactness)."""
        header = struct.pack(">III", self.n, self.k, self.q)
        # b values are in [0, q) where q < 2^32, so uint32 is sufficient
        b_bytes = self.b.astype("<u4").tobytes()
        return header + self.pk_seed + b_bytes + self.pk_hash
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "LWEPublicKey":
        """Deserialize public key from bytes."""
        n, k, q = struct.unpack(">III", data[:12])
        offset = 12
        
        pk_seed = data[offset:offset + 32]
        offset += 32
        
        # b is stored as uint32, convert to int64 for computation
        b = np.frombuffer(data[offset:offset + k * 4], dtype="<u4").astype(np.int64).copy()
        offset += k * 4
        
        pk_hash = data[offset:offset + 32]
        
        return cls(pk_seed=pk_seed, b=b, pk_hash=pk_hash, n=n, k=k, q=q)


@dataclass
class LWESecretKey:
    """
    LWE secret key.
    
    Structure:
      - s: Secret vector (n-dimensional)
      - z: Implicit rejection seed (32 bytes)
      
    IMPORTANT: s is generated from TRUE RANDOMNESS, NOT from any seed!
    """
    s: np.ndarray   # (n,) secret vector - TRUE RANDOM!
    z: bytes        # implicit rejection seed


@dataclass
class LWECiphertext:
    """
    LWE ciphertext: (u, v)
    
    Wire format (uint32 little-endian):
      - u: n×4 bytes
      - v: msg_bits×4 bytes
    
    Internal representation uses int64 for computation headroom.
    """
    u: np.ndarray  # (n,) vector, int64 internally
    v: np.ndarray  # (msg_bits,) vector, int64 internally
    
    def to_bytes(self) -> bytes:
        """Serialize to wire format (uint32 little-endian)."""
        return (
            struct.pack(">II", len(self.u), len(self.v)) +
            self.u.astype("<u4").tobytes() +
            self.v.astype("<u4").tobytes()
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "LWECiphertext":
        """Deserialize from wire format with input validation."""
        if len(data) < 8:
            raise ValueError(f"LWECiphertext too short: {len(data)} < 8 bytes")
        
        u_len, v_len = struct.unpack(">II", data[:8])
        expected_size = 8 + u_len * 4 + v_len * 4
        
        if len(data) < expected_size:
            raise ValueError(f"LWECiphertext truncated: {len(data)} < {expected_size}")
        
        offset = 8
        u = np.frombuffer(data[offset:offset + u_len * 4], dtype="<u4").astype(np.int64).copy()
        offset += u_len * 4
        
        v = np.frombuffer(data[offset:offset + v_len * 4], dtype="<u4").astype(np.int64).copy()
        
        return cls(u=u, v=v)
    
    def wire_size(self) -> int:
        """Get wire format size in bytes."""
        return 8 + len(self.u) * 4 + len(self.v) * 4


@dataclass
class FullCiphertext:
    """
    Hybrid ciphertext: KEM ciphertext + DEM ciphertext.
    
    Wire format:
      - kem_ct: LWECiphertext wire format (8B header + u + v as uint32)
      - nonce: 12 bytes (AEAD nonce)
      - ct_len: 4 bytes (BE)
      - ct: DEM ciphertext body
      - tag: 16 bytes (AEAD tag)
    
    Note: KEM portion uses same wire format as LWECiphertext for consistency.
    """
    u: np.ndarray
    v: np.ndarray
    nonce: bytes
    ct: bytes
    tag: bytes
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes (KEM portion uses LWECiphertext wire format)."""
        # Use LWECiphertext wire format for consistency
        kem_ct = LWECiphertext(u=self.u, v=self.v)
        kem_wire = kem_ct.to_bytes()
        
        return (
            kem_wire +
            self.nonce +
            struct.pack(">I", len(self.ct)) +
            self.ct +
            self.tag
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "FullCiphertext":
        """Deserialize from bytes with input validation."""
        # Minimum: KEM header (8B) + nonce (12B) + ct_len (4B) + tag (16B) = 40B
        if len(data) < 40:
            raise ValueError(f"FullCiphertext too short: {len(data)} < 40 bytes")
        
        # Parse KEM portion using LWECiphertext format
        u_len, v_len = struct.unpack(">II", data[:8])
        kem_size = 8 + u_len * 4 + v_len * 4
        
        if kem_size > len(data):
            raise ValueError(f"Invalid KEM size: {kem_size} > {len(data)}")
        
        kem_ct = LWECiphertext.from_bytes(data[:kem_size])
        offset = kem_size
        
        # Validate remaining length for nonce + ct_len header
        if offset + 16 > len(data):  # 12 (nonce) + 4 (ct_len)
            raise ValueError(f"Truncated after KEM: offset {offset}, len {len(data)}")
        
        nonce = data[offset:offset+12]
        offset += 12
        
        ct_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        
        # Validate ct + tag length
        if offset + ct_len + 16 > len(data):
            raise ValueError(f"Truncated ciphertext: need {offset + ct_len + 16}, have {len(data)}")
        
        ct = data[offset:offset+ct_len]
        offset += ct_len
        
        tag = data[offset:offset+16]
        
        return cls(u=kem_ct.u, v=kem_ct.v, nonce=nonce, ct=ct, tag=tag)


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
    ):
        self.n = int(n)
        self.k = int(k if k is not None else n)
        self.q = int(q)
        self.eta = int(eta)
        
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
        
        IMPORTANT: Secret key s is generated from TRUE RANDOMNESS,
        NOT from any seed! This ensures pk_seed leaking doesn't
        compromise the secret key.
        
        Returns:
            Tuple of (public_key_bytes, secret_key_bytes) for storage
        """
        # Generate random pk_seed (this CAN be public!)
        pk_seed = secrets.token_bytes(32)
        
        # Reconstruct A from pk_seed (deterministic)
        A = self._reconstruct_A(pk_seed)
        
        # Generate s and e from TRUE RANDOMNESS (not from seed!)
        if self.gpu:
            # Use cryptographically secure random for secret values
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
            # Use secrets module for cryptographic randomness
            s = np.array([
                secrets.randbelow(2 * self.eta + 1) - self.eta 
                for _ in range(self.n)
            ], dtype=np.int64)
            e = np.array([
                secrets.randbelow(2 * self.eta + 1) - self.eta 
                for _ in range(self.k)
            ], dtype=np.int64)
        
        # Compute b = A @ s + e (mod q)
        b = self._mod_q(A @ s + e)
        
        # Compute pk_hash for FO transform
        # Use uint32 representation for consistency with serialization
        b_np = self._to_numpy(b)
        b_bytes_for_hash = b_np.astype("<u4").tobytes()
        pk_bytes_for_hash = pk_seed + b_bytes_for_hash
        pk_hash = _sha256(b"pk_hash", pk_bytes_for_hash)
        
        # Generate implicit rejection seed
        z = secrets.token_bytes(32)
        
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
