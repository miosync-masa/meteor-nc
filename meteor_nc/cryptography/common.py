# meteor_nc/cryptography/common.py
"""
Meteor-NC Common Components

Shared utilities, constants, and data structures for the Meteor-NC cryptosystem.

Wire Format Specification:
  - Header fields: big-endian (">I", ">II", ">III")
  - Coefficient arrays (b, u, v): little-endian uint32 ("<u4")
  - This mixed endianness is intentional: headers follow network byte order,
    while coefficient arrays use native x86/ARM little-endian for efficiency.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import numpy as np


# =============================================================================
# Constants
# =============================================================================

Q_DEFAULT: int = 4294967291  # 2^32 - 5 (prime)

MSG_BYTES: int = 32
MSG_BITS: int = MSG_BYTES * 8

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


def _int_from_bytes(b: bytes) -> int:
    """Convert bytes to integer (big-endian, unsigned)."""
    return int.from_bytes(b, "big", signed=False)


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
    """
    Deterministic PRG using SHA-256 in counter mode.
    
    Used for deterministic matrix reconstruction from pk_seed.
    Cross-platform compatible (no PRNG implementation dependency).
    """
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


def _derive_key(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """
    HKDF-based key derivation with domain separation.
    
    Used for:
      - Shared secret derivation: K = HKDF(m || ct_wire, "meteor-nc-shared-secret")
      - AEAD key derivation: aead_key = HKDF(K, "meteor-nc-aead-key")
      - Implicit rejection: K_fail = HKDF(z || ct_wire, "meteor-nc-implicit-reject")
    """
    hkdf = HKDF()
    return hkdf.derive(ikm, info, length)


# =============================================================================
# Centered Binomial Distribution
# =============================================================================

class CenteredBinomial:
    """
    Centered binomial distribution sampler.
    
    Samples from: sum_{i=1}^{eta} b_i - sum_{i=1}^{eta} b'_i
    where b_i, b'_i are uniform in {0, 1}.
    
    Range: [-eta, eta]
    """
    
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
# Data Structures
# =============================================================================

@dataclass
class LWEPublicKey:
    """
    LWE public key.
    
    CORRECT KEY STRUCTURE:
      - pk_seed (32B): Public, used to reconstruct matrix A via SHA-256 PRG
      - b (k×4B as uint32): Public, computed as A @ s + e mod q during key_gen
    
    Wire format sizes:
      - 12 (header: n, k, q) + 32 (pk_seed) + k*4 (b as uint32) + 32 (pk_hash)
    
    Matrix A reconstruction:
      - Uses SHA-256 in counter mode (deterministic, implementation-independent)
      - Bias from u32 mod q (q=2^32-5) is negligible (~5/2^32 per element)
    """
    pk_seed: bytes      # 32 bytes, for A reconstruction
    b: np.ndarray       # (k,) vector, int64 internally
    pk_hash: bytes      # H(pk_seed || b) for FO transform
    n: int              # dimension
    k: int              # rows
    q: int              # modulus
    
    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        b_np = np.asarray(self.b).astype(np.int64)
        b_bytes = b_np.astype("<u4").tobytes()
        return (
            struct.pack(">III", self.n, self.k, self.q) +
            self.pk_seed +
            b_bytes +
            self.pk_hash
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "LWEPublicKey":
        """Deserialize from wire format with input validation."""
        if len(data) < 12:
            raise ValueError(f"LWEPublicKey too short: {len(data)} < 12 bytes")
        
        n, k, q = struct.unpack(">III", data[:12])
        expected_size = 12 + 32 + k * 4 + 32
        
        if len(data) < expected_size:
            raise ValueError(f"LWEPublicKey truncated: {len(data)} < {expected_size}")
        
        pk_seed = data[12:44]
        b_raw = np.frombuffer(data[44:44 + k * 4], dtype="<u4").astype(np.int64).copy()
        pk_hash = data[44 + k * 4:44 + k * 4 + 32]
        
        return cls(pk_seed=pk_seed, b=b_raw, pk_hash=pk_hash, n=n, k=k, q=q)


@dataclass
class LWESecretKey:
    """LWE secret key with implicit rejection component."""
    s: Any      # (n,) secret vector, generated from TRUE RANDOMNESS
    z: bytes    # implicit rejection seed (32 bytes)


@dataclass
class LWECiphertext:
    """
    LWE ciphertext: (u, v)
    
    Wire format (uint32 little-endian):
      - header: 8 bytes (u_len, v_len as big-endian u32)
      - u: u_len×4 bytes
      - v: v_len×4 bytes
    
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
# Optional GPU Detection
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
