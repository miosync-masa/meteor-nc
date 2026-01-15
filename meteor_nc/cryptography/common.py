# meteor_nc/common.py
"""
Meteor-NC Common Components

Shared utilities, constants, and data structures for the Meteor-NC cryptosystem.
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
    """Constant-time byte comparison. Returns 1 if equal, 0 otherwise."""
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
    """Deterministic PRG using SHA-256 in counter mode."""
    out = bytearray()
    ctr = 0
    while len(out) < out_len:
        out.extend(_sha256(domain, seed + struct.pack("<I", ctr)))
        ctr += 1
    return bytes(out[:out_len])


def cbd_vector_from_seed(seed: bytes, n: int, eta: int = 2) -> np.ndarray:
    """
    Deterministic centered binomial sample in [-eta, eta]^n from seed.
    Uses 2*eta bits per coefficient.
    
    This ensures CPU/GPU produce identical results for FO re-encryption.
    """
    nbits = n * 2 * eta
    nbytes = (nbits + 7) // 8
    buf = prg_sha256(seed, nbytes, domain=b"cbd")
    bits = np.unpackbits(np.frombuffer(buf, dtype=np.uint8))[:nbits].astype(np.int8)
    bits = bits.reshape(n, 2 * eta)
    a = bits[:, :eta].sum(axis=1)
    b = bits[:, eta:].sum(axis=1)
    return (a - b).astype(np.int64)
    
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
    """LWE public key: (A, b) where b = As + e (mod q)"""
    A: Any          # (k, n) matrix
    b: Any          # (k,) vector
    pk_hash: bytes  # H(pk) for FO transform


@dataclass
class LWESecretKey:
    """LWE secret key with implicit rejection component."""
    s: Any      # (n,) secret vector
    z: bytes    # implicit rejection seed


@dataclass
class LWECiphertext:
    """LWE ciphertext: (u, v)"""
    u: np.ndarray  # (n,) vector
    v: np.ndarray  # (MSG_BITS,) vector


@dataclass
class FullCiphertext:
    """Hybrid ciphertext: KEM ciphertext + DEM ciphertext"""
    u: np.ndarray
    v: np.ndarray
    nonce: bytes
    ct: bytes
    tag: bytes
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return (
            struct.pack(">I", len(self.u)) +
            self.u.astype(np.int64).tobytes() +
            self.v.astype(np.int64).tobytes() +
            self.nonce +
            struct.pack(">I", len(self.ct)) +
            self.ct +
            self.tag
        )
    
    @classmethod
    def from_bytes(cls, data: bytes, n: int, msg_bits: int = MSG_BITS) -> "FullCiphertext":
        """Deserialize from bytes."""
        offset = 0
        
        u_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        
        u = np.frombuffer(data[offset:offset + u_len*8], dtype=np.int64).copy()
        offset += u_len * 8
        
        v = np.frombuffer(data[offset:offset + msg_bits*8], dtype=np.int64).copy()
        offset += msg_bits * 8
        
        nonce = data[offset:offset+12]
        offset += 12
        
        ct_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        
        ct = data[offset:offset+ct_len]
        offset += ct_len
        
        tag = data[offset:offset+16]
        
        return cls(u=u, v=v, nonce=nonce, ct=ct, tag=tag)


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
