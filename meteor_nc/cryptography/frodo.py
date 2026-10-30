"""
Meteor-NC v3 core: FrodoKEM (SHAKE variants), vectorised with NumPy.

Why this exists
---------------
Meteor-NC v2 encrypted an n-bit message under a *single* scalar mask
(v = <b, r> + e2 + Delta*m). Differences v_i - v_j leak m_i XOR m_j, so a
passive eavesdropper recovers the shared secret from (pk, ct) alone.
v2 parameters (q ~ 2^32, |e| <= 3) were also far below their claimed levels.

v3 replaces the core with FrodoKEM, an unstructured (plain) LWE KEM:
  * every message chunk gets its own mask (matrix LWE, nbar = mbar = 8),
  * parameters and error tables are the published FrodoKEM ones
    (640 / 976 / 1344, SHAKE), whose concrete security is analysed in the
    FrodoKEM specification and its estimator scripts,
  * outputs are byte-identical to the FrodoKEM reference implementation
    (checked against the official NIST KAT files, see tests/test_frodo_kat.py).

No new hardness assumption and no new parameter choice is introduced here.

Side-channel note: this is pure Python/NumPy. Comparisons and selects use
hmac.compare_digest and byte masking, but Python offers no constant-time
guarantees. Treat this as a research / reference implementation.

Specification: FrodoKEM, "Learning With Errors Key Encapsulation",
https://frodokem.org/ ; algorithm numbers below refer to that document.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

import numpy as np


# ---------------------------------------------------------------------------
# Parameter sets (FrodoKEM specification, Tables 3-5)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FrodoParams:
    name: str
    n: int
    D: int                 # q = 2^D
    B: int                 # bits encoded per matrix entry
    chi: Tuple[int, ...]   # error distribution table (multiples of 2^-16)
    len_sec: int           # len_s = len_k = len_pkh = len_ss = len_mu (bytes)
    len_seedSE: int        # = len_salt (bytes)
    shake: str             # "shake128" | "shake256" (for hashing, not Gen)
    nist_level: int
    nbar: int = 8
    mbar: int = 8
    len_seedA: int = 16
    len_z: int = 16

    @property
    def q(self) -> int:
        return 1 << self.D

    @property
    def len_salt(self) -> int:
        return self.len_seedSE

    @property
    def pk_bytes(self) -> int:
        return self.len_seedA + self.D * self.n * self.nbar // 8

    @property
    def ct_bytes(self) -> int:
        return (self.D * self.mbar * self.n // 8
                + self.D * self.mbar * self.nbar // 8 + self.len_salt)

    @property
    def sk_bytes(self) -> int:
        return (self.len_sec + self.pk_bytes
                + 2 * self.n * self.nbar + self.len_sec)

    @property
    def ss_bytes(self) -> int:
        return self.len_sec


FRODO640 = FrodoParams(
    name="FrodoKEM-640-SHAKE", n=640, D=15, B=2,
    chi=(9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1),
    len_sec=16, len_seedSE=32, shake="shake128", nist_level=1)

FRODO976 = FrodoParams(
    name="FrodoKEM-976-SHAKE", n=976, D=16, B=3,
    chi=(11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1),
    len_sec=24, len_seedSE=48, shake="shake256", nist_level=3)

FRODO1344 = FrodoParams(
    name="FrodoKEM-1344-SHAKE", n=1344, D=16, B=4,
    chi=(18286, 14320, 6876, 2023, 364, 40, 2),
    len_sec=32, len_seedSE=64, shake="shake256", nist_level=5)

PARAMS_BY_LEVEL: Dict[int, FrodoParams] = {1: FRODO640, 3: FRODO976, 5: FRODO1344}
PARAMS_BY_NAME: Dict[str, FrodoParams] = {p.name: p for p in PARAMS_BY_LEVEL.values()}


def _cdf(chi: Tuple[int, ...]) -> np.ndarray:
    """Zero-centred CDF table T_chi (spec Section 2.2.4)."""
    t = [chi[0] // 2 - 1]
    for z in range(1, len(chi)):
        t.append(t[0] + sum(chi[1:z + 1]))
    return np.array(t, dtype=np.int64)


# ---------------------------------------------------------------------------
# FrodoKEM
# ---------------------------------------------------------------------------

class FrodoKEM:
    """FrodoKEM-{640,976,1344}-SHAKE, byte-compatible with the reference."""

    def __init__(self, params: FrodoParams = FRODO640,
                 randombytes: Optional[Callable[[int], bytes]] = None):
        self.p = params
        self.randombytes = randombytes or secrets.token_bytes
        self._T = _cdf(params.chi)[:-1]          # thresholds actually compared
        self._A_cache: Dict[bytes, np.ndarray] = {}

    # -- symmetric primitives ------------------------------------------------
    def _H(self, data: bytes, outlen: int) -> bytes:
        h = hashlib.shake_128() if self.p.shake == "shake128" else hashlib.shake_256()
        h.update(data)
        return h.digest(outlen)

    def gen_A(self, seedA: bytes) -> np.ndarray:
        """Algorithm 8 (Gen with SHAKE-128). Returns int64 n x n matrix mod q."""
        A = self._A_cache.get(seedA)
        if A is not None:
            return A
        n = self.p.n
        rows = bytearray()
        for i in range(n):
            rows += hashlib.shake_128(i.to_bytes(2, "little") + seedA).digest(2 * n)
        A = np.frombuffer(bytes(rows), dtype="<u2").astype(np.int64).reshape(n, n)
        A &= self.p.q - 1
        if len(self._A_cache) > 8:
            self._A_cache.clear()
        self._A_cache[seedA] = A
        return A

    def _sample(self, rbytes: bytes, rows: int, cols: int) -> np.ndarray:
        """Algorithms 5/6: sample a rows x cols matrix from chi."""
        r = np.frombuffer(rbytes, dtype="<u2").astype(np.int64)
        t = r >> 1
        e = (t[:, None] > self._T[None, :]).sum(axis=1)
        e = np.where(r & 1, -e, e)
        return e.reshape(rows, cols)

    # -- encode / decode / pack ---------------------------------------------
    def encode(self, mu: bytes) -> np.ndarray:
        """Algorithm 1."""
        p = self.p
        bits = np.unpackbits(np.frombuffer(mu, np.uint8), bitorder="little")
        bits = bits.astype(np.int64).reshape(p.mbar * p.nbar, p.B)
        vals = (bits << np.arange(p.B)).sum(axis=1)
        return (vals * (p.q >> p.B)).reshape(p.mbar, p.nbar)

    def decode(self, M: np.ndarray) -> bytes:
        """Algorithm 2: round(M * 2^B / q) mod 2^B, integer arithmetic."""
        p = self.p
        M = M & (p.q - 1)
        vals = (((M << p.B) + (1 << (p.D - 1))) >> p.D) & ((1 << p.B) - 1)
        bits = (vals.reshape(-1, 1) >> np.arange(p.B)) & 1
        return np.packbits(bits.reshape(-1).astype(np.uint8), bitorder="little").tobytes()

    def pack(self, C: np.ndarray) -> bytes:
        """Algorithm 3: D bits per entry, MSB first, row-major."""
        D = self.p.D
        v = (C & (self.p.q - 1)).reshape(-1)
        if D == 16:
            return v.astype(">u2").tobytes()
        bits = (v[:, None] >> np.arange(D - 1, -1, -1)) & 1
        return np.packbits(bits.reshape(-1).astype(np.uint8)).tobytes()

    def unpack(self, b: bytes, rows: int, cols: int) -> np.ndarray:
        """Algorithm 4."""
        D = self.p.D
        if D == 16:
            return np.frombuffer(b, dtype=">u2").astype(np.int64).reshape(rows, cols)
        bits = np.unpackbits(np.frombuffer(b, np.uint8))[: rows * cols * D]
        bits = bits.reshape(-1, D).astype(np.int64)
        return (bits << np.arange(D - 1, -1, -1)).sum(axis=1).reshape(rows, cols)

    # -- deterministic cores (used by KEM and by tests) ----------------------
    def keygen_from_seed(self, s_seedSE_z: bytes) -> Tuple[bytes, bytes]:
        """Algorithm 12 with explicit randomness s || seedSE || z."""
        p = self.p
        s = s_seedSE_z[:p.len_sec]
        seedSE = s_seedSE_z[p.len_sec:p.len_sec + p.len_seedSE]
        z = s_seedSE_z[p.len_sec + p.len_seedSE:]
        assert len(z) == p.len_z
        seedA = self._H(z, p.len_seedA)
        A = self.gen_A(seedA)
        r = self._H(b"\x5f" + seedSE, 4 * p.n * p.nbar)
        ST = self._sample(r[: 2 * p.n * p.nbar], p.nbar, p.n)
        E = self._sample(r[2 * p.n * p.nbar:], p.n, p.nbar)
        Bm = (A @ ST.T + E) & (p.q - 1)
        b = self.pack(Bm)
        pk = seedA + b
        pkh = self._H(pk, p.len_sec)
        sk = s + pk + ST.astype("<i2").tobytes() + pkh
        assert len(pk) == p.pk_bytes and len(sk) == p.sk_bytes
        return pk, sk

    def _encrypt(self, pk: bytes, mu: bytes, seedSE: bytes) -> Tuple[bytes, bytes]:
        p = self.p
        seedA, b = pk[:p.len_seedA], pk[p.len_seedA:]
        r = self._H(b"\x96" + seedSE, 2 * (2 * p.mbar * p.n + p.mbar * p.nbar))
        o1, o2 = 2 * p.mbar * p.n, 4 * p.mbar * p.n
        Sp = self._sample(r[:o1], p.mbar, p.n)
        Ep = self._sample(r[o1:o2], p.mbar, p.n)
        Epp = self._sample(r[o2:], p.mbar, p.nbar)
        A = self.gen_A(seedA)
        Bp = (Sp @ A + Ep) & (p.q - 1)
        Bm = self.unpack(b, p.n, p.nbar)
        C = (Sp @ Bm + Epp + self.encode(mu)) & (p.q - 1)
        return self.pack(Bp), self.pack(C)

    def encaps_from_seed(self, pk: bytes, mu_salt: bytes) -> Tuple[bytes, bytes]:
        """Algorithm 13 with explicit randomness mu || salt. Returns (ct, ss)."""
        p = self.p
        if len(pk) != p.pk_bytes:
            raise ValueError("Incorrect public key length")
        mu, salt = mu_salt[:p.len_sec], mu_salt[p.len_sec:]
        assert len(salt) == p.len_salt
        pkh = self._H(pk, p.len_sec)
        seedSE_k = self._H(pkh + mu + salt, p.len_seedSE + p.len_sec)
        seedSE, k = seedSE_k[:p.len_seedSE], seedSE_k[p.len_seedSE:]
        c1, c2 = self._encrypt(pk, mu, seedSE)
        ct = c1 + c2 + salt
        ss = self._H(ct + k, p.ss_bytes)
        return ct, ss

    # -- public KEM API ------------------------------------------------------
    def keygen(self) -> Tuple[bytes, bytes]:
        p = self.p
        return self.keygen_from_seed(self.randombytes(p.len_sec + p.len_seedSE + p.len_z))

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        p = self.p
        return self.encaps_from_seed(pk, self.randombytes(p.len_sec + p.len_salt))

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        """Algorithm 14 (implicit rejection)."""
        p = self.p
        if len(ct) != p.ct_bytes:
            raise ValueError("Incorrect ciphertext length")
        if len(sk) != p.sk_bytes:
            raise ValueError("Incorrect secret key length")
        l1 = p.D * p.mbar * p.n // 8
        l2 = p.D * p.mbar * p.nbar // 8
        c1, c2, salt = ct[:l1], ct[l1:l1 + l2], ct[l1 + l2:]
        o = 0
        s = sk[o:o + p.len_sec]; o += p.len_sec
        pk = sk[o:o + p.pk_bytes]; o += p.pk_bytes
        ST = np.frombuffer(sk[o:o + 2 * p.n * p.nbar], dtype="<i2").astype(np.int64)
        ST = ST.reshape(p.nbar, p.n); o += 2 * p.n * p.nbar
        pkh = sk[o:o + p.len_sec]

        Bp = self.unpack(c1, p.mbar, p.n)
        C = self.unpack(c2, p.mbar, p.nbar)
        M = (C - Bp @ ST.T) & (p.q - 1)
        mu = self.decode(M)
        seedSE_k = self._H(pkh + mu + salt, p.len_seedSE + p.len_sec)
        seedSE, k = seedSE_k[:p.len_seedSE], seedSE_k[p.len_seedSE:]
        c1p, c2p = self._encrypt(pk, mu, seedSE)
        ok = hmac.compare_digest(c1 + c2, c1p + c2p)
        mask = -int(ok) & 0xFF                     # 0xFF if ok else 0x00
        kbar = bytes((a & mask) | (b & ~mask & 0xFF) for a, b in zip(k, s))
        return self._H(c1 + c2 + salt + kbar, p.ss_bytes)


__all__ = ["FrodoParams", "FrodoKEM", "FRODO640", "FRODO976", "FRODO1344",
           "PARAMS_BY_LEVEL", "PARAMS_BY_NAME"]
