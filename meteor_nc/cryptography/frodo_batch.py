"""
Batched FrodoKEM (SHAKE) for NumPy or CuPy.

Same algorithm and byte output as ``frodo.FrodoKEM`` (and therefore the
FrodoKEM reference / NIST KATs), but every step after hashing works on a
whole batch of encapsulations or decapsulations at once, on CPU (NumPy) or
GPU (CuPy). The array module is chosen at construction time.

Exact integer matrix products on float GEMM
-------------------------------------------
GPUs are fastest at float GEMM, while FrodoKEM needs exact products mod 2^16.
Every product here has one "small" factor (secret or error entries, at most
12 in absolute value) and one "big" factor (entries < 2^16). The big factor
is split into bytes, big = lo + 256*hi with lo, hi in [0, 255], and each half
is multiplied in float32:

    |sum_k small[i,k] * half[k,j]|  <=  n * max|small| * 255
                                    <=  1344 * 6 * 255  (L5) ~ 2.1e6
                                    <=   640 * 12 * 255 (L1) ~ 2.0e6  <  2^24

Every partial sum is an integer below 2^24 in absolute value, so float32
represents it exactly regardless of summation order, and
small @ big = (small @ lo) + 256 * (small @ hi) exactly. With CuPy this runs
on cuBLAS SGEMM. TF32 must stay disabled (CuPy's default; do not set
CUPY_TF32=1), because TF32 rounds the inputs.

What stays on the CPU
---------------------
SHAKE (seed expansion, hashing of ct) runs per item with hashlib. It is the
remaining bottleneck and the natural target for a GPU Keccak kernel later.

Side channels: research implementation; no constant-time guarantees.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional, Tuple

import numpy as np

from .frodo import FrodoKEM, FrodoParams, FRODO640, _cdf

try:  # pragma: no cover - depends on the machine
    import cupy as _cp
    _cp.cuda.runtime.getDeviceCount()
    CUPY_AVAILABLE = True
except Exception:  # ImportError, CUDARuntimeError, ...
    _cp = None
    CUPY_AVAILABLE = False


def get_xp(backend: str = "auto"):
    """Return the array module for ``backend`` in {"auto", "numpy", "cupy"}."""
    if backend == "numpy":
        return np
    if backend == "cupy":
        if not CUPY_AVAILABLE:
            raise RuntimeError("CuPy with a CUDA device is not available")
        return _cp
    return _cp if CUPY_AVAILABLE else np


class BatchFrodoKEM:
    """Batched FrodoKEM-SHAKE; byte-identical to ``frodo.FrodoKEM``."""

    def __init__(self, params: FrodoParams = FRODO640, backend: str = "auto",
                 matmul: str = "f32split", chunk: int = 2048):
        if matmul not in ("f32split", "int64"):
            raise ValueError("matmul must be 'f32split' or 'int64'")
        self.p = params
        self.xp = get_xp(backend)
        self.backend = "cupy" if self.xp is not np else "numpy"
        self.matmul = matmul
        self.chunk = int(chunk)            # rows per device pass (bounds memory)
        import os
        try:
            tf32 = int(os.environ.get("CUPY_TF32", "0") or 0) > 0
        except ValueError:
            tf32 = True
        if self.xp is not np and matmul == "f32split" and tf32:
            raise RuntimeError("CUPY_TF32 enables TF32, which breaks exact float32 products; unset it")
        self.single = FrodoKEM(params)            # keygen, A generation, KATs
        self._T = [int(t) for t in _cdf(params.chi)[:-1]]   # host ints
        self._A_seed: Optional[bytes] = None
        self._A_dev: Any = None
        self._B_pk: Any = None
        self._gpu_shake = None
        if self.xp is not np:
            from .kernels.shake_kernel import GPUShake
            self._gpu_shake = GPUShake(params.shake)
        if matmul == "f32split":
            self._check_f32_exact()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _H(self, data: bytes, outlen: int) -> bytes:
        return self.single._H(data, outlen)

    def _to_host(self, a) -> np.ndarray:
        return a.get() if self.xp is not np else a

    def _hash_rows(self, data, outlen: int):
        """SHAKE (params.shake) of each row: (batch, inlen) uint8 -> (batch, outlen)."""
        if self._gpu_shake is not None:
            return self._gpu_shake(data, outlen)
        data = np.ascontiguousarray(data, dtype=np.uint8)
        out = np.empty((data.shape[0], outlen), dtype=np.uint8)
        for i in range(data.shape[0]):
            out[i] = np.frombuffer(self._H(data[i].tobytes(), outlen), np.uint8)
        return out

    def _const_rows(self, b: bytes, batch: int):
        """Broadcast a byte string to a (batch, len) device array."""
        xp = self.xp
        return xp.broadcast_to(xp.asarray(np.frombuffer(b, np.uint8)), (batch, len(b)))

    def _check_f32_exact(self):
        """Refuse to run if the float32 GEMM is not exact on this device.

        Catches TF32 or reduced-precision GEMM modes switched on in code
        (which no environment check can see). Uses the largest magnitudes
        the products can reach for these parameters.
        """
        xp, p = self.xp, self.p
        emax = len(self.p.chi) - 1
        small = xp.full((8, p.n), emax, dtype=xp.int64)
        small[1] = -emax
        small[2, ::2] = -emax
        big = xp.full((p.n, 64), p.q - 1, dtype=xp.int64)
        big[:, 1::3] = 0xFF
        big[3::7, :] = 0x1234 & (p.q - 1)
        exact = (small @ big) & (p.q - 1)
        if not bool(xp.all(self._mm(small, big) == exact)):
            raise RuntimeError("float32 GEMM is not exact on this device "
                               "(TF32 or reduced precision enabled?); use matmul='int64'")

    def _split(self, big):
        """Prepare a 'big' factor (entries in [0, 2^16)) for _mm."""
        if self.matmul == "int64":
            return (big,)
        xp = self.xp
        return ((big & 0xFF).astype(xp.float32), (big >> 8).astype(xp.float32))

    def _mm(self, small, big, small_left: bool = True):
        """Exact (small @ big) or (big @ small) mod q.

        ``small``: int entries with |x| <= 12. ``big``: entries in [0, 2^16),
        either an int array or the tuple returned by ``_split``.
        """
        xp, q = self.xp, self.p.q
        if not isinstance(big, tuple):
            big = self._split(big)
        if self.matmul == "int64":
            r = small @ big[0] if small_left else big[0] @ small
            return r & (q - 1)
        s = small.astype(xp.float32)
        lo, hi = big
        if small_left:
            r_lo, r_hi = s @ lo, s @ hi
        else:
            r_lo, r_hi = lo @ s, hi @ s
        r = r_lo.astype(xp.int64) + (r_hi.astype(xp.int64) << 8)
        return r & (q - 1)

    def _A(self, seedA: bytes):
        if self._A_seed != seedA:
            self._A_dev = self._split(self.xp.asarray(self.single.gen_A(seedA)))
            self._A_seed = seedA
        return self._A_dev

    def _sample(self, r_u16):
        """Algorithm 5 on an integer array of 16-bit samples (any shape)."""
        xp = self.xp
        t = (r_u16 >> 1).astype(xp.int32)
        e = xp.zeros(t.shape, dtype=xp.int32)
        for thr in self._T:                      # <= 12 thresholds
            e += (t > thr)
        sign = (r_u16 & 1).astype(bool)
        return xp.where(sign, -e, e).astype(xp.int64)

    def _pack(self, C):
        """Algorithm 3 on (batch, rows, cols) -> device uint8 (batch, bytes)."""
        xp, D = self.xp, self.p.D
        bsz = C.shape[0]
        v = (C & (self.p.q - 1)).reshape(bsz, -1)
        if D == 16:
            out = xp.empty((bsz, v.shape[1] * 2), dtype=xp.uint8)
            out[:, 0::2] = (v >> 8).astype(xp.uint8)
            out[:, 1::2] = (v & 0xFF).astype(xp.uint8)
            return out
        # D = 15: every 8 entries -> 120 bits -> 15 bytes (MSB first).
        g = v.reshape(bsz, -1, 8).astype(xp.uint64)
        u = xp.uint64
        hi = (g[..., 0] << u(45)) | (g[..., 1] << u(30)) | (g[..., 2] << u(15)) | g[..., 3]
        lo = (g[..., 4] << u(45)) | (g[..., 5] << u(30)) | (g[..., 6] << u(15)) | g[..., 7]
        # 120 bits = hi(60) || lo(60); emit 15 big-endian bytes.
        out = xp.empty(g.shape[:2] + (15,), dtype=xp.uint8)
        for k in range(15):
            bit = 112 - 8 * k                     # position of this byte's LSB
            if bit >= 60:
                byte = hi >> xp.uint64(bit - 60)
            elif bit + 8 <= 60:
                byte = lo >> xp.uint64(bit)
            else:                                 # straddles hi/lo boundary
                byte = (hi << xp.uint64(60 - bit)) | (lo >> xp.uint64(bit))
            out[..., k] = (byte & xp.uint64(0xFF)).astype(xp.uint8)
        return out.reshape(bsz, -1)

    def _unpack(self, b_dev, rows: int, cols: int):
        """Algorithm 4: device uint8 (batch, bytes) -> int64 (batch, rows, cols)."""
        xp, D = self.xp, self.p.D
        bsz = b_dev.shape[0]
        if D == 16:
            b = b_dev.reshape(bsz, -1, 2).astype(xp.int64)
            return ((b[..., 0] << 8) | b[..., 1]).reshape(bsz, rows, cols)
        g = b_dev.reshape(bsz, -1, 15).astype(xp.uint64)
        hi = xp.zeros(g.shape[:2], dtype=xp.uint64)
        lo = xp.zeros(g.shape[:2], dtype=xp.uint64)
        for k in range(15):
            bit = 112 - 8 * k
            byte = g[..., k]
            if bit >= 60:
                hi |= byte << xp.uint64(bit - 60)
            elif bit + 8 <= 60:
                lo |= byte << xp.uint64(bit)
            else:
                hi |= byte >> xp.uint64(60 - bit)
                lo |= (byte << xp.uint64(bit)) & xp.uint64((1 << 60) - 1)
        m = xp.uint64(0x7FFF)
        vals = xp.stack([(hi >> xp.uint64(45)) & m, (hi >> xp.uint64(30)) & m,
                         (hi >> xp.uint64(15)) & m, hi & m,
                         (lo >> xp.uint64(45)) & m, (lo >> xp.uint64(30)) & m,
                         (lo >> xp.uint64(15)) & m, lo & m], axis=-1)
        return vals.astype(xp.int64).reshape(bsz, rows, cols)

    def _encode(self, mu_dev):
        """Algorithm 1: device uint8 (batch, len_mu) -> int64 (batch, mbar, nbar)."""
        xp, p = self.xp, self.p
        bsz = mu_dev.shape[0]
        bits = (mu_dev[..., None] >> xp.arange(8, dtype=xp.uint8)) & 1  # LSB first
        bits = bits.reshape(bsz, p.mbar * p.nbar, p.B).astype(xp.int64)
        vals = (bits << xp.arange(p.B, dtype=xp.int64)).sum(axis=-1)
        return (vals * (p.q >> p.B)).reshape(bsz, p.mbar, p.nbar)

    def _decode(self, M):
        """Algorithm 2: int64 (batch, mbar, nbar) -> device uint8 (batch, len_mu)."""
        xp, p = self.xp, self.p
        bsz = M.shape[0]
        M = M & (p.q - 1)
        vals = (((M << p.B) + (1 << (p.D - 1))) >> p.D) & ((1 << p.B) - 1)
        bits = (vals.reshape(bsz, -1, 1) >> xp.arange(p.B, dtype=xp.int64)) & 1
        bits = bits.reshape(bsz, -1, 8)
        return (bits << xp.arange(8, dtype=xp.int64)).sum(axis=-1).astype(xp.uint8)

    # ------------------------------------------------------------------
    # batched core (all arrays on the device unless stated)
    # ------------------------------------------------------------------
    def _encrypt_batch(self, pk: bytes, mu_dev, seedSE_dev):
        """(c1 || c2) rows, device uint8 (batch, l1 + l2)."""
        xp, p = self.xp, self.p
        bsz = mu_dev.shape[0]
        prefix = self._const_rows(b"\x96", bsz)
        nbytes = 2 * (2 * p.mbar * p.n + p.mbar * p.nbar)
        rbytes = self._hash_rows(xp.concatenate([prefix, seedSE_dev], axis=1), nbytes)
        r = rbytes.view(xp.uint16).astype(xp.int32)      # little-endian 16-bit
        o1, o2 = p.mbar * p.n, 2 * p.mbar * p.n
        Sp = self._sample(r[:, :o1]).reshape(bsz * p.mbar, p.n)
        Ep = self._sample(r[:, o1:o2]).reshape(bsz, p.mbar, p.n)
        Epp = self._sample(r[:, o2:]).reshape(bsz, p.mbar, p.nbar)
        A = self._A(pk[:p.len_seedA])
        Bp = (self._mm(Sp, A).reshape(bsz, p.mbar, p.n) + Ep) & (p.q - 1)
        if self._B_pk is None or self._B_pk[0] != pk:
            Bm = self.single.unpack(pk[p.len_seedA:], p.n, p.nbar)
            self._B_pk = (pk, self._split(xp.asarray(Bm)))
        V = self._mm(Sp, self._B_pk[1]).reshape(bsz, p.mbar, p.nbar)
        C = (V + Epp + self._encode(mu_dev)) & (p.q - 1)
        return xp.concatenate([self._pack(Bp), self._pack(C)], axis=1)

    def _derive_seedSE_k(self, pkh: bytes, mu_dev, salt_dev):
        p = self.p
        bsz = mu_dev.shape[0]
        h = self._hash_rows(self.xp.concatenate(
            [self._const_rows(pkh, bsz), mu_dev, salt_dev], axis=1), p.len_seedSE + p.len_sec)
        return h[:, :p.len_seedSE], h[:, p.len_seedSE:]

    def _encaps_chunk(self, pk: bytes, mu_salt, to_host: bool = True):
        """Algorithm 13 for each row of ``mu_salt`` (uint8, batch x (len_mu+len_salt)).

        ``mu_salt`` may be a host or device array. Returns (ct, ss), uint8 arrays
        of shape (batch, ct_bytes) and (batch, ss_bytes); host arrays unless
        ``to_host`` is False.
        """
        xp, p = self.xp, self.p
        if len(pk) != p.pk_bytes:
            raise ValueError("Incorrect public key length")
        ms = xp.ascontiguousarray(xp.asarray(mu_salt), dtype=xp.uint8)
        if ms.ndim != 2 or ms.shape[1] != p.len_sec + p.len_salt:
            raise ValueError("mu_salt must have shape (batch, len_mu + len_salt)")
        mu, salt = ms[:, :p.len_sec], ms[:, p.len_sec:]
        seedSE, k = self._derive_seedSE_k(self._H(pk, p.len_sec), mu, salt)
        ct = xp.concatenate([self._encrypt_batch(pk, mu, seedSE), salt], axis=1)
        ss = self._hash_rows(xp.concatenate([ct, k], axis=1), p.ss_bytes)
        return (self._to_host(ct), self._to_host(ss)) if to_host else (ct, ss)

    def _chunked(self, fn, key: bytes, rows, to_host: bool, n_out: int):
        xp = self.xp
        bsz = rows.shape[0]
        if bsz <= self.chunk:
            return fn(key, rows, to_host)
        parts = [fn(key, rows[i:i + self.chunk], to_host) for i in range(0, bsz, self.chunk)]
        cat = np.concatenate if to_host else xp.concatenate
        if n_out == 1:
            return cat(parts, axis=0)
        return tuple(cat([p[j] for p in parts], axis=0) for j in range(n_out))

    def encaps_batch(self, pk: bytes, mu_salt, to_host: bool = True):
        """Algorithm 13 for each row of ``mu_salt`` (uint8, batch x (len_mu+len_salt)).

        ``mu_salt`` may be a host or device array. Returns (ct, ss), uint8 arrays
        of shape (batch, ct_bytes) and (batch, ss_bytes); host arrays unless
        ``to_host`` is False. Large batches are processed ``chunk`` rows at a time.
        """
        return self._chunked(self._encaps_chunk, pk, mu_salt, to_host, 2)

    def decaps_batch(self, sk: bytes, ct, to_host: bool = True):
        """Algorithm 14 for each row of ``ct`` (uint8, batch x ct_bytes)."""
        return self._chunked(self._decaps_chunk, sk, ct, to_host, 1)

    def encaps_batch_random(self, pk: bytes, batch: int, to_host: bool = True):
        """encaps_batch with fresh randomness from the OS CSPRNG."""
        import secrets
        p = self.p
        rnd = np.frombuffer(secrets.token_bytes(batch * (p.len_sec + p.len_salt)), np.uint8)
        return self.encaps_batch(pk, rnd.reshape(batch, -1), to_host=to_host)

    def _decaps_chunk(self, sk: bytes, ct, to_host: bool = True):
        """Algorithm 14 for each row of ``ct`` (uint8, batch x ct_bytes)."""
        xp, p = self.xp, self.p
        ct = xp.ascontiguousarray(xp.asarray(ct), dtype=xp.uint8)
        if ct.ndim != 2 or ct.shape[1] != p.ct_bytes:
            raise ValueError("Incorrect ciphertext shape")
        if len(sk) != p.sk_bytes:
            raise ValueError("Incorrect secret key length")
        bsz = ct.shape[0]
        l1 = p.D * p.mbar * p.n // 8
        l2 = p.D * p.mbar * p.nbar // 8
        o = 0
        s = sk[o:o + p.len_sec]; o += p.len_sec
        pk = sk[o:o + p.pk_bytes]; o += p.pk_bytes
        ST = np.frombuffer(sk[o:o + 2 * p.n * p.nbar], "<i2").astype(np.int64).reshape(p.nbar, p.n)
        o += 2 * p.n * p.nbar
        pkh = sk[o:o + p.len_sec]

        Bp = self._unpack(ct[:, :l1], p.mbar, p.n).reshape(bsz * p.mbar, p.n)
        C = self._unpack(ct[:, l1:l1 + l2], p.mbar, p.nbar)
        BpS = self._mm(xp.asarray(ST.T.copy()), Bp, small_left=False)
        mu = self._decode((C - BpS.reshape(bsz, p.mbar, p.nbar)) & (p.q - 1))
        salt = ct[:, l1 + l2:]
        seedSE, k = self._derive_seedSE_k(pkh, mu, salt)
        c12 = self._encrypt_batch(pk, mu, seedSE)
        ok = xp.all(c12 == ct[:, :l1 + l2], axis=1)
        # branch-free select: kbar = k if ok else s
        mask = (ok.astype(xp.uint8) * xp.uint8(0xFF))[:, None]
        kbar = (k & mask) | (self._const_rows(s, bsz) & ~mask)
        ss = self._hash_rows(xp.concatenate([ct, kbar], axis=1), p.ss_bytes)
        return self._to_host(ss) if to_host else ss


__all__ = ["BatchFrodoKEM", "CUPY_AVAILABLE", "get_xp"]
