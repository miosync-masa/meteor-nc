"""
Batched FrodoKEM (SHAKE) for NumPy or CuPy.

Same algorithm and byte output as ``frodo.FrodoKEM`` (and therefore the
FrodoKEM reference / NIST KATs), but every step works on a whole batch of
encapsulations or decapsulations at once, on CPU (NumPy) or GPU (CuPy).

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
on cuBLAS SGEMM ("f32split"). The halves (<= 255) and the small factors
(<= 12) are also exact in float16, so on the GPU the same products can run on
tensor cores with float16 inputs and float32 accumulation ("f16tc", cuBLAS
gemmEx). TF32 is refused, and a self-test at construction refuses (or, for
"auto", falls back) when a GEMM mode is not exact on the device.

Hashing
-------
With CuPy, every per-item SHAKE (seedSE||k derivation, noise expansion,
shared-secret hash) runs in a CUDA kernel, one thread per item
(kernels/shake_kernel.py; its C source is tested against hashlib on CPU).
With NumPy, hashlib is used. Only key generation and Gen(A) (once per public
key) run on the host.

Throughput notes
----------------
* Rows are processed in chunks; on the GPU the chunk size is derived from free
  device memory, because the SHAKE kernel needs many rows (threads) in flight.
* Results can stay on the device (``to_host=False``); host copies go through
  a reused pinned staging buffer.
* Hash inputs are passed to the SHAKE kernel as segments, so prefixes and
  (ct || k) are never concatenated in device memory.
* Noise sampling is one fused elementwise kernel on the GPU; intermediates
  are int32 / int16 rather than int64.

Side channels: research implementation; no constant-time guarantees.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from typing import Any, Optional

import numpy as np

from .frodo import FrodoKEM, FrodoParams, FRODO640, _cdf

try:  # pragma: no cover - depends on the machine
    import cupy as _cp
    _cp.cuda.runtime.getDeviceCount()
    CUPY_AVAILABLE = True
except Exception:  # ImportError, CUDARuntimeError, broken install, ...
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


# rough device bytes per row in flight, per unit of n (measured from the
# intermediates below with margin); used to size GPU chunks
_BYTES_PER_ROW_PER_N = 600


class BatchFrodoKEM:
    """Batched FrodoKEM-SHAKE; byte-identical to ``frodo.FrodoKEM``."""

    def __init__(self, params: FrodoParams = FRODO640, backend: str = "auto",
                 matmul: str = "auto", chunk: Optional[int] = None):
        if matmul not in ("auto", "f16tc", "f32split", "int64"):
            raise ValueError("matmul must be 'auto', 'f16tc', 'f32split' or 'int64'")
        self.p = params
        self.xp = get_xp(backend)
        self.backend = "cupy" if self.xp is not np else "numpy"
        if matmul == "f16tc" and self.xp is np:
            raise ValueError("matmul='f16tc' needs the CuPy backend")
        requested = matmul
        if matmul == "auto":
            matmul = "f16tc" if self.xp is not np else "f32split"
        self.matmul = matmul
        self.single = FrodoKEM(params)            # keygen, Gen(A), reference
        tf32 = False
        self._T = [int(t) for t in _cdf(params.chi)[:-1]]
        self._A_seed: Optional[bytes] = None
        self._A_dev: Any = None
        self._B_pk: Any = None
        self._shake = {}
        self._consts = {}
        self._stage = None
        self._sample_kernel = None
        self._pack15 = None
        if self.xp is not np:
            try:
                tf32 = int(os.environ.get("CUPY_TF32", "0") or 0) > 0
            except ValueError:
                tf32 = True
            if matmul == "f32split" and tf32:
                raise RuntimeError("CUPY_TF32 enables TF32, which breaks exact float32 products; unset it")
            self._sample_kernel = self._build_sample_kernel()
            if params.D == 15:
                from .kernels.pack_kernel import GPUPack15
                self._pack15 = GPUPack15()
        self.chunk = int(chunk) if chunk else self._auto_chunk()
        if self.matmul != "int64" and not self._gemm_ok(requested == "auto"):
            if requested == "auto" and self.matmul == "f16tc":
                self.matmul = "f32split"
                if tf32 or not self._gemm_ok(True):
                    self.matmul = "int64"
            else:
                raise RuntimeError(f"matmul='{self.matmul}' is not exact on this device "
                                   "(TF32 or reduced precision enabled?); use matmul='int64'")

    # ------------------------------------------------------------------
    # setup helpers
    # ------------------------------------------------------------------
    def _auto_chunk(self) -> int:
        if self.xp is np:
            return 512
        free, _total = self.xp.cuda.Device().mem_info
        rows = int(0.5 * free / (_BYTES_PER_ROW_PER_N * self.p.n))
        return max(1024, min(65536, rows))

    def _build_sample_kernel(self):
        """Fused Algorithm 5: uint16 sample -> int16 error, thresholds inlined."""
        body = "int t = r >> 1; int c = 0;\n"
        body += "".join(f"c += (t > {thr});\n" for thr in self._T)
        body += "e = (r & 1) ? -c : c;"
        return self.xp.ElementwiseKernel("uint16 r", "int16 e", body,
                                         f"frodo_sample_{self.p.n}")

    def _gemm_ok(self, tolerant: bool) -> bool:
        """_gemm_is_exact, treating a failing cuBLAS call as 'not exact' when
        ``tolerant`` (matmul='auto' then falls back to another mode)."""
        try:
            return self._gemm_is_exact()
        except Exception:
            if not tolerant:
                raise
            return False

    def _gemm_is_exact(self) -> bool:
        """Whether the current matmul mode is exact on this device.

        Catches TF32 or reduced-precision GEMM modes switched on in code
        (which no environment check can see), using the largest magnitudes
        the products can reach for these parameters, in both operand orders.
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
        ok = bool(xp.all(self._mm(small, big) == exact))
        bigT = xp.ascontiguousarray(big.T)
        exactT = (bigT @ small.T) & (p.q - 1)
        ok &= bool(xp.all(self._mm(xp.ascontiguousarray(small.T), bigT, small_left=False) == exactT))
        return ok

    # ------------------------------------------------------------------
    # primitives
    # ------------------------------------------------------------------
    def _H(self, data: bytes, outlen: int) -> bytes:
        return self.single._H(data, outlen)

    _STAGE_BYTES = 64 << 20

    def to_host(self, a) -> np.ndarray:
        """Device -> host copy into an ordinary NumPy array.

        Goes through a reused 64 MiB pinned staging buffer: allocating fresh
        pinned memory for every multi-GB result costs more than the copy.
        """
        if self.xp is np:
            return a
        a = self.xp.ascontiguousarray(a)
        out = np.empty(a.shape, dtype=a.dtype)
        src = a.view(self.xp.uint8).reshape(-1)
        dst = out.view(np.uint8).reshape(-1)
        if self._stage is None:
            import cupyx
            self._stage = cupyx.empty_pinned((self._STAGE_BYTES,), dtype=np.uint8)
        st = self._stage
        for o in range(0, src.size, self._STAGE_BYTES):
            n = min(self._STAGE_BYTES, src.size - o)
            src[o:o + n].get(out=st[:n])
            dst[o:o + n] = st[:n]
        return out

    def _hash_rows(self, segments, outlen: int, variant: Optional[str] = None, out=None):
        """SHAKE of each row of seg0 || seg1 || ... -> (batch, outlen) uint8.

        A segment is a (batch, len) uint8 array (rows may be strided) or
        ``bytes`` / a 1-D array shared by every row. On the GPU the segments
        are absorbed directly (no concatenation).
        """
        variant = variant or self.p.shake
        if not isinstance(segments, (list, tuple)):
            segments = [segments]
        xp = self.xp
        batch = next(sg.shape[0] for sg in segments if not isinstance(sg, bytes) and sg.ndim == 2)
        if xp is not np:
            g = self._shake.get(variant)
            if g is None:
                from .kernels.shake_kernel import GPUShake
                g = self._shake[variant] = GPUShake(variant)
            segs = [self._const_dev(sg) if isinstance(sg, bytes) else sg for sg in segments]
            return g(*segs, outlen=outlen, out=out)
        H = hashlib.shake_128 if variant == "shake128" else hashlib.shake_256
        rows = [np.broadcast_to(np.frombuffer(sg, np.uint8), (batch, len(sg)))
                if isinstance(sg, bytes) else
                (np.broadcast_to(sg, (batch, sg.shape[0])) if sg.ndim == 1 else sg)
                for sg in segments]
        data = np.ascontiguousarray(np.concatenate(rows, axis=1), dtype=np.uint8)
        res = np.empty((batch, outlen), dtype=np.uint8) if out is None else out
        for i in range(batch):
            res[i] = np.frombuffer(H(data[i].tobytes()).digest(outlen), np.uint8)
        return res

    def _const_dev(self, b: bytes):
        """Cached 1-D device copy of a constant byte string."""
        c = self._consts.get(b)
        if c is None:
            c = self._consts[b] = self.xp.asarray(np.frombuffer(b, np.uint8))
        return c

    def _const_rows(self, b: bytes, batch: int):
        xp = self.xp
        return xp.broadcast_to(xp.asarray(np.frombuffer(b, np.uint8)), (batch, len(b)))

    def _split(self, big):
        """Prepare a 'big' factor (entries in [0, 2^16)) for _mm."""
        xp = self.xp
        if self.matmul == "int64":
            return (big.astype(xp.int64),)
        ft = xp.float16 if self.matmul == "f16tc" else xp.float32
        return (xp.ascontiguousarray((big & 0xFF).astype(ft)),
                xp.ascontiguousarray((big >> 8).astype(ft)))

    def _gemm_f16(self, X, Y):
        """Row-major X (M,K) @ Y (K,N), float16 inputs, float32 accumulate/output,
        via cublasGemmEx (tensor cores)."""
        cp = self.xp
        from cupy_backends.cuda.libs import cublas
        from cupy_backends.cuda.api import runtime
        R16F = getattr(runtime, "CUDA_R_16F", 2)
        R32F = getattr(runtime, "CUDA_R_32F", 0)
        X = cp.ascontiguousarray(X, dtype=cp.float16)
        Y = cp.ascontiguousarray(Y, dtype=cp.float16)
        M, K = X.shape
        K2, N = Y.shape
        assert K == K2
        C = cp.empty((M, N), dtype=cp.float32)
        if M == 0:
            return C
        handle = cp.cuda.device.get_cublas_handle()   # bound to the current stream
        one = np.array(1.0, dtype=np.float32)
        zero = np.array(0.0, dtype=np.float32)
        mode = cublas.getPointerMode(handle)
        cublas.setPointerMode(handle, cublas.CUBLAS_POINTER_MODE_HOST)
        try:
            # column-major view: C^T (N,M) = Y^T (N,K) @ X^T (K,M)
            cublas.gemmEx(handle, cublas.CUBLAS_OP_N, cublas.CUBLAS_OP_N, N, M, K,
                          one.ctypes.data, Y.data.ptr, R16F, N,
                          X.data.ptr, R16F, K,
                          zero.ctypes.data, C.data.ptr, R32F, N,
                          getattr(cublas, "CUBLAS_COMPUTE_32F", 68),
                          getattr(cublas, "CUBLAS_GEMM_DEFAULT_TENSOR_OP", 99))
        finally:
            cublas.setPointerMode(handle, mode)
        return C

    def _mm(self, small, big, small_left: bool = True):
        """Exact (small @ big) or (big @ small) mod q (int32; int64 in 'int64' mode).

        ``small``: int entries with |x| <= 12. ``big``: entries in [0, 2^16),
        either an int array or the tuple returned by ``_split``.
        """
        xp, q = self.xp, self.p.q
        if not isinstance(big, tuple):
            big = self._split(big)
        if self.matmul == "int64":
            s = small.astype(xp.int64)
            r = s @ big[0] if small_left else big[0] @ s
            return r & (q - 1)
        lo, hi = big
        if self.matmul == "f16tc":
            s = small.astype(xp.float16)
            mm = self._gemm_f16
        else:
            s = small.astype(xp.float32)
            mm = xp.matmul
        if small_left:
            r_lo, r_hi = mm(s, lo), mm(s, hi)
        else:
            r_lo, r_hi = mm(lo, s), mm(hi, s)
        # |r_lo| < 2^24, |r_hi * 256| < 2^31: int32 is exact
        r = r_lo.astype(xp.int32) + (r_hi.astype(xp.int32) << 8)
        return r & (q - 1)

    def _A(self, seedA: bytes):
        if self._A_seed != seedA:
            self._A_dev = self._split(self.xp.asarray(self.single.gen_A(seedA)))
            self._A_seed = seedA
        return self._A_dev

    def _sample(self, r_u16):
        """Algorithm 5 on a uint16 array (any shape) -> int16 errors."""
        if self._sample_kernel is not None:
            return self._sample_kernel(r_u16)
        t = r_u16 >> 1
        e = np.zeros(t.shape, dtype=np.int16)
        for thr in self._T:
            e += (t > thr)
        return np.where(r_u16 & 1, -e, e).astype(np.int16)

    def _pack_into(self, C, out):
        """Algorithm 3: (batch, rows, cols) -> rows of ``out`` (device uint8)."""
        xp, D = self.xp, self.p.D
        bsz = C.shape[0]
        v = (C & (self.p.q - 1)).reshape(bsz, -1)
        if D == 16:
            out[:, 0::2] = (v >> 8).astype(xp.uint8)
            out[:, 1::2] = (v & 0xFF).astype(xp.uint8)
            return
        # D = 15: every 8 entries -> 120 bits -> 15 bytes (MSB first).
        if self._pack15 is not None:
            self._pack15.pack(v.astype(xp.int32), out)
            return
        u = xp.uint64
        g = v.reshape(bsz, -1, 8).astype(u)
        hi = (g[..., 0] << u(45)) | (g[..., 1] << u(30)) | (g[..., 2] << u(15)) | g[..., 3]
        lo = (g[..., 4] << u(45)) | (g[..., 5] << u(30)) | (g[..., 6] << u(15)) | g[..., 7]
        o = xp.empty(g.shape[:2] + (15,), dtype=xp.uint8)   # contiguous scratch
        for k in range(15):
            bit = 112 - 8 * k                     # position of this byte's LSB
            if bit >= 60:
                byte = hi >> u(bit - 60)
            elif bit + 8 <= 60:
                byte = lo >> u(bit)
            else:                                 # straddles hi/lo (bit = 56)
                byte = (hi << u(60 - bit)) | (lo >> u(bit))
            o[..., k] = (byte & u(0xFF)).astype(xp.uint8)
        out[...] = o.reshape(bsz, -1)

    def _unpack(self, b_dev, rows: int, cols: int):
        """Algorithm 4: device uint8 (batch, bytes) -> int32 (batch, rows, cols)."""
        xp, D = self.xp, self.p.D
        bsz = b_dev.shape[0]
        if D == 16:
            b = b_dev.reshape(bsz, -1, 2).astype(xp.int32)
            return ((b[..., 0] << 8) | b[..., 1]).reshape(bsz, rows, cols)
        if self._pack15 is not None:
            return self._pack15.unpack(b_dev, rows * cols).reshape(bsz, rows, cols)
        u = xp.uint64
        g = b_dev.reshape(bsz, -1, 15).astype(u)
        hi = xp.zeros(g.shape[:2], dtype=u)
        lo = xp.zeros(g.shape[:2], dtype=u)
        for k in range(15):
            bit = 112 - 8 * k
            byte = g[..., k]
            if bit >= 60:
                hi |= byte << u(bit - 60)
            elif bit + 8 <= 60:
                lo |= byte << u(bit)
            else:
                hi |= byte >> u(60 - bit)
                lo |= (byte << u(bit)) & u((1 << 60) - 1)
        m = u(0x7FFF)
        vals = xp.stack([(hi >> u(45)) & m, (hi >> u(30)) & m, (hi >> u(15)) & m, hi & m,
                         (lo >> u(45)) & m, (lo >> u(30)) & m, (lo >> u(15)) & m, lo & m],
                        axis=-1)
        return vals.astype(xp.int32).reshape(bsz, rows, cols)

    def _encode(self, mu_dev):
        """Algorithm 1: device uint8 (batch, len_mu) -> int32 (batch, mbar, nbar)."""
        xp, p = self.xp, self.p
        bsz = mu_dev.shape[0]
        bits = (mu_dev[..., None] >> xp.arange(8, dtype=xp.uint8)) & 1  # LSB first
        bits = bits.reshape(bsz, p.mbar * p.nbar, p.B).astype(xp.int32)
        vals = (bits << xp.arange(p.B, dtype=xp.int32)).sum(axis=-1, dtype=xp.int32)
        return (vals * (p.q >> p.B)).reshape(bsz, p.mbar, p.nbar)

    def _decode(self, M):
        """Algorithm 2: int (batch, mbar, nbar) -> device uint8 (batch, len_mu)."""
        xp, p = self.xp, self.p
        bsz = M.shape[0]
        M = (M & (p.q - 1)).astype(xp.int32)
        vals = (((M << p.B) + (1 << (p.D - 1))) >> p.D) & ((1 << p.B) - 1)
        bits = (vals.reshape(bsz, -1, 1) >> xp.arange(p.B, dtype=xp.int32)) & 1
        bits = bits.reshape(bsz, -1, 8)
        return (bits << xp.arange(8, dtype=xp.int32)).sum(axis=-1).astype(xp.uint8)

    # ------------------------------------------------------------------
    # batched core (all arrays on the device)
    # ------------------------------------------------------------------
    def _encrypt_into(self, pk: bytes, mu_dev, seedSE_dev, out):
        """Write (c1 || c2) rows into ``out`` (device uint8, batch x (l1 + l2))."""
        xp, p = self.xp, self.p
        bsz = mu_dev.shape[0]
        nbytes = 2 * (2 * p.mbar * p.n + p.mbar * p.nbar)
        rbytes = self._hash_rows([b"\x96", seedSE_dev], nbytes)
        r = rbytes.view(xp.uint16)                          # little-endian samples
        o1, o2 = p.mbar * p.n, 2 * p.mbar * p.n
        Sp = self._sample(r[:, :o1]).reshape(bsz * p.mbar, p.n)
        Ep = self._sample(r[:, o1:o2]).reshape(bsz, p.mbar, p.n)
        Epp = self._sample(r[:, o2:]).reshape(bsz, p.mbar, p.nbar)
        del rbytes, r
        A = self._A(pk[:p.len_seedA])
        Bp = (self._mm(Sp, A).reshape(bsz, p.mbar, p.n) + Ep) & (p.q - 1)
        del Ep
        if self._B_pk is None or self._B_pk[0] != pk:
            Bm = self.single.unpack(pk[p.len_seedA:], p.n, p.nbar)
            self._B_pk = (pk, self._split(xp.asarray(Bm)))
        V = self._mm(Sp, self._B_pk[1]).reshape(bsz, p.mbar, p.nbar)
        C = (V + Epp + self._encode(mu_dev)) & (p.q - 1)
        l1 = p.D * p.mbar * p.n // 8
        self._pack_into(Bp, out[:, :l1])
        self._pack_into(C, out[:, l1:])

    def _derive_seedSE_k(self, pkh: bytes, mu_dev, salt_dev):
        p = self.p
        bsz = mu_dev.shape[0]
        h = self._hash_rows([pkh, mu_dev, salt_dev], p.len_seedSE + p.len_sec)
        return h[:, :p.len_seedSE], h[:, p.len_seedSE:]

    def encaps_batch(self, pk: bytes, mu_salt, to_host: bool = True, prefix: bytes = b""):
        """Algorithm 13 for each row of ``mu_salt`` (uint8, batch x (len_mu+len_salt)).

        ``mu_salt`` may be a host or device array. Returns (ct, ss): uint8
        arrays (batch, len(prefix) + ct_bytes) and (batch, ss_bytes). Each ct
        row starts with ``prefix`` (e.g. a wire header). Host arrays unless
        ``to_host`` is False.
        """
        xp, p = self.xp, self.p
        if len(pk) != p.pk_bytes:
            raise ValueError("Incorrect public key length")
        ms = xp.ascontiguousarray(xp.asarray(mu_salt), dtype=xp.uint8)
        if ms.ndim != 2 or ms.shape[1] != p.len_sec + p.len_salt:
            raise ValueError("mu_salt must have shape (batch, len_mu + len_salt)")
        bsz, hp = ms.shape[0], len(prefix)
        l12 = p.ct_bytes - p.len_salt
        ct = xp.empty((bsz, hp + p.ct_bytes), dtype=xp.uint8)
        ss = xp.empty((bsz, p.ss_bytes), dtype=xp.uint8)
        if hp:
            ct[:, :hp] = xp.asarray(np.frombuffer(prefix, np.uint8))
        pkh = self._H(pk, p.len_sec)
        for a in range(0, bsz, self.chunk):
            b = min(bsz, a + self.chunk)
            mu, salt = ms[a:b, :p.len_sec], ms[a:b, p.len_sec:]
            seedSE, k = self._derive_seedSE_k(pkh, mu, salt)
            body = ct[a:b, hp:]
            self._encrypt_into(pk, mu, seedSE, body[:, :l12])
            body[:, l12:] = salt
            self._hash_rows([body, k], p.ss_bytes, out=ss[a:b])
        return (self.to_host(ct), self.to_host(ss)) if to_host else (ct, ss)

    def encaps_batch_random(self, pk: bytes, batch: int, to_host: bool = True,
                            prefix: bytes = b""):
        """encaps_batch with fresh randomness from the OS CSPRNG."""
        p = self.p
        rnd = np.frombuffer(secrets.token_bytes(batch * (p.len_sec + p.len_salt)), np.uint8)
        return self.encaps_batch(pk, rnd.reshape(batch, -1), to_host=to_host, prefix=prefix)

    def decaps_batch(self, sk: bytes, ct, to_host: bool = True, offset: int = 0):
        """Algorithm 14 for each row of ``ct`` (uint8, batch x (offset + ct_bytes)).

        The first ``offset`` bytes of each row (e.g. a wire header) are skipped.
        ``ct`` may be a host or device array.
        """
        xp, p = self.xp, self.p
        ct = xp.ascontiguousarray(xp.asarray(ct), dtype=xp.uint8)
        if ct.ndim != 2 or ct.shape[1] != offset + p.ct_bytes:
            raise ValueError("Incorrect ciphertext shape")
        if len(sk) != p.sk_bytes:
            raise ValueError("Incorrect secret key length")
        bsz = ct.shape[0]
        l1 = p.D * p.mbar * p.n // 8
        l12 = p.ct_bytes - p.len_salt
        o = 0
        s = sk[o:o + p.len_sec]; o += p.len_sec
        pk = sk[o:o + p.pk_bytes]; o += p.pk_bytes
        ST = np.frombuffer(sk[o:o + 2 * p.n * p.nbar], "<i2").reshape(p.nbar, p.n)
        o += 2 * p.n * p.nbar
        pkh = sk[o:o + p.len_sec]
        S = xp.asarray(np.ascontiguousarray(ST.T))
        s_row = xp.asarray(np.frombuffer(s, np.uint8))
        ss = xp.empty((bsz, p.ss_bytes), dtype=xp.uint8)
        for a in range(0, bsz, self.chunk):
            b = min(bsz, a + self.chunk)
            body = ct[a:b, offset:]
            m = b - a
            Bp = self._unpack(body[:, :l1], p.mbar, p.n).reshape(m * p.mbar, p.n)
            C = self._unpack(body[:, l1:l12], p.mbar, p.nbar)
            BpS = self._mm(S, Bp, small_left=False)
            del Bp
            mu = self._decode((C - BpS.reshape(m, p.mbar, p.nbar)) & (p.q - 1))
            salt = body[:, l12:]
            seedSE, k = self._derive_seedSE_k(pkh, mu, salt)
            c12 = xp.empty((m, l12), dtype=xp.uint8)
            self._encrypt_into(pk, mu, seedSE, c12)
            ok = xp.all(c12 == body[:, :l12], axis=1)
            del c12
            # branch-free select: kbar = k if ok else s
            mask = (ok.astype(xp.uint8) * xp.uint8(0xFF))[:, None]
            kbar = (k & mask) | (s_row[None, :] & ~mask)
            self._hash_rows([body, kbar], p.ss_bytes, out=ss[a:b])
        return self.to_host(ss) if to_host else ss


__all__ = ["BatchFrodoKEM", "CUPY_AVAILABLE", "get_xp"]
