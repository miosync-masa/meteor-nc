"""
Batched SHAKE128/SHAKE256 for the GPU (one CUDA thread per message).

The sponge is written once in plain C (``SHAKE_C_SOURCE``). The same text is
compiled two ways:
  * by NVRTC through CuPy (``GPUShake``), with DEVFN = __device__;
  * by the host C compiler in tests (tests/test_shake_kernel.py), with
    DEVFN = static, and compared with hashlib on many lengths.
So the logic that runs on the GPU is the logic that was tested on the CPU.

All messages in one call have the same input length and output length,
which is the case for every FrodoKEM hashing step.
"""

from __future__ import annotations

SHAKE_C_SOURCE = r"""
typedef unsigned long long u64;
typedef unsigned char u8;
typedef long long i64;   /* 64-bit on every platform (long is 32-bit on Windows) */

#define ROL64(a, n) (((a) << (n)) | ((a) >> (64 - (n))))

DEVFN void keccak_f1600(u64 *A) {
    const u64 RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
    const int ROT[25] = { 0,  1, 62, 28, 27,
                         36, 44,  6, 55, 20,
                          3, 10, 43, 25, 39,
                         41, 45, 15, 21,  8,
                         18,  2, 61, 56, 14};
    u64 C[5], D[5], B[25];
    for (int round = 0; round < 24; ++round) {
        for (int x = 0; x < 5; ++x)
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        for (int x = 0; x < 5; ++x)
            D[x] = C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1);
        for (int i = 0; i < 25; ++i)
            A[i] ^= D[i % 5];
        /* rho + pi: B[y, 2x+3y] = rot(A[x, y]) with lane index x + 5y */
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y) {
                int r = ROT[x + 5 * y];
                u64 v = A[x + 5 * y];
                B[y + 5 * ((2 * x + 3 * y) % 5)] = r ? ROL64(v, r) : v;
            }
        /* chi */
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x)
                A[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);
        A[0] ^= RC[round];
    }
}

/* SHAKE with domain byte 0x1F; rate = 168 (SHAKE128) or 136 (SHAKE256). */
DEVFN void shake_one(const u8 *in, i64 inlen, u8 *out, i64 outlen, int rate) {
    u64 A[25];
    for (int i = 0; i < 25; ++i) A[i] = 0;
    i64 pos = 0;
    while (inlen - pos >= rate) {
        for (int i = 0; i < rate; ++i)
            A[i >> 3] ^= ((u64)in[pos + i]) << (8 * (i & 7));
        keccak_f1600(A);
        pos += rate;
    }
    int rem = (int)(inlen - pos);
    for (int i = 0; i < rem; ++i)
        A[i >> 3] ^= ((u64)in[pos + i]) << (8 * (i & 7));
    A[rem >> 3] ^= ((u64)0x1F) << (8 * (rem & 7));
    A[(rate - 1) >> 3] ^= ((u64)0x80) << (8 * ((rate - 1) & 7));
    keccak_f1600(A);
    i64 o = 0;
    while (1) {
        for (int i = 0; i < rate && o < outlen; ++i, ++o)
            out[o] = (u8)(A[i >> 3] >> (8 * (i & 7)));
        if (o >= outlen) break;
        keccak_f1600(A);
    }
}
"""

CUDA_WRAPPER = r"""
#define DEVFN __device__
""" + SHAKE_C_SOURCE + r"""
extern "C" __global__
void shake_batch(const u8 *in, i64 inlen, u8 *out, i64 outlen, int rate, int batch) {
    int t = blockDim.x * blockIdx.x + threadIdx.x;
    if (t >= batch) return;
    shake_one(in + (i64)t * inlen, inlen, out + (i64)t * outlen, outlen, rate);
}
"""

C_WRAPPER = r"""
#define DEVFN static
""" + SHAKE_C_SOURCE + r"""
void shake_batch(const u8 *in, i64 inlen, u8 *out, i64 outlen, int rate, int batch) {
    for (int t = 0; t < batch; ++t)
        shake_one(in + (i64)t * inlen, inlen, out + (i64)t * outlen, outlen, rate);
}
"""

RATE = {"shake128": 168, "shake256": 136}


class GPUShake:
    """CuPy front-end: ``hash(in_dev (batch, inlen) uint8, outlen) -> (batch, outlen)``."""

    def __init__(self, variant: str):
        import cupy as cp
        self.cp = cp
        self.rate = RATE[variant]
        self._k = cp.RawKernel(CUDA_WRAPPER, "shake_batch")

    def __call__(self, data, outlen: int, threads: int = 128):
        cp = self.cp
        data = cp.ascontiguousarray(data, dtype=cp.uint8)
        batch, inlen = data.shape
        out = cp.empty((batch, outlen), dtype=cp.uint8)
        if batch:
            grid = ((batch + threads - 1) // threads,)
            self._k(grid, (threads,), (data, cp.int64(inlen), out, cp.int64(outlen),
                                       cp.int32(self.rate), cp.int32(batch)))
        return out


__all__ = ["SHAKE_C_SOURCE", "CUDA_WRAPPER", "C_WRAPPER", "RATE", "GPUShake"]
