"""
Batched SHAKE128/SHAKE256 for the GPU (one CUDA thread per message).

The sponge is written once in plain C (``SHAKE_C_SOURCE``). The same text is
compiled two ways:
  * by NVRTC through CuPy (``GPUShake``), with DEVFN = __device__;
  * by the host C compiler in tests (tests/test_shake_kernel.py), with
    DEVFN = static, and compared with hashlib on many lengths, alignments
    and segment layouts.
So the logic that runs on the GPU is the logic that was tested on the CPU.

Each message is the concatenation of up to three *segments*. A segment is a
(pointer, length, row stride) triple: stride > 0 gives one row per message,
stride 0 broadcasts the same bytes to every message. This lets callers hash
e.g. (constant prefix || per-row seed) or (ct row || k row) without first
concatenating them in device memory.

Performance notes: the permutation is fully unrolled so the state stays in
registers; lanes are loaded/stored 8 bytes at a time when the address allows
(4-byte and byte fallbacks otherwise).
"""

from __future__ import annotations

SHAKE_C_SOURCE = r"""
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef long long i64;
typedef unsigned long long uptr;

#define ROL64(a, n) (((a) << (n)) | ((a) >> (64 - (n))))

CONSTMEM u64 KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

/* One Keccak round on 25 named lanes (x + 5y order), fully unrolled. */
#define KECCAK_ROUND(rc) do {                                                   \
    u64 C0 = a00 ^ a05 ^ a10 ^ a15 ^ a20, C1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;     \
    u64 C2 = a02 ^ a07 ^ a12 ^ a17 ^ a22, C3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;     \
    u64 C4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;                                       \
    u64 D0 = C4 ^ ROL64(C1, 1), D1 = C0 ^ ROL64(C2, 1), D2 = C1 ^ ROL64(C3, 1); \
    u64 D3 = C2 ^ ROL64(C4, 1), D4 = C3 ^ ROL64(C0, 1);                         \
    a00 ^= D0; a05 ^= D0; a10 ^= D0; a15 ^= D0; a20 ^= D0;                      \
    a01 ^= D1; a06 ^= D1; a11 ^= D1; a16 ^= D1; a21 ^= D1;                      \
    a02 ^= D2; a07 ^= D2; a12 ^= D2; a17 ^= D2; a22 ^= D2;                      \
    a03 ^= D3; a08 ^= D3; a13 ^= D3; a18 ^= D3; a23 ^= D3;                      \
    a04 ^= D4; a09 ^= D4; a14 ^= D4; a19 ^= D4; a24 ^= D4;                      \
    /* rho + pi: B[y, 2x+3y] = rot(A[x, y], r[x, y]) */                         \
    u64 b00 = a00;              u64 b10 = ROL64(a01, 1);                         \
    u64 b20 = ROL64(a02, 62);   u64 b05 = ROL64(a03, 28);                        \
    u64 b15 = ROL64(a04, 27);   u64 b16 = ROL64(a05, 36);                        \
    u64 b01 = ROL64(a06, 44);   u64 b11 = ROL64(a07, 6);                         \
    u64 b21 = ROL64(a08, 55);   u64 b06 = ROL64(a09, 20);                        \
    u64 b07 = ROL64(a10, 3);    u64 b17 = ROL64(a11, 10);                        \
    u64 b02 = ROL64(a12, 43);   u64 b12 = ROL64(a13, 25);                        \
    u64 b22 = ROL64(a14, 39);   u64 b23 = ROL64(a15, 41);                        \
    u64 b08 = ROL64(a16, 45);   u64 b18 = ROL64(a17, 15);                        \
    u64 b03 = ROL64(a18, 21);   u64 b13 = ROL64(a19, 8);                         \
    u64 b14 = ROL64(a20, 18);   u64 b24 = ROL64(a21, 2);                         \
    u64 b09 = ROL64(a22, 61);   u64 b19 = ROL64(a23, 56);                        \
    u64 b04 = ROL64(a24, 14);                                                   \
    /* chi */                                                                   \
    a00 = b00 ^ (~b01 & b02); a01 = b01 ^ (~b02 & b03); a02 = b02 ^ (~b03 & b04); \
    a03 = b03 ^ (~b04 & b00); a04 = b04 ^ (~b00 & b01);                         \
    a05 = b05 ^ (~b06 & b07); a06 = b06 ^ (~b07 & b08); a07 = b07 ^ (~b08 & b09); \
    a08 = b08 ^ (~b09 & b05); a09 = b09 ^ (~b05 & b06);                         \
    a10 = b10 ^ (~b11 & b12); a11 = b11 ^ (~b12 & b13); a12 = b12 ^ (~b13 & b14); \
    a13 = b13 ^ (~b14 & b10); a14 = b14 ^ (~b10 & b11);                         \
    a15 = b15 ^ (~b16 & b17); a16 = b16 ^ (~b17 & b18); a17 = b17 ^ (~b18 & b19); \
    a18 = b18 ^ (~b19 & b15); a19 = b19 ^ (~b15 & b16);                         \
    a20 = b20 ^ (~b21 & b22); a21 = b21 ^ (~b22 & b23); a22 = b22 ^ (~b23 & b24); \
    a23 = b23 ^ (~b24 & b20); a24 = b24 ^ (~b20 & b21);                         \
    a00 ^= (rc);                                                                \
} while (0)

DEVFN void keccak_f1600(u64 *A) {
    u64 a00 = A[0],  a01 = A[1],  a02 = A[2],  a03 = A[3],  a04 = A[4];
    u64 a05 = A[5],  a06 = A[6],  a07 = A[7],  a08 = A[8],  a09 = A[9];
    u64 a10 = A[10], a11 = A[11], a12 = A[12], a13 = A[13], a14 = A[14];
    u64 a15 = A[15], a16 = A[16], a17 = A[17], a18 = A[18], a19 = A[19];
    u64 a20 = A[20], a21 = A[21], a22 = A[22], a23 = A[23], a24 = A[24];
    for (int round = 0; round < 24; ++round)
        KECCAK_ROUND(KECCAK_RC[round]);
    A[0] = a00;  A[1] = a01;  A[2] = a02;  A[3] = a03;  A[4] = a04;
    A[5] = a05;  A[6] = a06;  A[7] = a07;  A[8] = a08;  A[9] = a09;
    A[10] = a10; A[11] = a11; A[12] = a12; A[13] = a13; A[14] = a14;
    A[15] = a15; A[16] = a16; A[17] = a17; A[18] = a18; A[19] = a19;
    A[20] = a20; A[21] = a21; A[22] = a22; A[23] = a23; A[24] = a24;
}

/* little-endian 8-byte load at any alignment */
DEVFN u64 load64(const u8 *p) {
    uptr a = (uptr)p;
    if ((a & 7) == 0) return *(const u64 *)p;
    if ((a & 3) == 0) return (u64)(*(const u32 *)p) | ((u64)(*(const u32 *)(p + 4)) << 32);
    u64 v = 0;
    for (int i = 0; i < 8; ++i) v |= ((u64)p[i]) << (8 * i);
    return v;
}

DEVFN void store64(u8 *p, u64 v) {
    uptr a = (uptr)p;
    if ((a & 7) == 0) { *(u64 *)p = v; return; }
    if ((a & 3) == 0) { *(u32 *)p = (u32)v; *(u32 *)(p + 4) = (u32)(v >> 32); return; }
    for (int i = 0; i < 8; ++i) p[i] = (u8)(v >> (8 * i));
}

/* Absorb one segment; pos is the byte position inside the rate block. */
DEVFN void absorb(u64 *A, int *pos, const u8 *p, i64 len, int rate) {
    i64 i = 0;
    while (i < len) {
        if ((*pos & 7) == 0 && len - i >= 8) {
            A[*pos >> 3] ^= load64(p + i);
            i += 8; *pos += 8;
        } else {
            A[*pos >> 3] ^= ((u64)p[i]) << (8 * (*pos & 7));
            i += 1; *pos += 1;
        }
        if (*pos == rate) { keccak_f1600(A); *pos = 0; }
    }
}

/* SHAKE (domain byte 0x1F) of seg0 || seg1 || seg2; rate 168 or 136. */
DEVFN void shake_segments(const u8 *p0, i64 l0, const u8 *p1, i64 l1,
                          const u8 *p2, i64 l2, u8 *out, i64 outlen, int rate) {
    u64 A[25];
    for (int i = 0; i < 25; ++i) A[i] = 0;
    int pos = 0;
    absorb(A, &pos, p0, l0, rate);
    absorb(A, &pos, p1, l1, rate);
    absorb(A, &pos, p2, l2, rate);
    A[pos >> 3] ^= ((u64)0x1F) << (8 * (pos & 7));
    A[(rate - 1) >> 3] ^= ((u64)0x80) << (8 * ((rate - 1) & 7));
    keccak_f1600(A);
    i64 o = 0;
    while (1) {
        int lane = 0;
        while (lane * 8 < rate && outlen - o >= 8) {
            store64(out + o, A[lane]);
            ++lane; o += 8;
        }
        for (int b = lane * 8; b < rate && o < outlen; ++b, ++o)
            out[o] = (u8)(A[b >> 3] >> (8 * (b & 7)));
        if (o >= outlen) break;
        keccak_f1600(A);
    }
}

/* single-buffer form (kept for callers and tests) */
DEVFN void shake_one(const u8 *in, i64 inlen, u8 *out, i64 outlen, int rate) {
    shake_segments(in, inlen, in, 0, in, 0, out, outlen, rate);
}
"""

_KERNEL = r"""
GLOBAL void shake_seg(const u8 *p0, i64 l0, i64 s0,
                      const u8 *p1, i64 l1, i64 s1,
                      const u8 *p2, i64 l2, i64 s2,
                      u8 *out, i64 outlen, i64 out_stride, int rate, i64 batch) {
    LOOP_BEGIN
        shake_segments(p0 + t * s0, l0, p1 + t * s1, l1, p2 + t * s2, l2,
                       out + t * out_stride, outlen, rate);
    LOOP_END
}
"""

CUDA_WRAPPER = (
    "#define DEVFN __device__\n"
    "#define CONSTMEM __constant__\n"
    "#define GLOBAL extern \"C\" __global__\n"
    "#define LOOP_BEGIN { i64 t = (i64)blockDim.x * blockIdx.x + threadIdx.x; if (t < batch) {\n"
    "#define LOOP_END } }\n"
    + SHAKE_C_SOURCE + _KERNEL
)

C_WRAPPER = (
    "#define DEVFN static\n"
    "#define CONSTMEM static const\n"
    "#define GLOBAL\n"
    "#define LOOP_BEGIN for (i64 t = 0; t < batch; ++t) {\n"
    "#define LOOP_END }\n"
    + SHAKE_C_SOURCE + _KERNEL
)

RATE = {"shake128": 168, "shake256": 136}


class GPUShake:
    """CuPy front-end.

    ``g(seg0, seg1, ..., outlen=...)`` with up to three segments. Each
    segment is a CuPy uint8 array: 2-D (batch, len) with unit byte stride
    (rows may be strided, e.g. column slices), or 1-D (len,) broadcast to
    every row. ``g(data, outlen)`` with one 2-D array also works.
    Returns (batch, outlen) uint8, or writes into ``out``.
    """

    def __init__(self, variant: str):
        import cupy as cp
        self.cp = cp
        self.rate = RATE[variant]
        self._k = cp.RawModule(code=CUDA_WRAPPER).get_function("shake_seg")

    def __call__(self, *segments, outlen: int = None, out=None, threads: int = 128):
        cp = self.cp
        if outlen is None and len(segments) == 2 and isinstance(segments[1], int):
            segments, outlen = segments[:1], segments[1]
        if not 1 <= len(segments) <= 3:
            raise ValueError("1 to 3 segments")
        batch = None
        args = []
        for seg in segments:
            if seg.dtype != cp.uint8:
                raise TypeError("segments must be uint8")
            if seg.ndim == 2:
                if seg.shape[1] and seg.strides[1] != 1:
                    seg = cp.ascontiguousarray(seg)
                if batch is not None and seg.shape[0] != batch:
                    raise ValueError("segments disagree on batch size")
                batch = seg.shape[0]
                args.append((seg, seg.shape[1], seg.strides[0] if seg.shape[0] > 1 else 0))
            elif seg.ndim == 1:
                seg = cp.ascontiguousarray(seg)
                args.append((seg, seg.shape[0], 0))
            else:
                raise ValueError("segments must be 1-D or 2-D")
        if batch is None:
            raise ValueError("at least one segment must be 2-D")
        while len(args) < 3:
            args.append((args[0][0], 0, 0))
        if out is None:
            out = cp.empty((batch, outlen), dtype=cp.uint8)
        if out.shape != (batch, outlen) or (outlen and out.strides[1] != 1):
            raise ValueError("bad output buffer")
        if batch:
            flat = []
            for arr, ln, st in args:
                flat += [arr, cp.int64(ln), cp.int64(st)]
            grid = ((batch + threads - 1) // threads,)
            self._k(grid, (threads,), tuple(flat) + (
                out, cp.int64(outlen), cp.int64(out.strides[0]),
                cp.int32(self.rate), cp.int64(batch)))
        return out


__all__ = ["SHAKE_C_SOURCE", "CUDA_WRAPPER", "C_WRAPPER", "RATE", "GPUShake"]
