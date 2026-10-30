"""
FrodoKEM 15-bit Pack / Unpack (Algorithms 3 and 4 with D = 15) for the GPU.

Every 8 entries form 120 bits = 15 bytes, most significant bit first. One
thread handles one such group. As with the SHAKE kernel, the C body is shared
between the CUDA build (NVRTC through CuPy) and a host build used in
tests/test_pack_kernel.py, where it is checked against the reference
implementation in frodo.py.
"""

from __future__ import annotations

PACK_C_SOURCE = r"""
typedef unsigned long long u64;
typedef unsigned char u8;
typedef long long i64;

/* 8 entries (low 15 bits used) -> 15 bytes, MSB first */
DEVFN void pack15_group(const int *v, u8 *o) {
    u64 buf = 0;
    int bits = 0, j = 0;
    for (int i = 0; i < 8; ++i) {
        buf = (buf << 15) | (u64)(v[i] & 0x7FFF);
        bits += 15;
        while (bits >= 8) {
            bits -= 8;
            o[j++] = (u8)(buf >> bits);
            buf &= (((u64)1) << bits) - 1;
        }
    }
}

/* 15 bytes -> 8 entries */
DEVFN void unpack15_group(const u8 *b, int *v) {
    u64 buf = 0;
    int bits = 0, i = 0;
    for (int j = 0; j < 15; ++j) {
        buf = (buf << 8) | (u64)b[j];
        bits += 8;
        if (bits >= 15) {
            bits -= 15;
            v[i++] = (int)((buf >> bits) & 0x7FFF);
            buf &= (((u64)1) << bits) - 1;
        }
    }
}
"""

_KERNELS = r"""
/* v: (nrows, 8*gpr) int32 contiguous; out: rows of 15*gpr bytes, row stride out_stride */
GLOBAL void pack15(const int *v, i64 gpr, i64 nrows, u8 *out, i64 out_stride) {
    LOOP_BEGIN
        i64 row = t / gpr, g = t % gpr;
        pack15_group(v + (row * gpr + g) * 8, out + row * out_stride + g * 15);
    LOOP_END
}

/* in: rows of 15*gpr bytes, row stride in_stride; v: (nrows, 8*gpr) int32 */
GLOBAL void unpack15(const u8 *in, i64 in_stride, i64 gpr, i64 nrows, int *v) {
    LOOP_BEGIN
        i64 row = t / gpr, g = t % gpr;
        unpack15_group(in + row * in_stride + g * 15, v + (row * gpr + g) * 8);
    LOOP_END
}
"""

CUDA_WRAPPER = (
    "#define DEVFN __device__\n#define GLOBAL extern \"C\" __global__\n"
    "#define LOOP_BEGIN { i64 t = (i64)blockDim.x * blockIdx.x + threadIdx.x; "
    "if (t < gpr * nrows) {\n"
    "#define LOOP_END } }\n"
    + PACK_C_SOURCE + _KERNELS
)

C_WRAPPER = (
    "#define DEVFN static\n#define GLOBAL\n"
    "#define LOOP_BEGIN for (i64 t = 0; t < gpr * nrows; ++t) {\n"
    "#define LOOP_END }\n"
    + PACK_C_SOURCE + _KERNELS
)


class GPUPack15:
    """CuPy front-end for pack15 / unpack15."""

    def __init__(self):
        import cupy as cp
        self.cp = cp
        mod = cp.RawModule(code=CUDA_WRAPPER)
        self._pack = mod.get_function("pack15")
        self._unpack = mod.get_function("unpack15")

    @staticmethod
    def _grid(n, threads=256):
        return ((int(n) + threads - 1) // threads,), (threads,)

    def pack(self, v, out):
        """v: (rows, 8*g) int32 -> out: (rows, 15*g) uint8 view (row-strided ok)."""
        cp = self.cp
        v = cp.ascontiguousarray(v, dtype=cp.int32)
        rows, cols = v.shape
        gpr = cols // 8
        assert cols % 8 == 0 and out.shape == (rows, 15 * gpr) and out.strides[1] == 1
        if rows:
            g, b = self._grid(rows * gpr)
            self._pack(g, b, (v, cp.int64(gpr), cp.int64(rows), out, cp.int64(out.strides[0])))

    def unpack(self, b8, cols: int):
        """b8: (rows, 15*cols/8) uint8 view (row-strided ok) -> (rows, cols) int32."""
        cp = self.cp
        rows = b8.shape[0]
        gpr = cols // 8
        assert cols % 8 == 0 and b8.shape[1] == 15 * gpr and b8.strides[1] == 1
        v = cp.empty((rows, cols), dtype=cp.int32)
        if rows:
            g, b = self._grid(rows * gpr)
            self._unpack(g, b, (b8, cp.int64(b8.strides[0]), cp.int64(gpr), cp.int64(rows), v))
        return v


__all__ = ["PACK_C_SOURCE", "CUDA_WRAPPER", "C_WRAPPER", "GPUPack15"]
