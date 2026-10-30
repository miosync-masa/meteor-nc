"""
Check the GPU 15-bit pack/unpack kernel source against frodo.py on CPU.

The C text in kernels/pack_kernel.py is compiled with the host compiler and
called through ctypes, including on row-strided output/input buffers (as the
batch code uses them). If a CUDA device is present the GPU kernel is checked
too.
"""
import ctypes
import os
import shutil
import subprocess
import tempfile

import numpy as np
import pytest

from meteor_nc.cryptography.frodo import FRODO640, FrodoKEM
from meteor_nc.cryptography.kernels.pack_kernel import C_WRAPPER

CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
REF = FrodoKEM(FRODO640)          # D = 15


@pytest.fixture(scope="module")
def lib():
    if CC is None:
        pytest.skip("no C compiler")
    d = tempfile.mkdtemp()
    src, so = os.path.join(d, "pack.c"), os.path.join(d, "pack.so")
    with open(src, "w") as f:
        f.write(C_WRAPPER)
    subprocess.run([CC, "-O2", "-shared", "-fPIC", "-o", so, src], check=True)
    L = ctypes.CDLL(so)
    L.pack15.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_longlong,
                         ctypes.c_void_p, ctypes.c_longlong]
    L.unpack15.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_longlong,
                           ctypes.c_longlong, ctypes.c_void_p]
    return L


@pytest.mark.parametrize("rows,cols", [(1, 8), (3, 64), (5, 5120)])
def test_pack15_matches_reference(lib, rows, cols):
    rng = np.random.default_rng(rows * cols)
    v = rng.integers(0, 1 << 15, size=(rows, cols), dtype=np.int32)
    v[0, :8] = [0, 0x7FFF, 1, 0x4000, 0x3FFF, 0x5555, 0x2AAA, 0x7FFE]
    pad = 7                                   # row-strided destination
    buf = np.full((rows, cols * 15 // 8 + pad), 0xEE, dtype=np.uint8)
    out = buf[:, 3:3 + cols * 15 // 8]
    lib.pack15(v.ctypes.data, cols // 8, rows, out.ctypes.data, buf.strides[0])
    for r in range(rows):
        assert out[r].tobytes() == REF.pack(v[r].astype(np.int64).reshape(1, -1))
    assert (buf[:, :3] == 0xEE).all() and (buf[:, 3 + cols * 15 // 8:] == 0xEE).all()

    back = np.zeros((rows, cols), dtype=np.int32)
    lib.unpack15(out.ctypes.data, buf.strides[0], cols // 8, rows, back.ctypes.data)
    assert (back == v).all()
    for r in range(rows):
        assert (REF.unpack(out[r].tobytes(), 1, cols)[0] == v[r]).all()


def test_gpu_pack15_if_available():
    from meteor_nc.cryptography.frodo_batch import CUPY_AVAILABLE
    if not CUPY_AVAILABLE:
        pytest.skip("no CUDA device")
    import cupy as cp
    from meteor_nc.cryptography.kernels.pack_kernel import GPUPack15
    g = GPUPack15()
    rng = np.random.default_rng(3)
    v = rng.integers(0, 1 << 15, size=(9, 5120), dtype=np.int32)
    buf = cp.zeros((9, 9600 + 12), dtype=cp.uint8)
    g.pack(cp.asarray(v), buf[:, 12:])
    host = cp.asnumpy(buf)
    for r in range(9):
        assert host[r, 12:].tobytes() == REF.pack(v[r].astype(np.int64).reshape(1, -1))
    assert (cp.asnumpy(g.unpack(buf[:, 12:], 5120)) == v).all()
