"""
Check the GPU SHAKE kernel source against hashlib without a GPU.

The C text in kernels/shake_kernel.py is compiled with the host C compiler
(DEVFN=static) and called through ctypes. The CUDA build uses the identical
text with DEVFN=__device__. If a CUDA device is present, the GPU kernel is
checked too.
"""
import ctypes
import hashlib
import os
import shutil
import subprocess
import tempfile

import numpy as np
import pytest

from meteor_nc.cryptography.kernels.shake_kernel import C_WRAPPER, RATE

CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")


@pytest.fixture(scope="module")
def lib():
    if CC is None:
        pytest.skip("no C compiler")
    d = tempfile.mkdtemp()
    src, so = os.path.join(d, "shake.c"), os.path.join(d, "shake.so")
    with open(src, "w") as f:
        f.write(C_WRAPPER)
    subprocess.run([CC, "-O2", "-shared", "-fPIC", "-o", so, src], check=True)
    L = ctypes.CDLL(so)
    L.shake_batch.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p,
                              ctypes.c_longlong, ctypes.c_int, ctypes.c_int]
    return L


def _c_shake(L, data: np.ndarray, outlen: int, variant: str) -> np.ndarray:
    data = np.ascontiguousarray(data, dtype=np.uint8)
    out = np.zeros((data.shape[0], outlen), dtype=np.uint8)
    L.shake_batch(data.ctypes.data, data.shape[1], out.ctypes.data, outlen,
                  RATE[variant], data.shape[0])
    return out


# input lengths around both rates and the lengths FrodoKEM uses
INLENS = [0, 1, 16, 33, 49, 65, 135, 136, 137, 167, 168, 169, 335, 336, 337,
          9616, 9752 + 16, 21696 + 32]
OUTLENS = [1, 16, 32, 136, 168, 169, 20608, 41472]


@pytest.mark.parametrize("variant", ["shake128", "shake256"])
def test_matches_hashlib(lib, variant):
    rng = np.random.default_rng(1)
    H = getattr(hashlib, variant.replace("shake", "shake_"))
    for inlen in INLENS:
        for outlen in OUTLENS:
            data = rng.integers(0, 256, size=(3, inlen), dtype=np.uint8)
            got = _c_shake(lib, data, outlen, variant)
            for i in range(3):
                assert got[i].tobytes() == H(data[i].tobytes()).digest(outlen), (inlen, outlen)


def test_gpu_kernel_if_available():
    from meteor_nc.cryptography.frodo_batch import CUPY_AVAILABLE
    if not CUPY_AVAILABLE:
        pytest.skip("no CUDA device")
    import cupy as cp
    from meteor_nc.cryptography.kernels.shake_kernel import GPUShake
    rng = np.random.default_rng(2)
    for variant in ("shake128", "shake256"):
        g = GPUShake(variant)
        for inlen in (0, 33, 168, 337, 9768):
            data = rng.integers(0, 256, size=(64, inlen), dtype=np.uint8)
            got = cp.asnumpy(g(cp.asarray(data), 20608))
            for i in range(64):
                assert got[i].tobytes() == getattr(hashlib, variant.replace("shake", "shake_"))(data[i].tobytes()).digest(20608)
