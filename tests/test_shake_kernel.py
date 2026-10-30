"""
Check the GPU SHAKE kernel source against hashlib without a GPU.

The C text in kernels/shake_kernel.py is compiled with the host C compiler
(DEVFN=static) and called through ctypes. The CUDA build uses the identical
text with DEVFN=__device__. Covered: lengths around both rates, every
alignment of input and output (the 8-/4-/1-byte load/store paths), one to
three segments, broadcast (stride 0) segments and row-strided segments.
If a CUDA device is present, the GPU kernel is checked too.
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
HASH = {"shake128": hashlib.shake_128, "shake256": hashlib.shake_256}
P, L = ctypes.c_void_p, ctypes.c_longlong


@pytest.fixture(scope="module")
def lib():
    if CC is None:
        pytest.skip("no C compiler")
    d = tempfile.mkdtemp()
    src, so = os.path.join(d, "shake.c"), os.path.join(d, "shake.so")
    with open(src, "w") as f:
        f.write(C_WRAPPER)
    subprocess.run([CC, "-O2", "-shared", "-fPIC", "-o", so, src], check=True)
    lib = ctypes.CDLL(so)
    lib.shake_seg.argtypes = [P, L, L, P, L, L, P, L, L, P, L, L, ctypes.c_int, L]
    return lib


def _addr(a: np.ndarray, off: int = 0) -> int:
    return a.ctypes.data + off


def _run(lib, segs, outlen, variant, batch, out_off=0):
    """segs: list of (buffer, byte offset, length, row stride)."""
    segs = list(segs) + [(segs[0][0], 0, 0, 0)] * (3 - len(segs))
    stride_out = outlen + 11                       # rows not 8-aligned
    out = np.zeros(out_off + batch * stride_out + 16, dtype=np.uint8)
    args = []
    for buf, off, ln, st in segs:
        args += [_addr(buf, off), ln, st]
    lib.shake_seg(*args, _addr(out, out_off), outlen, stride_out, RATE[variant], batch)
    return [out[out_off + t * stride_out: out_off + t * stride_out + outlen].tobytes()
            for t in range(batch)]


INLENS = [0, 1, 7, 8, 9, 16, 33, 49, 65, 135, 136, 137, 167, 168, 169, 335, 336, 337,
          9768, 15816, 21728]
OUTLENS = [1, 7, 8, 16, 24, 32, 136, 168, 169, 20608, 43136]


@pytest.mark.parametrize("variant", ["shake128", "shake256"])
def test_single_segment_lengths_and_alignments(lib, variant):
    rng = np.random.default_rng(1)
    for inlen in INLENS:
        for outlen in OUTLENS:
            for in_off, out_off in ((0, 0), (4, 4), (3, 5)):
                stride = inlen + 13
                buf = rng.integers(0, 256, size=in_off + 3 * stride + 8, dtype=np.uint8)
                got = _run(lib, [(buf, in_off, inlen, stride)], outlen, variant, 3, out_off)
                for t in range(3):
                    msg = buf[in_off + t * stride: in_off + t * stride + inlen].tobytes()
                    assert got[t] == HASH[variant](msg).digest(outlen), (inlen, outlen, in_off, out_off)


@pytest.mark.parametrize("variant", ["shake128", "shake256"])
def test_segments_broadcast_and_strided(lib, variant):
    rng = np.random.default_rng(2)
    batch = 4
    cases = [
        [(1, 0), (32, 1)],                 # 0x96 || seedSE (broadcast prefix)
        [(16, 0), (16, 1), (32, 1)],       # pkh || mu || salt
        [(9752, 1), (16, 1)],              # ct row || k row
        [(14, 0), (32, 1)],                # KDF domain || ss
        [(5, 1), (0, 1), (171, 0)],        # empty middle segment
        [(168, 1), (168, 0), (1, 1)],      # boundaries exactly at the rate
    ]
    for case in cases:
        for off in (0, 4, 1):
            segs, parts = [], [[] for _ in range(batch)]
            for ln, per_row in case:
                stride = (ln + 9) if per_row else 0
                buf = rng.integers(0, 256, size=off + batch * max(stride, ln) + ln + 8, dtype=np.uint8)
                segs.append((buf, off, ln, stride))
                for t in range(batch):
                    parts[t].append(buf[off + t * stride: off + t * stride + ln].tobytes())
            for outlen in (16, 32, 20608):
                got = _run(lib, segs, outlen, variant, batch, off)
                for t in range(batch):
                    assert got[t] == HASH[variant](b"".join(parts[t])).digest(outlen), (case, off, outlen)


def test_gpu_kernel_if_available():
    from meteor_nc.cryptography.frodo_batch import CUPY_AVAILABLE
    if not CUPY_AVAILABLE:
        pytest.skip("no CUDA device")
    import cupy as cp
    from meteor_nc.cryptography.kernels.shake_kernel import GPUShake
    rng = np.random.default_rng(3)
    for variant in ("shake128", "shake256"):
        g = GPUShake(variant)
        for inlen in (0, 33, 168, 337, 9768):
            data = rng.integers(0, 256, size=(64, inlen + 12), dtype=np.uint8)
            dev = cp.asarray(data)
            got = cp.asnumpy(g(dev[:, 12:], outlen=20608))
            pre = cp.asarray(np.frombuffer(b"\x96", np.uint8))
            got2 = cp.asnumpy(g(pre, dev[:, 12:], dev[:, :5], outlen=40))
            for i in range(64):
                m = data[i, 12:].tobytes()
                assert got[i].tobytes() == HASH[variant](m).digest(20608)
                assert got2[i].tobytes() == HASH[variant](b"\x96" + m + data[i, :5].tobytes()).digest(40)
