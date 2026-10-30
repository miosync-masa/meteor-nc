"""
Timing checks for v3 batch decapsulation (BatchLWEKEM).

decaps_batch always runs the full re-encryption for every row and selects
k / s without branching, so batch time should not depend on how many rows
are valid. These are coarse statistical checks, not a constant-time proof
(Python/NumPy/CuPy give no such guarantee).

Environment: METEOR_BATCH_SC_REPS (default 25), METEOR_BATCH_SC_SIZE (32).
"""
import os
import time

import numpy as np
import pytest
from scipy import stats

from meteor_nc.cryptography.batch import BatchLWEKEM
from meteor_nc.cryptography.frodo_batch import CUPY_AVAILABLE

REPS = int(os.environ.get("METEOR_BATCH_SC_REPS", "25"))
SIZE = int(os.environ.get("METEOR_BATCH_SC_SIZE", "32"))
BACKEND = "cupy" if CUPY_AVAILABLE else "numpy"
T_MAX = 4.5          # Welch t threshold
REL_MAX = 0.05       # or: mean difference below 5% of the mean


def _sync():
    if BACKEND == "cupy":
        import cupy as cp
        cp.cuda.Stream.null.synchronize()


def _time(fn, arg):
    _sync()
    t = time.perf_counter()
    fn(arg)
    _sync()
    return time.perf_counter() - t


def _no_leak(a, b):
    t, _ = stats.ttest_ind(a, b, equal_var=False)
    rel = abs(np.mean(a) - np.mean(b)) / np.mean(a)
    return abs(t) < T_MAX or rel < REL_MAX, t, rel


@pytest.fixture(scope="module")
def setup():
    kem = BatchLWEKEM(n=256, backend=BACKEND)
    kem.key_gen()
    _, wires = kem.encaps_batch(SIZE)
    bad = wires.copy()
    bad[:, 40] ^= 1
    mixed = wires.copy()
    mixed[::2, 40] ^= 1
    for _ in range(3):
        kem.decaps_batch(wires)           # warm-up
    return kem, wires, bad, mixed


def _interleaved(kem, x, y):
    tx, ty = [], []
    for _ in range(REPS):
        tx.append(_time(kem.decaps_batch, x))
        ty.append(_time(kem.decaps_batch, y))
    return np.array(tx), np.array(ty)


def test_all_valid_vs_all_invalid(setup):
    kem, wires, bad, _ = setup
    ok, t, rel = _no_leak(*_interleaved(kem, wires, bad))
    assert ok, f"t={t:.2f}, rel={rel:.3%}"


def test_all_valid_vs_mixed(setup):
    kem, wires, _, mixed = setup
    ok, t, rel = _no_leak(*_interleaved(kem, wires, mixed))
    assert ok, f"t={t:.2f}, rel={rel:.3%}"


def test_rejection_outputs(setup):
    kem, wires, bad, mixed = setup
    good = kem.decaps_batch(wires)
    assert not (kem.decaps_batch(bad) == good).all(axis=1).any()
    same = (kem.decaps_batch(mixed) == good).all(axis=1)
    assert (same == (np.arange(SIZE) % 2 == 1)).all()


def test_scaling_is_roughly_linear(setup):
    kem, wires, _, _ = setup
    if BACKEND == "cupy":
        # at a few dozen rows a GPU batch costs the same fixed launch time
        # regardless of size; linear growth only shows at thousands of rows
        _, wires = kem.encaps_batch(16384)
        sizes = [4096, 8192, 16384]
    else:
        sizes = [max(1, SIZE // 4), max(2, SIZE // 2), SIZE]
    times = [np.median([_time(kem.decaps_batch, wires[:s]) for _ in range(5)]) for s in sizes]
    r = stats.linregress(sizes, times)
    assert r.slope > 0 and r.rvalue ** 2 > 0.8, (sizes, times)
