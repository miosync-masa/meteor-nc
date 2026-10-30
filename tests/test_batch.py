"""
Tests for the v3 batch backend (BatchLWEKEM / BatchHybridKEM).

Run on NumPy everywhere; on CuPy too when a CUDA device is present
(METEOR_BATCH_BACKENDS=numpy,cupy to choose explicitly).
"""
import os
import secrets

import numpy as np
import pytest

from meteor_nc.cryptography.batch import BatchCiphertext, BatchHybridKEM, BatchLWEKEM
from meteor_nc.cryptography.core import HybridKEM, LWEKEM
from meteor_nc.cryptography.frodo import FrodoKEM
from meteor_nc.cryptography.frodo_batch import CUPY_AVAILABLE, BatchFrodoKEM

_default = "numpy,cupy" if CUPY_AVAILABLE else "numpy"
BACKENDS = os.environ.get("METEOR_BATCH_BACKENDS", _default).split(",")
LEVELS = [256, 512, 1024]


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("n", LEVELS)
def test_batch_roundtrip_and_interop(backend, n):
    kem = BatchLWEKEM(n=n, backend=backend)
    pk, sk = kem.key_gen()
    K, wires = kem.encaps_batch(12)
    assert K.shape == (12, 32) and wires.shape == (12, kem.get_ciphertext_size())
    assert (kem.decaps_batch(wires) == K).all()
    # batch wires decapsulate with the single LWEKEM, and vice versa
    single = LWEKEM(n=n); single.load_public_key(pk); single.load_secret_key(sk)
    for i in range(3):
        assert single.decaps(wires[i].tobytes()) == K[i].tobytes()
    Ks, ws = zip(*[single.encaps() for _ in range(4)])
    assert [k.tobytes() for k in kem.decaps_batch(list(ws))] == list(Ks)


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("matmul", ["auto", "f16tc", "f32split", "int64"])
@pytest.mark.parametrize("n", LEVELS)
def test_byte_exact_with_single(backend, matmul, n):
    """Fixed randomness: batch ct/ss equal the single implementation's."""
    if matmul == "f16tc" and backend != "cupy":
        pytest.skip("f16tc needs CuPy")
    lw = LWEKEM(n=n); pk, sk = lw.key_gen()
    P = lw.params
    single = FrodoKEM(P)
    bk = BatchFrodoKEM(P, backend=backend, matmul=matmul)
    ms = np.frombuffer(secrets.token_bytes(8 * (P.len_sec + P.len_salt)), np.uint8).reshape(8, -1)
    ct, ss = bk.encaps_batch(lw.pk.frodo_pk, ms)
    for i in range(8):
        c, s = single.encaps_from_seed(lw.pk.frodo_pk, ms[i].tobytes())
        assert ct[i].tobytes() == c and ss[i].tobytes() == s


@pytest.mark.parametrize("backend", BACKENDS)
def test_batch_implicit_rejection_mixed(backend):
    kem = BatchLWEKEM(n=256, backend=backend)
    pk, sk = kem.key_gen()
    K, wires = kem.encaps_batch(16)
    bad = wires.copy()
    idx = [1, 4, 9, 15]
    for j, i in enumerate(idx):
        bad[i, 12 + 97 * (j + 1)] ^= 1 << j          # c1 / c2 / salt regions
    bad[15, -1] ^= 0x80                              # salt
    K2 = kem.decaps_batch(bad)
    for i in range(16):
        assert (K2[i] == K[i]).all() == (i not in idx)
    # rejection is deterministic and matches the single path
    single = LWEKEM(n=256); single.load_public_key(pk); single.load_secret_key(sk)
    for i in idx:
        assert single.decaps(bad[i].tobytes()) == K2[i].tobytes()
    assert (kem.decaps_batch(bad) == K2).all()


@pytest.mark.parametrize("backend", BACKENDS)
def test_batch_rejects_bad_shapes_and_headers(backend):
    kem = BatchLWEKEM(n=256, backend=backend)
    kem.key_gen()
    _, wires = kem.encaps_batch(2)
    with pytest.raises(ValueError):
        kem.decaps_batch(wires[:, :-1])
    hdr = wires.copy(); hdr[:, 3] = 2                # version 2
    with pytest.raises(ValueError):
        kem.decaps_batch(hdr)


@pytest.mark.parametrize("backend", BACKENDS)
def test_batch_hybrid_interop(backend):
    bh = BatchHybridKEM(n=256, backend=backend)
    pk, sk = bh.key_gen()
    msgs = [b"", b"a", secrets.token_bytes(1000)] + [f"m{i}".encode() for i in range(5)]
    cts = bh.encrypt_batch(msgs, aad=b"ad")
    assert bh.decrypt_batch(cts, aad=b"ad") == msgs
    h = HybridKEM(security_level=128, gpu=False); h.load_keys(pk, sk)
    assert h.decrypt(cts[2], aad=b"ad") == msgs[2]
    assert bh.decrypt(BatchCiphertext.from_bytes(h.encrypt(b"x", aad=b"ad")), aad=b"ad") == b"x"
    with pytest.raises(Exception):
        bh.decrypt(cts[0], aad=b"other")


def test_f32split_exact_on_extremes():
    from meteor_nc.cryptography.frodo import FRODO640, FRODO976, FRODO1344, _cdf
    for P in (FRODO640, FRODO976, FRODO1344):
        a = BatchFrodoKEM(P, backend="numpy", matmul="f32split")
        b = BatchFrodoKEM(P, backend="numpy", matmul="int64")
        emax = len(_cdf(P.chi)) - 1
        S = np.full((8, P.n), emax, np.int64); S[1] = -emax; S[2, ::2] = -emax
        A = np.full((P.n, P.n), (P.q - 1), np.int64); A[:, 1::3] = 0xFF; A[:, 2::5] = 0xFF00 & (P.q - 1)
        assert (a._mm(S, A) == b._mm(S, A)).all()
        assert (a._mm(S.T.copy(), A, small_left=False) == b._mm(S.T.copy(), A, small_left=False)).all()
