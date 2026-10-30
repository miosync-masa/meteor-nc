"""
Meteor-NC v3 GPU check and benchmark (e.g. Colab A100).

    !git clone https://github.com/miosync-masa/meteor-nc
    %cd /content/meteor-nc
    !git clone --depth 1 https://github.com/microsoft/PQCrypto-LWEKE /content/LWEKE
    !pip install -q pytest scipy cryptography
    !python benchmarks/bench_v3_gpu.py --kat /content/LWEKE/FrodoKEM/KAT

Colab ships a CuPy matching its CUDA (e.g. cupy-cuda13x); do not install a
second cupy-cuda1Xx package next to it (mixed CuPy builds fail to load cuBLAS).

1. Correctness on the GPU (aborts on any failure):
   - SHAKE kernel vs hashlib,
   - official FrodoKEM KATs through the GPU batch path (byte-exact),
   - GPU batch == CPU single for random inputs, incl. tampered ciphertexts,
   - f32split == int64 on the GPU.
2. Throughput per level and batch size: GPU-resident (raw shared secret,
   wires stay on the device) and end-to-end (K via SHAKE256, results copied
   to the host).
"""
import argparse
import hashlib
import os
import secrets
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cupy as cp  # noqa: E402

from meteor_nc.cryptography.batch import BatchLWEKEM  # noqa: E402
from meteor_nc.cryptography.frodo import FRODO640, FRODO976, FRODO1344, FrodoKEM  # noqa: E402
from meteor_nc.cryptography.frodo_batch import BatchFrodoKEM  # noqa: E402
from meteor_nc.cryptography.kernels.shake_kernel import GPUShake  # noqa: E402

LEVELS = [FRODO640, FRODO976, FRODO1344]
KAT_FILES = {FRODO640: "PQCkemKAT_19888_shake.rsp", FRODO976: "PQCkemKAT_31296_shake.rsp",
             FRODO1344: "PQCkemKAT_43088_shake.rsp"}


def sync():
    cp.cuda.Stream.null.synchronize()


def check_shake():
    rng = np.random.default_rng(0)
    for variant in ("shake128", "shake256"):
        g = GPUShake(variant)
        H = getattr(hashlib, variant.replace("shake", "shake_"))
        for inlen in (0, 1, 33, 135, 136, 137, 168, 169, 337, 9768, 21740):
            for outlen in (16, 32, 168, 20608, 43264):
                d = rng.integers(0, 256, size=(32, inlen), dtype=np.uint8)
                got = cp.asnumpy(g(cp.asarray(d), outlen))
                for i in range(32):
                    assert got[i].tobytes() == H(d[i].tobytes()).digest(outlen), (variant, inlen, outlen)
    print("[ok] GPU SHAKE kernel == hashlib")


def check_kats(kat_dir, count):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
    from test_frodo_kat import NistDrbg, _read_kats
    for P in LEVELS:
        entries = _read_kats(Path(kat_dir) / KAT_FILES[P])[:count]
        for mm in ("f16tc", "f32split", "int64"):
            bk = BatchFrodoKEM(P, backend="cupy", matmul=mm)
            for e in entries:
                drbg = NistDrbg(bytes.fromhex(e["seed"]))
                single = FrodoKEM(P, randombytes=drbg.randombytes)
                pk, sk = single.keygen()
                assert pk.hex().upper() == e["pk"]
                ms = np.frombuffer(drbg.randombytes(P.len_sec + P.len_salt), np.uint8)[None, :]
                ct, ss = bk.encaps_batch(pk, ms)
                assert ct[0].tobytes().hex().upper() == e["ct"], (P.name, mm, e["count"])
                assert ss[0].tobytes().hex().upper() == e["ss"], (P.name, mm, e["count"])
                assert bk.decaps_batch(sk, ct)[0].tobytes().hex().upper() == e["ss"]
        print(f"[ok] {P.name}: {len(entries)} KATs byte-exact on GPU (f16tc, f32split, int64)")


def check_random():
    for P in LEVELS:
        single = FrodoKEM(P)
        pk, sk = single.keygen()
        bk = BatchFrodoKEM(P, backend="cupy", chunk=100)
        assert bk.matmul == "f16tc", f"auto matmul fell back to {bk.matmul}"
        ms = np.frombuffer(secrets.token_bytes(257 * (P.len_sec + P.len_salt)), np.uint8).reshape(257, -1)
        ct, ss = bk.encaps_batch(pk, ms)
        bad = ct.copy()
        bad[::3, 7] ^= 1
        bad[1::7, -1] ^= 0x40
        ssd = bk.decaps_batch(sk, bad)
        for i in range(257):
            c, s = single.encaps_from_seed(pk, ms[i].tobytes())
            assert ct[i].tobytes() == c and ss[i].tobytes() == s
            assert ssd[i].tobytes() == single.decaps(sk, bad[i].tobytes())
        print(f"[ok] {P.name}: 257 random encaps/decaps (incl. tampered) == CPU single [{bk.matmul}]")


def bench(sizes, reps):
    """GPU-resident throughput (FrodoKEM ss, wires stay on the GPU) and
    end-to-end throughput (K = SHAKE256 KDF, wires and K copied to the host)."""
    print("\nlevel                 batch   encaps/s(gpu)  decaps/s(gpu)  encaps/s(e2e)  decaps/s(e2e)")
    for n, P in zip((256, 512, 1024), LEVELS):
        kem = BatchLWEKEM(n=n, backend="cupy")
        kem.key_gen()
        kem.encaps_batch(64)
        print(f"  [{P.name}: matmul={kem._batch.matmul}, chunk={kem._batch.chunk}]")
        for bs in sizes:
            _, wd = kem.encaps_batch(bs, raw=True, device=True)
            kem.decaps_batch(wd, raw=True, device=True)
            sync()

            def timed(fn):
                sync(); t = time.perf_counter()
                for _ in range(reps):
                    r = fn()
                sync()
                return (time.perf_counter() - t) / reps, r
            te, _ = timed(lambda: kem.encaps_batch(bs, raw=True, device=True))
            td, _ = timed(lambda: kem.decaps_batch(wd, raw=True, device=True))
            te2, (_, wh) = timed(lambda: kem.encaps_batch(bs))
            td2, _ = timed(lambda: kem.decaps_batch(wh))
            print(f"{P.name:20s} {bs:7d}   {bs/te:12,.0f}   {bs/td:12,.0f}   {bs/te2:12,.0f}   {bs/td2:12,.0f}")
        del kem
        cp.get_default_memory_pool().free_all_blocks()


def profile(bs):
    """Per-stage time of one encaps_batch / decaps_batch (device-synchronised)."""
    import collections
    import functools
    stages = ["_hash_rows", "_sample", "_mm", "_pack_into", "_unpack", "_encode",
              "_decode", "to_host", "_A"]
    for n, P in zip((256, 512, 1024), LEVELS):
        kem = BatchLWEKEM(n=n, backend="cupy")
        kem.key_gen()
        kem.encaps_batch(64)
        bk = kem._batch
        acc = collections.Counter()
        orig = {}
        for name in stages:
            f = getattr(bk, name)
            orig[name] = f

            def wrapped(*a, _f=f, _n=name, **k):
                sync(); t = time.perf_counter()
                r = _f(*a, **k)
                sync(); acc[_n] += time.perf_counter() - t
                return r
            setattr(bk, name, functools.wraps(f)(wrapped))
        for op in ("encaps", "decaps"):
            acc.clear()
            sync(); t = time.perf_counter()
            if op == "encaps":
                _, w = kem.encaps_batch(bs, raw=True, device=True)
            else:
                kem.decaps_batch(w, raw=True, device=True)
            sync(); total = time.perf_counter() - t
            other = total - sum(acc.values())
            parts = ", ".join(f"{k.lstrip('_')} {v / total:5.1%}" for k, v in acc.most_common())
            print(f"{P.name} {op} batch {bs}: {total * 1e3:7.1f} ms | {parts}, "
                  f"other {other / total:5.1%}  (chunk={bk.chunk}, matmul={bk.matmul})")
        for name, f in orig.items():
            setattr(bk, name, f)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--kat", help="FrodoKEM KAT directory (PQCrypto-LWEKE/FrodoKEM/KAT)")
    ap.add_argument("--kat-count", type=int, default=20)
    ap.add_argument("--sizes", default="1000,10000,100000")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--skip-checks", action="store_true")
    ap.add_argument("--profile", type=int, metavar="BATCH",
                    help="print a per-stage time breakdown at this batch size")
    a = ap.parse_args()
    if os.environ.get("CUPY_TF32") == "1":
        sys.exit("unset CUPY_TF32: TF32 breaks exact float32 products")
    dev = cp.cuda.runtime.getDeviceProperties(0)
    print(f"device: {dev['name'].decode()}  cupy {cp.__version__}")
    if not a.skip_checks:
        check_shake()
        if a.kat:
            check_kats(a.kat, a.kat_count)
        else:
            print("[skip] KATs (pass --kat DIR)")
        check_random()
    if a.profile:
        profile(a.profile)
    else:
        bench([int(x) for x in a.sizes.split(",")], a.reps)
