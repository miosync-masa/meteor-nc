"""
Byte-exact check of meteor_nc.cryptography.frodo against the official
FrodoKEM NIST KAT files (PQCkemKAT_*_shake.rsp).

The randomness is reproduced with the NIST AES-256 CTR_DRBG used to
generate the KATs. KAT files are read from $FRODO_KAT_DIR (or
tests/kat/ if present); the test is skipped when they are absent.

    git clone https://github.com/microsoft/PQCrypto-LWEKE
    FRODO_KAT_DIR=PQCrypto-LWEKE/FrodoKEM/KAT pytest tests/test_frodo_kat.py
"""
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from meteor_nc.cryptography.frodo import FrodoKEM, FRODO640, FRODO976, FRODO1344

KAT_FILES = {
    FRODO640: "PQCkemKAT_19888_shake.rsp",
    FRODO976: "PQCkemKAT_31296_shake.rsp",
    FRODO1344: "PQCkemKAT_43088_shake.rsp",
}
N_VECTORS = int(os.environ.get("FRODO_KAT_COUNT", "10"))


class NistDrbg:
    """AES-256 CTR_DRBG without derivation function (NIST PQC rng.c)."""

    def __init__(self, seed48: bytes):
        self.key, self.v = bytes(32), bytes(16)
        self._update(seed48)

    def _aes(self, block: bytes) -> bytes:
        enc = Cipher(algorithms.AES(self.key), modes.ECB()).encryptor()
        return enc.update(block) + enc.finalize()

    def _inc(self):
        self.v = ((int.from_bytes(self.v, "big") + 1) % (1 << 128)).to_bytes(16, "big")

    def _update(self, provided):
        tmp = b""
        for _ in range(3):
            self._inc()
            tmp += self._aes(self.v)
        if provided is not None:
            tmp = bytes(a ^ b for a, b in zip(tmp, provided))
        self.key, self.v = tmp[:32], tmp[32:]

    def randombytes(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            self._inc()
            out += self._aes(self.v)
        self._update(None)
        return out[:n]


def _kat_dir():
    for d in (os.environ.get("FRODO_KAT_DIR"), Path(__file__).parent / "kat"):
        if d and Path(d).is_dir():
            return Path(d)
    return None


def _read_kats(path: Path):
    entries, cur = [], {}
    for line in path.read_text().splitlines():
        if " = " in line:
            k, v = line.split(" = ", 1)
            cur[k.strip()] = v.strip()
            if k.strip() == "ss":
                entries.append(cur)
                cur = {}
    return entries


@pytest.mark.parametrize("params", [FRODO640, FRODO976, FRODO1344], ids=lambda p: p.name)
def test_kat(params):
    d = _kat_dir()
    if d is None or not (d / KAT_FILES[params]).exists():
        pytest.skip("FrodoKEM KAT files not available (set FRODO_KAT_DIR)")
    for e in _read_kats(d / KAT_FILES[params])[:N_VECTORS]:
        drbg = NistDrbg(bytes.fromhex(e["seed"]))
        kem = FrodoKEM(params, randombytes=drbg.randombytes)
        pk, sk = kem.keygen()
        assert pk.hex().upper() == e["pk"], f"pk mismatch at count {e['count']}"
        assert sk.hex().upper() == e["sk"], f"sk mismatch at count {e['count']}"
        ct, ss = kem.encaps(pk)
        assert ct.hex().upper() == e["ct"], f"ct mismatch at count {e['count']}"
        assert ss.hex().upper() == e["ss"], f"ss mismatch at count {e['count']}"
        assert kem.decaps(sk, ct) == ss
