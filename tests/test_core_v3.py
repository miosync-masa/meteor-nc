"""
Tests for the Meteor-NC v3 LWEKEM (FrodoKEM core).

Includes a regression test for the v2 break: in v2 every message bit shared
one scalar mask, so differences between ciphertext coordinates revealed the
message. The same difference attack is run against v3 and must fail.
"""
import numpy as np
import pytest

from meteor_nc.cryptography.core import LWEKEM, HybridKEM
from meteor_nc.cryptography.frodo import FrodoKEM

LEVELS = [(256, "FrodoKEM-640-SHAKE"), (512, "FrodoKEM-976-SHAKE"),
          (1024, "FrodoKEM-1344-SHAKE")]


@pytest.mark.parametrize("n,name", LEVELS)
def test_roundtrip_and_sizes(n, name):
    alice = LWEKEM(n=n)
    assert alice.params.name == name
    pk, sk = alice.key_gen()
    assert len(pk) == alice.get_public_key_size()
    bob = LWEKEM(n=n)
    bob.load_public_key(pk)
    for _ in range(5):
        K, wire = bob.encaps()
        assert len(K) == 32 and len(wire) == bob.get_ciphertext_size()
        assert alice.decaps(wire) == K


def test_keys_roundtrip_through_bytes():
    a = LWEKEM(n=256)
    pk, sk = a.key_gen()
    b = LWEKEM(n=256); b.load_public_key(pk)
    K, wire = b.encaps()
    c = LWEKEM(n=256); c.load_public_key(pk); c.load_secret_key(sk)
    assert c.decaps(wire) == K


def test_implicit_rejection_on_tamper():
    a = LWEKEM(n=256)
    pk, _ = a.key_gen()
    b = LWEKEM(n=256); b.load_public_key(pk)
    K, wire = b.encaps()
    for pos in (12, len(wire) // 2, len(wire) - 1):   # c1, c2, salt regions
        bad = bytearray(wire); bad[pos] ^= 0x01
        K_bad = a.decaps(bytes(bad))
        assert K_bad != K
        assert a.decaps(bytes(bad)) == K_bad          # deterministic rejection


def test_rejects_v2_and_cross_level_material():
    a = LWEKEM(n=256)
    pk, sk = a.key_gen()
    v2_header = (256).to_bytes(4, "big") + (256).to_bytes(4, "big") + (4294967291).to_bytes(4, "big")
    with pytest.raises(ValueError):
        LWEKEM(n=256).load_secret_key(v2_header + sk[12:])
    b = LWEKEM(n=512); b.key_gen()
    _, wire512 = b.encaps()
    with pytest.raises(ValueError):
        a.decaps(wire512)


def test_load_public_key_switches_level():
    a = LWEKEM(n=512)
    pk, _ = a.key_gen()
    b = LWEKEM(n=256)
    b.load_public_key(pk)
    assert b.params.n == 976
    K, wire = b.encaps()
    assert a.decaps(wire) == K


def test_seeded_keygen_is_deterministic():
    s = b"\x07" * 32
    assert LWEKEM(n=256, seed=s).key_gen() == LWEKEM(n=256, seed=s).key_gen()
    assert LWEKEM(n=256, seed=s).key_gen() != LWEKEM(n=256, seed=b"\x08" * 32).key_gen()


def test_hybrid_kem():
    h = HybridKEM(security_level=128, gpu=False)
    pk, sk = h.key_gen()
    s = HybridKEM(security_level=128, gpu=False); s.load_public_key(pk)
    ct = s.encrypt(b"hello frodo", aad=b"ad")
    r = HybridKEM(security_level=128, gpu=False); r.load_keys(pk, sk)
    assert r.decrypt(ct, aad=b"ad") == b"hello frodo"


@pytest.mark.parametrize("n", [256, 512, 1024])
def test_v2_difference_attack_fails(n):
    """Port of the v2 key-recovery attack. Using only (pk, ct), guess mu
    from differences of C entries relative to C[0,0], try every value of
    the reference entry, and check each guess by public re-encryption."""
    kem = LWEKEM(n=n)
    pk, _ = kem.key_gen()
    fr: FrodoKEM = kem._frodo
    p = kem.params
    l1 = p.D * p.mbar * p.n // 8
    l2 = p.D * p.mbar * p.nbar // 8
    for _ in range(5):
        _, wire = kem.encaps()
        ct = wire[12:]
        C = fr.unpack(ct[l1:l1 + l2], p.mbar, p.nbar).reshape(-1)
        salt = ct[l1 + l2:]
        diff = (C - C[0]) & (p.q - 1)
        recovered = False
        for ref in range(1 << p.B):
            vals = ((((diff << p.B) + (1 << (p.D - 1))) >> p.D) + ref) & ((1 << p.B) - 1)
            mu = fr.decode((vals * (p.q >> p.B)).reshape(p.mbar, p.nbar))
            ct2, _ = fr.encaps_from_seed(kem.pk.frodo_pk, mu + salt)
            recovered |= (ct2 == ct)
        assert not recovered
