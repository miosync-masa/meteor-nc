"""
Tests for the v3 protocol layer (envelope, MeteorNode, MeteorWeb4Node).

Each attack test corresponds to a hole found in the v2 protocol code
(SECURITY.md): secret seed published as the MeteorID, fail-open signature
checks, unauthenticated headers / sender spoofing, replays, plaintext hash
leak, DHT poisoning, forged stream chunks blocking genuine ones.
"""
import asyncio
import dataclasses
import hashlib
import logging
import secrets
import time

import pytest

from meteor_nc.cryptography.core import LWEKEM
from meteor_nc.cryptography.stream import EncryptedChunk, StreamDEM
from meteor_nc.protocols.envelope import (
    BROADCAST_ID, Envelope, EnvelopeError, MeteorIdentity, ReplayGuard,
    meteor_id_of, open_envelope, parse_bundle, seal,
)
from meteor_nc.protocols.meteor_protocol import MeteorNode, MeteorProtocol
from meteor_nc.protocols.web4 import MeteorWeb4Node, MessageType, Web4DHT, Web4Identity

logging.disable(logging.WARNING)


def pair():
    a, b = MeteorNode("Alice"), MeteorNode("Bob")
    a.add_peer("Bob", b.get_meteor_id(), b.get_public_key())
    b.add_peer("Alice", a.get_meteor_id(), a.get_public_key())
    return a, b


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------

def test_identity_is_self_certifying_and_hides_the_seed():
    seed = secrets.token_bytes(32)
    ident = MeteorIdentity(seed)
    assert ident.meteor_id == meteor_id_of(ident.bundle) != seed
    assert MeteorIdentity(seed).bundle == ident.bundle          # deterministic
    kem_pk, sign_pk = parse_bundle(ident.bundle)
    # the v2 attack: rebuilding the KEM key from the published ID must not work
    k = LWEKEM(n=256, seed=ident.meteor_id); pk, _ = k.key_gen()
    assert pk != kem_pk


def test_web4_identity_cannot_be_rebuilt_from_meteor_id():
    seed = secrets.token_bytes(32)
    ident = Web4Identity(seed)
    assert ident.meteor_id != seed
    with pytest.raises(TypeError):
        Web4Identity.from_meteor_id(ident.meteor_id)
    assert Web4Identity(ident.meteor_id).ed25519_public != ident.ed25519_public


def test_web4_verify_fails_closed():
    ident = Web4Identity()
    sig = ident.sign(b"m")
    assert ident.verify(b"m", sig, ident.bundle)
    assert not ident.verify(b"x", sig, ident.bundle)
    assert not ident.verify(b"m", sig, Web4Identity().bundle)
    assert not ident.verify(b"m", b"\x00" * len(sig), ident.bundle)
    assert not ident.verify(b"m", sig, b"not a bundle")


def test_hybrid_signature_needs_both_halves():
    """Breaking either algorithm alone must not be enough to forge."""
    from meteor_nc.protocols.envelope import ED25519_SIG, verify_signature
    alice, mallory = MeteorIdentity(), MeteorIdentity()
    _, keys = parse_bundle(alice.bundle)
    data = b"transfer 100"
    good = alice.sign(data)
    assert verify_signature(keys, good, data)
    m = mallory.sign(data)
    # "classical break": valid Ed25519 half, forged ML-DSA half
    assert not verify_signature(keys, good[:ED25519_SIG] + m[ED25519_SIG:], data)
    # "quantum break": forged Ed25519 half, valid ML-DSA half
    assert not verify_signature(keys, m[:ED25519_SIG] + good[ED25519_SIG:], data)
    assert not verify_signature(keys, good[:ED25519_SIG], data)
    assert not verify_signature(keys, good + b"\x00", data)


def test_add_peer_rejects_mismatched_bundle():
    a, b, m = MeteorNode("A"), MeteorNode("B"), MeteorNode("M")
    with pytest.raises(ValueError):
        a.add_peer("B", b.get_meteor_id(), m.get_public_key())     # substituted key
    with pytest.raises(ValueError):
        a.add_peer("B", b.get_meteor_id(), b"garbage")


# --------------------------------------------------------------------------
# MeteorNode messaging
# --------------------------------------------------------------------------

def test_roundtrip_bidirectional_and_wire():
    a, b = pair()
    assert b.receive(a.send("Bob", b"hello")) == b"hello"
    assert a.receive(b.send("Alice", b"")) == b""
    big = secrets.token_bytes(100_000)
    assert b.receive(Envelope.from_bytes(a.send("Bob", big).to_bytes())) == big


def test_seeded_node_reconnects_with_same_id():
    seed = secrets.token_bytes(32)
    n1, n2 = MeteorNode("x", seed=seed), MeteorNode("y", seed=seed)
    assert n1.get_meteor_id() == n2.get_meteor_id()
    assert n1.get_public_key() == n2.get_public_key()


@pytest.mark.parametrize("field,value", [
    ("sender_id", b"\x11" * 32),
    ("recipient_id", b"\x22" * 32),
    ("timestamp_ms", 1),
    ("msg_type", "other"),
    ("message_id", b"\x33" * 16),
    ("meta", {"x": 1}),
])
def test_header_tampering_is_rejected(field, value):
    a, b = pair()
    env = a.send("Bob", b"secret")
    with pytest.raises(ValueError):
        b.receive(dataclasses.replace(env, **{field: value}))


@pytest.mark.parametrize("part", ["payload", "tag", "signature", "kem_wire"])
def test_body_tampering_is_rejected(part):
    a, b = pair()
    env = a.send("Bob", b"secret message")
    val = bytearray(getattr(env, part))
    val[len(val) // 2] ^= 1
    with pytest.raises(ValueError):
        b.receive(dataclasses.replace(env, **{part: bytes(val)}))


def test_sender_spoofing_is_rejected():
    """Mallory knows Alice's public bundle and Bob's key, and claims to be Alice."""
    a, b = pair()
    mallory = MeteorIdentity()
    env = seal(mallory, "data", b"pay mallory", recipient_id=b.get_meteor_id(),
               recipient_bundle=b.get_public_key())
    env = dataclasses.replace(env, sender_id=a.get_meteor_id())
    env.signature = mallory.sign(env.signed_data())
    with pytest.raises(ValueError, match="signature"):
        b.receive(env)


def test_unknown_sender_is_rejected():
    _, b = pair()
    stranger = MeteorNode("Stranger")
    stranger.add_peer("Bob", b.get_meteor_id(), b.get_public_key())
    with pytest.raises(ValueError, match="unknown sender"):
        b.receive(stranger.send("Bob", b"hi"))


def test_replay_and_stale_messages_are_rejected():
    a, b = pair()
    env = a.send("Bob", b"once")
    assert b.receive(env) == b"once"
    with pytest.raises(ValueError, match="replay"):
        b.receive(env)
    g = ReplayGuard(window_s=60)
    with pytest.raises(EnvelopeError):
        g.check(b"s", b"i", int((time.time() - 3600) * 1000))


def test_message_for_someone_else_is_rejected():
    a, b = pair()
    c = MeteorNode("Carol")
    c.add_peer("Alice", a.get_meteor_id(), a.get_public_key())
    with pytest.raises(ValueError):
        c.receive(a.send("Bob", b"for bob"))


def test_no_plaintext_hash_on_the_wire():
    a, b = pair()
    msg = b"yes"
    wire = a.send("Bob", msg).to_bytes()
    for digest in (hashlib.sha256(msg).digest(), hashlib.sha256(msg).hexdigest().encode()):
        assert digest[:8] not in wire


def test_protocol_simulator():
    p = MeteorProtocol()
    p.add_node("C"); p.add_node("D"); p.connect("C", "D")
    p.send("C", "D", b"hi D")
    assert p.receive("D") == b"hi D"


# --------------------------------------------------------------------------
# Web4
# --------------------------------------------------------------------------

def web4_pair():
    a, b = MeteorWeb4Node("Alice"), MeteorWeb4Node("Bob")
    a.add_peer("Bob", b.meteor_id, b.get_public_key())
    b.add_peer("Alice", a.meteor_id, a.get_public_key())
    return a, b


def test_web4_direct_messages():
    async def run():
        a, b = web4_pair()
        got = []

        async def h(sender, data, env):
            got.append((sender, data, env.msg_type))
        b.on_message(h)
        assert await a.send_text("Bob", "hello web4")
        assert await a.send_binary("Bob", b"\x00\x01")
        assert got == [("Alice", b"hello web4", "text"), ("Alice", b"\x00\x01", "binary")]
        # replaying the same bytes is rejected
        env = seal(a.identity._core, "text", b"x", recipient_id=b.meteor_id,
                   recipient_bundle=b.get_public_key())
        assert await b._handle_incoming(env.to_bytes())
        assert not await b._handle_incoming(env.to_bytes())
        # unknown sender is rejected
        s = MeteorWeb4Node("S"); s.add_peer("Bob", b.meteor_id, b.get_public_key())
        assert not await s.send_text("Bob", "hi")
        # signed-only "text" (unencrypted) is rejected
        plain = seal(a.identity._core, "text", b"x", recipient_id=b.meteor_id, encrypt=False)
        assert not await b._handle_incoming(plain.to_bytes())
        for n in (a, b, s):
            await n.stop()
    asyncio.run(run())


def test_web4_pubsub_is_verified():
    async def run():
        a, b = web4_pair()
        raw = await a.pubsub_publish("chat", "hello all")
        name, text, env = b.open_pubsub(raw, "chat")
        assert (name, text) == ("Alice", "hello all")
        assert b.open_pubsub(raw, "other-topic") is None
        forged = Envelope.from_bytes(raw)
        forged.payload = b"evil"
        assert b.open_pubsub(forged.to_bytes(), "chat") is None
        stranger = MeteorWeb4Node("S")
        assert b.open_pubsub(await stranger.pubsub_publish("chat", "spam"), "chat") is None
        for n in (a, b, stranger):
            await n.stop()
    asyncio.run(run())


class FakeIPFS:
    def __init__(self):
        self.store, self._connected = {}, True

    def add_bytes(self, data):
        cid = "Qm" + hashlib.sha256(data).hexdigest()[:40]
        self.store[cid] = data
        return cid

    def get_bytes(self, cid):
        return self.store.get(cid)


def test_web4_ipfs_file_transfer(tmp_path):
    async def run():
        a, b = web4_pair()
        a.ipfs = b.ipfs = FakeIPFS()
        notices = []

        async def h(sender, data, env):
            notices.append(env)
        b.on_message(h)
        f = tmp_path / "secret.bin"
        content = secrets.token_bytes(5000)
        f.write_bytes(content)
        cid = await a.send_file_ipfs("Bob", str(f))
        assert cid and len(notices) == 1
        assert b.fetch_file_ipfs(notices[0]) == ("secret.bin", content)
        # content swapped on IPFS is detected via the signed blob hash
        a.ipfs.store[cid] = a.ipfs.store[cid][:-1] + b"\x00"
        with pytest.raises(ValueError):
            b.fetch_file_ipfs(notices[0])
        assert content[:16] not in a.ipfs.store[cid]
        for n in (a, b):
            await n.stop()
    asyncio.run(run())


def test_web4_stream():
    async def run():
        a, b = web4_pair()
        chunks = []

        async def h(sender, data, env):
            chunks.append((env.msg_type, env.meta, data))
        b.on_message(h)
        data = secrets.token_bytes(10_000)
        assert await a.send_stream("Bob", iter([data[:6000], data[6000:]]), chunk_size=4096)
        body = b"".join(d for t, m, d in sorted(
            (c for c in chunks if c[0] == "stream_chunk"), key=lambda c: c[1]["seq"]))
        assert body == data and chunks[-1][0] == "stream_end"
        for n in (a, b):
            await n.stop()
    asyncio.run(run())


def test_web4_p2p_send_does_not_fake_success():
    async def run():
        a = MeteorWeb4Node("A", local_delivery=False)
        b = MeteorWeb4Node("B", local_delivery=False)
        a.add_peer("B", b.meteor_id, b.get_public_key())
        assert not await a.send_text("B", "nowhere to go")
        assert not await a.p2p.send("12D3KooSomething", b"x")
    asyncio.run(run())


def test_dht_rejects_poisoned_records():
    import base64
    victim, attacker = Web4Identity(), Web4Identity()
    assert Web4DHT._verified(victim.meteor_id, {'public_key': base64.b64encode(victim.bundle).decode()})
    assert not Web4DHT._verified(victim.meteor_id, {'public_key': base64.b64encode(attacker.bundle).decode()})


# --------------------------------------------------------------------------
# StreamDEM replay handling
# --------------------------------------------------------------------------

def test_forged_chunk_does_not_block_genuine_chunk():
    key = secrets.token_bytes(32)
    enc = StreamDEM(session_key=key, gpu=False)
    dec = StreamDEM(session_key=key, stream_id=enc.stream_id, gpu=False)
    good = enc.encrypt_chunk(b"genuine")
    forged = EncryptedChunk(header=good.header, ciphertext=b"\x00" * len(good.ciphertext), tag=good.tag)
    with pytest.raises(Exception):
        dec.decrypt_chunk(forged)
    assert dec.decrypt_chunk(good) == b"genuine"
    with pytest.raises(ValueError):
        dec.decrypt_chunk(good)                                  # real replay still caught


# --------------------------------------------------------------------------
# concurrency
# --------------------------------------------------------------------------

def _race(fn, n):
    import threading
    barrier = threading.Barrier(n)
    results = [None] * n

    def worker(i):
        barrier.wait()
        try:
            results[i] = ("ok", fn())
        except Exception as e:  # noqa: BLE001
            results[i] = ("err", str(e))
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_concurrent_duplicate_delivery_is_accepted_once():
    a, b = pair()
    for _ in range(3):
        env = a.send("Bob", b"exactly once")
        res = _race(lambda: b.receive(env), 16)
        assert sum(r[0] == "ok" for r in res) == 1
        assert all("replay" in r[1] for r in res if r[0] == "err")


def test_concurrent_distinct_messages_all_accepted():
    a, b = pair()
    envs = [a.send("Bob", f"m{i}".encode()) for i in range(16)]
    it = iter(envs)
    import threading
    lock = threading.Lock()

    def take():
        with lock:
            e = next(it)
        return b.receive(e)
    res = _race(take, 16)
    assert sorted(r[1] for r in res) == sorted(f"m{i}".encode() for i in range(16))
    assert b.stats['messages_received'] == 16


def test_failed_decryption_releases_the_reservation():
    """A tampered copy that fails after the signature check must not burn the
    message id (the genuine copy is still accepted)."""
    from meteor_nc.protocols.envelope import ReplayGuard
    g = ReplayGuard()
    k = g.reserve(b"s", b"i", int(time.time() * 1000))
    with pytest.raises(EnvelopeError):
        g.reserve(b"s", b"i", int(time.time() * 1000))
    g.release(k)
    k = g.reserve(b"s", b"i", int(time.time() * 1000))
    g.confirm(k)
    with pytest.raises(EnvelopeError):
        g.reserve(b"s", b"i", int(time.time() * 1000))
