"""
Tests for meteor_nc.auth (v3): device secret storage, biometric gate,
and the challenge-response server.
"""
import logging
import os
import stat
import threading

import pytest

from meteor_nc.auth.core import (
    BiometricFailedError, BiometricRequiredError, BiometricStatus, FileDeviceKeyStore,
    MemoryDeviceKeyStore, MeteorAuth, MeteorAuthError, MeteorAuthServer,
    MockBiometricProvider, answer_challenge, verify_device_binding,
)
from meteor_nc.protocols.meteor_protocol import MeteorNode

logging.disable(logging.WARNING)


# --------------------------------------------------------------------------
# device binding
# --------------------------------------------------------------------------

def test_identity_depends_on_seed_and_device_secret():
    seed = os.urandom(32)
    dev_a, dev_b = MemoryDeviceKeyStore(), MemoryDeviceKeyStore()
    id_a = MeteorAuth(device_store=dev_a).get_meteor_id(seed)
    assert MeteorAuth(device_store=dev_a).get_meteor_id(seed) == id_a
    assert MeteorAuth(device_store=dev_b).get_meteor_id(seed) != id_a
    assert MeteorAuth(device_store=dev_a).get_meteor_id(os.urandom(32)) != id_a


def test_login_matches_get_meteor_id_and_verify_binding():
    store = MemoryDeviceKeyStore()
    auth = MeteorAuth(device_store=store)
    seed = auth.generate_seed()
    node = auth.login(seed, "client")
    assert node.get_meteor_id() == auth.get_meteor_id(seed)
    assert verify_device_binding(seed, node.get_meteor_id(), device_store=store)
    assert not verify_device_binding(seed, node.get_meteor_id(), device_store=MemoryDeviceKeyStore())


def test_device_fingerprint_is_stable_and_not_the_secret():
    store = MemoryDeviceKeyStore()
    auth = MeteorAuth(device_store=store)
    fp = auth.get_device_fingerprint()
    assert fp == MeteorAuth(device_store=store).get_device_fingerprint()
    assert fp != store.load_or_create()


def test_file_store_persists_with_owner_only_permissions(tmp_path):
    path = tmp_path / "sub" / "device_key"
    s1 = FileDeviceKeyStore(str(path))
    secret = s1.load_or_create()
    assert FileDeviceKeyStore(str(path)).load_or_create() == secret
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        os.chmod(path, 0o644)
        with pytest.raises(MeteorAuthError):
            FileDeviceKeyStore(str(path)).load_or_create()
        os.chmod(path, 0o600)
    path.write_bytes(b"short")
    with pytest.raises(MeteorAuthError):
        FileDeviceKeyStore(str(path)).load_or_create()


def test_file_store_concurrent_creation_yields_one_secret(tmp_path):
    path = str(tmp_path / "device_key")
    out, barrier = [], threading.Barrier(8)

    def worker():
        barrier.wait()
        out.append(FileDeviceKeyStore(path).load_or_create())
    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(set(out)) == 1


# --------------------------------------------------------------------------
# biometric gate
# --------------------------------------------------------------------------

def test_biometric_gate_blocks_key_derivation():
    seed = os.urandom(32)
    store = MemoryDeviceKeyStore()
    failing = MeteorAuth(require_biometric=True, device_store=store,
                         biometric_provider=MockBiometricProvider(BiometricStatus.FAILED))
    with pytest.raises(BiometricFailedError):
        failing.login(seed)
    with pytest.raises(BiometricFailedError):
        failing.get_meteor_id(seed)
    with pytest.raises(BiometricFailedError):
        failing.create_device_bound_seed(seed)
    unavailable = MeteorAuth(require_biometric=True, device_store=store,
                             biometric_provider=MockBiometricProvider(available=False))
    with pytest.raises(BiometricRequiredError):
        unavailable.login(seed)
    no_provider = MeteorAuth(require_biometric=True, device_store=store)
    with pytest.raises(BiometricRequiredError):
        no_provider.login(seed)
    ok = MeteorAuth(require_biometric=True, device_store=store,
                    biometric_provider=MockBiometricProvider(BiometricStatus.SUCCESS))
    assert ok.login(seed).get_meteor_id() == MeteorAuth(device_store=store).get_meteor_id(seed)


def test_skip_biometric_flag_is_gone():
    auth = MeteorAuth(require_biometric=True, device_store=MemoryDeviceKeyStore(),
                      biometric_provider=MockBiometricProvider(BiometricStatus.FAILED))
    with pytest.raises(TypeError):
        auth.login(os.urandom(32), skip_biometric=True)


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------

def _client(server, name):
    node = MeteorAuth(device_store=MemoryDeviceKeyStore()).login(os.urandom(32), name)
    node.add_peer("Server", server.get_server_id(), server.get_server_public_key())
    return node, server.register(node.get_meteor_id(), node.get_public_key(), {"user": name})


def test_challenge_response_success():
    server = MeteorAuthServer()
    alice, token = _client(server, "alice")
    ch = server.create_challenge(token)
    assert server.authenticate(token, answer_challenge(alice, "Server", ch))
    assert server.get_user(token).last_auth is not None


def test_response_must_come_from_the_tokens_owner():
    server = MeteorAuthServer()
    alice, token_a = _client(server, "alice")
    bob, _ = _client(server, "bob")
    ch = server.create_challenge(token_a)
    assert not server.authenticate(token_a, answer_challenge(bob, "Server", ch))


def test_challenges_are_single_use_and_expire():
    server = MeteorAuthServer(challenge_ttl_s=60)
    alice, token = _client(server, "alice")
    ch = server.create_challenge(token)
    assert not server.authenticate(token, answer_challenge(alice, "Server", b"wrong"))
    assert not server.authenticate(token, answer_challenge(alice, "Server", ch))   # consumed
    ch = server.create_challenge(token)
    msg = answer_challenge(alice, "Server", ch)
    assert server.authenticate(token, msg)
    server.challenges[token] = (ch, 0.0)                                             # stale
    assert not server.authenticate(token, answer_challenge(alice, "Server", ch))
    expired = MeteorAuthServer(challenge_ttl_s=-1)
    a2, t2 = _client(expired, "a2")
    assert not expired.authenticate(t2, answer_challenge(a2, "Server", expired.create_challenge(t2)))


def test_replayed_response_is_rejected():
    server = MeteorAuthServer()
    alice, token = _client(server, "alice")
    ch = server.create_challenge(token)
    msg = answer_challenge(alice, "Server", ch)
    assert server.authenticate(token, msg)
    server.challenges[token] = (ch, 1e18)
    assert not server.authenticate(token, msg)


def test_revoke_really_removes_the_user():
    server = MeteorAuthServer()
    alice, token = _client(server, "alice")
    msg = alice.send("Server", b"before revoke")
    assert server.revoke(token)
    assert server.get_user(token) is None
    with pytest.raises(ValueError):
        server.create_challenge(token)
    with pytest.raises(ValueError, match="unknown sender"):
        server.node.receive(msg)
    assert not server.revoke(token)


def test_register_rejects_mismatched_bundle():
    server = MeteorAuthServer()
    a, b = MeteorNode("a"), MeteorNode("b")
    with pytest.raises(ValueError):
        server.register(a.get_meteor_id(), b.get_public_key())
