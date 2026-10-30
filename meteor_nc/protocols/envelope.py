"""
Meteor-NC v3 protocol core: self-certifying identities and sealed envelopes.

Shared by ``meteor_protocol.MeteorNode`` and ``web4.MeteorWeb4Node``.

Identity
--------
A node has one *secret* seed. It is never published. From it we derive

* a KEM key pair (v3 LWEKEM / FrodoKEM) for confidentiality, and
* an Ed25519 key pair for sender authentication,

and publish a *bundle* holding both public keys. The node's MeteorID is

    MeteorID = SHA256("meteor-nc-v3-id" || bundle)

so anyone holding (MeteorID, bundle) can check that they belong together,
and nothing secret can be derived from the MeteorID. (In v2 the published
identifier was the seed itself; see SECURITY.md.)

Envelope
--------
Every message carries a header (version, type, sender, recipient, time,
random message id, hash of the KEM ciphertext, metadata). For encrypted
messages the payload is ChaCha20-Poly1305 under a key derived from a fresh
KEM shared secret, with the whole header as associated data. Every envelope
is signed (Ed25519) over the header and the ciphertext, and opening one

1. checks the sender's MeteorID against the sender bundle the caller holds,
2. verifies the signature,
3. rejects stale timestamps and replays (ReplayGuard),
4. decrypts.

Ed25519 is not post-quantum. For authentication that is acceptable today
(a signature only has to resist forgery when it is verified; recorded
traffic does not become forgeable later), and the bundle format carries an
algorithm id so ML-DSA can be added without changing the envelope.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..cryptography.core import LWEKEM

ID_DOMAIN = b"meteor-nc-v3-id"
BUNDLE_MAGIC = b"MNCB"
ENVELOPE_MAGIC = b"MNCE"
VERSION = 1
SIG_ED25519 = 1
BROADCAST_ID = b"\x00" * 32
DEFAULT_WINDOW_S = 300.0


class EnvelopeError(ValueError):
    """An envelope failed to parse, authenticate, or decrypt."""


def _h(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _lp(b: bytes) -> bytes:
    """Length-prefixed (u32 big-endian)."""
    return struct.pack(">I", len(b)) + b


# ---------------------------------------------------------------------------
# Bundles and identities
# ---------------------------------------------------------------------------

def make_bundle(kem_public: bytes, sign_public: bytes) -> bytes:
    return (BUNDLE_MAGIC + bytes([VERSION]) + _lp(kem_public)
            + bytes([SIG_ED25519]) + _lp(sign_public))


def parse_bundle(bundle: bytes) -> Tuple[bytes, bytes]:
    """Return (kem_public, sign_public); raise EnvelopeError if malformed."""
    try:
        if bundle[:4] != BUNDLE_MAGIC or bundle[4] != VERSION:
            raise EnvelopeError("not a v3 public bundle")
        o = 5
        (n,) = struct.unpack(">I", bundle[o:o + 4]); o += 4
        kem_pk = bundle[o:o + n]; o += n
        if bundle[o] != SIG_ED25519:
            raise EnvelopeError("unsupported signature algorithm")
        o += 1
        (m,) = struct.unpack(">I", bundle[o:o + 4]); o += 4
        sign_pk = bundle[o:o + m]; o += m
    except (IndexError, struct.error):
        raise EnvelopeError("truncated public bundle") from None
    if o != len(bundle) or len(kem_pk) != n or len(sign_pk) != 32:
        raise EnvelopeError("malformed public bundle")
    return kem_pk, sign_pk


def meteor_id_of(bundle: bytes) -> bytes:
    return _h(ID_DOMAIN, bundle)


def check_peer(meteor_id: bytes, bundle: bytes) -> None:
    """Raise EnvelopeError unless ``bundle`` belongs to ``meteor_id``."""
    parse_bundle(bundle)
    if len(meteor_id) != 32 or meteor_id_of(bundle) != meteor_id:
        raise EnvelopeError("MeteorID does not match the public bundle")


class MeteorIdentity:
    """Secret seed -> KEM keys + Ed25519 keys -> public bundle -> MeteorID."""

    def __init__(self, seed: Optional[bytes] = None, kem_n: int = 256):
        if seed is None:
            seed = secrets.token_bytes(32)
        if not isinstance(seed, (bytes, bytearray)) or len(seed) < 16:
            raise ValueError("seed must be at least 16 bytes")
        seed = bytes(seed)
        self._kem = LWEKEM(n=kem_n, seed=_h(b"meteor-nc-v3/kem-seed", seed))
        self.kem_public, _ = self._kem.key_gen()
        self._sign = Ed25519PrivateKey.from_private_bytes(_h(b"meteor-nc-v3/ed25519", seed))
        self.sign_public = self._sign.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.bundle = make_bundle(self.kem_public, self.sign_public)
        self.meteor_id = meteor_id_of(self.bundle)

    def sign(self, data: bytes) -> bytes:
        return self._sign.sign(data)

    def decaps(self, kem_wire: bytes) -> bytes:
        return self._kem.decaps(kem_wire)


def verify_signature(sign_public: bytes, signature: bytes, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(sign_public).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

class ReplayGuard:
    """Rejects envelopes outside a time window and (sender, id) repeats."""

    def __init__(self, window_s: float = DEFAULT_WINDOW_S):
        self.window_s = float(window_s)
        self._seen: Dict[Tuple[bytes, bytes], float] = {}

    def check(self, sender_id: bytes, message_id: bytes, timestamp_ms: int,
              now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        if abs(now - timestamp_ms / 1000.0) > self.window_s:
            raise EnvelopeError("timestamp outside the accepted window")
        if (sender_id, message_id) in self._seen:
            raise EnvelopeError("replayed message")

    def record(self, sender_id: bytes, message_id: bytes, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        self._seen[(sender_id, message_id)] = now + 2 * self.window_s
        if len(self._seen) > 4096:
            self._seen = {k: v for k, v in self._seen.items() if v > now}


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------

@dataclass
class Envelope:
    msg_type: str
    sender_id: bytes
    recipient_id: bytes
    timestamp_ms: int
    message_id: bytes
    kem_wire: bytes = b""
    payload: bytes = b""             # ciphertext (encrypted) or plaintext (signed-only)
    tag: bytes = b""                 # AEAD tag; empty for signed-only
    meta: Dict = field(default_factory=dict)
    signature: bytes = b""

    @property
    def encrypted(self) -> bool:
        return bool(self.kem_wire)

    @property
    def timestamp(self) -> float:
        return self.timestamp_ms / 1000.0

    def header(self) -> bytes:
        meta = json.dumps(self.meta, sort_keys=True, separators=(",", ":")).encode()
        return (ENVELOPE_MAGIC + bytes([VERSION, 1 if self.encrypted else 0])
                + _lp(self.msg_type.encode()) + self.sender_id + self.recipient_id
                + struct.pack(">Q", self.timestamp_ms) + self.message_id
                + _h(self.kem_wire) + _lp(meta))

    def signed_data(self) -> bytes:
        return b"meteor-nc-v3-sig" + self.header() + _h(self.payload, self.tag)

    def to_bytes(self) -> bytes:
        return (self.header() + _lp(self.kem_wire) + _lp(self.payload)
                + _lp(self.tag) + _lp(self.signature))

    @classmethod
    def from_bytes(cls, data: bytes) -> "Envelope":
        try:
            if data[:4] != ENVELOPE_MAGIC or data[4] != VERSION:
                raise EnvelopeError("not a v3 envelope")
            enc = data[5]
            o = 6

            def lp():
                nonlocal o
                (n,) = struct.unpack(">I", data[o:o + 4])
                v = data[o + 4:o + 4 + n]
                if len(v) != n:
                    raise EnvelopeError("truncated envelope")
                o += 4 + n
                return v

            msg_type = lp().decode()
            sender, recipient = data[o:o + 32], data[o + 32:o + 64]; o += 64
            (ts,) = struct.unpack(">Q", data[o:o + 8]); o += 8
            mid = data[o:o + 16]; o += 16
            kem_hash = data[o:o + 32]; o += 32
            meta = json.loads(lp().decode())
            env = cls(msg_type=msg_type, sender_id=sender, recipient_id=recipient,
                      timestamp_ms=ts, message_id=mid, meta=meta)
            env.kem_wire, env.payload, env.tag, env.signature = lp(), lp(), lp(), lp()
        except EnvelopeError:
            raise
        except Exception:
            raise EnvelopeError("malformed envelope") from None
        if (o != len(data) or len(sender) != 32 or len(recipient) != 32 or len(mid) != 16
                or _h(env.kem_wire) != kem_hash or enc != (1 if env.kem_wire else 0)
                or not isinstance(meta, dict)):
            raise EnvelopeError("malformed envelope")
        return env


def _message_key(K: bytes) -> bytes:
    return _h(b"meteor-nc-v3/message-key", K)


def seal(identity: MeteorIdentity, msg_type: str, payload: bytes,
         recipient_id: bytes = BROADCAST_ID, recipient_bundle: Optional[bytes] = None,
         meta: Optional[Dict] = None, encrypt: bool = True) -> Envelope:
    """Build and sign an envelope. With ``encrypt`` the payload is encrypted
    to ``recipient_bundle`` (whose MeteorID must equal ``recipient_id``)."""
    env = Envelope(msg_type=msg_type, sender_id=identity.meteor_id, recipient_id=recipient_id,
                   timestamp_ms=int(time.time() * 1000), message_id=secrets.token_bytes(16),
                   meta=dict(meta or {}))
    if encrypt:
        if recipient_bundle is None:
            raise ValueError("encrypted envelopes need the recipient bundle")
        check_peer(recipient_id, recipient_bundle)
        kem_pk, _ = parse_bundle(recipient_bundle)
        kem = LWEKEM(n=256)
        kem.load_public_key(kem_pk)
        K, env.kem_wire = kem.encaps()
        ct = ChaCha20Poly1305(_message_key(K)).encrypt(env.message_id[:12], payload, env.header())
        env.payload, env.tag = ct[:-16], ct[-16:]
    else:
        env.payload = payload
    env.signature = identity.sign(env.signed_data())
    return env


def open_envelope(identity: MeteorIdentity, env: Envelope, sender_bundle: bytes,
                  guard: Optional[ReplayGuard] = None, now: Optional[float] = None) -> bytes:
    """Authenticate (and decrypt) an envelope from the holder of ``sender_bundle``."""
    check_peer(env.sender_id, sender_bundle)
    _, sign_pk = parse_bundle(sender_bundle)
    if not verify_signature(sign_pk, env.signature, env.signed_data()):
        raise EnvelopeError("bad signature")
    if env.encrypted:
        if env.recipient_id != identity.meteor_id:
            raise EnvelopeError("not addressed to this node")
    elif env.recipient_id not in (identity.meteor_id, BROADCAST_ID):
        raise EnvelopeError("not addressed to this node")
    if guard is not None:
        guard.check(env.sender_id, env.message_id, env.timestamp_ms, now)
    if env.encrypted:
        if len(env.tag) != 16:
            raise EnvelopeError("bad tag length")
        K = identity.decaps(env.kem_wire)
        try:
            payload = ChaCha20Poly1305(_message_key(K)).decrypt(
                env.message_id[:12], env.payload + env.tag, env.header())
        except InvalidTag:
            raise EnvelopeError("decryption failed") from None
    else:
        payload = env.payload
    if guard is not None:
        guard.record(env.sender_id, env.message_id, now)
    return payload


__all__ = ["MeteorIdentity", "Envelope", "EnvelopeError", "ReplayGuard", "seal",
           "open_envelope", "make_bundle", "parse_bundle", "meteor_id_of", "check_peer",
           "verify_signature", "BROADCAST_ID"]
