# meteor_nc/protocols/meteor_protocol.py
"""
Meteor-Protocol: post-quantum P2P messaging (v3).

Built on the v3 envelope (protocols/envelope.py):
- self-certifying identity: MeteorID = H(public bundle), seed stays secret
- confidentiality: v3 LWEKEM (FrodoKEM) + ChaCha20-Poly1305, header as AAD
- sender authentication: Ed25519 signature over header and ciphertext
- replay protection: time window + (sender, message id) cache

Messages from senders that are not in the peer directory are rejected,
because their signature cannot be checked.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from .envelope import (
    Envelope,
    EnvelopeError,
    MeteorIdentity,
    ReplayGuard,
    check_peer,
    open_envelope,
    seal,
)

logger = logging.getLogger("meteor-protocol")

MeteorMessage = Envelope          # v3 wire message (to_bytes / from_bytes)


@dataclass
class MeteorPeer:
    """Peer in Meteor-Protocol network."""
    name: str
    meteor_id: bytes          # 32-byte identity = H(public bundle)
    public_key: bytes         # public bundle (KEM key + signing key)
    last_seen: Optional[float] = None

    def __post_init__(self):
        if len(self.meteor_id) != 32:
            raise ValueError("MeteorID must be exactly 32 bytes")
        check_peer(self.meteor_id, self.public_key)


class MeteorNode:
    """
    A node in the Meteor-Protocol network.

    Key generation:
    - seed=None: random identity
    - seed=bytes (>= 16 bytes, kept secret): deterministic identity, e.g. to
      log in again with the same MeteorID

    Example:
        >>> alice, bob = MeteorNode("Alice"), MeteorNode("Bob")
        >>> alice.add_peer("Bob", bob.get_meteor_id(), bob.get_public_key())
        >>> bob.add_peer("Alice", alice.get_meteor_id(), alice.get_public_key())
        >>> msg = alice.send("Bob", b"Hello Bob!")
        >>> bob.receive(msg)
        b'Hello Bob!'
    """

    def __init__(
        self,
        name: str = "Node",
        seed: Optional[bytes] = None,
        gpu: bool = False,                 # accepted for compatibility; CPU only
        device_id: int = 0,
        replay_window_s: float = 300.0,
    ):
        self.name = name
        self.gpu = False
        self.device_id = device_id
        self.identity = MeteorIdentity(seed if seed is not None else secrets.token_bytes(32))
        self.meteor_id = self.identity.meteor_id
        self.peers: Dict[str, MeteorPeer] = {}
        self._by_id: Dict[bytes, str] = {}
        self._guard = ReplayGuard(replay_window_s)
        self._lock = threading.Lock()          # stats / inbox under concurrent receive
        self.inbox: List[MeteorMessage] = []
        self.outbox: List[MeteorMessage] = []
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'messages_rejected': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'encryption_time': 0.0,
            'decryption_time': 0.0,
        }

    def get_meteor_id(self) -> bytes:
        """32-byte MeteorID (public)."""
        return self.meteor_id

    def get_public_key(self) -> bytes:
        """Public bundle to share with peers (KEM public key + signing key)."""
        return self.identity.bundle

    def add_peer(self, name: str, meteor_id: bytes, public_key: bytes):
        """Add a peer. Raises ValueError if the bundle does not match the MeteorID."""
        try:
            peer = MeteorPeer(name=name, meteor_id=meteor_id, public_key=public_key)
        except EnvelopeError as e:
            raise ValueError(f"cannot add peer {name!r}: {e}") from None
        if name in self.peers:
            self.remove_peer(name)
        with self._lock:
            self.peers[name] = peer
            self._by_id[meteor_id] = name
        logger.info("[%s] added peer %s (%s...)", self.name, name, meteor_id.hex()[:16])

    def get_peer(self, name: str) -> Optional[MeteorPeer]:
        return self.peers.get(name)

    def remove_peer(self, name: str) -> bool:
        """Forget a peer; its messages are rejected afterwards."""
        with self._lock:
            peer = self.peers.pop(name, None)
            if peer is None:
                return False
            if self._by_id.get(peer.meteor_id) == name:
                del self._by_id[peer.meteor_id]
                for other, p in self.peers.items():       # another name for the same ID
                    if p.meteor_id == peer.meteor_id:
                        self._by_id[peer.meteor_id] = other
                        break
            return True

    def send(self, peer_name: str, plaintext: bytes) -> MeteorMessage:
        """Encrypt and sign ``plaintext`` for a known peer."""
        peer = self.get_peer(peer_name)
        if peer is None:
            raise ValueError(f"Unknown peer: {peer_name}")
        start = time.time()
        message = seal(self.identity, "data", plaintext, recipient_id=peer.meteor_id,
                       recipient_bundle=peer.public_key)
        dt = time.time() - start
        self.stats['messages_sent'] += 1
        self.stats['bytes_sent'] += len(plaintext)
        self.stats['encryption_time'] += dt
        self.outbox.append(message)
        peer.last_seen = time.time()
        logger.info("[%s] -> [%s]: %d bytes (%.1f ms)", self.name, peer_name, len(plaintext), dt * 1e3)
        return message

    def receive(self, message: MeteorMessage) -> bytes:
        """Authenticate and decrypt a message. Raises ValueError if rejected."""
        if isinstance(message, (bytes, bytearray)):
            message = Envelope.from_bytes(bytes(message))
        start = time.time()
        sender_name = self._by_id.get(message.sender_id)
        try:
            if sender_name is None:
                raise EnvelopeError("unknown sender")
            if not message.encrypted:
                raise EnvelopeError("expected an encrypted message")
            plaintext = open_envelope(self.identity, message,
                                      self.peers[sender_name].public_key, self._guard)
        except EnvelopeError as e:
            with self._lock:
                self.stats['messages_rejected'] += 1
            raise ValueError(f"message rejected: {e}") from None
        dt = time.time() - start
        with self._lock:
            self.stats['messages_received'] += 1
            self.stats['bytes_received'] += len(plaintext)
            self.stats['decryption_time'] += dt
            self.inbox.append(message)
            self.peers[sender_name].last_seen = message.timestamp
        logger.info("[%s] <- [%s]: %d bytes (%.1f ms)", self.name, sender_name, len(plaintext), dt * 1e3)
        return plaintext

    def sender_name(self, message: MeteorMessage) -> Optional[str]:
        """Directory name of the (authenticated) sender of a received message."""
        return self._by_id.get(message.sender_id)

    def get_stats(self) -> Dict:
        return {
            'name': self.name,
            'meteor_id': self.meteor_id.hex(),
            'peers': len(self.peers),
            **self.stats,
            'avg_encrypt_ms': (self.stats['encryption_time'] / max(1, self.stats['messages_sent'])) * 1000,
            'avg_decrypt_ms': (self.stats['decryption_time'] / max(1, self.stats['messages_received'])) * 1000,
        }


class MeteorProtocol:
    """
    In-memory network simulator.

    Example:
        >>> protocol = MeteorProtocol()
        >>> protocol.add_node("Alice"); protocol.add_node("Bob")
        >>> protocol.connect("Alice", "Bob")
        >>> protocol.send("Alice", "Bob", b"Hello!")
        >>> protocol.receive("Bob")
        b'Hello!'
    """

    def __init__(self):
        self.nodes: Dict[str, MeteorNode] = {}
        self.message_pool: List[MeteorMessage] = []

    def add_node(self, name: str, gpu: bool = False) -> MeteorNode:
        node = MeteorNode(name=name, gpu=gpu)
        self.nodes[name] = node
        return node

    def connect(self, node1: str, node2: str):
        n1, n2 = self.nodes.get(node1), self.nodes.get(node2)
        if n1 is None or n2 is None:
            raise ValueError("Node not found")
        n1.add_peer(node2, n2.get_meteor_id(), n2.get_public_key())
        n2.add_peer(node1, n1.get_meteor_id(), n1.get_public_key())

    def send(self, sender: str, recipient: str, message: bytes):
        sender_node = self.nodes.get(sender)
        if sender_node is None:
            raise ValueError(f"Sender '{sender}' not found")
        self.message_pool.append(sender_node.send(recipient, message))

    def receive(self, recipient: str) -> Optional[bytes]:
        recipient_node = self.nodes.get(recipient)
        if recipient_node is None:
            raise ValueError(f"Recipient '{recipient}' not found")
        for i, message in enumerate(self.message_pool):
            if message.recipient_id == recipient_node.meteor_id:
                self.message_pool.pop(i)
                return recipient_node.receive(message)
        return None

    def get_stats(self) -> Dict:
        return {
            'nodes': len(self.nodes),
            'messages_in_pool': len(self.message_pool),
            'node_stats': {n: node.get_stats() for n, node in self.nodes.items()},
        }


def run_tests() -> bool:
    """Quick self-check (the full suite is tests/test_protocols.py)."""
    alice, bob = MeteorNode("Alice"), MeteorNode("Bob")
    alice.add_peer("Bob", bob.get_meteor_id(), bob.get_public_key())
    bob.add_peer("Alice", alice.get_meteor_id(), alice.get_public_key())
    ok = bob.receive(alice.send("Bob", b"Hello Bob!")) == b"Hello Bob!"
    ok &= alice.receive(bob.send("Alice", b"Hello Alice!")) == b"Hello Alice!"
    s = secrets.token_bytes(32)
    ok &= MeteorNode("A1", seed=s).get_meteor_id() == MeteorNode("A2", seed=s).get_meteor_id()
    print("Meteor-Protocol self-check:", "PASS" if ok else "FAIL")
    return bool(ok)


if __name__ == "__main__":
    run_tests()
