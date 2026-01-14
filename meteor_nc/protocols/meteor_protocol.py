# meteor_nc/protocols/meteor_protocol.py
"""
Meteor-Protocol: Quantum-Resistant P2P Communication Protocol

Built on Meteor-NC v2 cryptography:
- LWE-KEM for key encapsulation (Post-Quantum)
- XChaCha20-Poly1305 for data encryption
- 32-byte identity (DHT/IPFS/libp2p compatible)
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np

from ..cryptography.common import GPU_AVAILABLE, _sha256
from ..cryptography.core import LWEKEM, LWEPublicKey, LWESecretKey, LWECiphertext
from ..cryptography.stream import StreamDEM, EncryptedChunk, StreamHeader


@dataclass
class MeteorPeer:
    """Peer in Meteor-Protocol network."""
    name: str
    meteor_id: bytes          # 32-byte identity
    public_key: Optional[LWEPublicKey] = None
    last_seen: Optional[float] = None
    
    def __post_init__(self):
        if len(self.meteor_id) != 32:
            raise ValueError("MeteorID must be exactly 32 bytes")


@dataclass
class MeteorMessage:
    """Encrypted message in Meteor-Protocol."""
    sender_id: bytes          # 32 bytes
    recipient_id: bytes       # 32 bytes
    kem_ciphertext: dict      # LWE ciphertext (u, v)
    encrypted_payload: bytes  # XChaCha20-Poly1305 ciphertext
    tag: bytes                # 16-byte auth tag
    nonce: bytes              # 24-byte nonce
    timestamp: float
    
    def to_bytes(self) -> bytes:
        """Serialize for transmission."""
        return json.dumps({
            'sender_id': self.sender_id.hex(),
            'recipient_id': self.recipient_id.hex(),
            'kem_u': self.kem_ciphertext['u'].tolist(),
            'kem_v': self.kem_ciphertext['v'].tolist(),
            'payload': self.encrypted_payload.hex(),
            'tag': self.tag.hex(),
            'nonce': self.nonce.hex(),
            'timestamp': self.timestamp,
        }).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'MeteorMessage':
        """Deserialize from transmission."""
        obj = json.loads(data.decode('utf-8'))
        return cls(
            sender_id=bytes.fromhex(obj['sender_id']),
            recipient_id=bytes.fromhex(obj['recipient_id']),
            kem_ciphertext={
                'u': np.array(obj['kem_u'], dtype=np.int64),
                'v': np.array(obj['kem_v'], dtype=np.int64),
            },
            encrypted_payload=bytes.fromhex(obj['payload']),
            tag=bytes.fromhex(obj['tag']),
            nonce=bytes.fromhex(obj['nonce']),
            timestamp=obj['timestamp'],
        )


class MeteorNode:
    """
    A node in the Meteor-Protocol network.
    
    Features:
    - 32-byte MeteorID (DHT/IPFS compatible)
    - Post-Quantum key encapsulation (LWE-KEM)
    - Authenticated encryption (XChaCha20-Poly1305)
    - No session state required
    
    Example:
        >>> alice = MeteorNode("Alice")
        >>> bob = MeteorNode("Bob")
        >>> 
        >>> # Exchange IDs (32 bytes each)
        >>> alice.add_peer("Bob", bob.get_meteor_id(), bob.get_public_key())
        >>> bob.add_peer("Alice", alice.get_meteor_id(), alice.get_public_key())
        >>> 
        >>> # Send encrypted message
        >>> msg = alice.send("Bob", b"Hello Bob!")
        >>> plaintext = bob.receive(msg)
    """
    
    def __init__(
        self,
        name: str = "Node",
        seed: Optional[bytes] = None,
        gpu: bool = True,
        device_id: int = 0,
    ):
        self.name = name
        self.gpu = gpu and GPU_AVAILABLE
        self.device_id = device_id
        
        # Master seed (32 bytes)
        self.seed = seed or secrets.token_bytes(32)
        
        # Derive MeteorID from seed
        self.meteor_id = _sha256(b"meteor-id", self.seed)
        
        # Initialize KEM
        self._kem = LWEKEM(
            n=256,
            gpu=self.gpu,
            device_id=device_id,
            seed=self.seed,
        )
        self._kem.key_gen()
        
        # Peer directory
        self.peers: Dict[str, MeteorPeer] = {}
        
        # Message queues
        self.inbox: List[MeteorMessage] = []
        self.outbox: List[MeteorMessage] = []
        
        # Statistics
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'encryption_time': 0.0,
            'decryption_time': 0.0,
        }
    
    def get_meteor_id(self) -> bytes:
        """Get 32-byte MeteorID (for DHT/sharing)."""
        return self.meteor_id
    
    def get_public_key(self) -> LWEPublicKey:
        """Get public key for peer registration."""
        return self._kem.pk
    
    def add_peer(
        self,
        name: str,
        meteor_id: bytes,
        public_key: LWEPublicKey,
    ):
        """Add peer to directory."""
        peer = MeteorPeer(
            name=name,
            meteor_id=meteor_id,
            public_key=public_key,
        )
        self.peers[name] = peer
        print(f"[{self.name}] Added peer: {name} ({meteor_id.hex()[:16]}...)")
    
    def get_peer(self, name: str) -> Optional[MeteorPeer]:
        """Get peer by name."""
        return self.peers.get(name)
    
    def send(self, peer_name: str, plaintext: bytes) -> MeteorMessage:
        """
        Send encrypted message to peer.
        
        Uses hybrid encryption:
        1. KEM encapsulation → shared secret K
        2. Derive session key from K
        3. XChaCha20-Poly1305 encrypt payload
        """
        peer = self.get_peer(peer_name)
        if peer is None:
            raise ValueError(f"Unknown peer: {peer_name}")
        if peer.public_key is None:
            raise ValueError(f"No public key for peer: {peer_name}")
        
        start = time.time()
        
        # 1. KEM encapsulation with peer's public key
        peer_kem = LWEKEM(n=256, gpu=self.gpu, device_id=self.device_id)
        peer_kem.pk = peer.public_key
        peer_kem.delta = peer_kem.q // 2
        
        K, kem_ct = peer_kem.encaps()
        
        # 2. Create StreamDEM with derived key
        session_key = _sha256(b"session", K)
        nonce = secrets.token_bytes(24)
        
        # 3. Encrypt payload
        stream = StreamDEM(
            session_key=session_key,
            stream_id=nonce[:16],
            gpu=self.gpu,
            device_id=self.device_id,
        )
        
        chunk = stream.encrypt_chunk(plaintext)
        
        encrypt_time = time.time() - start
        
        # Create message
        message = MeteorMessage(
            sender_id=self.meteor_id,
            recipient_id=peer.meteor_id,
            kem_ciphertext={'u': kem_ct.u, 'v': kem_ct.v},
            encrypted_payload=chunk.ciphertext,
            tag=chunk.tag,
            nonce=nonce,
            timestamp=time.time(),
        )
        
        # Update stats
        self.stats['messages_sent'] += 1
        self.stats['bytes_sent'] += len(plaintext)
        self.stats['encryption_time'] += encrypt_time
        
        self.outbox.append(message)
        peer.last_seen = time.time()
        
        print(f"[{self.name}] → [{peer_name}]: {len(plaintext)} bytes ({encrypt_time*1000:.1f}ms)")
        
        return message
    
    def receive(self, message: MeteorMessage) -> bytes:
        """
        Receive and decrypt message.
        
        Uses hybrid decryption:
        1. KEM decapsulation → shared secret K
        2. Derive session key from K
        3. XChaCha20-Poly1305 decrypt payload
        """
        # Verify recipient
        if message.recipient_id != self.meteor_id:
            raise ValueError("Message not for this node")
        
        start = time.time()
        
        # 1. KEM decapsulation
        kem_ct = LWECiphertext(
            u=message.kem_ciphertext['u'],
            v=message.kem_ciphertext['v'],
        )
        K = self._kem.decaps(kem_ct)
        
        # 2. Derive session key
        session_key = _sha256(b"session", K)
        
        # 3. Decrypt payload
        stream = StreamDEM(
            session_key=session_key,
            stream_id=message.nonce[:16],
            gpu=self.gpu,
            device_id=self.device_id,
        )
        
        # Reconstruct chunk
        header = StreamHeader(
            stream_id=message.nonce[:16],
            seq=0,
            chunk_len=len(message.encrypted_payload),
            flags=0,
        )
        chunk = EncryptedChunk(
            header=header,
            ciphertext=message.encrypted_payload,
            tag=message.tag,
        )
        
        plaintext = stream.decrypt_chunk(chunk)
        
        decrypt_time = time.time() - start
        
        # Update stats
        self.stats['messages_received'] += 1
        self.stats['bytes_received'] += len(plaintext)
        self.stats['decryption_time'] += decrypt_time
        
        self.inbox.append(message)
        
        # Find sender
        sender_name = "Unknown"
        for name, peer in self.peers.items():
            if peer.meteor_id == message.sender_id:
                sender_name = name
                peer.last_seen = message.timestamp
                break
        
        print(f"[{self.name}] ← [{sender_name}]: {len(plaintext)} bytes ({decrypt_time*1000:.1f}ms)")
        
        return plaintext
    
    def get_stats(self) -> Dict:
        """Get node statistics."""
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
    Meteor-Protocol network simulator.
    
    Example:
        >>> protocol = MeteorProtocol()
        >>> protocol.add_node("Alice")
        >>> protocol.add_node("Bob")
        >>> protocol.connect("Alice", "Bob")
        >>> protocol.send("Alice", "Bob", b"Hello!")
        >>> msg = protocol.receive("Bob")
    """
    
    def __init__(self):
        self.nodes: Dict[str, MeteorNode] = {}
        self.message_pool: List[MeteorMessage] = []
    
    def add_node(self, name: str, gpu: bool = True) -> MeteorNode:
        """Add node to network."""
        node = MeteorNode(name=name, gpu=gpu)
        self.nodes[name] = node
        print(f"\n[Protocol] Node '{name}' joined")
        print(f"  MeteorID: {node.get_meteor_id().hex()[:32]}...")
        return node
    
    def connect(self, node1: str, node2: str):
        """Connect two nodes (exchange keys)."""
        n1 = self.nodes.get(node1)
        n2 = self.nodes.get(node2)
        
        if n1 is None or n2 is None:
            raise ValueError("Node not found")
        
        # Exchange IDs and public keys
        n1.add_peer(node2, n2.get_meteor_id(), n2.get_public_key())
        n2.add_peer(node1, n1.get_meteor_id(), n1.get_public_key())
        
        print(f"\n[Protocol] {node1} ↔ {node2} connected")
    
    def send(self, sender: str, recipient: str, message: bytes):
        """Send message between nodes."""
        sender_node = self.nodes.get(sender)
        if sender_node is None:
            raise ValueError(f"Sender '{sender}' not found")
        
        encrypted = sender_node.send(recipient, message)
        self.message_pool.append(encrypted)
    
    def receive(self, recipient: str) -> Optional[bytes]:
        """Receive message for node."""
        recipient_node = self.nodes.get(recipient)
        if recipient_node is None:
            raise ValueError(f"Recipient '{recipient}' not found")
        
        for i, message in enumerate(self.message_pool):
            if message.recipient_id == recipient_node.meteor_id:
                self.message_pool.pop(i)
                return recipient_node.receive(message)
        
        return None
    
    def get_stats(self) -> Dict:
        """Get network statistics."""
        return {
            'nodes': len(self.nodes),
            'messages_in_pool': len(self.message_pool),
            'node_stats': {n: node.get_stats() for n, node in self.nodes.items()},
        }


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute MeteorProtocol tests."""
    print("=" * 70)
    print("Meteor-Protocol Test Suite")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Node creation
    print("\n[Test 1] Node Creation")
    print("-" * 40)
    
    alice = MeteorNode("Alice", gpu=True)
    bob = MeteorNode("Bob", gpu=True)
    
    alice_id = alice.get_meteor_id()
    bob_id = bob.get_meteor_id()
    
    node_ok = len(alice_id) == 32 and len(bob_id) == 32 and alice_id != bob_id
    results["node_creation"] = node_ok
    print(f"  Alice ID: {alice_id.hex()[:32]}...")
    print(f"  Bob ID:   {bob_id.hex()[:32]}...")
    print(f"  Result: {'PASS' if node_ok else 'FAIL'}")
    
    # Test 2: Peer exchange
    print("\n[Test 2] Peer Exchange")
    print("-" * 40)
    
    alice.add_peer("Bob", bob.get_meteor_id(), bob.get_public_key())
    bob.add_peer("Alice", alice.get_meteor_id(), alice.get_public_key())
    
    peer_ok = alice.get_peer("Bob") is not None and bob.get_peer("Alice") is not None
    results["peer_exchange"] = peer_ok
    print(f"  Result: {'PASS' if peer_ok else 'FAIL'}")
    
    # Test 3: Single message
    print("\n[Test 3] Single Message")
    print("-" * 40)
    
    original = b"Hello Bob! This is a secret message."
    msg = alice.send("Bob", original)
    decrypted = bob.receive(msg)
    
    single_ok = original == decrypted
    results["single_message"] = single_ok
    print(f"  Original:  {original}")
    print(f"  Decrypted: {decrypted}")
    print(f"  Result: {'PASS' if single_ok else 'FAIL'}")
    
    # Test 4: Bidirectional
    print("\n[Test 4] Bidirectional Communication")
    print("-" * 40)
    
    msg1 = alice.send("Bob", b"Hello Bob!")
    msg2 = bob.send("Alice", b"Hello Alice!")
    
    dec1 = bob.receive(msg1)
    dec2 = alice.receive(msg2)
    
    bidir_ok = dec1 == b"Hello Bob!" and dec2 == b"Hello Alice!"
    results["bidirectional"] = bidir_ok
    print(f"  Result: {'PASS' if bidir_ok else 'FAIL'}")
    
    # Test 5: Protocol simulator
    print("\n[Test 5] Protocol Simulator")
    print("-" * 40)
    
    protocol = MeteorProtocol()
    protocol.add_node("Charlie", gpu=True)
    protocol.add_node("Diana", gpu=True)
    protocol.connect("Charlie", "Diana")
    
    protocol.send("Charlie", "Diana", b"Hi Diana!")
    received = protocol.receive("Diana")
    
    proto_ok = received == b"Hi Diana!"
    results["protocol"] = proto_ok
    print(f"  Result: {'PASS' if proto_ok else 'FAIL'}")
    
    # Test 6: Performance
    print("\n[Test 6] Performance Benchmark")
    print("-" * 40)
    
    import time
    
    test_sizes = [100, 1000, 10000]
    perf_ok = True
    
    for size in test_sizes:
        data = secrets.token_bytes(size)
        
        start = time.perf_counter()
        msg = alice.send("Bob", data)
        enc_time = time.perf_counter() - start
        
        start = time.perf_counter()
        dec = bob.receive(msg)
        dec_time = time.perf_counter() - start
        
        ok = data == dec
        perf_ok = perf_ok and ok
        
        print(f"  {size:5d} bytes: enc={enc_time*1000:.1f}ms, dec={dec_time*1000:.1f}ms {'✓' if ok else '✗'}")
    
    results["performance"] = perf_ok
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
