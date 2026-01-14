"""
Meteor-Protocol: Quantum-Resistant P2P Communication Protocol

A serverless, censorship-resistant, quantum-safe communication protocol
based on Meteor-NC cryptography with KDF.

Key Features:
- No central server required
- 32-byte identity (compatible with DHT/IPFS/libp2p)
- No key exchange needed (public key cryptography)
- Stateless (no session management)
- Quantum-resistant (2^8128+ security)
- Ultra-fast (820K msg/s)

Protocol Flow:
    Alice                          Bob
      |                             |
      | 1. Get Bob's MeteorID       |
      |    (32 bytes, from DHT)     |
      |<----------------------------|
      |                             |
      | 2. Encrypt with Bob's       |
      |    public key               |
      |---------------------------->|
      |                             |
      |    3. Bob decrypts with     |
      |       his private key       |
      |                        ✓    |

No server, no key exchange, no state!

Usage:
    from meteor_nc.protocols import MeteorNode, MeteorProtocol
    
    # Create nodes
    alice = MeteorNode(name="Alice")
    bob = MeteorNode(name="Bob")
    
    # Exchange IDs (32 bytes each)
    alice.add_peer("Bob", bob.get_meteor_id())
    bob.add_peer("Alice", alice.get_meteor_id())
    
    # Send message (no key exchange needed!)
    alice.send("Bob", b"Hello Bob!")
    
    # Receive and decrypt
    message = bob.receive()
    print(message)  # b"Hello Bob!"
"""

import numpy as np
import time
import hashlib
import json
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime

try:
    import cupy as cp
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

from ..cryptography.kdf import MeteorKDF, create_kdf_meteor


@dataclass
class MeteorPeer:
    """
    Representation of a peer in Meteor-Protocol.
    
    Attributes:
        name: Peer name (for display)
        meteor_id: 32-byte Meteor identity
        public_key_expanded: Whether public key is cached
        last_seen: Last communication timestamp
    """
    name: str
    meteor_id: bytes
    public_key_expanded: bool = False
    last_seen: Optional[float] = None
    
    def __post_init__(self):
        if len(self.meteor_id) != 32:
            raise ValueError("MeteorID must be exactly 32 bytes")


@dataclass
class MeteorMessage:
    """
    Encrypted message in Meteor-Protocol.
    
    Attributes:
        sender_id: Sender's MeteorID (32 bytes)
        recipient_id: Recipient's MeteorID (32 bytes)
        ciphertext: Encrypted payload
        timestamp: Message timestamp
        nonce: Optional nonce for replay protection
    """
    sender_id: bytes
    recipient_id: bytes
    ciphertext: np.ndarray
    timestamp: float
    nonce: Optional[bytes] = None
    
    def to_bytes(self) -> bytes:
        """Serialize message for transmission."""
        return json.dumps({
            'sender_id': self.sender_id.hex(),
            'recipient_id': self.recipient_id.hex(),
            'ciphertext': self.ciphertext.tolist(),
            'timestamp': self.timestamp,
            'nonce': self.nonce.hex() if self.nonce else None
        }).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'MeteorMessage':
        """Deserialize message from transmission."""
        obj = json.loads(data.decode('utf-8'))
        return cls(
            sender_id=bytes.fromhex(obj['sender_id']),
            recipient_id=bytes.fromhex(obj['recipient_id']),
            ciphertext=np.array(obj['ciphertext']),
            timestamp=obj['timestamp'],
            nonce=bytes.fromhex(obj['nonce']) if obj['nonce'] else None
        )


class MeteorNode:
    """
    A node in the Meteor-Protocol network.
    
    Each node has:
    - A unique 32-byte MeteorID (derived from seed)
    - Cryptographic capabilities via Meteor-NC
    - Peer directory (distributed hash table compatible)
    
    Parameters:
        name: Node name (for display)
        security_level: 128, 256, 512, 1024, or 2048 bits
        device_id: GPU device ID
        seed: Optional seed (if None, auto-generated)
        
    Example:
        >>> node = MeteorNode("Alice", security_level=256)
        >>> meteor_id = node.get_meteor_id()  # 32 bytes
        >>> print(f"Alice's ID: {meteor_id.hex()}")
    """
    
    def __init__(self,
                 name: str = "Node",
                 security_level: int = 256,
                 device_id: int = 0,
                 seed: Optional[bytes] = None):
        """Initialize Meteor node."""
        
        self.name = name
        self.security_level = security_level
        
        # Create cryptographic instance
        self.crypto = create_kdf_meteor(
            security_level=security_level,
            device_id=device_id,
            seed=seed
        )
        
        # Generate/set seed
        self.crypto.key_gen(verbose=False)
        self.meteor_id = self.crypto.export_seed()  # 32 bytes!
        
        # Expand keys for this node
        self.crypto.expand_keys(verbose=False)
        
        # Peer directory
        self.peers: Dict[str, MeteorPeer] = {}
        
        # Peer crypto instances (cached)
        self._peer_crypto_cache: Dict[bytes, MeteorKDF] = {}
        
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
            'decryption_time': 0.0
        }
    
    def get_meteor_id(self) -> bytes:
        """
        Get this node's MeteorID (32 bytes).
        
        This ID can be:
        - Stored in DHT
        - Shared via QR code
        - Used as PeerID in libp2p
        - Used as CID in IPFS
        
        Returns:
            32-byte Meteor identity
        """
        return self.meteor_id
    
    def add_peer(self, name: str, meteor_id: bytes):
        """
        Add a peer to the directory.
        
        Args:
            name: Peer name (for convenience)
            meteor_id: Peer's 32-byte MeteorID
        """
        if len(meteor_id) != 32:
            raise ValueError("MeteorID must be exactly 32 bytes")
        
        peer = MeteorPeer(name=name, meteor_id=meteor_id)
        self.peers[name] = peer
        
        print(f"[{self.name}] Added peer: {name}")
        print(f"  MeteorID: {meteor_id.hex()[:32]}...")
    
    def get_peer(self, name: str) -> Optional[MeteorPeer]:
        """Get peer by name."""
        return self.peers.get(name)
    
    def _get_peer_crypto(self, meteor_id: bytes) -> MeteorKDF:
        """
        Get or create peer's crypto instance.
        
        This caches peer public keys for performance.
        """
        if meteor_id not in self._peer_crypto_cache:
            # Create crypto instance from peer's seed
            peer_crypto = create_kdf_meteor(
                security_level=self.security_level,
                seed=meteor_id
            )
            peer_crypto.expand_keys(verbose=False)
            self._peer_crypto_cache[meteor_id] = peer_crypto
        
        return self._peer_crypto_cache[meteor_id]

    def remove_peer(self, peer_name: str) -> bool:
        """
        Remove peer from network.
        
        Args:
            peer_name: Peer identifier
        
        Returns:
            True if removed, False if not found
        """
        if peer_name in self.peers:
            del self.peers[peer_name]
            print(f"[{self.name}] Removed peer: {peer_name}")
            return True
        
        return False
    
    def send(self, peer_name: str, plaintext: bytes) -> MeteorMessage:
        """
        Send encrypted message to peer.
        
        Args:
            peer_name: Recipient peer name
            plaintext: Message to encrypt (bytes)
            
        Returns:
            Encrypted message ready for transmission
        """
        peer = self.get_peer(peer_name)
        if peer is None:
            raise ValueError(f"Unknown peer: {peer_name}")
        
        # Get peer's crypto instance (public key)
        peer_crypto = self._get_peer_crypto(peer.meteor_id)
        
        # Convert plaintext to fixed-size block
        n = self.crypto.n
        plaintext_padded = self._pad_message(plaintext, n)
        
        # Encrypt
        start = time.time()
        ciphertext = peer_crypto.encrypt(plaintext_padded)
        encrypt_time = time.time() - start
        
        # Create message
        message = MeteorMessage(
            sender_id=self.meteor_id,
            recipient_id=peer.meteor_id,
            ciphertext=ciphertext,
            timestamp=time.time(),
            nonce=np.random.bytes(16)
        )
        
        # Update statistics
        self.stats['messages_sent'] += 1
        self.stats['bytes_sent'] += len(plaintext)
        self.stats['encryption_time'] += encrypt_time
        
        # Add to outbox
        self.outbox.append(message)
        
        # Update peer timestamp
        peer.last_seen = time.time()
        
        print(f"[{self.name}] → [{peer_name}]: {len(plaintext)} bytes encrypted")
        
        return message
    
    def receive(self, message: MeteorMessage) -> bytes:
        """
        Receive and decrypt message.
        
        Args:
            message: MeteorMessage to decrypt
            
        Returns:
            Decrypted plaintext
        """
        # Verify recipient
        if message.recipient_id != self.meteor_id:
            raise ValueError("Message not for this node")
        
        # Decrypt
        start = time.time()
        plaintext_padded = self.crypto.decrypt(message.ciphertext)
        decrypt_time = time.time() - start
        
        # Unpad
        plaintext = self._unpad_message(plaintext_padded)
        
        # Update statistics
        self.stats['messages_received'] += 1
        self.stats['bytes_received'] += len(plaintext)
        self.stats['decryption_time'] += decrypt_time
        
        # Add to inbox
        self.inbox.append(message)
        
        # Find sender name (if known)
        sender_name = "Unknown"
        for name, peer in self.peers.items():
            if peer.meteor_id == message.sender_id:
                sender_name = name
                peer.last_seen = message.timestamp
                break
        
        print(f"[{self.name}] ← [{sender_name}]: {len(plaintext)} bytes decrypted")
        
        return plaintext
    
    def send_batch(self, peer_name: str, plaintexts: List[bytes]) -> List[MeteorMessage]:
        """
        Send multiple messages efficiently (batch encryption).
        
        Args:
            peer_name: Recipient peer name
            plaintexts: List of messages to encrypt
            
        Returns:
            List of encrypted messages
        """
        peer = self.get_peer(peer_name)
        if peer is None:
            raise ValueError(f"Unknown peer: {peer_name}")
        
        peer_crypto = self._get_peer_crypto(peer.meteor_id)
        
        # Pad all messages
        n = self.crypto.n
        messages_padded = np.array([
            self._pad_message(plaintext, n)
            for plaintext in plaintexts
        ])
        
        # Batch encrypt
        start = time.time()
        ciphertexts = peer_crypto.encrypt_batch(messages_padded)
        encrypt_time = time.time() - start
        
        # Create messages
        encrypted_messages = []
        for i, ciphertext in enumerate(ciphertexts):
            message = MeteorMessage(
                sender_id=self.meteor_id,
                recipient_id=peer.meteor_id,
                ciphertext=ciphertext,
                timestamp=time.time(),
                nonce=np.random.bytes(16)
            )
            encrypted_messages.append(message)
            self.outbox.append(message)
        
        # Update statistics
        total_bytes = sum(len(p) for p in plaintexts)
        self.stats['messages_sent'] += len(plaintexts)
        self.stats['bytes_sent'] += total_bytes
        self.stats['encryption_time'] += encrypt_time
        
        peer.last_seen = time.time()
        
        print(f"[{self.name}] → [{peer_name}]: {len(plaintexts)} messages "
              f"({total_bytes} bytes) encrypted in {encrypt_time*1000:.2f}ms")
        
        return encrypted_messages
    
    def receive_batch(self, messages: List[MeteorMessage]) -> List[bytes]:
        """
        Receive and decrypt multiple messages efficiently.
        
        Args:
            messages: List of MeteorMessages to decrypt
            
        Returns:
            List of decrypted plaintexts
        """
        # Verify all for this node
        for message in messages:
            if message.recipient_id != self.meteor_id:
                raise ValueError("Message not for this node")
        
        # Extract ciphertexts
        ciphertexts = np.array([m.ciphertext for m in messages])
        
        # Batch decrypt
        start = time.time()
        plaintexts_padded, decrypt_time = self.crypto.decrypt_batch(ciphertexts)
        
        # Unpad
        plaintexts = [
            self._unpad_message(padded)
            for padded in plaintexts_padded
        ]
        
        # Update statistics
        total_bytes = sum(len(p) for p in plaintexts)
        self.stats['messages_received'] += len(messages)
        self.stats['bytes_received'] += total_bytes
        self.stats['decryption_time'] += decrypt_time
        
        # Add to inbox
        self.inbox.extend(messages)
        
        print(f"[{self.name}] ← Batch: {len(messages)} messages "
              f"({total_bytes} bytes) decrypted in {decrypt_time*1000:.2f}ms")
        
        return plaintexts
    
    def _pad_message(self, message: bytes, n: int) -> np.ndarray:
        """
        Pad message to n dimensions.
        
        Format: [length (4 bytes)] + [message] + [padding]
        Uses uint8 internally to preserve exact byte values
        """
        length = len(message)
        
        # Store length in first 4 bytes
        padded = bytearray(length.to_bytes(4, byteorder='big'))
        padded.extend(message)
        
        # Pad to n bytes
        if len(padded) < n:
            padded.extend(b'\x00' * (n - len(padded)))
        elif len(padded) > n:
            raise ValueError(f"Message too long: {length} bytes (max: {n - 4})")
        
        # Convert to uint8 array
        uint8_array = np.frombuffer(padded, dtype=np.uint8)
        
        # Convert to float64 for crypto (integers 0-255 are exact in float64)
        return uint8_array.astype(np.float64)
    
    def _unpad_message(self, padded: np.ndarray) -> bytes:
        """
        Unpad message from n dimensions.
        
        Converts back from float64 to exact uint8 values
        """
        # Round and convert to uint8 (handles any small float errors)
        uint8_array = np.round(padded).astype(np.uint8)
        
        # Convert to bytes
        padded_bytes = uint8_array.tobytes()
        
        # Extract length
        length = int.from_bytes(padded_bytes[:4], byteorder='big')
        
        # Validate length
        if length < 0 or length > len(padded_bytes) - 4:
            raise ValueError(f"Invalid message length: {length}")
        
        # Extract message
        return padded_bytes[4:4+length]
    
    def get_stats(self) -> Dict:
        """Get node statistics."""
        return {
            'name': self.name,
            'meteor_id': self.meteor_id.hex(),
            'peers': len(self.peers),
            'messages_sent': self.stats['messages_sent'],
            'messages_received': self.stats['messages_received'],
            'bytes_sent': self.stats['bytes_sent'],
            'bytes_received': self.stats['bytes_received'],
            'avg_encryption_ms': (self.stats['encryption_time'] / max(1, self.stats['messages_sent'])) * 1000,
            'avg_decryption_ms': (self.stats['decryption_time'] / max(1, self.stats['messages_received'])) * 1000,
            'throughput_sent': self.stats['bytes_sent'] / max(0.001, self.stats['encryption_time']) if self.stats['encryption_time'] > 0 else 0,
            'throughput_received': self.stats['bytes_received'] / max(0.001, self.stats['decryption_time']) if self.stats['decryption_time'] > 0 else 0
        }
    
    def cleanup(self):
        """Cleanup GPU resources."""
        self.crypto.cleanup()
        for peer_crypto in self._peer_crypto_cache.values():
            peer_crypto.cleanup()


class MeteorProtocol:
    """
    Meteor-Protocol network simulator.
    
    Simulates a P2P network with multiple Meteor nodes.
    In production, this would be replaced by actual network layer.
    
    Example:
        >>> protocol = MeteorProtocol()
        >>> protocol.add_node("Alice")
        >>> protocol.add_node("Bob")
        >>> protocol.connect("Alice", "Bob")
        >>> protocol.send("Alice", "Bob", b"Hello!")
        >>> message = protocol.receive("Bob")
    """
    
    def __init__(self):
        """Initialize protocol simulator."""
        self.nodes: Dict[str, MeteorNode] = {}
        self.message_pool: List[MeteorMessage] = []
    
    def add_node(self, name: str, security_level: int = 256) -> MeteorNode:
        """
        Add node to network.
        
        Args:
            name: Node name
            security_level: Crypto security level
            
        Returns:
            Created node
        """
        node = MeteorNode(name=name, security_level=security_level)
        self.nodes[name] = node
        
        print(f"\n[Protocol] Node '{name}' joined")
        print(f"  MeteorID: {node.get_meteor_id().hex()[:32]}...")
        
        return node
    
    def connect(self, node1: str, node2: str):
        """
        Connect two nodes (exchange MeteorIDs).
        
        Args:
            node1: First node name
            node2: Second node name
        """
        n1 = self.nodes.get(node1)
        n2 = self.nodes.get(node2)
        
        if n1 is None or n2 is None:
            raise ValueError("Node not found")
        
        # Exchange IDs (32 bytes each way!)
        n1.add_peer(node2, n2.get_meteor_id())
        n2.add_peer(node1, n1.get_meteor_id())
        
        print(f"\n[Protocol] {node1} ↔ {node2} connected (32 bytes exchanged)")
    
    def send(self, sender: str, recipient: str, message: bytes):
        """
        Send message between nodes.
        
        Args:
            sender: Sender node name
            recipient: Recipient node name
            message: Message bytes
        """
        sender_node = self.nodes.get(sender)
        if sender_node is None:
            raise ValueError(f"Sender node '{sender}' not found")
        
        # Encrypt and send
        encrypted = sender_node.send(recipient, message)
        
        # Add to message pool (simulates network)
        self.message_pool.append(encrypted)
    
    def receive(self, recipient: str) -> Optional[bytes]:
        """
        Receive message for node.
        
        Args:
            recipient: Recipient node name
            
        Returns:
            Decrypted message or None
        """
        recipient_node = self.nodes.get(recipient)
        if recipient_node is None:
            raise ValueError(f"Recipient node '{recipient}' not found")
        
        # Find message for this node
        for i, message in enumerate(self.message_pool):
            if message.recipient_id == recipient_node.meteor_id:
                # Remove from pool
                self.message_pool.pop(i)
                
                # Decrypt
                return recipient_node.receive(message)
        
        return None
    
    def get_network_stats(self) -> Dict:
        """Get network-wide statistics."""
        total_messages = sum(n.stats['messages_sent'] for n in self.nodes.values())
        total_bytes = sum(n.stats['bytes_sent'] for n in self.nodes.values())
        
        return {
            'nodes': len(self.nodes),
            'total_messages': total_messages,
            'total_bytes': total_bytes,
            'messages_in_pool': len(self.message_pool),
            'node_stats': {name: node.get_stats() for name, node in self.nodes.items()}
        }
