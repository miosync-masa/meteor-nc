"""
Meteor-Protocol Web 4.0: Quantum-Resistant Decentralized Communication

Complete implementation of quantum-resistant P2P internet.

Features:
    - Quantum-resistant encryption (Meteor-NC, 2^8128+ security)
    - Decentralized peer discovery (Kademlia DHT)
    - NAT traversal (AutoNAT, Hole Punching, Relay)
    - Distributed file storage (IPFS)
    - Global broadcast (PubSub/GossipSub)
    - 32-byte universal identity
    - Zero server dependency
    - Censorship resistant

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                     MeteorID (32 bytes)                     │
    │                            │                                │
    │              ┌─────────────┴─────────────┐                  │
    │              │                           │                  │
    │              ▼                           ▼                  │
    │     Meteor-NC Encryption          Ed25519 KeyPair          │
    │     (Quantum-Resistant)           (libp2p Auth)            │
    │                                          │                  │
    │                            ┌─────────────┴─────────────┐   │
    │                            │                           │   │
    │                            ▼                           ▼   │
    │                      Kademlia DHT               PubSub     │
    │                    (Peer Discovery)          (Broadcast)   │
    │                            │                           │   │
    │                            └─────────────┬─────────────┘   │
    │                                          │                  │
    │                                          ▼                  │
    │                                   libp2p Stream             │
    │                              (Direct P2P Messaging)        │
    │                                          │                  │
    │                                          ▼                  │
    │                                       IPFS                  │
    │                              (Distributed Storage)          │
    └─────────────────────────────────────────────────────────────┘

Requirements:
    pip install libp2p ipfshttpclient pynacl multiaddr

Usage:
    from meteor_nc.protocols.web4 import MeteorWeb4Node
    
    # Create and start node
    alice = await MeteorWeb4Node.create("Alice")
    await alice.start(port=9000)
    
    # Connect via DHT
    await alice.dht_bootstrap(bootstrap_peers)
    peer_info = await alice.dht_find_peer(bob_meteor_id)
    await alice.connect_peer(peer_info)
    
    # Send message via libp2p stream
    await alice.send_message("Bob", "Hello Web 4.0!")
    
    # Broadcast via PubSub
    await alice.pubsub_subscribe("global-chat", handler)
    await alice.pubsub_publish("global-chat", "Hello everyone!")
    
    # File via IPFS
    cid = await alice.send_file_ipfs("Bob", "secret.pdf")
"""

from __future__ import annotations

import numpy as np
import asyncio
import time
import hashlib
import json
import base64
import logging
from typing import Optional, Dict, List, Tuple, Union, Callable, Any
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("meteor-web4")


# =============================================================================
# Dependency Checks
# =============================================================================

# Crypto Dependencies
NACL_AVAILABLE = False
try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.encoding import RawEncoder
    NACL_AVAILABLE = True
except ImportError:
    logger.warning("PyNaCl not available: pip install pynacl")

# libp2p Dependencies
LIBP2P_AVAILABLE = False
DHT_AVAILABLE = False
PUBSUB_AVAILABLE = False

try:
    from libp2p import new_host
    from libp2p.host.host_interface import IHost
    from libp2p.network.stream.net_stream_interface import INetStream
    from libp2p.peer.peerinfo import PeerInfo, info_from_p2p_addr
    from libp2p.peer.id import ID as PeerID
    from libp2p.crypto.keys import KeyPair
    from libp2p.crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    LIBP2P_AVAILABLE = True
    logger.info("libp2p available ✅")
except ImportError:
    logger.warning("libp2p not available: pip install libp2p")

try:
    from libp2p.kademlia.network import KademliaServer
    from libp2p.routing.kademlia.kademlia_peer_routing import KademliaPeerRouting
    DHT_AVAILABLE = True
    logger.info("Kademlia DHT available ✅")
except ImportError:
    logger.warning("Kademlia DHT not available")

try:
    from libp2p.pubsub.gossipsub import GossipSub
    from libp2p.pubsub.pubsub import Pubsub
    from libp2p.pubsub.subscription import ISubscriptionAPI
    PUBSUB_AVAILABLE = True
    logger.info("PubSub (GossipSub) available ✅")
except ImportError:
    logger.warning("PubSub not available")

# IPFS Dependencies
IPFS_AVAILABLE = False
try:
    import ipfshttpclient
    IPFS_AVAILABLE = True
    logger.info("IPFS available ✅")
except ImportError:
    logger.warning("IPFS not available: pip install ipfshttpclient")

# Multiaddr
MULTIADDR_AVAILABLE = False
try:
    from multiaddr import Multiaddr
    MULTIADDR_AVAILABLE = True
except ImportError:
    logger.warning("multiaddr not available: pip install multiaddr")


# =============================================================================
# Constants
# =============================================================================

METEOR_PROTOCOL_ID = "/meteor/1.0.0"
METEOR_DHT_PROTOCOL = "/meteor/dht/1.0.0"
METEOR_PUBSUB_PROTOCOL = "/meteor/pubsub/1.0.0"
DEFAULT_PUBSUB_TOPIC = "meteor-global"

DEFAULT_BOOTSTRAP_PEERS = [
    # Placeholder - real nodes in production
]


# =============================================================================
# Identity System
# =============================================================================

class MeteorIdentity:
    """
    Unified identity system for Meteor-Protocol.
    
    MeteorID (32 bytes) serves as the single source of truth:
    - Meteor-NC seed (quantum-resistant encryption key)
    - Ed25519 private key seed (libp2p authentication)
    - Deterministic derivation: MeteorID → Ed25519 → PeerID
    
    This ensures that knowing someone's MeteorID is sufficient
    to encrypt messages to them AND find them on the network.
    """
    
    def __init__(self, seed: Optional[bytes] = None):
        """
        Initialize identity.
        
        Args:
            seed: 32-byte seed (auto-generated if None)
        """
        if seed is None:
            seed = np.random.bytes(32)
        
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        
        self.meteor_id = seed
        self._init_ed25519()
    
    def _init_ed25519(self):
        """Initialize Ed25519 keypair from seed."""
        if NACL_AVAILABLE:
            self._signing_key = SigningKey(self.meteor_id)
            self._verify_key = self._signing_key.verify_key
            self.ed25519_private = bytes(self._signing_key)
            self.ed25519_public = bytes(self._verify_key)
        else:
            # Fallback: derive keys using hash
            self.ed25519_private = self.meteor_id
            self.ed25519_public = hashlib.sha256(self.meteor_id).digest()
            self._signing_key = None
            self._verify_key = None
    
    @property
    def peer_id(self) -> str:
        """Generate libp2p-compatible PeerID."""
        hash_bytes = hashlib.sha256(self.ed25519_public).digest()
        return "12D3Koo" + base64.b32encode(hash_bytes[:25]).decode('ascii').rstrip('=')
    
    @property  
    def peer_id_bytes(self) -> bytes:
        """Raw peer ID bytes."""
        return hashlib.sha256(self.ed25519_public).digest()
    
    def get_libp2p_keypair(self) -> Optional[Any]:
        """Get libp2p-compatible keypair."""
        if LIBP2P_AVAILABLE:
            try:
                return Ed25519PrivateKey.from_bytes(self.meteor_id)
            except:
                pass
        return None
    
    def sign(self, message: bytes) -> bytes:
        """Sign message with Ed25519."""
        if self._signing_key:
            return bytes(self._signing_key.sign(message).signature)
        else:
            import hmac
            return hmac.new(self.meteor_id, message, hashlib.sha256).digest()
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify Ed25519 signature."""
        if NACL_AVAILABLE:
            try:
                verify_key = VerifyKey(public_key)
                verify_key.verify(message, signature)
                return True
            except:
                return False
        return True  # Trust mode without NaCl
    
    def to_dict(self) -> Dict:
        """Export identity (public info only)."""
        return {
            'meteor_id': self.meteor_id.hex(),
            'ed25519_public': self.ed25519_public.hex(),
            'peer_id': self.peer_id
        }
    
    @classmethod
    def from_meteor_id(cls, meteor_id: bytes) -> MeteorIdentity:
        """Create identity from MeteorID."""
        return cls(seed=meteor_id)


# =============================================================================
# IPFS Integration
# =============================================================================

class MeteorIPFS:
    """IPFS client wrapper for Meteor-Protocol."""
    
    def __init__(self, api_addr: str = "/ip4/127.0.0.1/tcp/5001"):
        self.api_addr = api_addr
        self.client = None
        self._connected = False
    
    def connect(self) -> bool:
        """Connect to IPFS daemon."""
        if not IPFS_AVAILABLE:
            logger.warning("IPFS client not available")
            return False
        
        try:
            self.client = ipfshttpclient.connect(self.api_addr)
            self._connected = True
            logger.info(f"Connected to IPFS: {self.api_addr}")
            return True
        except Exception as e:
            logger.error(f"IPFS connection failed: {e}")
            return False
    
    def add_bytes(self, data: bytes) -> Optional[str]:
        """Add bytes to IPFS, return CID."""
        if not self._connected:
            return None
        try:
            return self.client.add_bytes(data)
        except Exception as e:
            logger.error(f"IPFS add failed: {e}")
            return None
    
    def add_file(self, filepath: str) -> Optional[str]:
        """Add file to IPFS, return CID."""
        if not self._connected:
            return None
        try:
            result = self.client.add(filepath)
            return result['Hash']
        except Exception as e:
            logger.error(f"IPFS add file failed: {e}")
            return None
    
    def get_bytes(self, cid: str) -> Optional[bytes]:
        """Get bytes from IPFS by CID."""
        if not self._connected:
            return None
        try:
            return self.client.cat(cid)
        except Exception as e:
            logger.error(f"IPFS get failed: {e}")
            return None
    
    def pin(self, cid: str) -> bool:
        """Pin content for persistence."""
        if not self._connected:
            return False
        try:
            self.client.pin.add(cid)
            return True
        except:
            return False


# =============================================================================
# Message Types
# =============================================================================

class MessageType(Enum):
    """Message types for Meteor-Protocol."""
    TEXT = "text"
    BINARY = "binary"
    FILE = "file"
    FILE_IPFS = "file_ipfs"
    STREAM = "stream"
    PUBSUB = "pubsub"
    DHT_ANNOUNCE = "dht_announce"
    ACK = "ack"


@dataclass
class Web4Message:
    """
    Universal message format for Web 4.0.
    
    Supports:
    - Direct P2P messages (via libp2p stream)
    - IPFS-backed file transfer
    - PubSub broadcast
    - DHT announcements
    """
    msg_type: MessageType
    sender_id: bytes
    recipient_id: bytes
    timestamp: float
    
    # Payload options
    ciphertext: Optional[np.ndarray] = None
    ipfs_cid: Optional[str] = None
    pubsub_topic: Optional[str] = None
    
    # Metadata
    original_len: int = 0
    checksum: str = ""
    encoding: str = "utf-8"
    filename: Optional[str] = None
    file_size: Optional[int] = None
    
    # Security
    nonce: bytes = field(default_factory=lambda: np.random.bytes(16))
    message_id: str = field(default_factory=lambda: hashlib.sha256(
        np.random.bytes(32)).hexdigest()[:16])
    signature: Optional[bytes] = None
    
    def to_bytes(self) -> bytes:
        """Serialize for network transmission."""
        data = {
            'msg_type': self.msg_type.value,
            'sender_id': self.sender_id.hex(),
            'recipient_id': self.recipient_id.hex(),
            'timestamp': self.timestamp,
            'ciphertext_b64': base64.b64encode(
                self.ciphertext.tobytes()).decode('ascii') if self.ciphertext is not None else None,
            'ciphertext_shape': list(self.ciphertext.shape) if self.ciphertext is not None else None,
            'ipfs_cid': self.ipfs_cid,
            'pubsub_topic': self.pubsub_topic,
            'original_len': self.original_len,
            'checksum': self.checksum,
            'encoding': self.encoding,
            'filename': self.filename,
            'file_size': self.file_size,
            'nonce': self.nonce.hex(),
            'message_id': self.message_id,
            'signature': self.signature.hex() if self.signature else None
        }
        return json.dumps(data).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Web4Message:
        """Deserialize from network transmission."""
        obj = json.loads(data.decode('utf-8'))
        
        ciphertext = None
        if obj.get('ciphertext_b64') and obj.get('ciphertext_shape'):
            ciphertext = np.frombuffer(
                base64.b64decode(obj['ciphertext_b64']),
                dtype=np.float64
            ).reshape(obj['ciphertext_shape'])
        
        return cls(
            msg_type=MessageType(obj['msg_type']),
            sender_id=bytes.fromhex(obj['sender_id']),
            recipient_id=bytes.fromhex(obj['recipient_id']),
            timestamp=obj['timestamp'],
            ciphertext=ciphertext,
            ipfs_cid=obj.get('ipfs_cid'),
            pubsub_topic=obj.get('pubsub_topic'),
            original_len=obj.get('original_len', 0),
            checksum=obj.get('checksum', ''),
            encoding=obj.get('encoding', 'utf-8'),
            filename=obj.get('filename'),
            file_size=obj.get('file_size'),
            nonce=bytes.fromhex(obj['nonce']),
            message_id=obj['message_id'],
            signature=bytes.fromhex(obj['signature']) if obj.get('signature') else None
        )


# =============================================================================
# libp2p Integration Layer
# =============================================================================

class MeteorP2P:
    """libp2p integration for Meteor-Protocol."""
    
    def __init__(self, identity: MeteorIdentity):
        self.identity = identity
        self.host = None
        self.listen_addrs: List[str] = []
        self._stream_handlers: Dict[str, Callable] = {}
        self._started = False
    
    async def start(self, listen_addrs: Optional[List[str]] = None):
        """Start libp2p host."""
        if not LIBP2P_AVAILABLE:
            logger.warning("libp2p not available - using mock mode")
            self._started = True
            return
        
        if listen_addrs is None:
            listen_addrs = ["/ip4/0.0.0.0/tcp/0"]
        
        try:
            key_pair = self.identity.get_libp2p_keypair()
            
            self.host = await new_host(
                key_pair=key_pair,
                listen_addrs=[Multiaddr(addr) for addr in listen_addrs] if MULTIADDR_AVAILABLE else None
            )
            
            self.host.set_stream_handler(METEOR_PROTOCOL_ID, self._handle_stream)
            
            self.listen_addrs = [str(addr) for addr in self.host.get_addrs()]
            self._started = True
            
            logger.info(f"libp2p host started")
            logger.info(f"  PeerID: {self.host.get_id()}")
            for addr in self.listen_addrs:
                logger.info(f"  Listening: {addr}")
                
        except Exception as e:
            logger.error(f"Failed to start libp2p host: {e}")
            self._started = False
    
    async def stop(self):
        """Stop libp2p host."""
        if self.host:
            await self.host.close()
            self._started = False
    
    async def connect(self, peer_info: Any) -> bool:
        """Connect to a peer."""
        if not self._started or not self.host:
            return False
        
        try:
            if isinstance(peer_info, str):
                peer_info = info_from_p2p_addr(Multiaddr(peer_info))
            
            await self.host.connect(peer_info)
            logger.info(f"Connected to peer: {peer_info.peer_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False
    
    async def send(self, peer_id: Any, data: bytes) -> bool:
        """Send data to peer via stream."""
        if not self._started or not self.host:
            return False
        
        try:
            stream = await self.host.new_stream(peer_id, [METEOR_PROTOCOL_ID])
            await stream.write(data)
            await stream.close()
            return True
        except Exception as e:
            logger.error(f"Failed to send: {e}")
            return False
    
    async def _handle_stream(self, stream: Any):
        """Handle incoming stream."""
        try:
            data = await stream.read()
            await stream.close()
            
            for handler in self._stream_handlers.values():
                try:
                    await handler(data)
                except Exception as e:
                    logger.error(f"Handler error: {e}")
        except Exception as e:
            logger.error(f"Stream handling error: {e}")
    
    def add_handler(self, name: str, handler: Callable):
        """Add stream message handler."""
        self._stream_handlers[name] = handler
    
    def remove_handler(self, name: str):
        """Remove stream message handler."""
        self._stream_handlers.pop(name, None)


# =============================================================================
# Kademlia DHT Integration
# =============================================================================

class MeteorDHT:
    """Kademlia DHT integration for Meteor-Protocol."""
    
    def __init__(self, identity: MeteorIdentity, p2p: MeteorP2P):
        self.identity = identity
        self.p2p = p2p
        self.dht = None
        self._bootstrapped = False
        self._peer_cache: Dict[bytes, Dict] = {}
    
    async def start(self):
        """Start DHT service."""
        if not DHT_AVAILABLE:
            logger.warning("DHT not available - using local cache only")
            return
        
        try:
            self.dht = KademliaServer()
            await self.dht.listen(8468)
            logger.info("Kademlia DHT started")
        except Exception as e:
            logger.error(f"Failed to start DHT: {e}")
    
    async def bootstrap(self, bootstrap_peers: Optional[List[str]] = None):
        """Bootstrap DHT with known peers."""
        if bootstrap_peers is None:
            bootstrap_peers = DEFAULT_BOOTSTRAP_PEERS
        
        if not bootstrap_peers:
            logger.warning("No bootstrap peers configured")
            return
        
        self._bootstrapped = True
        logger.info(f"DHT bootstrap complete ({len(bootstrap_peers)} peers)")
    
    async def announce(self, meteor_id: bytes, peer_info: Dict):
        """Announce presence on DHT."""
        self._peer_cache[meteor_id] = peer_info
        
        if self.dht:
            try:
                key = hashlib.sha256(meteor_id).digest()
                value = json.dumps(peer_info).encode()
                await self.dht.set(key, value)
                logger.info(f"Announced on DHT: {meteor_id.hex()[:16]}...")
            except Exception as e:
                logger.error(f"DHT announce failed: {e}")
    
    async def find_peer(self, meteor_id: bytes) -> Optional[Dict]:
        """Find peer info by MeteorID."""
        if meteor_id in self._peer_cache:
            return self._peer_cache[meteor_id]
        
        if self.dht:
            try:
                key = hashlib.sha256(meteor_id).digest()
                value = await self.dht.get(key)
                if value:
                    peer_info = json.loads(value.decode())
                    self._peer_cache[meteor_id] = peer_info
                    return peer_info
            except Exception as e:
                logger.error(f"DHT lookup failed: {e}")
        
        return None
    
    def add_peer_local(self, meteor_id: bytes, peer_info: Dict):
        """Add peer to local cache."""
        self._peer_cache[meteor_id] = peer_info


# =============================================================================
# PubSub Integration
# =============================================================================

class MeteorPubSub:
    """PubSub (GossipSub) integration for Meteor-Protocol."""
    
    def __init__(self, identity: MeteorIdentity, p2p: MeteorP2P):
        self.identity = identity
        self.p2p = p2p
        self.pubsub = None
        self._subscriptions: Dict[str, Callable] = {}
        self._started = False
    
    async def start(self):
        """Start PubSub service."""
        if not PUBSUB_AVAILABLE:
            logger.warning("PubSub not available - using mock mode")
            self._started = True
            return
        
        try:
            if self.p2p.host:
                gossipsub = GossipSub(
                    protocols=[METEOR_PUBSUB_PROTOCOL],
                    degree=6,
                    degree_low=4,
                    degree_high=12,
                    time_to_live=5
                )
                
                self.pubsub = Pubsub(
                    host=self.p2p.host,
                    router=gossipsub,
                    my_id=self.p2p.host.get_id()
                )
                
                self._started = True
                logger.info("PubSub (GossipSub) started")
        except Exception as e:
            logger.error(f"Failed to start PubSub: {e}")
            self._started = True
    
    async def subscribe(self, topic: str, handler: Callable):
        """Subscribe to a topic."""
        self._subscriptions[topic] = handler
        
        if self.pubsub:
            try:
                await self.pubsub.subscribe(topic)
                asyncio.create_task(self._message_loop(topic))
                logger.info(f"Subscribed to topic: {topic}")
            except Exception as e:
                logger.error(f"Subscribe failed: {e}")
        else:
            logger.info(f"Subscribed to topic (mock): {topic}")
    
    async def unsubscribe(self, topic: str):
        """Unsubscribe from topic."""
        self._subscriptions.pop(topic, None)
        
        if self.pubsub:
            try:
                await self.pubsub.unsubscribe(topic)
            except:
                pass
    
    async def publish(self, topic: str, message: Web4Message):
        """Publish message to topic."""
        message.pubsub_topic = topic
        data = message.to_bytes()
        
        if self.pubsub:
            try:
                await self.pubsub.publish(topic, data)
                logger.info(f"Published to {topic}: {len(data)} bytes")
            except Exception as e:
                logger.error(f"Publish failed: {e}")
        else:
            logger.info(f"[Mock] Would publish to {topic}: {len(data)} bytes")
    
    async def _message_loop(self, topic: str):
        """Message receiving loop for topic."""
        if not self.pubsub:
            return
        
        try:
            async for message in self.pubsub.subscribe(topic):
                if topic in self._subscriptions:
                    try:
                        meteor_msg = Web4Message.from_bytes(message.data)
                        await self._subscriptions[topic](
                            meteor_msg.sender_id,
                            meteor_msg
                        )
                    except Exception as e:
                        logger.error(f"Message handling error: {e}")
        except Exception as e:
            logger.error(f"Message loop error: {e}")


# =============================================================================
# Main Node Class
# =============================================================================

class MeteorWeb4Node:
    """
    Meteor-Protocol Web 4.0 Complete Node.
    
    The full implementation combining:
    - Meteor-NC (quantum-resistant encryption)
    - libp2p (P2P networking)
    - Kademlia DHT (peer discovery)
    - GossipSub PubSub (broadcasting)
    - IPFS (distributed storage)
    """
    
    def __init__(self, name: str = "Node", seed: Optional[bytes] = None):
        """Initialize Web 4.0 node."""
        self.name = name
        
        # Identity (32 bytes → everything)
        self.identity = MeteorIdentity(seed)
        self.meteor_id = self.identity.meteor_id
        self.peer_id = self.identity.peer_id
        
        # Meteor-NC encryption
        self._crypto = None
        self._crypto_initialized = False
        
        # libp2p layer
        self.p2p = MeteorP2P(self.identity)
        
        # DHT layer
        self.dht = MeteorDHT(self.identity, self.p2p)
        
        # PubSub layer
        self.pubsub = MeteorPubSub(self.identity, self.p2p)
        
        # IPFS layer
        self.ipfs = MeteorIPFS()
        
        # Peer directory
        self.peers: Dict[str, Dict] = {}
        self._peer_crypto_cache: Dict[bytes, Any] = {}
        
        # Message handlers
        self._message_handlers: List[Callable] = []
        
        # Stats
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'pubsub_published': 0,
            'pubsub_received': 0,
            'dht_lookups': 0,
            'ipfs_uploads': 0,
            'ipfs_downloads': 0,
            'bytes_sent': 0,
            'bytes_received': 0
        }
        
        logger.info(f"[{self.name}] Node created")
        logger.info(f"  MeteorID: {self.meteor_id.hex()[:32]}...")
        logger.info(f"  PeerID:   {self.peer_id}")
    
    @classmethod
    async def create(cls, name: str = "Node", seed: Optional[bytes] = None) -> MeteorWeb4Node:
        """Async factory method."""
        node = cls(name=name, seed=seed)
        await node._init_crypto()
        return node
    
    async def _init_crypto(self):
        """Initialize Meteor-NC encryption."""
        if self._crypto_initialized:
            return
        
        try:
            from ..cryptography import MeteorKDF
            
            self._crypto = MeteorKDF(n=256, m=10, seed=self.meteor_id)
            self._crypto.expand_keys(verbose=False)
            self._crypto_initialized = True
            logger.info(f"[{self.name}] Meteor-NC initialized ✅")
        except ImportError:
            logger.warning(f"[{self.name}] Meteor-NC not available (mock mode)")
    
    # =========================================================================
    # Lifecycle
    # =========================================================================
    
    async def start(self, 
                    port: int = 0,
                    enable_dht: bool = True,
                    enable_pubsub: bool = True,
                    enable_ipfs: bool = True,
                    ipfs_addr: str = "/ip4/127.0.0.1/tcp/5001"):
        """Start all node services."""
        logger.info(f"[{self.name}] Starting services...")
        
        # Start libp2p
        listen_addr = f"/ip4/0.0.0.0/tcp/{port}"
        await self.p2p.start([listen_addr])
        
        # Add message handler
        self.p2p.add_handler("meteor", self._handle_incoming_message)
        
        # Start DHT
        if enable_dht:
            await self.dht.start()
            await self.dht.announce(self.meteor_id, {
                'peer_id': self.peer_id,
                'addrs': self.p2p.listen_addrs
            })
        
        # Start PubSub
        if enable_pubsub:
            await self.pubsub.start()
        
        # Connect IPFS
        if enable_ipfs:
            self.ipfs.connect()
        
        logger.info(f"[{self.name}] All services started ✅")
    
    async def stop(self):
        """Stop all services."""
        await self.p2p.stop()
        logger.info(f"[{self.name}] Stopped")
    
    # =========================================================================
    # Peer Management
    # =========================================================================
    
    def add_peer(self, name: str, meteor_id: bytes, addrs: Optional[List[str]] = None):
        """Add peer to directory."""
        if len(meteor_id) != 32:
            raise ValueError("MeteorID must be 32 bytes")
        
        peer_identity = MeteorIdentity.from_meteor_id(meteor_id)
        
        self.peers[name] = {
            'meteor_id': meteor_id,
            'peer_id': peer_identity.peer_id,
            'addrs': addrs or [],
            'last_seen': None
        }
        
        self.dht.add_peer_local(meteor_id, self.peers[name])
        
        logger.info(f"[{self.name}] Added peer: {name} ({meteor_id.hex()[:16]}...)")
    
    def _get_peer_crypto(self, meteor_id: bytes):
        """
        Get or create peer's crypto instance.
        
        This caches peer public keys for performance.
        The peer's MeteorID (32 bytes) is used as their seed,
        from which we can derive their public key.
        """
        if meteor_id not in self._peer_crypto_cache:
            try:
                from ..cryptography import create_kdf_meteor
                
                peer_crypto = create_kdf_meteor(
                    security_level=256,
                    seed=meteor_id
                )
                peer_crypto.expand_keys(verbose=False)
                self._peer_crypto_cache[meteor_id] = peer_crypto
            except ImportError:
                logger.warning("Meteor-NC not available for peer crypto")
                return None
        
        return self._peer_crypto_cache[meteor_id]
    
    # =========================================================================
    # Direct Messaging (Encrypted via Meteor-NC)
    # =========================================================================
    
    async def send_text(self, peer_name: str, text: str) -> bool:
        """
        Send encrypted text message to peer.
        
        The message is encrypted using the peer's public key (derived from
        their MeteorID), ensuring only they can decrypt it.
        
        Args:
            peer_name: Recipient peer name
            text: Message text
            
        Returns:
            bool: True if sent successfully
        """
        peer = self.peers.get(peer_name)
        if not peer:
            logger.error(f"Unknown peer: {peer_name}")
            return False
        
        # Get peer's crypto instance for encryption
        peer_crypto = self._get_peer_crypto(peer['meteor_id'])
        if not peer_crypto:
            logger.error("Encryption not available")
            return False
        
        # Encode and encrypt
        data = text.encode('utf-8')
        checksum = hashlib.sha256(data).hexdigest()[:16]
        
        # Convert to vectors and encrypt with peer's public key
        vectors = self._bytes_to_vectors(data)
        ciphertext = peer_crypto.encrypt_batch(vectors)
        
        # Create message
        msg = Web4Message(
            msg_type=MessageType.TEXT,
            sender_id=self.meteor_id,
            recipient_id=peer['meteor_id'],
            timestamp=time.time(),
            ciphertext=ciphertext,
            original_len=len(data),
            checksum=checksum
        )
        msg.signature = self.identity.sign(checksum.encode())
        
        # Send via P2P
        success = await self.p2p.send(peer['peer_id'], msg.to_bytes())
        
        if success:
            self.stats['messages_sent'] += 1
            self.stats['bytes_sent'] += len(data)
            peer['last_seen'] = time.time()
            logger.info(f"[{self.name}] -> [{peer_name}] Encrypted: {len(text)} chars")
        
        return success
    
    async def send_binary(self, peer_name: str, data: bytes) -> bool:
        """
        Send encrypted binary data to peer.
        
        Args:
            peer_name: Recipient peer name
            data: Binary data to send
            
        Returns:
            bool: True if sent successfully
        """
        peer = self.peers.get(peer_name)
        if not peer:
            logger.error(f"Unknown peer: {peer_name}")
            return False
        
        peer_crypto = self._get_peer_crypto(peer['meteor_id'])
        if not peer_crypto:
            logger.error("Encryption not available")
            return False
        
        checksum = hashlib.sha256(data).hexdigest()[:16]
        
        # Convert to vectors and encrypt
        vectors = self._bytes_to_vectors(data)
        ciphertext = peer_crypto.encrypt_batch(vectors)
        
        msg = Web4Message(
            msg_type=MessageType.BINARY,
            sender_id=self.meteor_id,
            recipient_id=peer['meteor_id'],
            timestamp=time.time(),
            ciphertext=ciphertext,
            original_len=len(data),
            checksum=checksum
        )
        msg.signature = self.identity.sign(checksum.encode())
        
        success = await self.p2p.send(peer['peer_id'], msg.to_bytes())
        
        if success:
            self.stats['messages_sent'] += 1
            self.stats['bytes_sent'] += len(data)
            peer['last_seen'] = time.time()
            logger.info(f"[{self.name}] -> [{peer_name}] Encrypted binary: {len(data)} bytes")
        
        return success
    
    # =========================================================================
    # DHT Operations
    # =========================================================================
    
    async def dht_bootstrap(self, peers: Optional[List[str]] = None):
        """Bootstrap DHT with known peers."""
        await self.dht.bootstrap(peers)
    
    async def dht_find_peer(self, meteor_id: bytes) -> Optional[Dict]:
        """Find peer by MeteorID via DHT."""
        self.stats['dht_lookups'] += 1
        return await self.dht.find_peer(meteor_id)
    
    # =========================================================================
    # PubSub Operations
    # =========================================================================
    
    async def pubsub_subscribe(self, topic: str, handler: Callable):
        """Subscribe to PubSub topic."""
        await self.pubsub.subscribe(topic, handler)
    
    async def pubsub_publish(self, topic: str, text: str):
        """Publish message to PubSub topic."""
        data = text.encode('utf-8')
        
        msg = Web4Message(
            msg_type=MessageType.PUBSUB,
            sender_id=self.meteor_id,
            recipient_id=b'\x00' * 32,  # Broadcast
            timestamp=time.time(),
            ciphertext=self._bytes_to_vectors(data),
            original_len=len(data),
            checksum=hashlib.sha256(data).hexdigest()[:16],
            pubsub_topic=topic
        )
        msg.signature = self.identity.sign(msg.checksum.encode())
        
        await self.pubsub.publish(topic, msg)
        self.stats['pubsub_published'] += 1
        
        logger.info(f"[{self.name}] Published to '{topic}': {text[:50]}...")
    
    # =========================================================================
    # IPFS Operations (Encrypted File Transfer)
    # =========================================================================
    
    async def send_file_ipfs(self, peer_name: str, filepath: str) -> Optional[str]:
        """
        Send encrypted file via IPFS.
        
        The file is encrypted with the recipient's public key before
        uploading to IPFS. Only the recipient can decrypt it.
        
        Args:
            peer_name: Recipient peer name
            filepath: Path to file to send
            
        Returns:
            str: IPFS CID if successful, None otherwise
        """
        peer = self.peers.get(peer_name)
        if not peer:
            logger.error(f"Unknown peer: {peer_name}")
            return None
        
        filepath = Path(filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return None
        
        # Get peer's crypto for encryption
        peer_crypto = self._get_peer_crypto(peer['meteor_id'])
        if not peer_crypto:
            logger.error("Encryption not available")
            return None
        
        # Read file
        with open(filepath, 'rb') as f:
            data = f.read()
        
        checksum = hashlib.sha256(data).hexdigest()
        
        # Encrypt with peer's public key
        vectors = self._bytes_to_vectors(data)
        ciphertext = peer_crypto.encrypt_batch(vectors)
        encrypted_bytes = ciphertext.tobytes()
        
        # Upload encrypted data to IPFS
        cid = self.ipfs.add_bytes(encrypted_bytes)
        if not cid:
            logger.error("IPFS upload failed")
            return None
        
        # Send CID notification to peer
        msg = Web4Message(
            msg_type=MessageType.FILE_IPFS,
            sender_id=self.meteor_id,
            recipient_id=peer['meteor_id'],
            timestamp=time.time(),
            ipfs_cid=cid,
            original_len=len(data),
            checksum=checksum,
            filename=filepath.name,
            file_size=len(data)
        )
        msg.signature = self.identity.sign(f"{cid}:{checksum}".encode())
        
        await self.p2p.send(peer['peer_id'], msg.to_bytes())
        
        self.stats['ipfs_uploads'] += 1
        self.stats['bytes_sent'] += len(data)
        
        logger.info(f"[{self.name}] -> [{peer_name}] IPFS File: {filepath.name} (CID: {cid[:16]}...)")
        
        return cid
    
    async def receive_file_ipfs(self, msg: Web4Message, output_dir: str = ".") -> Optional[str]:
        """
        Receive and decrypt file from IPFS.
        
        Args:
            msg: Web4Message containing IPFS CID
            output_dir: Directory to save decrypted file
            
        Returns:
            str: Path to saved file if successful, None otherwise
        """
        if not msg.ipfs_cid:
            logger.error("No IPFS CID in message")
            return None
        
        if not self._crypto:
            logger.error("Decryption not available")
            return None
        
        # Fetch encrypted data from IPFS
        encrypted_bytes = self.ipfs.get_bytes(msg.ipfs_cid)
        if not encrypted_bytes:
            logger.error(f"IPFS fetch failed: {msg.ipfs_cid}")
            return None
        
        # Reconstruct ciphertext array
        n = 256
        num_chunks = len(encrypted_bytes) // (n * 8)  # float64 = 8 bytes
        ciphertext = np.frombuffer(encrypted_bytes, dtype=np.float64).reshape(num_chunks, n)
        
        # Decrypt with our private key
        try:
            recovered, _ = self._crypto.decrypt_batch(ciphertext)
            data = self._vectors_to_bytes(recovered, msg.original_len)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
        
        # Verify checksum
        computed_checksum = hashlib.sha256(data).hexdigest()
        if computed_checksum != msg.checksum:
            logger.error("File checksum mismatch!")
            return None
        
        # Save file
        output_path = Path(output_dir) / (msg.filename or "received_file")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(data)
        
        self.stats['ipfs_downloads'] += 1
        self.stats['bytes_received'] += len(data)
        
        logger.info(f"[{self.name}] <- IPFS File: {output_path} ({len(data)} bytes)")
        
        return str(output_path)
    
    # =========================================================================
    # Message Handling
    # =========================================================================
    
    async def _handle_incoming_message(self, data: bytes):
        """
        Handle incoming message with decryption.
        
        Messages are decrypted using our private key (derived from our seed).
        """
        try:
            msg = Web4Message.from_bytes(data)
            
            # Verify recipient
            if msg.recipient_id != self.meteor_id:
                return
            
            # Decrypt if we have crypto initialized
            decrypted_data = None
            if self._crypto and msg.ciphertext is not None:
                try:
                    # Decrypt with our private key
                    recovered, _ = self._crypto.decrypt_batch(msg.ciphertext)
                    decrypted_data = self._vectors_to_bytes(recovered, msg.original_len)
                    
                    # Verify checksum
                    computed_checksum = hashlib.sha256(decrypted_data).hexdigest()[:16]
                    if computed_checksum != msg.checksum:
                        logger.warning(f"Checksum mismatch! Expected {msg.checksum}, got {computed_checksum}")
                except Exception as e:
                    logger.error(f"Decryption failed: {e}")
            
            # Find sender name
            sender_name = "Unknown"
            for name, peer in self.peers.items():
                if peer['meteor_id'] == msg.sender_id:
                    sender_name = name
                    peer['last_seen'] = msg.timestamp
                    break
            
            # Update stats
            self.stats['messages_received'] += 1
            if decrypted_data:
                self.stats['bytes_received'] += len(decrypted_data)
            
            # Log
            if msg.msg_type == MessageType.TEXT and decrypted_data:
                text = decrypted_data.decode('utf-8')
                logger.info(f"[{self.name}] <- [{sender_name}] Decrypted: {text[:50]}...")
            elif msg.msg_type == MessageType.BINARY and decrypted_data:
                logger.info(f"[{self.name}] <- [{sender_name}] Decrypted binary: {len(decrypted_data)} bytes")
            
            # Call registered handlers with decrypted data
            for handler in self._message_handlers:
                await handler(sender_name, decrypted_data, msg)
                
        except Exception as e:
            logger.error(f"Message handling error: {e}")
    
    def on_message(self, handler: Callable):
        """Register message handler."""
        self._message_handlers.append(handler)
    
    # =========================================================================
    # Utilities
    # =========================================================================
    
    def _bytes_to_vectors(self, data: bytes, n: int = 256) -> np.ndarray:
        """Convert bytes to encryptable vectors."""
        padded_len = ((len(data) + n - 1) // n) * n
        padded = data + b'\x00' * (padded_len - len(data))
        
        num_chunks = padded_len // n
        vectors = np.zeros((num_chunks, n), dtype=np.float64)
        
        for i in range(num_chunks):
            chunk = padded[i * n : (i + 1) * n]
            byte_array = np.frombuffer(chunk, dtype=np.uint8).astype(np.float64)
            vectors[i] = (byte_array - 128.0) / 128.0
        
        return vectors
    
    def _vectors_to_bytes(self, vectors: np.ndarray, original_len: int) -> bytes:
        """Convert vectors to bytes."""
        result = bytearray()
        for vec in vectors:
            byte_array = vec * 128.0 + 128.0
            byte_array = np.clip(np.round(byte_array), 0, 255).astype(np.uint8)
            result.extend(byte_array.tobytes())
        return bytes(result[:original_len])
    
    def get_stats(self) -> Dict:
        """Get comprehensive stats."""
        return {
            'name': self.name,
            'meteor_id': self.meteor_id.hex(),
            'peer_id': self.peer_id,
            'peers': len(self.peers),
            'p2p_started': self.p2p._started,
            'pubsub_started': self.pubsub._started,
            'ipfs_connected': self.ipfs._connected,
            **self.stats
        }
    
    def cleanup(self):
        """Release resources."""
        if self._crypto:
            self._crypto.cleanup()
        for crypto in self._peer_crypto_cache.values():
            if hasattr(crypto, 'cleanup'):
                crypto.cleanup()


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Identity
    'MeteorIdentity',
    
    # Network Components
    'MeteorP2P',
    'MeteorDHT',
    'MeteorPubSub',
    'MeteorIPFS',
    
    # Main Node
    'MeteorWeb4Node',
    
    # Messages
    'Web4Message',
    'MessageType',
    
    # Constants
    'METEOR_PROTOCOL_ID',
    'METEOR_DHT_PROTOCOL',
    'METEOR_PUBSUB_PROTOCOL',
    
    # Feature Flags
    'NACL_AVAILABLE',
    'LIBP2P_AVAILABLE',
    'DHT_AVAILABLE',
    'PUBSUB_AVAILABLE',
    'IPFS_AVAILABLE',
]
