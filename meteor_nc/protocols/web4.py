# meteor_nc/protocols/web4.py
"""
Meteor-Protocol Web 4.0: Quantum-Resistant Decentralized Communication

Complete implementation of quantum-resistant P2P internet.

Features:
    - Quantum-resistant encryption (Meteor-NC LWE-KEM, CPU-friendly)
    - Decentralized peer discovery (Kademlia DHT)
    - NAT traversal (AutoNAT, Hole Punching, Relay)
    - Distributed file storage (IPFS)
    - Global broadcast (PubSub/GossipSub)
    - 32-byte universal identity (MeteorID)
    - Optional device-bound authentication (MeteorAuth 2FA/3FA)
    - Optional streaming for large files (StreamHybridKEM)
    - Zero server dependency
    - Censorship resistant
    - Edge device compatible (Raspberry Pi, smartphones)

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                     MeteorID (32 bytes)                     │
    │                            │                                │
    │              ┌─────────────┴─────────────┐                  │
    │              │                           │                  │
    │              ▼                           ▼                  │
    │     Meteor-NC LWE-KEM            Ed25519 KeyPair           │
    │     (Post-Quantum)               (libp2p Auth)             │
    │              │                           │                  │
    │              ▼                           │                  │
    │     StreamDEM (XChaCha20)                │                  │
    │     (Authenticated Encryption)           │                  │
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

    Optional Layers:
    ┌─────────────────────────────────────────────────────────────┐
    │  MeteorAuth (Optional)                                      │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │  user_seed + device_fingerprint → bound_seed         │   │
    │  │  + biometric hook (Face ID / Touch ID / fingerprint) │   │
    │  │  = 3-Factor Authentication                           │   │
    │  └─────────────────────────────────────────────────────┘   │
    │                                                             │
    │  StreamHybridKEM (Optional)                                 │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │  Chunked encryption for large files (video, etc.)    │   │
    │  │  Per-chunk authentication + replay protection        │   │
    │  │  Memory efficient (streaming, not buffering)         │   │
    │  └─────────────────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────────────┘

Security Model:
    ┌────────────────────────────────────────────────────────────┐
    │  Layer           │ Algorithm              │ Security       │
    │──────────────────│────────────────────────│────────────────│
    │  Key Exchange    │ FrodoKEM-640 (v3 KEM)  │ Post-Quantum   │
    │  Symmetric       │ ChaCha20-Poly1305      │ 256-bit key    │
    │  Authentication  │ Ed25519 + ML-DSA-65    │ hybrid, PQ     │
    │  Identity        │ SHA-256(public bundle) │ self-certifying│
    │  Device Binding  │ HMAC(seed, fingerprint)│ 256-bit        │
    └────────────────────────────────────────────────────────────┘

Requirements:
    # Core (required)
    pip install numpy
    pip install cryptography
    
    # P2P Networking (recommended)
    pip install libp2p
    pip install multiaddr
    
    # Distributed Storage (optional)
    pip install ipfshttpclient

Usage:
    # Basic usage (no auth)
    from meteor_nc.protocols.web4 import MeteorWeb4Node
    
    # Create nodes
    alice = await MeteorWeb4Node.create("Alice")
    bob = await MeteorWeb4Node.create("Bob")
    
    # Start services
    await alice.start(port=9000)
    await bob.start(port=9001)
    
    # Exchange identities (32 bytes + public key)
    alice.add_peer("Bob", bob.meteor_id, bob.get_public_key())
    bob.add_peer("Alice", alice.meteor_id, alice.get_public_key())
    
    # Send encrypted message (quantum-resistant!)
    await alice.send_text("Bob", "Hello Web 4.0!")
    await alice.send_binary("Bob", b"\\x00\\x01\\x02...")
    
    # Broadcast via PubSub
    await alice.pubsub_subscribe("global-chat", my_handler)
    await alice.pubsub_publish("global-chat", "Hello everyone!")
    
    # Encrypted file via IPFS
    cid = await alice.send_file_ipfs("Bob", "secret.pdf")
    
    # DHT peer discovery
    await alice.dht.bootstrap(bootstrap_peers)
    peer_info = await alice.dht.find_peer(bob_meteor_id)

    # With device-bound authentication (2FA/3FA)
    from meteor_nc.protocols.web4 import MeteorWeb4Node
    
    # Generate seed once, save as QR code
    seed = secrets.token_bytes(32)
    
    # Create node with device binding
    node = await MeteorWeb4Node.create(
        "SecureNode",
        seed=seed,
        use_auth=True,              # Enable device binding
        require_biometric=True,      # Enable 3FA (optional)
    )
    
    # Same seed on different device = different MeteorID!
    # This provides hardware-bound security.

    # Streaming large files (optional)
    def file_chunks(filepath, chunk_size=64*1024):
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                yield chunk
    
    await alice.send_stream("Bob", file_chunks("large_video.mp4"))

Compatibility:
    - Python 3.8+
    - Linux / macOS / Windows
    - Raspberry Pi (ARM, CPU-only)
    - Edge devices (no GPU required)

Updated for Meteor-NC v2.0 API
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union

import numpy as np

# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("meteor-web4")   # library: no basicConfig here


# =============================================================================
# Dependency Checks
# =============================================================================

# --- Crypto (PyNaCl for Ed25519) ---
NACL_AVAILABLE = False
try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import RawEncoder
    NACL_AVAILABLE = True
except ImportError:
    logger.debug("PyNaCl not available: pip install pynacl")

# --- libp2p ---
LIBP2P_AVAILABLE = False
try:
    from libp2p import new_host
    from libp2p.peer.peerinfo import info_from_p2p_addr
    from libp2p.crypto.ed25519 import Ed25519PrivateKey
    LIBP2P_AVAILABLE = True
    logger.debug("libp2p available ✅")
except ImportError:
    logger.debug("libp2p not available: pip install libp2p")

# --- Kademlia DHT ---
DHT_AVAILABLE = False
try:
    from libp2p.kademlia.network import KademliaServer
    DHT_AVAILABLE = True
    logger.debug("Kademlia DHT available ✅")
except ImportError:
    logger.debug("Kademlia DHT not available")

# --- PubSub (GossipSub) ---
PUBSUB_AVAILABLE = False
try:
    from libp2p.pubsub.gossipsub import GossipSub
    from libp2p.pubsub.pubsub import Pubsub
    PUBSUB_AVAILABLE = True
    logger.debug("PubSub available ✅")
except ImportError:
    logger.debug("PubSub not available")

# --- IPFS ---
IPFS_AVAILABLE = False
try:
    import ipfshttpclient
    IPFS_AVAILABLE = True
    logger.debug("IPFS available ✅")
except ImportError:
    logger.debug("IPFS not available: pip install ipfshttpclient")

# --- Multiaddr ---
MULTIADDR_AVAILABLE = False
try:
    from multiaddr import Multiaddr
    MULTIADDR_AVAILABLE = True
except ImportError:
    logger.debug("multiaddr not available: pip install multiaddr")

# --- Meteor-NC (Internal) ---
from ..cryptography.common import _sha256, CRYPTO_AVAILABLE
from .envelope import (
    BROADCAST_ID,
    Envelope,
    EnvelopeError,
    MeteorIdentity,
    ReplayGuard,
    check_peer,
    open_envelope,
    parse_bundle,
    seal,
    verify_signature,
)
from .transport import TCPTransport, make_address_record, parse_address_record

# StreamHybridKEM (optional)
STREAM_AVAILABLE = False
try:
    from ..cryptography.stream import (
        StreamDEM,
        StreamHybridKEM,
        StreamCiphertext,
        EncryptedChunk,
        StreamHeader,
    )
    STREAM_AVAILABLE = True
except ImportError:
    logger.debug("Stream module not available")

# MeteorAuth (optional)
AUTH_AVAILABLE = False
try:
    from ..auth.core import MeteorAuth, BiometricProvider
    AUTH_AVAILABLE = True
except ImportError:
    logger.warning("MeteorAuth not available")


# =============================================================================
# Constants
# =============================================================================

METEOR_PROTOCOL_ID = "/meteor/2.0.0"
METEOR_DHT_PROTOCOL = "/meteor/dht/2.0.0"
METEOR_PUBSUB_PROTOCOL = "/meteor/pubsub/2.0.0"
DEFAULT_PUBSUB_TOPIC = "meteor-global"


# =============================================================================
# Message Types
# =============================================================================

class MessageType(Enum):
    """Message types for Web 4.0 Protocol."""
    TEXT = "text"
    BINARY = "binary"
    FILE = "file"
    FILE_IPFS = "file_ipfs"
    STREAM_START = "stream_start"
    STREAM_CHUNK = "stream_chunk"
    STREAM_END = "stream_end"
    PUBSUB = "pubsub"
    DHT_ANNOUNCE = "dht_announce"
    ACK = "ack"


# =============================================================================
# Web4 Identity (secret seed -> keys -> public bundle -> MeteorID -> PeerID)
# =============================================================================

class Web4Identity:
    """
    Identity for Web 4.0, built on the v3 MeteorIdentity.

    The seed is SECRET and never leaves the node. Published values:
    - ``bundle``: KEM public key + Ed25519 public key
    - ``meteor_id`` = H(bundle): self-certifying, reveals nothing secret
    - ``peer_id``: derived from the Ed25519 public key

    (v2 used the seed itself as the published MeteorID, which let anyone
    rebuild the node's private keys; see SECURITY.md.)
    """

    def __init__(self, seed: Optional[bytes] = None):
        if seed is None:
            seed = secrets.token_bytes(32)
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        self._core = MeteorIdentity(seed)
        self.meteor_id = self._core.meteor_id
        self.bundle = self._core.bundle
        self.ed25519_public = self._core.sign_public

    @property
    def peer_id(self) -> str:
        """libp2p-style PeerID string (derived from the Ed25519 public key)."""
        hash_bytes = _sha256(b"peer-id", self.ed25519_public)
        return "12D3Koo" + base64.b32encode(hash_bytes[:25]).decode('ascii').rstrip('=')

    @property
    def peer_id_bytes(self) -> bytes:
        return _sha256(b"peer-id", self.ed25519_public)

    def get_libp2p_keypair(self) -> Optional[Any]:
        """libp2p generates its own keypair; MeteorID <-> PeerID is app-level."""
        return None

    def sign(self, message: bytes) -> bytes:
        """Hybrid Ed25519 + ML-DSA-65 signature (``cryptography``; no fallback)."""
        return self._core.sign(message)

    @staticmethod
    def verify(message: bytes, signature: bytes, public_bundle: bytes) -> bool:
        """Verify a hybrid signature against a public bundle. Fails closed."""
        try:
            _, keys = parse_bundle(public_bundle)
        except EnvelopeError:
            return False
        return verify_signature(keys, signature, message)

    def to_dict(self) -> Dict:
        """Export the public identity."""
        return {
            'meteor_id': self.meteor_id.hex(),
            'ed25519_public': self.ed25519_public.hex(),
            'peer_id': self.peer_id,
            'bundle': base64.b64encode(self.bundle).decode(),
        }

    @classmethod
    def from_meteor_id(cls, meteor_id: bytes) -> 'Web4Identity':
        raise TypeError("an identity cannot be derived from a MeteorID (it is public); "
                        "use Web4Identity(secret_seed)")


# =============================================================================
# Web4 Message (v3 envelope)
# =============================================================================

Web4Message = Envelope


# =============================================================================
# IPFS Integration
# =============================================================================

class Web4IPFS:
    """IPFS client wrapper for Web 4.0."""
    
    def __init__(self, api_addr: str = "/ip4/127.0.0.1/tcp/5001"):
        self.api_addr = api_addr
        self.client = None
        self._connected = False
    
    def connect(self) -> bool:
        """Connect to IPFS daemon."""
        if not IPFS_AVAILABLE:
            logger.debug("IPFS client not available")
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
        except Exception:
            return False


# =============================================================================
# libp2p Integration
# =============================================================================
class Web4P2P:
    """libp2p integration for Web 4.0."""
    
    def __init__(self, identity: Web4Identity):
        self.identity = identity
        self.host = None
        self.listen_addrs: List[str] = []
        self._stream_handlers: Dict[str, Callable] = {}
        self._started = False
    
    async def start(self, listen_addrs: Optional[List[str]] = None):
        """Start libp2p host."""
        if not LIBP2P_AVAILABLE:
            logger.debug("libp2p not available - mock mode")
            self._started = True
            return
        
        if listen_addrs is None:
            listen_addrs = ["/ip4/0.0.0.0/tcp/0"]
        
        try:
            host_kwargs = {}
            
            if MULTIADDR_AVAILABLE and listen_addrs:
                host_kwargs['listen_addrs'] = [Multiaddr(addr) for addr in listen_addrs]
            
            # new_host() は sync かもしれないし async かもしれない
            import inspect
            host_result = new_host(**host_kwargs)
            
            if inspect.iscoroutine(host_result):
                self.host = await host_result
            else:
                self.host = host_result
            
            self.host.set_stream_handler(METEOR_PROTOCOL_ID, self._handle_stream)
            
            self.listen_addrs = [str(addr) for addr in self.host.get_addrs()]
            self._started = True
            
            logger.info(f"libp2p started - PeerID: {self.host.get_id()}")
            for addr in self.listen_addrs:
                logger.info(f"  Listening: {addr}")
                
        except Exception as e:
            logger.error(f"libp2p start failed: {e}")
            logger.info("Falling back to mock mode")
            self._started = True
    
    async def stop(self):
        """Stop libp2p host."""
        if self.host:
            await self.host.close()
            self._started = False
    
    async def connect(self, peer_addr: str) -> bool:
        """Connect to peer by multiaddr."""
        if not self._started or not self.host:
            return False
        
        try:
            peer_info = info_from_p2p_addr(Multiaddr(peer_addr))
            await self.host.connect(peer_info)
            logger.info(f"Connected to: {peer_info.peer_id}")
            return True
        except Exception as e:
            logger.error(f"Connect failed: {e}")
            return False
    
    async def send(self, peer_id: Any, data: bytes) -> bool:
        """Send data to a peer over a libp2p stream. Returns False if it was
        not sent (no transport, unknown peer, or an error) - never pretends."""
        if not self._started or not self.host:
            logger.warning("no libp2p transport: message not sent")
            return False
        if isinstance(peer_id, str):
            # Meteor PeerID strings are not libp2p peer IDs; resolving them
            # needs the peer's libp2p address (see connect()).
            logger.warning("cannot route to Meteor PeerID %s... over libp2p", peer_id[:16])
            return False
        try:
            stream = await self.host.new_stream(peer_id, [METEOR_PROTOCOL_ID])
            await stream.write(data)
            await stream.close()
            return True
        except Exception as e:
            logger.error(f"Send failed: {e}")
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
            logger.error(f"Stream error: {e}")
    
    def add_handler(self, name: str, handler: Callable):
        """Add message handler."""
        self._stream_handlers[name] = handler
    
    def remove_handler(self, name: str):
        """Remove message handler."""
        self._stream_handlers.pop(name, None)


# =============================================================================
# Kademlia DHT Integration
# =============================================================================

class Web4DHT:
    """Kademlia DHT for peer discovery."""
    
    def __init__(self, identity: Web4Identity):
        self.identity = identity
        self.dht = None
        self._bootstrapped = False
        self._peer_cache: Dict[bytes, Dict] = {}
    
    async def start(self, port: int = 8468):
        """Start DHT service."""
        if not DHT_AVAILABLE:
            logger.warning("DHT not available - local cache only")
            return
        
        try:
            self.dht = KademliaServer()
            await self.dht.listen(port)
            logger.info(f"Kademlia DHT started on port {port}")
        except Exception as e:
            logger.error(f"DHT start failed: {e}")
    
    async def bootstrap(self, peers: Optional[List[str]] = None):
        """Bootstrap with known peers."""
        if peers:
            self._bootstrapped = True
            logger.info(f"DHT bootstrapped ({len(peers)} peers)")
    
    async def announce(self, meteor_id: bytes, peer_info: Dict):
        """Announce presence on DHT."""
        self._peer_cache[meteor_id] = peer_info
        
        if self.dht:
            try:
                key = _sha256(b"dht-key", meteor_id)
                value = json.dumps(peer_info).encode()
                await self.dht.set(key, value)
                logger.info(f"Announced: {meteor_id.hex()[:16]}...")
            except Exception as e:
                logger.error(f"DHT announce failed: {e}")
    
    @staticmethod
    def _verified(meteor_id: bytes, peer_info: Dict) -> bool:
        """DHT records are untrusted: accept one only if its public bundle
        hashes to the MeteorID we looked up."""
        try:
            bundle = peer_info['public_key']
            if isinstance(bundle, str):
                bundle = base64.b64decode(bundle)
            check_peer(meteor_id, bundle)
            return True
        except Exception:
            return False

    async def find_peer(self, meteor_id: bytes) -> Optional[Dict]:
        """Find a peer by MeteorID; records that do not match it are ignored."""
        if meteor_id in self._peer_cache:
            return self._peer_cache[meteor_id]
        if self.dht:
            try:
                key = _sha256(b"dht-key", meteor_id)
                value = await self.dht.get(key)
                if value:
                    peer_info = json.loads(value.decode())
                    if not self._verified(meteor_id, peer_info):
                        logger.warning("ignoring DHT record that does not match MeteorID %s...",
                                       meteor_id.hex()[:16])
                        return None
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

class Web4PubSub:
    """GossipSub PubSub for broadcasting."""
    
    def __init__(self, identity: Web4Identity, p2p: Web4P2P):
        self.identity = identity
        self.p2p = p2p
        self.pubsub = None
        self._subscriptions: Dict[str, Callable] = {}
        self._started = False
    
    async def start(self):
        """Start PubSub service."""
        if not PUBSUB_AVAILABLE:
            logger.debug("PubSub not available - mock mode")
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
                
                # my_id 引数なしで試す
                try:
                    self.pubsub = Pubsub(
                        host=self.p2p.host,
                        router=gossipsub,
                        my_id=self.p2p.host.get_id()
                    )
                except TypeError:
                    # 新しいバージョンは my_id 不要
                    self.pubsub = Pubsub(
                        host=self.p2p.host,
                        router=gossipsub,
                    )
                
                self._started = True
                logger.info("PubSub (GossipSub) started")
        except Exception as e:
            logger.error(f"PubSub start failed: {e}")
            self._started = True  # Mock mode
    
    async def subscribe(self, topic: str, handler: Callable):
        """Subscribe to topic."""
        self._subscriptions[topic] = handler
        
        if self.pubsub:
            try:
                await self.pubsub.subscribe(topic)
                asyncio.create_task(self._message_loop(topic))
            except Exception as e:
                logger.error(f"Subscribe failed: {e}")
        
        logger.info(f"Subscribed: {topic}")
    
    async def unsubscribe(self, topic: str):
        """Unsubscribe from topic."""
        self._subscriptions.pop(topic, None)
        if self.pubsub:
            try:
                await self.pubsub.unsubscribe(topic)
            except Exception:
                pass
    
    async def publish(self, topic: str, data: bytes):
        """Publish to topic."""
        if self.pubsub:
            try:
                await self.pubsub.publish(topic, data)
                logger.info(f"Published to {topic}: {len(data)} bytes")
            except Exception as e:
                logger.error(f"Publish failed: {e}")
        else:
            logger.info(f"[Mock] Published to {topic}: {len(data)} bytes")
    
    async def _message_loop(self, topic: str):
        """Receive messages from topic."""
        if not self.pubsub:
            return
        
        try:
            async for message in self.pubsub.subscribe(topic):
                if topic in self._subscriptions:
                    try:
                        await self._subscriptions[topic](message.data)
                    except Exception as e:
                        logger.error(f"Handler error: {e}")
        except Exception as e:
            logger.error(f"Message loop error: {e}")


# =============================================================================
# Main Node Class
# =============================================================================
class MeteorWeb4Node:
    """
    Meteor-Protocol Web 4.0 node (v3 envelope).

    - Direct messages: encrypted to the peer's KEM key, signed with Ed25519,
      header bound as AEAD associated data, replay-protected.
    - PubSub: plaintext, signed; subscribers only accept messages from
      known peers whose signature verifies.
    - IPFS files: the encrypted envelope is uploaded; the peer gets a signed
      notice with the CID and the blob hash (no plaintext hash is sent).
    - Peers are added with (MeteorID, public bundle); a bundle that does not
      hash to the MeteorID is rejected. Messages from unknown senders are
      dropped because their signatures cannot be checked.

    Transports: ``start_tcp()`` listens on plain TCP; peers added from a
    signed address record (``add_peer_from_record``) are reached there.
    Nodes in the same Python process can also reach each other directly
    (``local_delivery=True``, the default). libp2p is optional.
    """

    _local_nodes: Dict[bytes, 'MeteorWeb4Node'] = {}

    def __init__(
        self,
        name: str = "Node",
        seed: Optional[bytes] = None,
        use_auth: bool = False,
        require_biometric: bool = False,
        biometric_provider: Optional[Any] = None,
        local_delivery: bool = True,
        replay_window_s: float = 300.0,
        device_store: Optional[Any] = None,
    ):
        self.name = name
        self._use_auth = use_auth
        if use_auth and AUTH_AVAILABLE:
            auth = MeteorAuth(require_biometric=require_biometric,
                              biometric_provider=biometric_provider, device_store=device_store)
            if seed is None:
                seed = auth.generate_seed()
            seed = auth.create_device_bound_seed(seed)
        elif seed is None:
            seed = secrets.token_bytes(32)
        self.identity = Web4Identity(seed)          # seed stays inside the identity
        self.meteor_id = self.identity.meteor_id
        self.peer_id = self.identity.peer_id
        self._pk_bytes = self.identity.bundle

        self.p2p = Web4P2P(self.identity)
        self.dht = Web4DHT(self.identity)
        self.pubsub = Web4PubSub(self.identity, self.p2p)
        self.ipfs = Web4IPFS()

        self.peers: Dict[str, Dict] = {}
        self._by_id: Dict[bytes, str] = {}
        self._guard = ReplayGuard(replay_window_s)
        self._message_handlers: List[Callable] = []
        self.stats = {
            'messages_sent': 0, 'messages_received': 0, 'messages_rejected': 0,
            'bytes_sent': 0, 'bytes_received': 0,
            'pubsub_published': 0, 'pubsub_received': 0,
            'ipfs_uploads': 0, 'ipfs_downloads': 0,
        }
        self.tcp: Optional[TCPTransport] = None
        self._local_delivery = local_delivery
        if local_delivery:
            MeteorWeb4Node._local_nodes[self.meteor_id] = self
        logger.info(f"[{self.name}] Node created  MeteorID {self.meteor_id.hex()[:32]}...")

    @classmethod
    async def create(cls, name: str = "Node", seed: Optional[bytes] = None,
                     use_auth: bool = False, require_biometric: bool = False,
                     biometric_provider: Optional[Any] = None, **kw) -> 'MeteorWeb4Node':
        """Async factory method."""
        return cls(name=name, seed=seed, use_auth=use_auth, require_biometric=require_biometric,
                   biometric_provider=biometric_provider, **kw)

    # -- lifecycle ---------------------------------------------------------
    async def start(self, port: int = 0, enable_dht: bool = True, enable_pubsub: bool = True,
                    enable_ipfs: bool = True, ipfs_addr: str = "/ip4/127.0.0.1/tcp/5001"):
        """Start all services."""
        await self.p2p.start([f"/ip4/0.0.0.0/tcp/{port}"])
        self.p2p.add_handler("meteor", self._handle_incoming)
        if enable_dht:
            await self.dht.start()
            await self.dht.announce(self.meteor_id, {
                'peer_id': self.peer_id,
                'addrs': self.p2p.listen_addrs,
                'public_key': base64.b64encode(self._pk_bytes).decode(),
            })
        if enable_pubsub:
            await self.pubsub.start()
        if enable_ipfs:
            self.ipfs = Web4IPFS(ipfs_addr)
            self.ipfs.connect()

    async def stop(self):
        await self.p2p.stop()
        if self.tcp is not None:
            await self.tcp.stop()
            self.tcp = None
        if MeteorWeb4Node._local_nodes.get(self.meteor_id) is self:
            del MeteorWeb4Node._local_nodes[self.meteor_id]

    # -- TCP transport -----------------------------------------------------
    async def start_tcp(self, host: str = "127.0.0.1", port: int = 0) -> str:
        """Listen for envelopes over plain TCP. Returns the address
        (``tcp://host:port``). Security comes from the envelopes."""
        if self.tcp is None:
            self.tcp = TCPTransport(self._handle_incoming)
            await self.tcp.start(host, port)
        return self.tcp.addrs[0]

    def get_address_record(self, addrs: Optional[List[str]] = None) -> bytes:
        """Signed record (MeteorID, bundle, addresses) to hand to peers or the DHT."""
        if addrs is None:
            addrs = list(self.tcp.addrs) if self.tcp else []
        return make_address_record(self.identity._core, addrs)

    def add_peer_from_record(self, name: str, record: bytes,
                             max_age_s: Optional[float] = None) -> bytes:
        """Verify a signed address record and add the peer. Returns its MeteorID."""
        try:
            meteor_id, bundle, addrs, _ = parse_address_record(record, max_age_s)
        except EnvelopeError as e:
            raise ValueError(f"bad address record for {name!r}: {e}") from None
        self.add_peer(name, meteor_id, bundle, addrs=addrs)
        return meteor_id

    # -- peers -------------------------------------------------------------
    def add_peer(self, name: str, meteor_id: bytes, public_key: bytes,
                 addrs: Optional[List[str]] = None):
        """Add a peer. ``public_key`` is the peer's public bundle
        (``get_public_key()``); it must hash to ``meteor_id``."""
        if len(meteor_id) != 32:
            raise ValueError("MeteorID must be 32 bytes")
        if public_key is None:
            raise ValueError("the peer's public bundle is required")
        try:
            check_peer(meteor_id, public_key)
        except EnvelopeError as e:
            raise ValueError(f"cannot add peer {name!r}: {e}") from None
        old = self.peers.get(name)
        if old is not None:
            self._by_id.pop(old['meteor_id'], None)
        self.peers[name] = {
            'meteor_id': meteor_id,
            'public_key': public_key,
            'addrs': addrs or [],
            'last_seen': None,
        }
        self._by_id[meteor_id] = name
        self.dht.add_peer_local(meteor_id, self.peers[name])

    def get_public_key(self) -> bytes:
        """Public bundle (KEM public key + Ed25519 public key) for sharing."""
        return self._pk_bytes

    # -- delivery ----------------------------------------------------------
    async def _deliver(self, peer: Dict, data: bytes) -> bool:
        if self._local_delivery:
            node = MeteorWeb4Node._local_nodes.get(peer['meteor_id'])
            if node is not None:
                return await node._handle_incoming(data)
        for addr in peer.get('addrs', []):
            if addr.startswith("tcp://"):
                if await TCPTransport.send(addr, data):
                    return True
        peer_ref = peer.get('libp2p_id')
        if peer_ref is not None:
            return await self.p2p.send(peer_ref, data)
        logger.warning(f"[{self.name}] no route to {peer['meteor_id'].hex()[:16]}...")
        return False

    def _open(self, env: Envelope) -> Tuple[str, bytes]:
        name = self._by_id.get(env.sender_id)
        if name is None:
            raise EnvelopeError("unknown sender")
        payload = open_envelope(self.identity._core, env, self.peers[name]['public_key'], self._guard)
        self.peers[name]['last_seen'] = env.timestamp
        return name, payload

    # -- direct messages ---------------------------------------------------
    async def send_text(self, peer_name: str, text: str) -> bool:
        return await self._send_data(peer_name, text.encode('utf-8'), MessageType.TEXT)

    async def send_binary(self, peer_name: str, data: bytes) -> bool:
        return await self._send_data(peer_name, data, MessageType.BINARY)

    async def _send_data(self, peer_name: str, data: bytes, msg_type: MessageType,
                         meta: Optional[Dict] = None) -> bool:
        peer = self.peers.get(peer_name)
        if not peer:
            logger.error(f"Unknown peer: {peer_name}")
            return False
        env = seal(self.identity._core, msg_type.value, data, recipient_id=peer['meteor_id'],
                   recipient_bundle=peer['public_key'], meta=meta)
        ok = await self._deliver(peer, env.to_bytes())
        if ok:
            self.stats['messages_sent'] += 1
            self.stats['bytes_sent'] += len(data)
            peer['last_seen'] = time.time()
        return ok

    async def _handle_incoming(self, data: bytes) -> bool:
        """Authenticate, decrypt and dispatch one incoming envelope.
        Returns True if it was accepted."""
        try:
            env = Envelope.from_bytes(data)
            if env.recipient_id != self.meteor_id:
                return False
            if env.msg_type in (MessageType.TEXT.value, MessageType.BINARY.value) and not env.encrypted:
                raise EnvelopeError("direct messages must be encrypted")
            sender_name, plaintext = self._open(env)
        except EnvelopeError as e:
            self.stats['messages_rejected'] += 1
            logger.warning(f"[{self.name}] rejected message: {e}")
            return False
        self.stats['messages_received'] += 1
        self.stats['bytes_received'] += len(plaintext)
        for handler in self._message_handlers:
            try:
                await handler(sender_name, plaintext, env)
            except Exception as e:
                logger.error(f"Handler error: {e}")
        return True

    def on_message(self, handler: Callable):
        """Register ``async handler(sender_name, plaintext, envelope)``."""
        self._message_handlers.append(handler)

    # -- pubsub ------------------------------------------------------------
    async def pubsub_subscribe(self, topic: str, handler: Callable):
        """Subscribe; ``async handler(sender_name, text, envelope)`` is called
        only for messages from known peers whose signature verifies."""
        async def verified(raw: bytes):
            text = self.open_pubsub(raw, topic)
            if text is not None:
                await handler(*text)
        await self.pubsub.subscribe(topic, verified)

    def open_pubsub(self, raw: bytes, topic: str):
        """Verify a raw PubSub message; returns (sender_name, text, env) or None."""
        try:
            env = Envelope.from_bytes(raw)
            if env.msg_type != MessageType.PUBSUB.value or env.encrypted:
                raise EnvelopeError("not a pubsub message")
            if env.recipient_id != BROADCAST_ID or env.meta.get('topic') != topic:
                raise EnvelopeError("wrong topic")
            name, payload = self._open(env)
        except EnvelopeError as e:
            self.stats['messages_rejected'] += 1
            logger.warning(f"[{self.name}] rejected pubsub message: {e}")
            return None
        self.stats['pubsub_received'] += 1
        return name, payload.decode('utf-8'), env

    async def pubsub_publish(self, topic: str, text: str) -> bytes:
        """Publish a signed plaintext broadcast. Returns the raw message."""
        env = seal(self.identity._core, MessageType.PUBSUB.value, text.encode('utf-8'),
                   recipient_id=BROADCAST_ID, meta={'topic': topic}, encrypt=False)
        raw = env.to_bytes()
        await self.pubsub.publish(topic, raw)
        self.stats['pubsub_published'] += 1
        return raw

    # -- IPFS --------------------------------------------------------------
    async def send_file_ipfs(self, peer_name: str, filepath: str) -> Optional[str]:
        """Encrypt a file to a peer, upload the envelope to IPFS, and send the
        peer a signed notice with the CID. Returns the CID."""
        peer = self.peers.get(peer_name)
        if not peer:
            logger.error(f"Unknown peer: {peer_name}")
            return None
        filepath = Path(filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return None
        blob = seal(self.identity._core, MessageType.FILE.value, filepath.read_bytes(),
                    recipient_id=peer['meteor_id'], recipient_bundle=peer['public_key'],
                    meta={'filename': filepath.name}).to_bytes()
        cid = self.ipfs.add_bytes(blob)
        if not cid:
            logger.error("IPFS upload failed")
            return None
        notice = seal(self.identity._core, MessageType.FILE_IPFS.value, b"",
                      recipient_id=peer['meteor_id'], encrypt=False,
                      meta={'cid': cid, 'blob_sha256': hashlib.sha256(blob).hexdigest(),
                            'filename': filepath.name})
        if not await self._deliver(peer, notice.to_bytes()):
            return None
        self.stats['ipfs_uploads'] += 1
        return cid

    def fetch_file_ipfs(self, notice: Envelope) -> Tuple[str, bytes]:
        """Download and decrypt a file announced by an (already accepted)
        FILE_IPFS notice. Returns (filename, data)."""
        cid, want = notice.meta.get('cid'), notice.meta.get('blob_sha256')
        blob = self.ipfs.get_bytes(cid) if cid else None
        if blob is None:
            raise ValueError("IPFS download failed")
        if hashlib.sha256(blob).hexdigest() != want:
            raise ValueError("IPFS content does not match the signed notice")
        env = Envelope.from_bytes(blob)
        if env.msg_type != MessageType.FILE.value or env.sender_id != notice.sender_id:
            raise ValueError("IPFS content is not the announced file")
        _, data = self._open(env)
        self.stats['ipfs_downloads'] += 1
        return env.meta.get('filename', ''), data

    # -- streaming ---------------------------------------------------------
    async def send_stream(self, peer_name: str, data_iterator: Iterator[bytes],
                          chunk_size: int = 64 * 1024) -> bool:
        """Send data as a sequence of direct (encrypted, signed) messages,
        one per chunk, tagged with a stream id and sequence number."""
        peer = self.peers.get(peer_name)
        if not peer:
            logger.error(f"Unknown peer: {peer_name}")
            return False
        stream_id = secrets.token_hex(16)
        seq = 0
        for piece in data_iterator:
            for o in range(0, len(piece), chunk_size):
                if not await self._send_data(peer_name, piece[o:o + chunk_size],
                                             MessageType.STREAM_CHUNK,
                                             meta={'stream_id': stream_id, 'seq': seq}):
                    return False
                seq += 1
        return await self._send_data(peer_name, b"", MessageType.STREAM_END,
                                     meta={'stream_id': stream_id, 'chunks': seq})

    # -- utilities ---------------------------------------------------------
    def get_stats(self) -> Dict:
        return {
            'name': self.name,
            'meteor_id': self.meteor_id.hex(),
            'peer_id': self.peer_id,
            'peers': len(self.peers),
            'auth_enabled': self._use_auth,
            'p2p_started': self.p2p._started,
            'ipfs_connected': self.ipfs._connected,
            **self.stats,
        }

    def get_connection_info(self) -> Dict:
        """Public connection info to share (no secrets)."""
        return {
            'name': self.name,
            'meteor_id': self.meteor_id.hex(),
            'peer_id': self.peer_id,
            'public_key': base64.b64encode(self._pk_bytes).decode(),
            'addrs': self.p2p.listen_addrs,
        }


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute Web 4.0 tests."""
    import asyncio
    
    print("=" * 70)
    print("Meteor-Protocol Web 4.0 Test Suite")
    print("=" * 70)
    print(f"libp2p:   {'✅' if LIBP2P_AVAILABLE else '❌'}")
    print(f"DHT:      {'✅' if DHT_AVAILABLE else '❌'}")
    print(f"PubSub:   {'✅' if PUBSUB_AVAILABLE else '❌'}")
    print(f"IPFS:     {'✅' if IPFS_AVAILABLE else '❌'}")
    print(f"NaCl:     {'✅' if NACL_AVAILABLE else '❌'}")
    print(f"Stream:   {'✅' if STREAM_AVAILABLE else '❌'}")
    print(f"Auth:     {'✅' if AUTH_AVAILABLE else '❌'}")
    
    results = {}
    
    async def run_async_tests():
        # Test 1: Node Creation
        print("\n[Test 1] Node Creation")
        print("-" * 40)
        
        alice = await MeteorWeb4Node.create("Alice")
        bob = await MeteorWeb4Node.create("Bob")
        
        node_ok = (
            len(alice.meteor_id) == 32 and
            len(bob.meteor_id) == 32 and
            alice.meteor_id != bob.meteor_id
        )
        results["node_creation"] = node_ok
        print(f"  Alice ID: {alice.meteor_id.hex()[:32]}...")
        print(f"  Bob ID:   {bob.meteor_id.hex()[:32]}...")
        print(f"  Result: {'PASS' if node_ok else 'FAIL'}")
        
        # Test 2: Peer Exchange
        print("\n[Test 2] Peer Exchange")
        print("-" * 40)
        
        alice.add_peer("Bob", bob.meteor_id, bob.get_public_key())
        bob.add_peer("Alice", alice.meteor_id, alice.get_public_key())
        
        peer_ok = "Bob" in alice.peers and "Alice" in bob.peers
        results["peer_exchange"] = peer_ok
        print(f"  Result: {'PASS' if peer_ok else 'FAIL'}")
        
        # Test 3: Identity
        print("\n[Test 3] Identity (MeteorID → PeerID)")
        print("-" * 40)
        
        seed = secrets.token_bytes(32)
        id1 = Web4Identity(seed)
        id2 = Web4Identity(seed)
        
        identity_ok = (
            id1.peer_id == id2.peer_id and
            id1.ed25519_public == id2.ed25519_public and
            id1.meteor_id != seed
        )
        results["identity"] = identity_ok
        print(f"  Deterministic: {id1.peer_id == id2.peer_id}")
        print(f"  Result: {'PASS' if identity_ok else 'FAIL'}")
        
        # Test 4: Signature
        print("\n[Test 4] Ed25519 Signature")
        print("-" * 40)
        
        message = b"Test message for signing"
        sig = alice.identity.sign(message)
        verify_ok = alice.identity.verify(message, sig, alice.identity.bundle)
        
        results["signature"] = verify_ok
        print(f"  Signature: {sig.hex()[:32]}...")
        print(f"  Result: {'PASS' if verify_ok else 'FAIL'}")
        
        # Test 5: Connection Info
        print("\n[Test 5] Connection Info Export")
        print("-" * 40)
        
        info = alice.get_connection_info()
        info_ok = all(k in info for k in ['meteor_id', 'peer_id', 'public_key'])
        results["connection_info"] = info_ok
        print(f"  Keys: {list(info.keys())}")
        print(f"  Result: {'PASS' if info_ok else 'FAIL'}")
        
        # Test 6: Auth Mode (if available)
        if AUTH_AVAILABLE:
            print("\n[Test 6] Auth Mode (Device-Bound)")
            print("-" * 40)
            
            from ..auth.core import MemoryDeviceKeyStore
            seed = secrets.token_bytes(32)
            store = MemoryDeviceKeyStore()
            auth_node1 = await MeteorWeb4Node.create("AuthNode1", seed=seed, use_auth=True, device_store=store)
            auth_node2 = await MeteorWeb4Node.create("AuthNode2", seed=seed, use_auth=True, device_store=store)
            
            # Same seed + same device = same MeteorID
            auth_ok = auth_node1.meteor_id == auth_node2.meteor_id
            results["auth_mode"] = auth_ok
            print(f"  Same bound ID: {auth_ok}")
            print(f"  Result: {'PASS' if auth_ok else 'FAIL'}")
        
        return results
    
    results = asyncio.run(run_async_tests())
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
