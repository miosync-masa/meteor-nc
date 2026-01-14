"""
Meteor-NC Protocol Module

P2P communication protocols built on Meteor-NC cryptography.

Components:
    - basic: Core P2P messaging (MeteorNode, MeteorProtocol)
    - advanced: Testing & validation suite (MeteorNetwork, LatencySimulator)
    - web4: Full Web 4.0 implementation (libp2p, DHT, PubSub, IPFS)

Protocol Flow:
    1. Generate MeteorID (32 bytes) from seed
    2. Exchange IDs (no key exchange needed!)
    3. Encrypt with recipient's public key
    4. Decrypt with own private key

Example:
    >>> from meteor_nc.protocols import MeteorNode, MeteorProtocol
    >>>
    >>> # Create nodes
    >>> alice = MeteorNode(name="Alice")
    >>> bob = MeteorNode(name="Bob")
    >>>
    >>> # Exchange IDs (32 bytes each)
    >>> alice.add_peer("Bob", bob.get_meteor_id())
    >>> bob.add_peer("Alice", alice.get_meteor_id())
    >>>
    >>> # Send/receive (no key exchange!)
    >>> msg = alice.send("Bob", b"Hello!")
    >>> plaintext = bob.receive(msg)
"""

from .basic import (
    MeteorNode,
    MeteorProtocol,
    MeteorPeer,
    MeteorMessage,
)

from .advanced import (
    MeteorNetwork,
    LatencySimulator,
    LatencyProfile,
    SessionManager,
)

from .web4 import (
    MeteorWeb4Node,
    MeteorIdentity,
    MeteorP2P,
    MeteorDHT,
    MeteorPubSub,
    MeteorIPFS,
    Web4Message,
    MessageType,
)

__all__ = [
    # Basic P2P
    'MeteorNode',
    'MeteorProtocol',
    'MeteorPeer',
    'MeteorMessage',
    
    # Advanced Testing
    'MeteorNetwork',
    'LatencySimulator',
    'LatencyProfile',
    'SessionManager',
    
    # Web 4.0
    'MeteorWeb4Node',
    'MeteorIdentity',
    'MeteorP2P',
    'MeteorDHT',
    'MeteorPubSub',
    'MeteorIPFS',
    'Web4Message',
    'MessageType',
]
