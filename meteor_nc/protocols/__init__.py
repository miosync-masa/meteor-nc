# meteor_nc/protocols/__init__.py
"""Meteor-NC Protocol Layer"""

from .meteor_protocol import (
    MeteorNode,
    MeteorPeer,
    MeteorMessage,
    MeteorProtocol,
)

from .advanced import (
    MeteorNetwork,
    LatencySimulator,
    LatencyProfile,
    SessionManager,
    run_comprehensive_tests,
)

# Web 4.0 Protocol (optional dependencies)
WEB4_AVAILABLE = False
try:
    from .web4 import (
        MeteorWeb4Node,
        Web4Identity,
        Web4Message,
        Web4P2P,
        Web4DHT,
        Web4PubSub,
        Web4IPFS,
        MessageType,
        # Availability flags
        LIBP2P_AVAILABLE,
        DHT_AVAILABLE,
        PUBSUB_AVAILABLE,
        IPFS_AVAILABLE,
        NACL_AVAILABLE,
        STREAM_AVAILABLE,
        AUTH_AVAILABLE,
    )
    WEB4_AVAILABLE = True
except ImportError:
    # Web4 dependencies not installed
    pass

__all__ = [
    # Basic Protocol
    "MeteorNode",
    "MeteorPeer",
    "MeteorMessage",
    "MeteorProtocol",
    
    # Advanced Testing
    "MeteorNetwork",
    "LatencySimulator",
    "LatencyProfile",
    "SessionManager",
    "run_comprehensive_tests",
    
    # Web 4.0 Protocol
    "MeteorWeb4Node",
    "Web4Identity",
    "Web4Message",
    "Web4P2P",
    "Web4DHT",
    "Web4PubSub",
    "Web4IPFS",
    "MessageType",
    
    # Availability Flags
    "WEB4_AVAILABLE",
    "LIBP2P_AVAILABLE",
    "DHT_AVAILABLE",
    "PUBSUB_AVAILABLE",
    "IPFS_AVAILABLE",
    "NACL_AVAILABLE",
    "STREAM_AVAILABLE",
    "AUTH_AVAILABLE",
]
