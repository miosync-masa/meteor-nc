# meteor_nc/__init__.py
"""
Meteor-NC: Post-Quantum Hybrid Cryptosystem

WEB 4.0 Protocol Ready!
- Post-Quantum Key Encapsulation (LWE-KEM)
- Kyber-Style Coefficient Compression (v2.0) ← NEW!
- High-Speed Streaming Encryption (XChaCha20-Poly1305)
- P2P Communication Protocol (libp2p)
- Decentralized Peer Discovery (Kademlia DHT)
- Global Broadcast (PubSub/GossipSub)
- Distributed Storage (IPFS)
- Device-Bound Authentication (2FA/3FA)
- Edge Device Compatible (CPU-only, no GPU required)

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │  meteor_nc                                              │
    │  ├── cryptography/     # Core crypto primitives         │
    │  │   ├── core.py       # LWEKEM, HybridKEM (CPU)        │
    │  │   ├── batch.py      # BatchKEM (GPU accelerated)     │
    │  │   ├── compression.py # Coefficient compression (v2)  │
    │  │   ├── stream.py     # StreamDEM (chunked encryption) │
    │  │   └── practical.py  # High-level API                 │
    │  │                                                      │
    │  ├── protocols/        # P2P communication              │
    │  │   ├── meteor_protocol.py  # Basic P2P               │
    │  │   ├── advanced.py         # Testing & validation    │
    │  │   └── web4.py             # Full Web 4.0 stack      │
    │  │                                                      │
    │  └── auth/             # Authentication                 │
    │      └── core.py       # Device-bound 2FA/3FA          │
    └─────────────────────────────────────────────────────────┘

v2.0 Compression:
    - Wire-based FO transform (canonical form for verification)
    - Ciphertext sizes: 518B (n=256), 1094B (n=512), 2310B (n=1024)
    - ~75% bandwidth reduction vs uncompressed
"""

__version__ = "2.1.0"

# =============================================================================
# Core Cryptography (CPU/GPU optional)
# =============================================================================

from .cryptography.common import (
    HKDF,
    Q_DEFAULT,
    MSG_BYTES,
    MSG_BITS,
    SECURITY_PARAMS,
    GPU_AVAILABLE,
    CRYPTO_AVAILABLE,
)

from .cryptography.core import (
    LWEKEM,
    HybridKEM,
    SymmetricMixer,
)

# =============================================================================
# Compression (v2.0) ← NEW!
# =============================================================================

COMPRESSION_AVAILABLE = False
try:
    from .cryptography.compression import (
        compress,
        decompress,
        compress_ciphertext,
        decompress_ciphertext,
        compressed_size,
        get_compression_params,
        COMPRESSION_PARAMS,
    )
    COMPRESSION_AVAILABLE = True
except ImportError:
    pass

# =============================================================================
# Batch KEM (GPU required)
# =============================================================================

BATCH_AVAILABLE = False
try:
    from .cryptography.batch import BatchLWEKEM, BatchHybridKEM, BatchCiphertext
    BATCH_AVAILABLE = True
except ImportError:
    pass

# Batch Multi-Level (n=256/512/1024)
BATCH_MULTILEVEL_AVAILABLE = False
try:
    from .cryptography.kernels import BATCH_V2_AVAILABLE, BLAKE3_V2_AVAILABLE
    BATCH_MULTILEVEL_AVAILABLE = BATCH_V2_AVAILABLE and BLAKE3_V2_AVAILABLE
except ImportError:
    pass

# =============================================================================
# Stream DEM (XChaCha20-Poly1305)
# =============================================================================

STREAM_AVAILABLE = False
try:
    from .cryptography.stream import (
        StreamDEM,
        StreamHybridKEM,
        StreamCiphertext,
        EncryptedChunk,
        StreamHeader,
    )
    STREAM_AVAILABLE = True
except ImportError:
    pass

# =============================================================================
# Practical API (String/File encryption)
# =============================================================================

PRACTICAL_AVAILABLE = False
try:
    from .cryptography.practical import (
        MeteorPractical,
        quick_encrypt,
        quick_decrypt,
    )
    PRACTICAL_AVAILABLE = True
except ImportError:
    pass

# =============================================================================
# Protocol Layer (Basic P2P)
# =============================================================================

PROTOCOL_AVAILABLE = False
try:
    from .protocols.meteor_protocol import (
        MeteorNode,
        MeteorPeer,
        MeteorMessage,
        MeteorProtocol,
    )
    PROTOCOL_AVAILABLE = True
except ImportError:
    pass

# =============================================================================
# Advanced Protocol Testing
# =============================================================================

ADVANCED_AVAILABLE = False
try:
    from .protocols.advanced import (
        MeteorNetwork,
        LatencySimulator,
        LatencyProfile,
        SessionManager,
        run_comprehensive_tests,
    )
    ADVANCED_AVAILABLE = True
except ImportError:
    pass

# =============================================================================
# Web 4.0 Protocol (Full Stack)
# =============================================================================

WEB4_AVAILABLE = False
LIBP2P_AVAILABLE = False
DHT_AVAILABLE = False
PUBSUB_AVAILABLE = False
IPFS_AVAILABLE = False
NACL_AVAILABLE = False

try:
    from .protocols.web4 import (
        MeteorWeb4Node,
        Web4Identity,
        Web4Message,
        Web4P2P,
        Web4DHT,
        Web4PubSub,
        Web4IPFS,
        MessageType,
        LIBP2P_AVAILABLE,
        DHT_AVAILABLE,
        PUBSUB_AVAILABLE,
        IPFS_AVAILABLE,
        NACL_AVAILABLE,
    )
    WEB4_AVAILABLE = True
except ImportError:
    pass

# =============================================================================
# Authentication (Device-Bound 2FA/3FA)
# =============================================================================

AUTH_AVAILABLE = False
try:
    from .auth.core import (
        MeteorAuth,
        MeteorAuthServer,
        UserRecord,
        BiometricProvider,
        BiometricStatus,
        CallbackBiometricProvider,
        MockBiometricProvider,
        verify_device_binding,
        generate_recovery_codes,
    )
    AUTH_AVAILABLE = True
except ImportError:
    pass

# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Version
    "__version__",
    
    # -------------------------------------------------------------------------
    # Core Cryptography
    # -------------------------------------------------------------------------
    "HKDF",
    "LWEKEM",
    "HybridKEM",
    "SymmetricMixer",
    
    # -------------------------------------------------------------------------
    # Compression (v2.0)
    # -------------------------------------------------------------------------
    "compress",
    "decompress",
    "compress_ciphertext",
    "decompress_ciphertext",
    "compressed_size",
    "get_compression_params",
    "COMPRESSION_PARAMS",
    
    # -------------------------------------------------------------------------
    # Batch KEM (GPU)
    # -------------------------------------------------------------------------
    "BatchLWEKEM",
    "BatchHybridKEM",
    "BatchCiphertext",
    
    # -------------------------------------------------------------------------
    # Stream DEM
    # -------------------------------------------------------------------------
    "StreamDEM",
    "StreamHybridKEM",
    "StreamCiphertext",
    "EncryptedChunk",
    "StreamHeader",
    
    # -------------------------------------------------------------------------
    # Practical API
    # -------------------------------------------------------------------------
    "MeteorPractical",
    "quick_encrypt",
    "quick_decrypt",
    
    # -------------------------------------------------------------------------
    # Protocol (Basic)
    # -------------------------------------------------------------------------
    "MeteorNode",
    "MeteorPeer",
    "MeteorMessage",
    "MeteorProtocol",
    
    # -------------------------------------------------------------------------
    # Protocol (Advanced Testing)
    # -------------------------------------------------------------------------
    "MeteorNetwork",
    "LatencySimulator",
    "LatencyProfile",
    "SessionManager",
    "run_comprehensive_tests",
    
    # -------------------------------------------------------------------------
    # Web 4.0 Protocol
    # -------------------------------------------------------------------------
    "MeteorWeb4Node",
    "Web4Identity",
    "Web4Message",
    "Web4P2P",
    "Web4DHT",
    "Web4PubSub",
    "Web4IPFS",
    "MessageType",
    
    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------
    "MeteorAuth",
    "MeteorAuthServer",
    "UserRecord",
    "BiometricProvider",
    "BiometricStatus",
    "CallbackBiometricProvider",
    "MockBiometricProvider",
    "verify_device_binding",
    "generate_recovery_codes",
    
    # -------------------------------------------------------------------------
    # Constants
    # -------------------------------------------------------------------------
    "Q_DEFAULT",
    "MSG_BYTES",
    "MSG_BITS",
    "SECURITY_PARAMS",
    
    # -------------------------------------------------------------------------
    # Availability Flags
    # -------------------------------------------------------------------------
    "GPU_AVAILABLE",
    "CRYPTO_AVAILABLE",
    "COMPRESSION_AVAILABLE",
    "BATCH_AVAILABLE",
    "BATCH_MULTILEVEL_AVAILABLE",
    "STREAM_AVAILABLE",
    "PRACTICAL_AVAILABLE",
    "PROTOCOL_AVAILABLE",
    "ADVANCED_AVAILABLE",
    "WEB4_AVAILABLE",
    "LIBP2P_AVAILABLE",
    "DHT_AVAILABLE",
    "PUBSUB_AVAILABLE",
    "IPFS_AVAILABLE",
    "NACL_AVAILABLE",
    "AUTH_AVAILABLE",
]


# =============================================================================
# Quick Status Check
# =============================================================================

def status() -> dict:
    """
    Get availability status of all components.
    
    Example:
        >>> import meteor_nc
        >>> meteor_nc.status()
        {
            'version': '2.1.0',
            'core': True,
            'gpu': False,
            'compression': True,
            'batch': False,
            'stream': True,
            ...
        }
    """
    return {
        'version': __version__,
        'core': True,  # Always available
        'gpu': GPU_AVAILABLE,
        'crypto': CRYPTO_AVAILABLE,
        'compression': COMPRESSION_AVAILABLE,
        'batch': BATCH_AVAILABLE,
        'batch_multilevel': BATCH_MULTILEVEL_AVAILABLE,
        'stream': STREAM_AVAILABLE,
        'practical': PRACTICAL_AVAILABLE,
        'protocol': PROTOCOL_AVAILABLE,
        'advanced': ADVANCED_AVAILABLE,
        'web4': WEB4_AVAILABLE,
        'libp2p': LIBP2P_AVAILABLE,
        'dht': DHT_AVAILABLE,
        'pubsub': PUBSUB_AVAILABLE,
        'ipfs': IPFS_AVAILABLE,
        'nacl': NACL_AVAILABLE,
        'auth': AUTH_AVAILABLE,
    }
