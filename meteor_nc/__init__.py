# meteor_nc/__init__.py
"""
Meteor-NC: Post-Quantum Hybrid Cryptosystem
WEB4.0 Protocol Ready!

- Post-Quantum Key Encapsulation (LWE-KEM)
- High-Speed Streaming Encryption (XChaCha20-Poly1305)
- P2P Communication Protocol
"""

__version__ = "2.0.0"

# Core (CPU/GPU optional)
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

# Batch KEM (GPU required)
try:
    from .cryptography.batch import BatchLWEKEM
    BATCH_AVAILABLE = True
except ImportError:
    BATCH_AVAILABLE = False

# Stream DEM (XChaCha20-Poly1305)
try:
    from .cryptography.stream import StreamDEM, EncryptedChunk, StreamHeader
    STREAM_AVAILABLE = True
except ImportError:
    STREAM_AVAILABLE = False

# Practical API (String/File encryption)
try:
    from .cryptography.practical import (
        MeteorPractical,
        create_meteor,
        quick_encrypt,
        quick_decrypt,
    )
    PRACTICAL_AVAILABLE = True
except ImportError:
    PRACTICAL_AVAILABLE = False

# Protocol Layer (P2P Communication)
try:
    from .protocols.meteor_protocol import (
        MeteorNode,
        MeteorPeer,
        MeteorMessage,
        MeteorProtocol,
    )
    PROTOCOL_AVAILABLE = True
except ImportError:
    PROTOCOL_AVAILABLE = False

# Advanced Protocol Testing
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
    ADVANCED_AVAILABLE = False

__all__ = [
    # Version
    "__version__",
    
    # Core Cryptography
    "HKDF",
    "LWEKEM",
    "HybridKEM",
    "SymmetricMixer",
    
    # Batch KEM
    "BatchLWEKEM",
    
    # Stream DEM
    "StreamDEM",
    "EncryptedChunk",
    "StreamHeader",
    
    # Practical API
    "MeteorPractical",
    "create_meteor",
    "quick_encrypt",
    "quick_decrypt",
    
    # Protocol (Basic)
    "MeteorNode",
    "MeteorPeer",
    "MeteorMessage",
    "MeteorProtocol",
    
    # Protocol (Advanced)
    "MeteorNetwork",
    "LatencySimulator",
    "LatencyProfile",
    "SessionManager",
    "run_comprehensive_tests",
    
    # Constants
    "Q_DEFAULT",
    "MSG_BYTES",
    "MSG_BITS",
    "SECURITY_PARAMS",
    
    # Availability Flags
    "GPU_AVAILABLE",
    "CRYPTO_AVAILABLE",
    "BATCH_AVAILABLE",
    "STREAM_AVAILABLE",
    "PRACTICAL_AVAILABLE",
    "PROTOCOL_AVAILABLE",
    "ADVANCED_AVAILABLE",
]
