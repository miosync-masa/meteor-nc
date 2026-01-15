# meteor_nc/cryptography/__init__.py
"""
Meteor-NC Cryptography Module
"""

from .common import (
    HKDF,
    Q_DEFAULT,
    MSG_BYTES,
    MSG_BITS,
    SECURITY_PARAMS,
    GPU_AVAILABLE,
    CRYPTO_AVAILABLE,
    _sha256,
    prg_sha256,
    uniform_vector_from_seed,
    small_error_from_seed,
)

from .core import (
    LWEKEM,
    HybridKEM,
    SymmetricMixer,
)

# Batch KEM (GPU required)
try:
    from .batch import BatchLWEKEM
    BATCH_AVAILABLE = True
except ImportError:
    BATCH_AVAILABLE = False

# Stream DEM
try:
    from .stream import StreamDEM, EncryptedChunk, StreamHeader
    STREAM_AVAILABLE = True
except ImportError:
    STREAM_AVAILABLE = False

# Practical encryption
try:
    from .practical import MeteorPractical, create_meteor, quick_encrypt, quick_decrypt
    PRACTICAL_AVAILABLE = True
except ImportError:
    PRACTICAL_AVAILABLE = False

__all__ = [
    # CORE
    "LWEKEM",
    "HybridKEM",
    "SymmetricMixer",
    # Batch
    "BatchLWEKEM",
    # Stream
    "StreamDEM",
    "EncryptedChunk",
    "StreamHeader",
    # Practical
    "MeteorPractical",
    "create_meteor",
    "quick_encrypt",
    "quick_decrypt",
    # common
    "HKDF",
    "Q_DEFAULT",
    "MSG_BYTES",
    "MSG_BITS",
    "SECURITY_PARAMS",
    "prg_sha256",
    "uniform_vector_from_seed",
    "small_error_from_seed",
    # Flags
    "GPU_AVAILABLE",
    "CRYPTO_AVAILABLE",
    "BATCH_AVAILABLE",
    "STREAM_AVAILABLE",
    "PRACTICAL_AVAILABLE",
]
