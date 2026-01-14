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

__all__ = [
    "HKDF",
    "LWEKEM",
    "HybridKEM",
    "SymmetricMixer",
    "BatchLWEKEM",
    "Q_DEFAULT",
    "MSG_BYTES",
    "MSG_BITS",
    "SECURITY_PARAMS",
    "GPU_AVAILABLE",
    "CRYPTO_AVAILABLE",
    "BATCH_AVAILABLE",
]
