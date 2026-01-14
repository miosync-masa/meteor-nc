# meteor_nc/__init__.py
"""
Meteor-NC: Post-Quantum Hybrid Cryptosystem
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

# Batch (GPU required) - optional import
try:
    from .cryptography.batch import BatchLWEKEM
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
    "__version__",
]
