# meteor_nc/cryptography/__init__.py
"""
Meteor-NC Cryptography Module

Correct PKE Design:
  - Public key (pk_seed + b) allows encryption
  - Secret key (s) required for decryption
  - pk_seed leak does NOT compromise secret key

Wire Format:
  - Header fields: big-endian
  - Coefficient arrays: little-endian uint32
"""

 Common utilities and data structures
from .common import (
    # Constants
    Q_DEFAULT,
    SECURITY_PARAMS,
    MSG_BYTES,
    MSG_BITS,
    GPU_AVAILABLE,
    CRYPTO_AVAILABLE,
    # Utilities
    _sha256,
    _ct_eq,
    _derive_key,
    prg_sha256,
    small_error_from_seed,
    # HKDF
    HKDF,
    # Data structures
    LWEPublicKey,
    LWESecretKey,
    LWECiphertext,
    FullCiphertext,
    # CBD
    CenteredBinomial,
)

# Compression (v2.0)
from .compression import (
    compress,
    decompress,
    compress_ciphertext,
    decompress_ciphertext,
    compressed_size,
    get_compression_params,
    COMPRESSION_PARAMS,
)

# Core KEM
from .core import (
    LWEKEM,
    HybridKEM,
    SymmetricMixer,
)

# Batch KEM (GPU required)
try:
    from .batch import BatchLWEKEM, BatchHybridKEM, BatchCiphertext
    BATCH_AVAILABLE = True
except ImportError:
    BATCH_AVAILABLE = False

# Batch Multi-Level (n=256/512/1024)
try:
    from .kernels import BATCH_V2_AVAILABLE, BLAKE3_V2_AVAILABLE
    BATCH_MULTILEVEL_AVAILABLE = BATCH_V2_AVAILABLE and BLAKE3_V2_AVAILABLE
except ImportError:
    BATCH_MULTILEVEL_AVAILABLE = False

# Stream DEM
try:
    from .stream import (
        StreamDEM,
        StreamHybridKEM,
        StreamCiphertext,
        EncryptedChunk,
        StreamHeader,
    )
    STREAM_AVAILABLE = True
except ImportError:
    STREAM_AVAILABLE = False

# Practical encryption
try:
    from .practical import MeteorPractical, quick_encrypt, quick_decrypt
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
    "BatchHybridKEM",
    "BatchCiphertext",
    # Compression
    "compress",
    "decompress",
    "compress_ciphertext",
    "decompress_ciphertext",
    "compressed_size",
    "get_compression_params",
    "COMPRESSION_PARAMS",
    # Stream
    "StreamDEM",
    "StreamHybridKEM",
    "StreamCiphertext",
    "EncryptedChunk",
    "StreamHeader",
    # Practical
    "MeteorPractical",
    "quick_encrypt",
    "quick_decrypt",
    # Data structures
    "LWEPublicKey",
    "LWESecretKey",
    "LWECiphertext",
    "FullCiphertext",
    "CenteredBinomial",
    # Common
    "HKDF",
    "Q_DEFAULT",
    "MSG_BYTES",
    "MSG_BITS",
    "SECURITY_PARAMS",
    "prg_sha256",
    "small_error_from_seed",
    # Flags
    "GPU_AVAILABLE",
    "CRYPTO_AVAILABLE",
    "BATCH_AVAILABLE",
    "BATCH_MULTILEVEL_AVAILABLE",
    "STREAM_AVAILABLE",
    "PRACTICAL_AVAILABLE",
]
