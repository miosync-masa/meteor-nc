# meteor_nc/cryptography/kernels/__init__.py
"""
Meteor-NC CUDA Kernels

v1: n=256 optimized (original)
v2: n=256/512/1024 multi-level support
"""

# =============================================================================
# v1: Original n=256 optimized kernels (DO NOT MODIFY)
# =============================================================================
from .blake3_kernel import GPUBlake3
from .batch_kernels import (
    cbd_i32,
    matmul_AT_R,
    bdot_R,
    b_from_As,
    sdot_U,
    unpack_to_encoded,
    pack_bits_gpu,
)

# =============================================================================
# v2: Multi-level support (n=256/512/1024)
# =============================================================================
try:
    from .batch_kernels_v2 import (
        unpack_to_encoded_v2,
        pack_bits_v2,
    )
    BATCH_V2_AVAILABLE = True
except ImportError:
    BATCH_V2_AVAILABLE = False

try:
    from .blake3_kernel_v2 import GPUBlake3V2
    BLAKE3_V2_AVAILABLE = True
except ImportError:
    BLAKE3_V2_AVAILABLE = False

# =============================================================================
# Optional: ChaCha20-Poly1305
# =============================================================================
try:
    from .chacha_poly_kernel import GPUChaCha20Poly1305
    CHACHA_GPU_AVAILABLE = True
except ImportError:
    CHACHA_GPU_AVAILABLE = False


# =============================================================================
# Exports
# =============================================================================
__all__ = [
    # v1: n=256 optimized (original)
    "GPUBlake3",
    "cbd_i32",
    "matmul_AT_R",
    "bdot_R",
    "b_from_As",
    "sdot_U",
    "unpack_to_encoded",
    "pack_bits_gpu",
    
    # v2: Multi-level (n=256/512/1024)
    "GPUBlake3V2",
    "unpack_to_encoded_v2",
    "pack_bits_v2",
    "BATCH_V2_AVAILABLE",
    "BLAKE3_V2_AVAILABLE",
    
    # Optional
    "GPUChaCha20Poly1305",
    "CHACHA_GPU_AVAILABLE",
]
