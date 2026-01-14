# meteor_nc/cryptography/kernels/__init__.py
"""
Meteor-NC CUDA Kernels
"""

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

try:
    from .chacha_poly_kernel import GPUChaCha20Poly1305
    CHACHA_GPU_AVAILABLE = True
except ImportError:
    CHACHA_GPU_AVAILABLE = False

__all__ = [
    "GPUBlake3",
    "GPUChaCha20Poly1305",
    "cbd_i32",
    "matmul_AT_R",
    "bdot_R",
    "b_from_As",
    "sdot_U",
    "unpack_to_encoded",
    "pack_bits_gpu",
    "CHACHA_GPU_AVAILABLE",
]
