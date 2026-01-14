"""
Meteor-NC Cryptography Module

High-performance post-quantum public-key cryptography based on
non-commutative matrix projections.

Core Components:
    - MeteorNC: GPU-accelerated encryption with APN
    - MeteorKDF: 32-byte seed key derivation (HKDF RFC 5869)
    - MeteorPractical: String/file encryption utilities
    - HKDF: RFC 5869 compliant key derivation function

Class Hierarchy:
    MeteorNC → MeteorKDF → MeteorPractical

Layer Count Formula (Table 1 in paper):
    m = max(8, n // 32 + 2)
    
    n=128  → m=8
    n=256  → m=10
    n=512  → m=18
    n=1024 → m=34
    n=2048 → m=66

Adaptive Precision Noise (Algorithm 5):
    - Dynamic κ estimation via PowerIteration/InverseIteration
    - σeff = max(σ0, ||C||·ε·κ/√n)
    - Ensures IND-CPA security with < 10⁻¹⁰ decryption error

HKDF Integration:
    - RFC 5869 compliant (HMAC-SHA256)
    - Used for deterministic key expansion
    - Supports domain separation for Auth system integration

Example:
    >>> from meteor_nc.cryptography import create_meteor, create_kdf_meteor
    >>>
    >>> # Quick start (auto m calculation)
    >>> crypto = create_meteor(256)  # n=256, m=10
    >>> crypto.key_gen()
    >>>
    >>> # With KDF for compact storage
    >>> kdf = create_kdf_meteor(256)
    >>> kdf.key_gen()
    >>> seed = kdf.export_seed()  # Only 32 bytes!
    >>>
    >>> # Practical string encryption
    >>> from meteor_nc.cryptography import create_practical_meteor
    >>> practical = create_practical_meteor(256)
    >>> practical.key_gen()
    >>> practical.expand_keys()
    >>> enc = practical.encrypt_string("Hello!")
    >>>
    >>> # HKDF for custom key derivation
    >>> from meteor_nc.cryptography import HKDF
    >>> hkdf = HKDF(salt=b"my-app")
    >>> key = hkdf.derive(master_key, info=b"auth-token", length=32)
"""

from .core import (
    MeteorNC,
    MeteorNC_GPU,  # Backward compatibility
    create_meteor,
    create_meteor_gpu,  # Backward compatibility
    check_gpu_available,
    compute_layer_count,
)

from .kdf import (
    MeteorKDF,
    MeteorNC_KDF,  # Backward compatibility
    create_kdf_meteor,
    HKDF,  # RFC 5869 key derivation
)

from .string import (
    MeteorPractical,
    MeteorNC_Practical,  # Backward compatibility
    create_practical_meteor,
    quick_encrypt_string,
    quick_decrypt_string,
)

# CPU-only versions (no CuPy required)
from .core_cpu import (
    MeteorNC_CPU,
    create_meteor_cpu,
)

from .kdf_cpu import (
    MeteorKDF_CPU,
    create_kdf_meteor_cpu,
)

__all__ = [
    # Core (GPU)
    'MeteorNC',
    'MeteorNC_GPU',
    'create_meteor',
    'create_meteor_gpu',
    'check_gpu_available',
    'compute_layer_count',
    
    # Core (CPU)
    'MeteorNC_CPU',
    'create_meteor_cpu',
    
    # KDF (GPU)
    'MeteorKDF',
    'MeteorNC_KDF',
    'create_kdf_meteor',
    'HKDF',
    
    # KDF (CPU)
    'MeteorKDF_CPU',
    'create_kdf_meteor_cpu',
    
    # Practical (String/File)
    'MeteorPractical',
    'MeteorNC_Practical',
    'create_practical_meteor',
    'quick_encrypt_string',
    'quick_decrypt_string',
]
