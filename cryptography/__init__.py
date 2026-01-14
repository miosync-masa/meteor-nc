"""
Meteor-NC Cryptography Module

High-performance post-quantum public-key cryptography based on
non-commutative matrix projections.

Core Components:
    - MeteorNC: GPU-accelerated encryption with APN
    - MeteorKDF: 32-byte seed key derivation
    - MeteorPractical: String/file encryption utilities

Example:
    >>> from meteor_nc.cryptography import MeteorNC, create_meteor
    >>>
    >>> # Quick start
    >>> crypto = create_meteor(256)
    >>> crypto.key_gen()
    >>>
    >>> # Encrypt/Decrypt
    >>> ciphertext = crypto.encrypt(message)
    >>> plaintext = crypto.decrypt(ciphertext)
    >>>
    >>> # Or use KDF for compact storage
    >>> from meteor_nc.cryptography import MeteorKDF
    >>> kdf = MeteorKDF(n=256, m=10)
    >>> kdf.key_gen()
    >>> seed = kdf.export_seed()  # Only 32 bytes!
"""

from .core import (
    MeteorNC,
    MeteorNC_GPU,  # Backward compatibility
    create_meteor,
    create_meteor_gpu,  # Backward compatibility
    check_gpu_available,
)

from .kdf import (
    MeteorKDF,
    MeteorNC_KDF,  # Backward compatibility
    create_kdf_meteor,
)

from .string import (
    MeteorPractical,
    MeteorNC_Practical,  # Backward compatibility
    quick_encrypt_string,
    quick_decrypt_string,
)

__all__ = [
    # Core
    'MeteorNC',
    'MeteorNC_GPU',
    'create_meteor',
    'create_meteor_gpu',
    'check_gpu_available',
    
    # KDF
    'MeteorKDF',
    'MeteorNC_KDF',
    'create_kdf_meteor',
    
    # Practical (String/File)
    'MeteorPractical',
    'MeteorNC_Practical',
    'quick_encrypt_string',
    'quick_decrypt_string',
]
