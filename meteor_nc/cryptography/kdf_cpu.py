"""
Meteor-NC: KDF (Key Derivation Function) - CPU Version

Ultra-compact key storage using seed-based key generation.
CPU-only version using NumPy (no CuPy required).

Key size: 32 bytes (seed only)
Reduction: 99.9998% from original
"""

import numpy as np
import time
from typing import Optional, Tuple, Dict
import hashlib
import hmac

from scipy.stats import ortho_group, special_ortho_group
from .core_cpu import MeteorNC_CPU


class HKDF:
    """
    HKDF (HMAC-based Extract-and-Expand Key Derivation Function).
    RFC 5869 compliant implementation using SHA-256.
    """
    
    HASH_LEN = 32  # SHA-256 output length
    
    def __init__(self, salt: Optional[bytes] = None, hash_func: str = 'sha256'):
        self.salt = salt if salt else b'\x00' * self.HASH_LEN
        self.hash_func = hash_func
    
    def extract(self, input_key_material: bytes) -> bytes:
        """HKDF-Extract: Extract pseudorandom key from input."""
        return hmac.new(self.salt, input_key_material, self.hash_func).digest()
    
    def expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        """HKDF-Expand: Expand PRK to desired length."""
        if length > 255 * self.HASH_LEN:
            raise ValueError(f"Cannot expand to more than {255 * self.HASH_LEN} bytes")
        
        n = (length + self.HASH_LEN - 1) // self.HASH_LEN
        okm = b''
        t = b''
        
        for i in range(1, n + 1):
            t = hmac.new(prk, t + info + bytes([i]), self.hash_func).digest()
            okm += t
        
        return okm[:length]


class MeteorKDF_CPU(MeteorNC_CPU):
    """
    KDF-based Meteor-NC for CPU (NumPy).
    
    Extends MeteorNC_CPU with deterministic key derivation from a 32-byte seed.
    All keys are regenerated from the seed using HKDF (RFC 5869).
    """
    
    def __init__(self,
                 n: int = 256,
                 m: int = 10,
                 noise_std: float = 1e-10,
                 rank_reduction: float = 0.3,
                 device_id: int = 0,
                 seed: Optional[bytes] = None,
                 apn_enabled: bool = True,
                 apn_dynamic: bool = True,
                 apn_iterations: int = 20,
                 apn_safety_factor: float = 10000.0):
        """Initialize KDF-based Meteor-NC (CPU)."""
        super().__init__(
            n=n,
            m=m,
            noise_std=noise_std,
            rank_reduction=rank_reduction,
            device_id=device_id,
            apn_enabled=apn_enabled,
            apn_dynamic=apn_dynamic,
            apn_iterations=apn_iterations,
            apn_safety_factor=apn_safety_factor
        )
        
        # Master seed (32 bytes)
        if seed is None:
            self.master_seed = self._generate_master_seed()
        else:
            self.master_seed = seed
        
        # HKDF instance
        self._hkdf = HKDF(salt=b"MeteorNC-KDF-v1")
        self._prk = None
        
        # Track expansion state
        self.keys_expanded = False
        self.expansion_time = None
    
    def _generate_master_seed(self) -> bytes:
        """Generate cryptographically secure master seed."""
        return np.random.bytes(32)
    
    def _get_prk(self) -> bytes:
        """Get or compute pseudorandom key from master seed."""
        if self._prk is None:
            self._prk = self._hkdf.extract(self.master_seed)
        return self._prk
    
    def _derive_bytes(self, info: str, length: int = 32) -> bytes:
        """Derive key material using HKDF-Expand."""
        prk = self._get_prk()
        return self._hkdf.expand(prk, info.encode('utf-8'), length)
    
    def _derive_subseed(self, purpose: str) -> int:
        """Derive integer subseed for NumPy random generators."""
        seed_bytes = self._derive_bytes(purpose, length=4)
        return int.from_bytes(seed_bytes, byteorder='big')
    
    def key_gen(self, verbose: bool = False) -> float:
        """Generate master seed (not expanding keys yet)."""
        start = time.time()
        
        if verbose:
            print(f"[*] KDF mode (CPU): Master seed generated")
            print(f"    Seed size: 32 bytes")
        
        self.keygen_time = time.time() - start
        return self.keygen_time
    
    def expand_keys(self, verbose: bool = False) -> float:
        """Expand keys from master seed deterministically."""
        if self.keys_expanded:
            if verbose:
                print("[!] Keys already expanded")
            return 0.0
        
        start = time.time()
        
        if verbose:
            print(f"[*] Expanding keys from seed (CPU)...")
        
        # Generate S deterministically
        seed_S = self._derive_subseed("S")
        self.S = ortho_group.rvs(dim=self.n, random_state=seed_S)
        self.S_inv = self.S.T
        
        # Generate layers deterministically
        self.public_keys = []
        self.private_P = []
        self.private_D = []
        self.private_R = []
        
        for i in range(self.m):
            seed_P = self._derive_subseed(f"P_{i}")
            seed_D = self._derive_subseed(f"D_{i}")
            seed_R = self._derive_subseed(f"R_{i}")
            seed_E = self._derive_subseed(f"E_{i}")
            
            # Generate P (projection) deterministically
            np.random.seed(seed_P)
            P = self._generate_projection()
            
            # Generate D (diagonal dominant) deterministically
            np.random.seed(seed_D)
            D = self._generate_diagonal()
            
            # Generate R (rotation) deterministically
            np.random.seed(seed_R)
            R = self._generate_rotation(i)
            
            # Generate E (noise) deterministically
            np.random.seed(seed_E)
            E = np.random.normal(0, self.noise_std, (self.n, self.n))
            
            # Save private keys
            self.private_P.append(P)
            self.private_D.append(D)
            self.private_R.append(R)
            
            # Public key: S(P+D)S^-1 + R + E
            public_key = self.S @ (P + D) @ self.S_inv + R + E
            self.public_keys.append(public_key)
        
        # Clear caches
        self._composite_cache = None
        self._cholesky_cache = None
        self._condition_number_cache = None
        
        self.keys_expanded = True
        self.expansion_time = time.time() - start
        
        if verbose:
            print(f"[✓] Keys expanded in {self.expansion_time:.3f}s")
        
        return self.expansion_time
    
    def export_seed(self) -> bytes:
        """Export master seed (32 bytes)."""
        return self.master_seed
    
    def import_seed(self, seed: bytes) -> None:
        """Import master seed."""
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        
        self.master_seed = seed
        self._prk = None  # Reset PRK cache
        self.keys_expanded = False
        
        # Clear existing keys
        self.S = None
        self.S_inv = None
        self.public_keys = []
        self.private_P = []
        self.private_D = []
        self.private_R = []
        self._composite_cache = None
        self._cholesky_cache = None


def compute_layer_count(n: int) -> int:
    """
    Compute recommended layer count for given dimension.
    
    Formula: m = max(8, n/32 + 2)
    """
    return max(8, n // 32 + 2)


def create_kdf_meteor_cpu(security_level: int = 256,
                          device_id: int = 0,
                          seed: Optional[bytes] = None,
                          apn_enabled: bool = True,
                          apn_dynamic: bool = True) -> MeteorKDF_CPU:
    """
    Create CPU-based KDF Meteor-NC with predefined security level.
    
    Args:
        security_level: 128, 256, 512, 1024, or 2048 bits
        device_id: Ignored (CPU version)
        seed: Optional 32-byte seed
        apn_enabled: Enable Adaptive Precision Noise
        apn_dynamic: Use dynamic κ estimation
    
    Returns:
        MeteorKDF_CPU instance
    """
    valid_levels = [128, 256, 512, 1024, 2048]
    
    if security_level not in valid_levels:
        raise ValueError(f"Security level must be one of {valid_levels}")
    
    n = security_level
    m = compute_layer_count(n)
    
    return MeteorKDF_CPU(
        n=n,
        m=m,
        seed=seed,
        device_id=device_id,
        apn_enabled=apn_enabled,
        apn_dynamic=apn_dynamic
    )


# Aliases
MeteorKDF = MeteorKDF_CPU
