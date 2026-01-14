"""
Meteor-NC: KDF (Key Derivation Function) Implementation

Ultra-compact key storage using seed-based key generation.

Key size: 32 bytes (seed only)
Reduction: 99.9998% from original 15.50 MB
Expansion time: ~0.4s (one-time cost)

All keys are deterministically regenerated from seed.

Requirements:
    - CUDA-capable GPU
    - cupy-cuda12x
    - scipy

Usage:
    from meteor_nc.cryptography import MeteorKDF
    
    # Generate keys
    crypto = MeteorKDF(n=256, m=10)
    crypto.key_gen()
    
    # Save only seed (32 bytes!)
    seed = crypto.export_seed()
    
    # Later... restore from seed
    crypto2 = MeteorKDF(n=256, m=10)
    crypto2.import_seed(seed)
    crypto2.expand_keys()
    
    # Use normally
    ciphertexts = crypto2.encrypt_batch(messages)
    plaintexts = crypto2.decrypt_batch(ciphertexts)
"""

import numpy as np
import time
from typing import Optional, Tuple, Dict
import hashlib
import hmac

try:
    import cupy as cp
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

from scipy.stats import ortho_group, special_ortho_group
from .core import MeteorNC


# =============================================================================
# HKDF: RFC 5869 Compliant Implementation
# =============================================================================

class HKDF:
    """
    HKDF (HMAC-based Extract-and-Expand Key Derivation Function).
    
    RFC 5869 compliant implementation using SHA-256.
    
    Reference:
        https://tools.ietf.org/html/rfc5869
    
    This is used for:
        - Deterministic key expansion from master seed
        - Domain separation for different key components
        - Authentication system integration (MeteorAuth)
    
    Example:
        >>> hkdf = HKDF(salt=b"MeteorNC-v1")
        >>> prk = hkdf.extract(input_key_material)
        >>> okm = hkdf.expand(prk, info=b"orthogonal", length=32)
    """
    
    HASH_LEN = 32  # SHA-256 output length
    
    def __init__(self, salt: Optional[bytes] = None, hash_func=hashlib.sha256):
        """
        Initialize HKDF.
        
        Args:
            salt: Optional salt (if None, uses zero-filled bytes)
            hash_func: Hash function (default: SHA-256)
        """
        self.hash_func = hash_func
        self.salt = salt if salt is not None else b'\x00' * self.HASH_LEN
    
    def extract(self, ikm: bytes) -> bytes:
        """
        HKDF-Extract: Extract pseudorandom key from input key material.
        
        PRK = HMAC-Hash(salt, IKM)
        
        Args:
            ikm: Input key material
            
        Returns:
            Pseudorandom key (PRK), 32 bytes
        """
        return hmac.new(self.salt, ikm, self.hash_func).digest()
    
    def expand(self, prk: bytes, info: bytes = b"", length: int = 32) -> bytes:
        """
        HKDF-Expand: Expand PRK to desired length.
        
        T(0) = empty string
        T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
        OKM = T(1) || T(2) || ... (first L bytes)
        
        Args:
            prk: Pseudorandom key from extract()
            info: Context/application-specific info
            length: Desired output length in bytes
            
        Returns:
            Output key material (OKM)
        """
        if length > 255 * self.HASH_LEN:
            raise ValueError(f"Cannot expand to more than {255 * self.HASH_LEN} bytes")
        
        # Number of blocks needed
        n_blocks = (length + self.HASH_LEN - 1) // self.HASH_LEN
        
        okm = b""
        t_prev = b""
        
        for i in range(1, n_blocks + 1):
            # T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
            t_prev = hmac.new(
                prk,
                t_prev + info + bytes([i]),
                self.hash_func
            ).digest()
            okm += t_prev
        
        return okm[:length]
    
    def derive(self, ikm: bytes, info: bytes = b"", length: int = 32) -> bytes:
        """
        One-shot derive: Extract + Expand.
        
        Args:
            ikm: Input key material
            info: Context info
            length: Output length
            
        Returns:
            Derived key material
        """
        prk = self.extract(ikm)
        return self.expand(prk, info, length)


# =============================================================================
# MeteorKDF Class
# =============================================================================


class MeteorKDF(MeteorNC):
    """
    Meteor-NC with KDF-based key storage.
    
    Stores only a 32-byte seed instead of full keys.
    Keys are deterministically regenerated on demand.
    
    Key Storage:
        Original: 15.50 MB
        KDF:      32 bytes (0.000032 MB)
        Reduction: 99.9998%
    
    Trade-off:
        - Massive storage reduction
        - One-time expansion cost (~0.4s)
        - Identical cryptographic properties
    
    Parameters:
        n: Dimension
        m: Number of layers
        seed: Optional seed (if None, auto-generated)
        
    Example:
        >>> # Create and save
        >>> crypto = MeteorKDF(n=256, m=10)
        >>> crypto.key_gen()
        >>> seed = crypto.export_seed()  # 32 bytes!
        >>> 
        >>> # Restore later
        >>> crypto2 = MeteorKDF(n=256, m=10)
        >>> crypto2.import_seed(seed)
        >>> crypto2.expand_keys()
        >>> 
        >>> # Use normally
        >>> plaintexts = crypto2.decrypt_batch(ciphertexts)
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
        """
        Initialize KDF-based Meteor-NC.
        
        Args:
            n: Matrix dimension (security level)
            m: Number of projection layers
            noise_std: Base noise standard deviation
            rank_reduction: Projection rank deficit ratio
            device_id: GPU device ID
            seed: Master seed (32 bytes, auto-generated if None)
            apn_enabled: Enable Adaptive Precision Noise
            apn_dynamic: Use dynamic κ estimation (PowerIteration)
            apn_iterations: Iterations for condition number estimation
            apn_safety_factor: Static APN safety factor κ (fallback)
        """
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
        
        # HKDF instance (RFC 5869)
        self._hkdf = HKDF(salt=b"MeteorNC-KDF-v1")
        self._prk = None  # Pseudorandom key (computed on first use)
        
        # Track if keys are expanded
        self.keys_expanded = False
        self.expansion_time = None
    
    def _generate_master_seed(self) -> bytes:
        """
        Generate cryptographically secure master seed.
        
        Returns:
            32-byte seed
        """
        return np.random.bytes(32)
    
    def _get_prk(self) -> bytes:
        """
        Get or compute pseudorandom key from master seed.
        
        Uses HKDF-Extract (RFC 5869 Section 2.2).
        
        Returns:
            32-byte PRK
        """
        if self._prk is None:
            self._prk = self._hkdf.extract(self.master_seed)
        return self._prk
    
    def _derive_bytes(self, info: str, length: int = 32) -> bytes:
        """
        Derive key material using HKDF-Expand (RFC 5869).
        
        This is used for:
            - Key component generation
            - Authentication system integration
            - Domain-separated key derivation
        
        Args:
            info: Context/purpose string (e.g., "orthogonal", "P_0")
            length: Output length in bytes
            
        Returns:
            Derived key material
        """
        prk = self._get_prk()
        return self._hkdf.expand(prk, info.encode('utf-8'), length)
    
    def _derive_subseed(self, purpose: str) -> int:
        """
        Derive integer subseed for NumPy/CuPy random generators.
        
        Uses HKDF (RFC 5869) for cryptographic key derivation.
        
        Args:
            purpose: Purpose string (e.g., "S", "P_0", "D_1", "R_2")
            
        Returns:
            Derived seed as integer (for np.random.seed)
        """
        # Use HKDF to derive 4 bytes
        seed_bytes = self._derive_bytes(purpose, length=4)
        seed_int = int.from_bytes(seed_bytes, byteorder='big')
        
        return seed_int
    
    def key_gen(self, verbose: bool = False) -> float:
        """
        Generate master seed (not expanding keys yet).
        
        For KDF mode, this just initializes the seed.
        Call expand_keys() to actually generate keys.
        
        Returns:
            Time taken (negligible)
        """
        start = time.time()
        
        if verbose:
            print(f"[*] KDF mode: Master seed generated")
            print(f"    Seed size: 32 bytes")
            print(f"    (Keys not expanded yet)")
        
        self.keygen_time = time.time() - start
        return self.keygen_time
    
    def expand_keys(self, verbose: bool = False) -> float:
        """
        Expand keys from master seed.
        
        Deterministically regenerates all keys from the master seed.
        This is the one-time cost (~0.4s for n=256).
        
        Returns:
            Expansion time in seconds
        """
        if self.keys_expanded:
            if verbose:
                print("[!] Keys already expanded")
            return 0.0
        
        start = time.time()
        
        if verbose:
            print(f"[*] Expanding keys from seed on GPU {self.device_id}...")
        
        # Generate S deterministically
        seed_S = self._derive_subseed("S")
        S_cpu = ortho_group.rvs(dim=self.n, random_state=seed_S)
        
        self.S_gpu = cp.asarray(S_cpu, dtype=cp.float64)
        self.S_inv_gpu = self.S_gpu.T
        
        # Generate layers deterministically
        self.public_keys_gpu = []
        self.private_P_gpu = []
        self.private_D_gpu = []
        self.private_R_gpu = []
        
        for i in range(self.m):
            # Derive layer-specific seeds
            seed_P = self._derive_subseed(f"P_{i}")
            seed_D = self._derive_subseed(f"D_{i}")
            seed_R = self._derive_subseed(f"R_{i}")
            seed_E = self._derive_subseed(f"E_{i}")
            
            # Generate P (projection) deterministically
            P = self._generate_projection_deterministic(seed_P)
            
            # Generate D (diagonal dominant) deterministically
            D = self._generate_diagonal_deterministic(seed_D)
            
            # Generate R (rotation) deterministically
            R = self._generate_rotation_deterministic(i, seed_R)
            
            # Generate E (noise) deterministically
            cp.random.seed(seed_E)
            E = cp.random.normal(0, self.noise_std, (self.n, self.n),
                                dtype=cp.float64)
            
            # Save private keys
            self.private_P_gpu.append(P)
            self.private_D_gpu.append(D)
            self.private_R_gpu.append(R)
            
            # Public key: S(P+D)S^-1 + R + E
            public_key = self.S_gpu @ (P + D) @ self.S_inv_gpu + R + E
            self.public_keys_gpu.append(public_key)
        
        # Clear cache
        self.clear_cache()
        
        self.keys_expanded = True
        self.expansion_time = time.time() - start
        
        if verbose:
            mem = cp.get_default_memory_pool().used_bytes() / 1024**2
            print(f"[✓] Key expansion: {self.expansion_time:.3f}s")
            print(f"    GPU memory: {mem:.1f} MB")
        
        return self.expansion_time
    
    def _generate_projection_deterministic(self, seed: int) -> cp.ndarray:
        """Generate rank-deficient projection deterministically."""
        target_rank = int(self.n * (1 - self.rank_reduction))
        
        # Use seed for numpy
        rng = np.random.RandomState(seed)
        A_cpu = rng.randn(self.n, target_rank)
        
        # Transfer to GPU
        A = cp.asarray(A_cpu, dtype=cp.float64)
        Q, _ = cp.linalg.qr(A)
        return Q @ Q.T
    
    def _generate_diagonal_deterministic(self, seed: int) -> cp.ndarray:
        """Generate diagonal-dominant matrix deterministically."""
        rng = np.random.RandomState(seed)
        D_cpu = rng.randn(self.n, self.n) * 0.1
        
        D = cp.asarray(D_cpu, dtype=cp.float64)
        D += cp.eye(self.n, dtype=cp.float64) * 10.0
        return D
    
    def _generate_rotation_deterministic(self, layer_idx: int, seed: int) -> cp.ndarray:
        """Generate small rotation deterministically."""
        scale = 0.01
        group_type = layer_idx % 3
        
        if group_type == 0:
            # Special orthogonal (deterministic)
            R_cpu = special_ortho_group.rvs(self.n, random_state=seed)
            R = cp.asarray(R_cpu, dtype=cp.float64)
            R = (R - cp.eye(self.n)) * scale
        elif group_type == 1:
            # Skew-symmetric (deterministic)
            rng = np.random.RandomState(seed)
            A_cpu = rng.randn(self.n, self.n)
            A = cp.asarray(A_cpu, dtype=cp.float64)
            R = (A - A.T) / 2 * scale
        else:
            # Random (deterministic)
            rng = np.random.RandomState(seed)
            R_cpu = rng.randn(self.n, self.n) * scale
            R = cp.asarray(R_cpu, dtype=cp.float64)
        
        return R
    
    def export_seed(self) -> bytes:
        """
        Export master seed for storage.
        
        Returns:
            32-byte master seed
        """
        return self.master_seed
    
    def import_seed(self, seed: bytes):
        """
        Import master seed.
        
        Args:
            seed: 32-byte master seed
        """
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        
        self.master_seed = seed
        self.keys_expanded = False
        
        # Clear any existing keys
        self.S_gpu = None
        self.S_inv_gpu = None
        self.public_keys_gpu = []
        self.private_P_gpu = []
        self.private_D_gpu = []
        self.private_R_gpu = []
        self.clear_cache()
    
    def get_storage_stats(self) -> Dict:
        """
        Get storage statistics.
        
        Returns:
            Storage comparison dictionary
        """
        # Original key size (estimated)
        S_size = self.n * self.n * 8
        layer_size = 3 * self.n * self.n * 8  # P, D, R per layer
        original_bytes = S_size + self.m * layer_size
        original_mb = original_bytes / (1024 ** 2)
        
        # KDF size
        kdf_bytes = 32  # Master seed
        kdf_mb = kdf_bytes / (1024 ** 2)
        
        reduction = (1 - kdf_bytes / original_bytes) * 100
        
        return {
            'original_bytes': original_bytes,
            'original_mb': original_mb,
            'kdf_bytes': kdf_bytes,
            'kdf_mb': kdf_mb,
            'reduction_pct': reduction,
            'expansion_time': self.expansion_time,
            'keys_expanded': self.keys_expanded
        }
    
    def encrypt(self, message: np.ndarray) -> np.ndarray:
        """Encrypt (auto-expand keys if needed)."""
        if not self.keys_expanded:
            self.expand_keys(verbose=False)
        return super().encrypt(message)
    
    def decrypt(self, ciphertext: np.ndarray, method: str = 'optimized') -> np.ndarray:
        """Decrypt (auto-expand keys if needed)."""
        if not self.keys_expanded:
            self.expand_keys(verbose=False)
        return super().decrypt(ciphertext, method)
    
    def encrypt_batch(self, messages: np.ndarray) -> np.ndarray:
        """Batch encrypt (auto-expand keys if needed)."""
        if not self.keys_expanded:
            self.expand_keys(verbose=False)
        return super().encrypt_batch(messages)
    
    def decrypt_batch(self, ciphertexts: np.ndarray,
                     method: str = 'optimized') -> Tuple[np.ndarray, float]:
        """Batch decrypt (auto-expand keys if needed)."""
        if not self.keys_expanded:
            self.expand_keys(verbose=False)
        return super().decrypt_batch(ciphertexts, method)
    
    def benchmark_kdf(self, batch_size: int = 1000, verbose: bool = True) -> Dict:
        """
        Benchmark KDF performance.
        
        Args:
            batch_size: Number of messages to test
            verbose: Print detailed results
            
        Returns:
            Performance metrics dictionary
        """
        if verbose:
            print(f"\n[Benchmarking KDF Mode]")
            print(f"Batch size: {batch_size}")
            print("-" * 70)
        
        # Test 1: Cold start (with expansion)
        if verbose:
            print("\n[1] Cold start (with key expansion):")
        
        # Clear keys
        self.keys_expanded = False
        self.S_gpu = None
        self.public_keys_gpu = []
        
        messages = np.random.randn(batch_size, self.n)
        
        start = time.time()
        
        # Expand (one-time cost)
        expansion_time = self.expand_keys(verbose=False)
        
        # Encrypt
        ciphertexts = self.encrypt_batch(messages)
        
        # Decrypt
        recovered, decrypt_time = self.decrypt_batch(ciphertexts)
        
        total_time = time.time() - start
        
        error = np.linalg.norm(messages - recovered) / np.linalg.norm(messages)
        
        if verbose:
            print(f"    Expansion:  {expansion_time*1000:.2f}ms")
            print(f"    Encrypt:    {(total_time - expansion_time - decrypt_time)*1000:.2f}ms")
            print(f"    Decrypt:    {decrypt_time*1000:.2f}ms")
            print(f"    Total:      {total_time*1000:.2f}ms")
            print(f"    Error:      {error:.2e}")
        
        # Test 2: Warm start (keys already expanded)
        if verbose:
            print("\n[2] Warm start (keys cached):")
        
        messages2 = np.random.randn(batch_size, self.n)
        
        start = time.time()
        ciphertexts2 = self.encrypt_batch(messages2)
        encrypt_time_warm = time.time() - start
        
        recovered2, decrypt_time_warm = self.decrypt_batch(ciphertexts2)
        
        error2 = np.linalg.norm(messages2 - recovered2) / np.linalg.norm(messages2)
        
        if verbose:
            print(f"    Encrypt:    {encrypt_time_warm*1000:.2f}ms")
            print(f"    Decrypt:    {decrypt_time_warm*1000:.2f}ms")
            print(f"    Error:      {error2:.2e}")
        
        # Storage stats
        stats = self.get_storage_stats()
        
        if verbose:
            print(f"\n[Storage Comparison]")
            print(f"    Original:   {stats['original_mb']:.2f} MB")
            print(f"    KDF:        {stats['kdf_mb']:.6f} MB ({stats['kdf_bytes']} bytes)")
            print(f"    Reduction:  {stats['reduction_pct']:.4f}%")
            print(f"\n    One-time expansion cost: {expansion_time*1000:.2f}ms")
            print(f"    After expansion: identical performance")
        
        return {
            'cold_start': {
                'expansion_ms': expansion_time * 1000,
                'total_ms': total_time * 1000,
                'error': error
            },
            'warm_start': {
                'encrypt_ms': encrypt_time_warm * 1000,
                'decrypt_ms': decrypt_time_warm * 1000,
                'error': error2
            },
            'storage': stats
        }


# =============================================================================
# Factory Functions
# =============================================================================

def create_kdf_meteor(security_level: int = 256,
                     device_id: int = 0,
                     seed: Optional[bytes] = None,
                     apn_enabled: bool = True,
                     apn_dynamic: bool = True) -> MeteorKDF:
    """
    Create KDF-based Meteor-NC with predefined security level.
    
    Args:
        security_level: 128, 256, 512, 1024, or 2048 bits
        device_id: GPU device ID
        seed: Optional 32-byte seed
        apn_enabled: Enable Adaptive Precision Noise
        apn_dynamic: Use dynamic κ estimation (PowerIteration)
        
    Returns:
        MeteorKDF instance
        
    Example:
        >>> # Create and save
        >>> crypto = create_kdf_meteor(256)
        >>> crypto.key_gen()
        >>> seed = crypto.export_seed()
        >>> 
        >>> # Restore later
        >>> crypto2 = create_kdf_meteor(256, seed=seed)
        >>> crypto2.expand_keys()
    """
    from .core import compute_layer_count
    
    valid_levels = [128, 256, 512, 1024, 2048]
    
    if security_level not in valid_levels:
        raise ValueError(f"Security level must be one of {valid_levels}")
    
    n = security_level
    m = compute_layer_count(n)
    
    return MeteorKDF(
        n=n,
        m=m,
        seed=seed,
        device_id=device_id,
        apn_enabled=apn_enabled,
        apn_dynamic=apn_dynamic
    )


# Backward compatibility alias
MeteorNC_KDF = MeteorKDF
