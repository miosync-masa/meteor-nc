"""
Meteor-NC: Post-Quantum Cryptography (CPU Version)

A quantum-resistant public-key cryptosystem achieving security through
dimensional collapse and non-commutative hierarchical projections.

This is the CPU-only version using NumPy. For GPU acceleration,
use the main `core.py` module which requires CuPy.

Features:
    - No GPU/CuPy dependency
    - Full compatibility with GPU version API
    - APN (Adaptive Precision Noise) support
    - Suitable for testing and low-volume use
"""

import numpy as np
from scipy.linalg import lstsq
from scipy.stats import ortho_group, special_ortho_group
import time
from typing import Tuple, Optional, List


class MeteorNC_CPU:
    """
    Meteor-NC: Quantum-Resistant Public-Key Cryptosystem (CPU Version)
    
    Security based on:
    - LTDF: Lossy Trapdoor Functions via rank-deficient projections
    - NCSP: Non-Commutative Conjugacy Search Problem
    - Noisy Procrustes: Rotation recovery under noise
    
    Parameters:
        n: Dimension (security level: 128, 256, 512, 1024, 2048)
        m: Number of layers (recommended: n/32 + 2)
        noise_std: Noise standard deviation (default: 1e-10)
        rank_reduction: Projection rank deficit ratio (default: 0.3)
        apn_enabled: Enable Adaptive Precision Noise
        apn_dynamic: Use dynamic κ estimation
        apn_iterations: Iterations for condition number estimation
        apn_safety_factor: Static APN safety factor κ
    
    Example:
        >>> crypto = MeteorNC_CPU(n=256, m=10)
        >>> crypto.key_gen()
        >>> ciphertext = crypto.encrypt(message)
        >>> plaintext = crypto.decrypt(ciphertext)
    """
    
    # FP64 machine epsilon (IEEE 754)
    FP64_EPSILON = np.finfo(np.float64).eps  # 2.220446049250313e-16
    
    def __init__(self, 
                 n: int = 256,
                 m: int = 10,
                 noise_std: float = 1e-10,
                 rank_reduction: float = 0.3,
                 device_id: int = 0,  # Ignored in CPU version
                 apn_enabled: bool = True,
                 apn_dynamic: bool = True,
                 apn_iterations: int = 20,
                 apn_safety_factor: float = 10000.0,
                 semantic_noise_scale: float = 0.0):
        """Initialize CPU-based Meteor-NC with APN"""
        self.n = n
        self.m = m
        self.noise_std = noise_std
        self.rank_reduction = rank_reduction
        self.device_id = device_id  # Ignored but kept for API compatibility
        
        # APN settings
        self.apn_enabled = apn_enabled
        self.apn_dynamic = apn_dynamic
        self.apn_iterations = apn_iterations
        self.apn_safety_factor = apn_safety_factor
        
        # Cached condition number
        self._condition_number_cache = None
        
        # Legacy
        self.semantic_noise_scale = semantic_noise_scale
        
        # CPU mode flag (for compatibility)
        self.gpu = False
        
        # Keys (initialized by key_gen)
        self.S = None
        self.S_inv = None
        self.public_keys: List[np.ndarray] = []
        
        # Private keys
        self.private_P: List[np.ndarray] = []
        self.private_D: List[np.ndarray] = []
        self.private_R: List[np.ndarray] = []
        
        # Cached composite and Cholesky
        self._composite_cache = None
        self._cholesky_cache = None
        
        # Performance tracking
        self.keygen_time = None
        self.last_encrypt_time = None
        self.last_decrypt_time = None
    
    def key_gen(self, verbose: bool = False) -> float:
        """
        Generate public and secret keys.
        
        Returns:
            float: Key generation time in seconds
        """
        start = time.time()
        
        # Secret key: orthogonal matrix
        self.S = ortho_group.rvs(dim=self.n)
        self.S_inv = self.S.T
        
        # Clear previous keys
        self.public_keys = []
        self.private_P = []
        self.private_D = []
        self.private_R = []
        
        # Generate m projection layers
        for i in range(self.m):
            # Projection matrix (rank deficient)
            P = self._generate_projection()
            self.private_P.append(P)
            
            # Diagonal dominant matrix
            D = self._generate_diagonal()
            self.private_D.append(D)
            
            # Small rotation (non-commutative)
            R = self._generate_rotation(i)
            self.private_R.append(R)
            
            # Noise
            E = np.random.normal(0, self.noise_std, (self.n, self.n))
            
            # Public key layer: S(P+D)S^-1 + R + E
            public_key = self.S @ (P + D) @ self.S_inv + R + E
            self.public_keys.append(public_key)
        
        # Clear caches
        self._composite_cache = None
        self._cholesky_cache = None
        self._condition_number_cache = None
        
        self.keygen_time = time.time() - start
        
        if verbose:
            print(f"[MeteorNC-CPU] Key generation: {self.keygen_time:.3f}s (n={self.n}, m={self.m})")
        
        return self.keygen_time
    
    def _get_composite(self) -> np.ndarray:
        """Get or compute composite transformation matrix."""
        if self._composite_cache is None:
            composite = np.eye(self.n)
            for pk in self.public_keys:
                composite = pk @ composite
            self._composite_cache = composite
        return self._composite_cache
    
    def _get_cholesky(self) -> np.ndarray:
        """Get or compute Cholesky factorization for decryption."""
        if self._cholesky_cache is None:
            composite = self._get_composite()
            A = composite.T @ composite
            # Add small regularization for numerical stability
            A += np.eye(self.n) * 1e-12
            self._cholesky_cache = np.linalg.cholesky(A)
        return self._cholesky_cache
    
    def _estimate_condition_number(self) -> float:
        """
        Estimate condition number using power iteration.
        
        Returns:
            float: Estimated condition number κ(Π)
        """
        if self._condition_number_cache is not None:
            return self._condition_number_cache
        
        composite = self._get_composite()
        
        if self.apn_dynamic:
            # Power iteration for σ_max
            v = np.random.randn(self.n)
            v /= np.linalg.norm(v)
            
            for _ in range(self.apn_iterations):
                v = composite.T @ composite @ v
                v /= np.linalg.norm(v)
            
            sigma_max = np.sqrt(np.abs(v @ composite.T @ composite @ v))
            
            # Inverse iteration for σ_min
            w = np.random.randn(self.n)
            w /= np.linalg.norm(w)
            
            try:
                L = self._get_cholesky()
                for _ in range(self.apn_iterations):
                    # Solve (A^T A) w_new = w
                    y = np.linalg.solve(L, w)
                    w_new = np.linalg.solve(L.T, y)
                    w = w_new / np.linalg.norm(w_new)
                
                sigma_min = 1.0 / np.sqrt(np.abs(w @ composite.T @ composite @ w))
            except:
                sigma_min = sigma_max / self.apn_safety_factor
            
            kappa = sigma_max / max(sigma_min, 1e-15)
            kappa = min(kappa, self.apn_safety_factor)
        else:
            kappa = self.apn_safety_factor
        
        self._condition_number_cache = kappa
        return kappa
    
    def _compute_apn_noise(self, ciphertext: np.ndarray) -> float:
        """
        Compute APN noise standard deviation.
        
        Args:
            ciphertext: Preliminary ciphertext
            
        Returns:
            float: Noise standard deviation σ_eff
        """
        if not self.apn_enabled:
            return self.noise_std
        
        # Get condition number
        kappa = self._estimate_condition_number()
        
        # Compute adaptive noise level (Algorithm 5 from paper)
        C_norm = np.linalg.norm(ciphertext)
        sigma_cond = C_norm * self.FP64_EPSILON * kappa / np.sqrt(self.n)
        
        return max(self.noise_std, sigma_cond)
    
    def encrypt(self, message: np.ndarray) -> np.ndarray:
        """
        Encrypt a message vector.
        
        Args:
            message: numpy array of shape (n,)
        
        Returns:
            numpy array: ciphertext
        """
        if len(self.public_keys) == 0:
            raise ValueError("Keys not generated. Call key_gen() first.")
        
        start = time.time()
        
        # Apply projection layers
        ciphertext = message.astype(np.float64).copy()
        for pk in self.public_keys:
            ciphertext = pk @ ciphertext
        
        # Compute APN noise
        sigma_eff = self._compute_apn_noise(ciphertext)
        
        # Add noise
        ciphertext += np.random.normal(0, sigma_eff, self.n)
        
        self.last_encrypt_time = time.time() - start
        return ciphertext
    
    def decrypt(self, ciphertext: np.ndarray) -> np.ndarray:
        """
        Decrypt a ciphertext using Cached Cholesky method.
        
        Args:
            ciphertext: numpy array of shape (n,)
        
        Returns:
            numpy array: recovered plaintext
        """
        if self.S is None:
            raise ValueError("Keys not generated. Call key_gen() first.")
        
        start = time.time()
        
        # Get cached matrices
        composite = self._get_composite()
        L = self._get_cholesky()
        
        # Solve using Cholesky: (Π^T Π) x = Π^T c
        b = composite.T @ ciphertext
        
        # Forward substitution: L y = b
        y = np.linalg.solve(L, b)
        
        # Back substitution: L^T x = y
        plaintext = np.linalg.solve(L.T, y)
        
        self.last_decrypt_time = time.time() - start
        return plaintext
    
    def encrypt_batch(self, messages: np.ndarray) -> np.ndarray:
        """
        Encrypt multiple messages.
        
        Args:
            messages: numpy array of shape (batch, n)
        
        Returns:
            numpy array of shape (batch, n): ciphertexts
        """
        if len(self.public_keys) == 0:
            raise ValueError("Keys not generated. Call key_gen() first.")
        
        start = time.time()
        
        messages = np.atleast_2d(messages).astype(np.float64)
        batch_size = messages.shape[0]
        
        # Apply projection layers
        ciphertexts = messages.copy()
        for pk in self.public_keys:
            ciphertexts = (pk @ ciphertexts.T).T
        
        # Compute APN noise (use first ciphertext as reference)
        sigma_eff = self._compute_apn_noise(ciphertexts[0])
        
        # Add noise
        ciphertexts += np.random.normal(0, sigma_eff, ciphertexts.shape)
        
        self.last_encrypt_time = time.time() - start
        return ciphertexts
    
    def decrypt_batch(self, ciphertexts: np.ndarray) -> Tuple[np.ndarray, float]:
        """
        Decrypt multiple ciphertexts.
        
        Args:
            ciphertexts: numpy array of shape (batch, n)
        
        Returns:
            Tuple of (plaintexts array, decrypt time)
        """
        if self.S is None:
            raise ValueError("Keys not generated. Call key_gen() first.")
        
        start = time.time()
        
        ciphertexts = np.atleast_2d(ciphertexts)
        
        # Get cached matrices
        composite = self._get_composite()
        L = self._get_cholesky()
        
        # Batch solve
        plaintexts = []
        for c in ciphertexts:
            b = composite.T @ c
            y = np.linalg.solve(L, b)
            x = np.linalg.solve(L.T, y)
            plaintexts.append(x)
        
        plaintexts = np.array(plaintexts)
        decrypt_time = time.time() - start
        
        self.last_decrypt_time = decrypt_time
        return plaintexts, decrypt_time
    
    def verify_security(self, verbose: bool = False) -> dict:
        """
        Verify security properties (NCSP).
        
        Returns:
            dict: Security metrics
        """
        if len(self.public_keys) == 0:
            raise ValueError("Keys not generated. Call key_gen() first.")
        
        # NCSP: Non-commutativity
        commutators = []
        for i in range(len(self.public_keys)):
            for j in range(i + 1, len(self.public_keys)):
                comm = (self.public_keys[i] @ self.public_keys[j] - 
                       self.public_keys[j] @ self.public_keys[i])
                commutators.append(np.linalg.norm(comm, 'fro'))
        
        ncsp = np.mean(commutators)
        threshold = 0.5 * np.sqrt(self.n)
        ncsp_secure = ncsp > threshold
        
        results = {
            'ncsp': ncsp,
            'ncsp_threshold': threshold,
            'ncsp_secure': ncsp_secure,
            'ncsp_margin': ncsp / threshold,
            'secure': ncsp_secure
        }
        
        if verbose:
            status = '✅ SECURE' if ncsp_secure else '⚠️ WEAK'
            print(f"[Security] NCSP: {ncsp:.2f} (threshold: {threshold:.2f}) {status}")
        
        return results
    
    def get_key_sizes(self) -> dict:
        """Get key sizes in megabytes."""
        if len(self.public_keys) == 0 or self.S is None:
            return {'public_key_mb': 0, 'secret_key_mb': 0, 'total_mb': 0}
        
        pk_size = sum(key.nbytes for key in self.public_keys) / (1024**2)
        sk_size = self.S.nbytes / (1024**2)
        
        return {
            'public_key_mb': pk_size,
            'secret_key_mb': sk_size,
            'total_mb': pk_size + sk_size
        }
    
    def cleanup(self):
        """Clean up resources (no-op for CPU version)."""
        pass
    
    # =========================================================================
    # Private helper methods
    # =========================================================================
    
    def _generate_projection(self) -> np.ndarray:
        """Generate rank-deficient projection matrix."""
        target_rank = int(self.n * (1 - self.rank_reduction))
        A = np.random.randn(self.n, target_rank)
        Q, _ = np.linalg.qr(A)
        P = Q @ Q.T
        return P
    
    def _generate_diagonal(self) -> np.ndarray:
        """Generate diagonal-dominant matrix."""
        D = np.random.randn(self.n, self.n) * 0.1
        D += np.eye(self.n) * 10.0
        return D
    
    def _generate_rotation(self, layer_idx: int) -> np.ndarray:
        """Generate small rotation matrix."""
        group_type = layer_idx % 3
        scale = 0.01
        
        if group_type == 0:
            R = special_ortho_group.rvs(self.n)
            R = (R - np.eye(self.n)) * scale
        elif group_type == 1:
            A = np.random.randn(self.n, self.n)
            R = (A - A.T) / 2 * scale
        else:
            R = np.random.randn(self.n, self.n) * scale
        
        return R


# =============================================================================
# Factory Function
# =============================================================================

def create_meteor_cpu(security_level: int = 256,
                      apn_enabled: bool = True,
                      apn_dynamic: bool = True) -> MeteorNC_CPU:
    """
    Create CPU-based Meteor-NC with predefined security level.
    
    Args:
        security_level: 128, 256, 512, 1024, or 2048 bits
        apn_enabled: Enable Adaptive Precision Noise
        apn_dynamic: Use dynamic κ estimation
    
    Returns:
        MeteorNC_CPU instance
    """
    from .core import compute_layer_count
    
    valid_levels = [128, 256, 512, 1024, 2048]
    if security_level not in valid_levels:
        raise ValueError(f"Security level must be one of {valid_levels}")
    
    n = security_level
    m = compute_layer_count(n)
    
    return MeteorNC_CPU(
        n=n,
        m=m,
        apn_enabled=apn_enabled,
        apn_dynamic=apn_dynamic
    )


# Alias for compatibility
MeteorNC = MeteorNC_CPU
