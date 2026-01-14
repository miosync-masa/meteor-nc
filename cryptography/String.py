"""
Meteor-NC: String & File Encryption Extension

Extends MeteorKDF with practical string, binary, and file encryption.

Features:
    - String encryption/decryption (UTF-8)
    - Binary data encryption/decryption
    - File encryption/decryption
    - Base64 serialization for transport
    - Checksum verification

Usage:
    from meteor_nc.cryptography import MeteorPractical
    
    # Create and initialize
    crypto = MeteorPractical(n=256)
    crypto.key_gen()
    crypto.expand_keys()
    
    # String encryption
    encrypted = crypto.encrypt_string("Hello, World!")
    decrypted = crypto.decrypt_string(encrypted)
    
    # File encryption
    crypto.encrypt_file("secret.pdf", "secret.enc")
    crypto.decrypt_file("secret.enc", "recovered.pdf")
"""

import numpy as np
import time
import base64
import json
import hashlib
from typing import Optional, Tuple, Dict, Union
from pathlib import Path

from .kdf import MeteorKDF
from .core import compute_layer_count


class MeteorPractical(MeteorKDF):
    """
    Practical Meteor-NC with string/binary/file encryption.
    
    Inherits from MeteorKDF, adding high-level encryption methods
    for practical use cases.
    
    Encoding Strategy:
        - 1 byte → 1 float64 element (precision guarantee)
        - n bytes per chunk (dimension-sized blocks)
        - Normalization: [0,255] → [-1,1]
    
    Parameters:
        n: Dimension (default 256)
        m: Number of layers (auto-computed if None)
        seed: Optional seed for key restoration
        device_id: GPU device ID
        
    Example:
        >>> crypto = MeteorPractical()
        >>> crypto.key_gen()
        >>> crypto.expand_keys()
        >>>
        >>> # String
        >>> enc = crypto.encrypt_string("Secret message")
        >>> dec = crypto.decrypt_string(enc)
        >>> print(dec)  # "Secret message"
        >>>
        >>> # File
        >>> crypto.encrypt_file("doc.pdf", "doc.enc")
        >>> crypto.decrypt_file("doc.enc", "doc_recovered.pdf")
    """
    
    def __init__(self, 
                 n: int = 256, 
                 m: Optional[int] = None, 
                 seed: Optional[bytes] = None,
                 device_id: int = 0):
        """Initialize practical Meteor-NC."""
        # Auto-compute m if not provided
        if m is None:
            m = compute_layer_count(n)
        
        # Initialize parent (MeteorKDF)
        super().__init__(n=n, m=m, seed=seed, device_id=device_id)
        
        # Additional statistics for practical operations
        self.practical_stats = {
            'strings_encrypted': 0,
            'strings_decrypted': 0,
            'bytes_encrypted': 0,
            'bytes_decrypted': 0,
            'files_encrypted': 0,
            'files_decrypted': 0,
            'total_bytes_processed': 0
        }
    
    # =========================================================================
    # Byte/Vector Conversion
    # =========================================================================
    
    def _bytes_to_vectors(self, data: bytes) -> np.ndarray:
        """
        Convert bytes to encryption-ready vectors.
        
        Strategy:
            - 1 byte = 1 float64 element
            - Normalize: [0,255] → [-1,1]
            - Zero-pad to multiples of n
        
        Args:
            data: Input bytes
            
        Returns:
            Array of shape (num_chunks, n)
        """
        # Pad to multiple of n
        padded_len = ((len(data) + self.n - 1) // self.n) * self.n
        padded = data + b'\x00' * (padded_len - len(data))
        
        # Convert to float64 array
        byte_array = np.frombuffer(padded, dtype=np.uint8).astype(np.float64)
        
        # Normalize [0,255] → [-1,1]
        normalized = (byte_array - 128.0) / 128.0
        
        # Reshape to (num_chunks, n)
        num_chunks = padded_len // self.n
        return normalized.reshape(num_chunks, self.n)
    
    def _vectors_to_bytes(self, vectors: np.ndarray, original_len: int) -> bytes:
        """
        Convert decrypted vectors back to bytes.
        
        Args:
            vectors: Decrypted vectors of shape (num_chunks, n)
            original_len: Original byte length (for truncation)
            
        Returns:
            Original bytes
        """
        # Flatten
        flat = vectors.flatten()
        
        # Denormalize [-1,1] → [0,255]
        denormalized = flat * 128.0 + 128.0
        
        # Clip and convert to uint8
        byte_array = np.clip(np.round(denormalized), 0, 255).astype(np.uint8)
        
        # Truncate to original length
        return byte_array.tobytes()[:original_len]
    
    # =========================================================================
    # String Encryption
    # =========================================================================
    
    def encrypt_string(self, text: str, encoding: str = 'utf-8') -> Dict:
        """
        Encrypt a string.
        
        Args:
            text: String to encrypt
            encoding: Text encoding (default UTF-8)
            
        Returns:
            Dictionary with ciphertext and metadata
        """
        # Auto-expand keys if needed
        if not self._keys_expanded:
            self.expand_keys()
        
        # Encode string to bytes
        data = text.encode(encoding)
        original_len = len(data)
        
        # Convert to vectors
        vectors = self._bytes_to_vectors(data)
        
        # Encrypt
        start = time.time()
        ciphertext = self.encrypt_batch(vectors)
        encrypt_time = time.time() - start
        
        # Compute checksum
        checksum = hashlib.sha256(data).hexdigest()
        
        # Update stats
        self.practical_stats['strings_encrypted'] += 1
        self.practical_stats['bytes_encrypted'] += original_len
        self.practical_stats['total_bytes_processed'] += original_len
        
        return {
            'ciphertext': ciphertext,
            'original_len': original_len,
            'encoding': encoding,
            'checksum': checksum,
            'encrypt_time': encrypt_time,
            'num_chunks': len(vectors)
        }
    
    def decrypt_string(self, encrypted: Dict) -> str:
        """
        Decrypt an encrypted string.
        
        Args:
            encrypted: Dictionary from encrypt_string()
            
        Returns:
            Decrypted string
        """
        # Auto-expand keys if needed
        if not self._keys_expanded:
            self.expand_keys()
        
        # Decrypt
        start = time.time()
        decrypted_vectors, _ = self.decrypt_batch(encrypted['ciphertext'])
        decrypt_time = time.time() - start
        
        # Convert back to bytes
        data = self._vectors_to_bytes(decrypted_vectors, encrypted['original_len'])
        
        # Verify checksum
        actual_checksum = hashlib.sha256(data).hexdigest()
        if actual_checksum != encrypted['checksum']:
            raise ValueError(
                f"Checksum mismatch! Expected {encrypted['checksum'][:16]}..., "
                f"got {actual_checksum[:16]}..."
            )
        
        # Update stats
        self.practical_stats['strings_decrypted'] += 1
        self.practical_stats['bytes_decrypted'] += encrypted['original_len']
        self.practical_stats['total_bytes_processed'] += encrypted['original_len']
        
        # Decode to string
        return data.decode(encrypted.get('encoding', 'utf-8'))
    
    # =========================================================================
    # Binary Encryption
    # =========================================================================
    
    def encrypt_bytes(self, data: bytes) -> Dict:
        """
        Encrypt binary data.
        
        Args:
            data: Bytes to encrypt
            
        Returns:
            Dictionary with ciphertext and metadata
        """
        if not self._keys_expanded:
            self.expand_keys()
        
        original_len = len(data)
        vectors = self._bytes_to_vectors(data)
        
        start = time.time()
        ciphertext = self.encrypt_batch(vectors)
        encrypt_time = time.time() - start
        
        checksum = hashlib.sha256(data).hexdigest()
        
        self.practical_stats['bytes_encrypted'] += original_len
        self.practical_stats['total_bytes_processed'] += original_len
        
        return {
            'ciphertext': ciphertext,
            'original_len': original_len,
            'checksum': checksum,
            'encrypt_time': encrypt_time,
            'num_chunks': len(vectors)
        }
    
    def decrypt_bytes(self, encrypted: Dict) -> bytes:
        """
        Decrypt encrypted binary data.
        
        Args:
            encrypted: Dictionary from encrypt_bytes()
            
        Returns:
            Decrypted bytes
        """
        if not self._keys_expanded:
            self.expand_keys()
        
        start = time.time()
        decrypted_vectors, _ = self.decrypt_batch(encrypted['ciphertext'])
        decrypt_time = time.time() - start
        
        data = self._vectors_to_bytes(decrypted_vectors, encrypted['original_len'])
        
        actual_checksum = hashlib.sha256(data).hexdigest()
        if actual_checksum != encrypted['checksum']:
            raise ValueError(
                f"Checksum mismatch! Expected {encrypted['checksum'][:16]}..., "
                f"got {actual_checksum[:16]}..."
            )
        
        self.practical_stats['bytes_decrypted'] += encrypted['original_len']
        self.practical_stats['total_bytes_processed'] += encrypted['original_len']
        
        return data
    
    # =========================================================================
    # File Encryption
    # =========================================================================
    
    def encrypt_file(self, input_path: str, output_path: str) -> Dict:
        """
        Encrypt a file.
        
        Args:
            input_path: Path to input file
            output_path: Path to output encrypted file
            
        Returns:
            Encryption metadata
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Read file
        data = input_path.read_bytes()
        original_len = len(data)
        
        # Encrypt
        encrypted = self.encrypt_bytes(data)
        
        # Prepare output data
        output_data = {
            'ciphertext': encrypted['ciphertext'].tolist(),
            'original_len': encrypted['original_len'],
            'checksum': encrypted['checksum'],
            'original_name': input_path.name,
            'n': self.n,
            'm': self.m
        }
        
        # Write encrypted file
        output_path.write_text(json.dumps(output_data))
        
        self.practical_stats['files_encrypted'] += 1
        
        return {
            'input_file': str(input_path),
            'output_file': str(output_path),
            'original_size': original_len,
            'encrypted_size': output_path.stat().st_size,
            'encrypt_time': encrypted['encrypt_time']
        }
    
    def decrypt_file(self, input_path: str, output_path: str) -> Dict:
        """
        Decrypt an encrypted file.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to output decrypted file
            
        Returns:
            Decryption metadata
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Encrypted file not found: {input_path}")
        
        # Read encrypted file
        encrypted_data = json.loads(input_path.read_text())
        
        # Reconstruct encrypted dict
        encrypted = {
            'ciphertext': np.array(encrypted_data['ciphertext']),
            'original_len': encrypted_data['original_len'],
            'checksum': encrypted_data['checksum']
        }
        
        # Decrypt
        start = time.time()
        data = self.decrypt_bytes(encrypted)
        decrypt_time = time.time() - start
        
        # Write decrypted file
        output_path.write_bytes(data)
        
        self.practical_stats['files_decrypted'] += 1
        
        return {
            'input_file': str(input_path),
            'output_file': str(output_path),
            'decrypted_size': len(data),
            'original_name': encrypted_data.get('original_name', 'unknown'),
            'decrypt_time': decrypt_time
        }
    
    # =========================================================================
    # Serialization (for network transport)
    # =========================================================================
    
    def serialize_encrypted(self, encrypted: Dict) -> str:
        """
        Serialize encrypted data to JSON string.
        
        Args:
            encrypted: Dictionary from encrypt_string/encrypt_bytes
            
        Returns:
            JSON string (Base64 encoded ciphertext)
        """
        ciphertext_bytes = encrypted['ciphertext'].tobytes()
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode('ascii')
        
        serialized = {
            'ciphertext_b64': ciphertext_b64,
            'ciphertext_shape': list(encrypted['ciphertext'].shape),
            'original_len': encrypted['original_len'],
            'checksum': encrypted['checksum'],
            'encoding': encrypted.get('encoding', 'utf-8'),
            'n': self.n,
            'm': self.m
        }
        
        return json.dumps(serialized)
    
    def deserialize_encrypted(self, json_str: str) -> Dict:
        """
        Deserialize JSON string to encrypted dictionary.
        
        Args:
            json_str: JSON string from serialize_encrypted
            
        Returns:
            Dictionary compatible with decrypt_string/decrypt_bytes
        """
        data = json.loads(json_str)
        
        ciphertext_bytes = base64.b64decode(data['ciphertext_b64'])
        ciphertext = np.frombuffer(ciphertext_bytes, dtype=np.float64)
        ciphertext = ciphertext.reshape(data['ciphertext_shape'])
        
        return {
            'ciphertext': ciphertext,
            'original_len': data['original_len'],
            'checksum': data['checksum'],
            'encoding': data.get('encoding', 'utf-8')
        }
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def get_practical_stats(self) -> Dict:
        """Get practical operation statistics."""
        return {
            **self.practical_stats,
            'n': self.n,
            'm': self.m,
            'keys_expanded': self._keys_expanded
        }


# =========================================================================
# Factory Functions
# =========================================================================

def create_practical_meteor(security_level: int = 256,
                            device_id: int = 0,
                            seed: Optional[bytes] = None) -> MeteorPractical:
    """
    Factory function for MeteorPractical.
    
    Automatically computes optimal layer count.
    
    Args:
        security_level: Security level (128, 256, 512, 1024, 2048)
        device_id: GPU device ID
        seed: Optional seed for key restoration
        
    Returns:
        Configured MeteorPractical instance
        
    Example:
        >>> crypto = create_practical_meteor(256)
        >>> crypto.key_gen()
        >>> crypto.expand_keys()
        >>> enc = crypto.encrypt_string("Hello!")
    """
    valid_levels = [128, 256, 512, 1024, 2048]
    
    if security_level not in valid_levels:
        raise ValueError(f"Security level must be one of {valid_levels}")
    
    n = security_level
    m = compute_layer_count(n)
    
    return MeteorPractical(n=n, m=m, seed=seed, device_id=device_id)


# =========================================================================
# Quick Helper Functions
# =========================================================================

def quick_encrypt_string(text: str, 
                         seed: Optional[bytes] = None,
                         security_level: int = 256) -> Tuple[str, bytes]:
    """
    Quick one-shot string encryption.
    
    Args:
        text: String to encrypt
        seed: Optional seed (generated if None)
        security_level: Security level
        
    Returns:
        Tuple of (encrypted JSON string, seed)
        
    Example:
        >>> json_str, seed = quick_encrypt_string("Secret!")
        >>> # Save seed securely
        >>> text = quick_decrypt_string(json_str, seed)
    """
    crypto = create_practical_meteor(security_level)
    
    if seed is not None:
        crypto.import_seed(seed)
        crypto.expand_keys()
    else:
        seed = crypto.key_gen()
        crypto.expand_keys()
    
    enc = crypto.encrypt_string(text)
    json_str = crypto.serialize_encrypted(enc)
    
    crypto.cleanup()
    
    return json_str, seed


def quick_decrypt_string(json_str: str, 
                         seed: bytes,
                         security_level: int = 256) -> str:
    """
    Quick one-shot string decryption.
    
    Args:
        json_str: Encrypted JSON from quick_encrypt_string
        seed: Seed used for encryption
        security_level: Security level
        
    Returns:
        Decrypted string
    """
    crypto = create_practical_meteor(security_level)
    crypto.import_seed(seed)
    crypto.expand_keys()
    
    enc = crypto.deserialize_encrypted(json_str)
    text = crypto.decrypt_string(enc)
    
    crypto.cleanup()
    
    return text


# =========================================================================
# Backward Compatibility
# =========================================================================

MeteorNC_Practical = MeteorPractical
