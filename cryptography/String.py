"""
Meteor-NC: String & File Encryption Extension

Supports encryption for strings, binary data, and files.

Provides practical encryption functionalities as an upper layer of the KDF implementation.

Features:
    - String encryption/decryption
    - Binary data encryption/decryption
    - File encryption/decryption
    - Base64 serialization support

Usage:
    from meteor_nc.cryptography import MeteorPractical
    
    # Initialization
    crypto = MeteorPractical(n=256, m=10)
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


class MeteorPractical:
    """
    Practical Meteor-NC implementation with encryption capabilities.
    
    Internally uses a KDF to provide encryption/decryption for strings,
    binary data, and files.
    
    Encoding Strategy:
        - 1 byte → 1 float64 element (to guarantee precision)
        - 256 bytes per chunk (when n=256)
        - Normalization: [0,255] → [-1,1] (approximates a Gaussian distribution)
    
    Parameters:
        n: Dimension (default 256)
        m: Number of layers (default 10)
        
    Example:
        >>> crypto = MeteorPractical()
        >>> crypto.key_gen()
        >>>
        >>> # String
        >>> enc = crypto.encrypt_string("Secret message")
        >>> dec = crypto.decrypt_string(enc)
        >>> print(dec)  # "Secret message"
    """
    
    def __init__(self, n: int = 256, m: int = 10, device_id: int = 0):
        """Initialize practical Meteor-NC."""
        self.n = n
        self.m = m
        self.device_id = device_id
        
        # KDF instance used internally
        self._kdf = None
        self._keys_ready = False
        
        # Statistics
        self.stats = {
            'strings_encrypted': 0,
            'bytes_processed': 0,
            'files_encrypted': 0
        }
    
    def _init_kdf(self):
        """Lazily initialize the KDF instance."""
        if self._kdf is None:
            try:
                from .kdf import MeteorKDF
                self._kdf = MeteorKDF(
                    n=self.n, 
                    m=self.m, 
                    device_id=self.device_id
                )
            except ImportError:
                raise ImportError(
                    "KDF module is required.\n"
                    "Ensure meteor_nc.cryptography.kdf is available."
                )
    
    def key_gen(self, verbose: bool = False) -> bytes:
        """
        Generate keys (seed only).
        
        Returns:
            32-byte master seed
        """
        self._init_kdf()
        self._kdf.key_gen(verbose=verbose)
        return self._kdf.export_seed()
    
    def expand_keys(self, verbose: bool = False) -> float:
        """
        Expand keys from the seed.
        
        Returns:
            Expansion time in seconds
        """
        self._init_kdf()
        expand_time = self._kdf.expand_keys(verbose=verbose)
        self._keys_ready = True
        return expand_time
    
    def import_seed(self, seed: bytes):
        """Import a seed."""
        self._init_kdf()
        self._kdf.import_seed(seed)
        self._keys_ready = False
    
    def export_seed(self) -> bytes:
        """Export the current seed."""
        self._init_kdf()
        return self._kdf.export_seed()
    
    # =========================================================================
    # Internal conversion methods
    # =========================================================================
    
    def _bytes_to_vectors(self, data: bytes) -> np.ndarray:
        """
        Convert byte sequence into vector chunks.
        
        Strategy:
            - 1 byte = 1 float64 element
            - Normalize: [0,255] → [-1,1]
            - Zero-pad to multiples of n
        
        Args:
            data: Input byte sequence
            
        Returns:
            numpy array of shape (num_chunks, n)
        """
        original_len = len(data)
        padded_len = ((original_len + self.n - 1) // self.n) * self.n
        padding_len = padded_len - original_len
        
        # Zero padding
        padded = data + b'\x00' * padding_len
        
        # Split into chunks and normalize
        num_chunks = padded_len // self.n
        vectors = np.zeros((num_chunks, self.n), dtype=np.float64)
        
        for i in range(num_chunks):
            chunk = padded[i * self.n : (i + 1) * self.n]
            byte_array = np.frombuffer(chunk, dtype=np.uint8).astype(np.float64)
            vectors[i] = (byte_array - 128.0) / 128.0
        
        return vectors
    
    def _vectors_to_bytes(self, vectors: np.ndarray, original_len: int) -> bytes:
        """
        Restore byte sequence from vector chunks.
        
        Args:
            vectors: Array of shape (num_chunks, n)
            original_len: Original byte length (used to remove padding)
            
        Returns:
            Reconstructed byte sequence
        """
        result = bytearray()
        
        for vec in vectors:
            byte_array = vec * 128.0 + 128.0
            byte_array = np.clip(np.round(byte_array), 0, 255).astype(np.uint8)
            result.extend(byte_array.tobytes())
        
        return bytes(result[:original_len])
    
    def _ensure_keys(self):
        """Ensure keys are prepared."""
        if not self._keys_ready:
            if self._kdf is None:
                raise ValueError("Call key_gen() first")
            self.expand_keys(verbose=False)
    
    # =========================================================================
    # String encryption
    # =========================================================================
    
    def encrypt_string(self, text: str, encoding: str = 'utf-8') -> dict:
        """
        Encrypt a string.
        
        Args:
            text: String to encrypt
            encoding: Character encoding
            
        Returns:
            Dictionary containing ciphertext and metadata
        """
        self._ensure_keys()
        
        data = text.encode(encoding)
        original_len = len(data)
        
        checksum = hashlib.sha256(data).hexdigest()[:16]
        
        vectors = self._bytes_to_vectors(data)
        ciphertexts = self._kdf.encrypt_batch(vectors)
        
        self.stats['strings_encrypted'] += 1
        self.stats['bytes_processed'] += original_len
        
        return {
            'ciphertext': ciphertexts,
            'original_len': original_len,
            'encoding': encoding,
            'checksum': checksum
        }
    
    def decrypt_string(self, encrypted: dict) -> str:
        """
        Decrypt ciphertext into a string.
        
        Args:
            encrypted: Result from encrypt_string()
            
        Returns:
            Decrypted string
        """
        self._ensure_keys()
        
        ciphertexts = encrypted['ciphertext']
        original_len = encrypted['original_len']
        encoding = encrypted.get('encoding', 'utf-8')
        expected_checksum = encrypted.get('checksum')
        
        recovered, _ = self._kdf.decrypt_batch(ciphertexts)
        data = self._vectors_to_bytes(recovered, original_len)
        
        if expected_checksum:
            actual_checksum = hashlib.sha256(data).hexdigest()[:16]
            if actual_checksum != expected_checksum:
                raise ValueError(
                    f"Checksum mismatch! Data is corrupted.\n"
                    f"Expected: {expected_checksum}, Actual: {actual_checksum}"
                )
        
        return data.decode(encoding)
    
    # =========================================================================
    # Binary encryption
    # =========================================================================
    
    def encrypt_bytes(self, data: bytes) -> dict:
        """
        Encrypt a byte sequence.
        
        Args:
            data: Input bytes
            
        Returns:
            Dictionary containing encrypted result
        """
        self._ensure_keys()
        
        original_len = len(data)
        checksum = hashlib.sha256(data).hexdigest()[:16]
        
        vectors = self._bytes_to_vectors(data)
        ciphertexts = self._kdf.encrypt_batch(vectors)
        
        self.stats['bytes_processed'] += original_len
        
        return {
            'ciphertext': ciphertexts,
            'original_len': original_len,
            'checksum': checksum
        }
    
    def decrypt_bytes(self, encrypted: dict) -> bytes:
        """
        Decrypt into bytes.
        
        Args:
            encrypted: Result from encrypt_bytes()
            
        Returns:
            Decrypted data
        """
        self._ensure_keys()
        
        ciphertexts = encrypted['ciphertext']
        original_len = encrypted['original_len']
        expected_checksum = encrypted.get('checksum')
        
        recovered, _ = self._kdf.decrypt_batch(ciphertexts)
        data = self._vectors_to_bytes(recovered, original_len)
        
        if expected_checksum:
            actual_checksum = hashlib.sha256(data).hexdigest()[:16]
            if actual_checksum != expected_checksum:
                raise ValueError("Checksum mismatch!")
        
        return data
    
    # =========================================================================
    # File encryption
    # =========================================================================
    
    def encrypt_file(self, input_path: str, output_path: str, 
                     verbose: bool = False) -> dict:
        """
        Encrypt a file.
        
        Args:
            input_path: Input file path
            output_path: Output file path
            verbose: Show progress
            
        Returns:
            Metadata dictionary
        """
        self._ensure_keys()
        
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"File not found: {input_path}")
        
        if verbose:
            print(f"[*] Encrypting: {input_path}")
        
        start = time.time()
        
        with open(input_path, 'rb') as f:
            data = f.read()
        
        original_len = len(data)
        original_name = input_path.name
        checksum = hashlib.sha256(data).hexdigest()
        
        if verbose:
            print(f"    Size: {original_len:,} bytes")
        
        vectors = self._bytes_to_vectors(data)
        ciphertexts = self._kdf.encrypt_batch(vectors)
        
        metadata = {
            'version': '1.0',
            'algorithm': 'Meteor-NC',
            'n': self.n,
            'm': self.m,
            'original_name': original_name,
            'original_len': original_len,
            'checksum': checksum,
            'chunks': ciphertexts.shape[0],
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(output_path, 'wb') as f:
            meta_json = json.dumps(metadata).encode('utf-8')
            meta_b64 = base64.b64encode(meta_json)
            header = f"MNC1:{len(meta_b64)}:".encode('ascii')
            f.write(header)
            f.write(meta_b64)
            f.write(b'\n')
            f.write(ciphertexts.tobytes())
        
        elapsed = time.time() - start
        
        self.stats['files_encrypted'] += 1
        self.stats['bytes_processed'] += original_len
        
        if verbose:
            output_size = output_path.stat().st_size
            ratio = output_size / original_len * 100
            print(f"[✓] Done: {elapsed:.2f}s")
            print(f"    Output: {output_path} ({output_size:,} bytes, {ratio:.1f}%)")
        
        return metadata
    
    def decrypt_file(self, input_path: str, output_path: Optional[str] = None,
                     verbose: bool = False) -> str:
        """
        Decrypt a file.
        
        Args:
            input_path: Encrypted file path
            output_path: Output file path (default: original name)
            verbose: Show progress
            
        Returns:
            Output file path
        """
        self._ensure_keys()
        
        input_path = Path(input_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"File not found: {input_path}")
        
        if verbose:
            print(f"[*] Decrypting: {input_path}")
        
        start = time.time()
        
        with open(input_path, 'rb') as f:
            header_line = b''
            while True:
                c = f.read(1)
                if c == b'\n':
                    break
                header_line += c
            
            parts = header_line.split(b':')
            if parts[0] != b'MNC1':
                raise ValueError("Invalid file format")
            
            meta_len = int(parts[1])
            meta_b64 = parts[2][:meta_len]
            meta_json = base64.b64decode(meta_b64)
            metadata = json.loads(meta_json.decode('utf-8'))
            
            ciphertext_bytes = f.read()
        
        if metadata['n'] != self.n or metadata['m'] != self.m:
            raise ValueError(
                f"Parameter mismatch: "
                f"File(n={metadata['n']}, m={metadata['m']}) vs "
                f"Current(n={self.n}, m={self.m})"
            )
        
        chunks = metadata['chunks']
        ciphertexts = np.frombuffer(ciphertext_bytes, dtype=np.float64)
        ciphertexts = ciphertexts.reshape(chunks, self.n)
        
        if verbose:
            print(f"    Chunks: {chunks}")
        
        recovered, _ = self._kdf.decrypt_batch(ciphertexts)
        data = self._vectors_to_bytes(recovered, metadata['original_len'])
        
        actual_checksum = hashlib.sha256(data).hexdigest()
        if actual_checksum != metadata['checksum']:
            raise ValueError("Checksum mismatch! File is corrupted or the key is incorrect.")
        
        if output_path is None:
            output_path = input_path.parent / metadata['original_name']
        output_path = Path(output_path)
        
        with open(output_path, 'wb') as f:
            f.write(data)
        
        elapsed = time.time() - start
        
        if verbose:
            print(f"[✓] Done: {elapsed:.2f}s")
            print(f"    Output: {output_path} ({len(data):,} bytes)")
        
        return str(output_path)
    
    # =========================================================================
    # Serialization (JSON-compatible output)
    # =========================================================================
    
    def serialize_encrypted(self, encrypted: dict) -> str:
        """
        Serialize encrypted result into JSON.
        
        Base64-encoded for text-based storage and transfer.
        
        Args:
            encrypted: Result from encrypt_string/bytes()
            
        Returns:
            JSON string
        """
        serialized = {
            'ciphertext_b64': base64.b64encode(
                encrypted['ciphertext'].tobytes()
            ).decode('ascii'),
            'shape': list(encrypted['ciphertext'].shape),
            'original_len': encrypted['original_len'],
            'checksum': encrypted.get('checksum'),
            'encoding': encrypted.get('encoding'),
            'algorithm': 'Meteor-NC',
            'n': self.n,
            'm': self.m
        }
        return json.dumps(serialized, ensure_ascii=False, indent=2)
    
    def deserialize_encrypted(self, json_str: str) -> dict:
        """
        Deserialize JSON string back into encrypted structure.
        
        Args:
            json_str: Output from serialize_encrypted()
            
        Returns:
            Dictionary ready for decryption
        """
        data = json.loads(json_str)
        
        if data['n'] != self.n or data['m'] != self.m:
            raise ValueError("Parameter mismatch")
        
        ciphertext_bytes = base64.b64decode(data['ciphertext_b64'])
        ciphertext = np.frombuffer(ciphertext_bytes, dtype=np.float64)
        ciphertext = ciphertext.reshape(data['shape'])
        
        return {
            'ciphertext': ciphertext,
            'original_len': data['original_len'],
            'checksum': data.get('checksum'),
            'encoding': data.get('encoding')
        }
    
    # =========================================================================
    # Utilities
    # =========================================================================
    
    def get_stats(self) -> dict:
        """Return statistics."""
        return {
            **self.stats,
            'chunk_size_bytes': self.n,
            'overhead_ratio': (self.n * 8) / self.n  # float64 = 8 bytes
        }
    
    def cleanup(self):
        """Release resources."""
        if self._kdf:
            self._kdf.cleanup()


# =============================================================================
# Helper functions
# =============================================================================

def quick_encrypt_string(text: str, seed: Optional[bytes] = None) -> Tuple[str, bytes]:
    """
    One-liner string encryption.
    
    Args:
        text: Text to encrypt
        seed: Seed (auto-generated if omitted)
        
    Returns:
        Tuple of (encrypted JSON, seed)
    """
    crypto = MeteorPractical()
    
    if seed:
        crypto.import_seed(seed)
    else:
        seed = crypto.key_gen()
    
    crypto.expand_keys()
    
    enc = crypto.encrypt_string(text)
    json_str = crypto.serialize_encrypted(enc)
    
    crypto.cleanup()
    
    return json_str, seed


def quick_decrypt_string(json_str: str, seed: bytes) -> str:
    """
    Decrypt encrypted JSON string.
    
    Args:
        json_str: Encrypted JSON
        seed: Seed used for encryption
        
    Returns:
        Decrypted text
    """
    crypto = MeteorPractical()
    crypto.import_seed(seed)
    crypto.expand_keys()
    
    enc = crypto.deserialize_encrypted(json_str)
    text = crypto.decrypt_string(enc)
    
    crypto.cleanup()
    
    return text


# Backward compatibility alias
MeteorNC_Practical = MeteorPractical
