# meteor_nc/cryptography/practical.py
"""
Meteor-NC Practical Encryption

High-level API for string, binary, and file encryption.
Built on top of HybridKEM (Post-Quantum) + StreamDEM.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

import numpy as np

from .common import GPU_AVAILABLE, CRYPTO_AVAILABLE, _sha256
from .core import HybridKEM, LWEKEM
from .stream import StreamDEM, EncryptedChunk

if not CRYPTO_AVAILABLE:
    raise ImportError("cryptography library required for practical encryption")


@dataclass
class EncryptedData:
    """Container for encrypted data with metadata."""
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    original_len: int
    checksum: str
    metadata: Optional[Dict] = None


class MeteorPractical:
    """
    Practical Meteor-NC encryption.
    
    Provides high-level APIs for:
    - String encryption/decryption
    - Binary data encryption/decryption  
    - File encryption/decryption
    - Serialization for network transport
    
    Uses:
    - HybridKEM for key establishment (Post-Quantum secure)
    - StreamDEM (XChaCha20-Poly1305) for data encryption
    
    Example:
        >>> crypto = MeteorPractical()
        >>> crypto.key_gen()
        >>>
        >>> # String encryption
        >>> encrypted = crypto.encrypt_string("Hello, World!")
        >>> decrypted = crypto.decrypt_string(encrypted)
        >>>
        >>> # File encryption
        >>> crypto.encrypt_file("secret.pdf", "secret.enc")
        >>> crypto.decrypt_file("secret.enc", "recovered.pdf")
    """
    
    def __init__(
        self,
        security_level: int = 128,
        gpu: bool = True,
        device_id: int = 0,
        seed: Optional[bytes] = None,
    ):
        """
        Initialize MeteorPractical.
        
        Args:
            security_level: Security level (128 or 256)
            gpu: Enable GPU acceleration
            device_id: GPU device ID
            seed: Optional seed for deterministic keys
        """
        self.security_level = security_level
        self.gpu = gpu and GPU_AVAILABLE
        self.device_id = device_id
        
        # Master seed
        self.master_seed = seed or secrets.token_bytes(32)
        
        # Initialize KEM
        self._kem = HybridKEM(
            security_level=security_level,
            gpu=self.gpu,
            device_id=device_id,
            seed=self.master_seed,
        )
        
        # Session key (derived after key_gen)
        self._session_key: Optional[bytes] = None
        self._stream: Optional[StreamDEM] = None
        
        # Statistics
        self.stats = {
            'strings_encrypted': 0,
            'strings_decrypted': 0,
            'bytes_encrypted': 0,
            'bytes_decrypted': 0,
            'files_encrypted': 0,
            'files_decrypted': 0,
        }
    
    def key_gen(self) -> float:
        """
        Generate keys.
        
        Returns:
            Key generation time in seconds
        """
        start = time.time()
        
        # Generate KEM keys
        self._kem.key_gen()
        
        # Derive session key for StreamDEM
        self._session_key = _sha256(b"stream-session", self.master_seed)
        
        # Derive deterministic stream_id from seed
        stream_id = _sha256(b"stream-id", self.master_seed)[:16]
        
        # Initialize StreamDEM with deterministic stream_id
        self._stream = StreamDEM(
            session_key=self._session_key,
            stream_id=stream_id,
            gpu=self.gpu,
            device_id=self.device_id,
    )
    
    return time.time() - start
    
    @property
    def keys_ready(self) -> bool:
        """Check if keys are generated."""
        return self._stream is not None
    
    def _ensure_keys(self):
        """Ensure keys are generated."""
        if not self.keys_ready:
            raise ValueError("Keys not initialized. Call key_gen() first.")
    
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
            Dictionary with encrypted data and metadata
        """
        self._ensure_keys()
        
        data = text.encode(encoding)
        result = self._encrypt_bytes_internal(data)
        
        self.stats['strings_encrypted'] += 1
        
        return {
            **result,
            'encoding': encoding,
            'type': 'string',
        }
    
    def decrypt_string(self, encrypted: Dict) -> str:
        """
        Decrypt an encrypted string.
        
        Args:
            encrypted: Dictionary from encrypt_string()
            
        Returns:
            Decrypted string
        """
        self._ensure_keys()
        
        data = self._decrypt_bytes_internal(encrypted)
        
        self.stats['strings_decrypted'] += 1
        
        encoding = encrypted.get('encoding', 'utf-8')
        return data.decode(encoding)
    
    # =========================================================================
    # Binary Encryption
    # =========================================================================
    
    def encrypt_bytes(self, data: bytes) -> Dict:
        """
        Encrypt binary data.
        
        Args:
            data: Bytes to encrypt
            
        Returns:
            Dictionary with encrypted data and metadata
        """
        self._ensure_keys()
        
        result = self._encrypt_bytes_internal(data)
        
        self.stats['bytes_encrypted'] += len(data)
        
        return {
            **result,
            'type': 'binary',
        }
    
    def decrypt_bytes(self, encrypted: Dict) -> bytes:
        """
        Decrypt encrypted binary data.
        
        Args:
            encrypted: Dictionary from encrypt_bytes()
            
        Returns:
            Decrypted bytes
        """
        self._ensure_keys()
        
        data = self._decrypt_bytes_internal(encrypted)
        
        self.stats['bytes_decrypted'] += len(data)
        
        return data
    
    def _encrypt_bytes_internal(self, data: bytes) -> Dict:
        """Internal encryption using StreamDEM."""
        start = time.time()
        
        # Compute checksum
        checksum = hashlib.sha256(data).hexdigest()
        
        # Encrypt with StreamDEM
        chunk = self._stream.encrypt_chunk(data)
        
        encrypt_time = time.time() - start
        
        return {
            'ciphertext': chunk.ciphertext,
            'tag': chunk.tag,  # ← これ追加！
            'seq': chunk.header.seq,
            'stream_id': chunk.header.stream_id,
            'original_len': len(data),
            'checksum': checksum,
            'encrypt_time': encrypt_time,
        }
        
    def _decrypt_bytes_internal(self, encrypted: Dict) -> bytes:
        """Internal decryption using StreamDEM."""
        start = time.time()
        
        # Reconstruct chunk
        from .stream import StreamHeader, EncryptedChunk
        
        header = StreamHeader(
            stream_id=encrypted['stream_id'],
            seq=encrypted['seq'],
            chunk_len=len(encrypted['ciphertext']),
            flags=0,
        )
        
        chunk = EncryptedChunk(
            header=header,
            ciphertext=encrypted['ciphertext'],
            tag=encrypted['tag'],  # ← これ修正！
        )
        
        # Decrypt
        data = self._stream.decrypt_chunk(chunk)
        
        decrypt_time = time.time() - start
        
        # Verify checksum
        actual_checksum = hashlib.sha256(data).hexdigest()
        if actual_checksum != encrypted['checksum']:
            raise ValueError(
                f"Checksum mismatch! Data may be corrupted or tampered."
            )
        
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
        self._ensure_keys()
        
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Read and encrypt
        data = input_path.read_bytes()
        encrypted = self.encrypt_bytes(data)
        
        # Serialize to file
        output_data = self._serialize_for_file(encrypted, input_path.name)
        output_path.write_text(output_data)
        
        self.stats['files_encrypted'] += 1
        
        return {
            'input_file': str(input_path),
            'output_file': str(output_path),
            'original_size': len(data),
            'encrypted_size': len(output_data),
            'encrypt_time': encrypted['encrypt_time'],
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
        self._ensure_keys()
        
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Encrypted file not found: {input_path}")
        
        # Read and deserialize
        file_data = input_path.read_text()
        encrypted = self._deserialize_from_file(file_data)
        
        # Decrypt
        start = time.time()
        data = self.decrypt_bytes(encrypted)
        decrypt_time = time.time() - start
        
        # Write output
        output_path.write_bytes(data)
        
        self.stats['files_decrypted'] += 1
        
        return {
            'input_file': str(input_path),
            'output_file': str(output_path),
            'decrypted_size': len(data),
            'decrypt_time': decrypt_time,
        }
    
    # =========================================================================
    # Serialization
    # =========================================================================
    
    def serialize(self, encrypted: Dict) -> str:
        """
        Serialize encrypted data to JSON string.
        
        Args:
            encrypted: Dictionary from encrypt_string/encrypt_bytes
            
        Returns:
            JSON string for network transport
        """
        return json.dumps({
            'ciphertext_b64': base64.b64encode(encrypted['ciphertext']).decode('ascii'),
            'tag_b64': base64.b64encode(encrypted['tag']).decode('ascii'),  # ← 追加
            'stream_id_b64': base64.b64encode(encrypted['stream_id']).decode('ascii'),
            'seq': encrypted['seq'],
            'original_len': encrypted['original_len'],
            'checksum': encrypted['checksum'],
            'encoding': encrypted.get('encoding'),
            'type': encrypted.get('type', 'binary'),
            'security_level': self.security_level,
        })
    
    def deserialize(self, json_str: str) -> Dict:
        """
        Deserialize JSON string to encrypted dictionary.
        
        Args:
            json_str: JSON string from serialize()
            
        Returns:
            Dictionary for decrypt_string/decrypt_bytes
        """
        data = json.loads(json_str)
        
        return {
            'ciphertext': base64.b64decode(data['ciphertext_b64']),
            'tag': base64.b64decode(data['tag_b64']),  # ← 追加
            'stream_id': base64.b64decode(data['stream_id_b64']),
            'seq': data['seq'],
            'original_len': data['original_len'],
            'checksum': data['checksum'],
            'encoding': data.get('encoding'),
            'type': data.get('type', 'binary'),
        }
    
    def _serialize_for_file(self, encrypted: Dict, original_name: str) -> str:
        """Serialize for file storage."""
        data = json.loads(self.serialize(encrypted))
        data['original_name'] = original_name
        return json.dumps(data, indent=2)
    
    def _deserialize_from_file(self, file_data: str) -> Dict:
        """Deserialize from file storage."""
        return self.deserialize(file_data)
    
    # =========================================================================
    # Seed Management
    # =========================================================================
    
    def export_seed(self) -> bytes:
        """Export master seed for key recovery."""
        return self.master_seed
    
    def get_stats(self) -> Dict:
        """Get operation statistics."""
        return {
            **self.stats,
            'security_level': self.security_level,
            'gpu_enabled': self.gpu,
            'keys_ready': self.keys_ready,
        }


# =========================================================================
# Factory Functions
# =========================================================================

def create_meteor(
    security_level: int = 128,
    gpu: bool = True,
    seed: Optional[bytes] = None,
) -> MeteorPractical:
    """
    Create a MeteorPractical instance.
    
    Args:
        security_level: 128 or 256
        gpu: Enable GPU acceleration
        seed: Optional seed for deterministic keys
        
    Returns:
        Configured MeteorPractical instance
    """
    return MeteorPractical(
        security_level=security_level,
        gpu=gpu,
        seed=seed,
    )


def quick_encrypt(data: Union[str, bytes], seed: Optional[bytes] = None) -> Tuple[str, bytes]:
    """
    Quick one-shot encryption.
    
    Args:
        data: String or bytes to encrypt
        seed: Optional seed (generated if None)
        
    Returns:
        Tuple of (encrypted JSON string, seed)
    """
    crypto = create_meteor(seed=seed)
    crypto.key_gen()
    
    if isinstance(data, str):
        encrypted = crypto.encrypt_string(data)
    else:
        encrypted = crypto.encrypt_bytes(data)
    
    return crypto.serialize(encrypted), crypto.export_seed()


def quick_decrypt(json_str: str, seed: bytes) -> Union[str, bytes]:
    """
    Quick one-shot decryption.
    
    Args:
        json_str: Encrypted JSON from quick_encrypt
        seed: Seed used for encryption
        
    Returns:
        Decrypted string or bytes
    """
    crypto = create_meteor(seed=seed)
    crypto.key_gen()
    
    encrypted = crypto.deserialize(json_str)
    
    if encrypted.get('type') == 'string':
        return crypto.decrypt_string(encrypted)
    else:
        return crypto.decrypt_bytes(encrypted)


# =========================================================================
# Test Suite
# =========================================================================

def run_tests() -> bool:
    """Execute practical encryption tests."""
    print("=" * 70)
    print("Meteor-NC Practical Encryption Test Suite")
    print("=" * 70)
    
    results = {}
    
    # Test 1: String encryption
    print("\n[Test 1] String Encryption")
    print("-" * 40)
    
    crypto = MeteorPractical(gpu=True)
    crypto.key_gen()
    
    test_strings = [
        "Hello, World!",
        "日本語テスト",
        "🎉🔥💪",
        "A" * 1000,
        "",
    ]
    
    string_ok = True
    for s in test_strings:
        enc = crypto.encrypt_string(s)
        dec = crypto.decrypt_string(enc)
        ok = (s == dec)
        string_ok = string_ok and ok
        print(f"  '{s[:20]}...': {'PASS' if ok else 'FAIL'}")
    
    results['string'] = string_ok
    
    # Test 2: Binary encryption
    print("\n[Test 2] Binary Encryption")
    print("-" * 40)
    
    test_sizes = [0, 1, 100, 1000, 10000]
    binary_ok = True
    
    for size in test_sizes:
        data = secrets.token_bytes(size) if size > 0 else b""
        enc = crypto.encrypt_bytes(data)
        dec = crypto.decrypt_bytes(enc)
        ok = (data == dec)
        binary_ok = binary_ok and ok
        print(f"  Size {size:5d}: {'PASS' if ok else 'FAIL'}")
    
    results['binary'] = binary_ok
    
    # Test 3: Serialization
    print("\n[Test 3] Serialization")
    print("-" * 40)
    
    enc = crypto.encrypt_string("Serialize test")
    json_str = crypto.serialize(enc)
    dec_enc = crypto.deserialize(json_str)
    dec = crypto.decrypt_string(dec_enc)
    
    serial_ok = (dec == "Serialize test")
    results['serialization'] = serial_ok
    print(f"  Round-trip: {'PASS' if serial_ok else 'FAIL'}")
    
    # Test 4: Quick functions
    print("\n[Test 4] Quick Functions")
    print("-" * 40)
    
    json_str, seed = quick_encrypt("Quick test")
    dec = quick_decrypt(json_str, seed)
    
    quick_ok = (dec == "Quick test")
    results['quick'] = quick_ok
    print(f"  Quick encrypt/decrypt: {'PASS' if quick_ok else 'FAIL'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
