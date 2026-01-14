# meteor_nc/cryptography/stream.py
"""
Meteor-NC Stream DEM (Data Encapsulation Mechanism)

GPU-accelerated XChaCha20-Poly1305 for streaming encryption.
Designed for high-throughput media delivery (GB/s target).
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np

from .common import GPU_AVAILABLE, _sha256

if GPU_AVAILABLE:
    import cupy as cp
    from .kernels.chacha_poly_kernel import GPUChaCha20Poly1305


@dataclass
class StreamHeader:
    """Per-chunk header for authenticated encryption."""
    stream_id: bytes      # 16 bytes
    seq: int              # 64-bit sequence number
    chunk_len: int        # Payload length
    flags: int            # Reserved for codec/container


@dataclass  
class EncryptedChunk:
    """Encrypted chunk with authentication tag."""
    header: StreamHeader
    ciphertext: bytes
    tag: bytes            # 16 bytes Poly1305 tag


class StreamDEM:
    """
    Streaming Data Encapsulation Mechanism.
    
    Uses XChaCha20-Poly1305 for:
    - 192-bit nonce (no collision risk)
    - High-speed GPU encryption
    - Per-chunk authentication
    """
    
    NONCE_BYTES = 24      # XChaCha20
    TAG_BYTES = 16        # Poly1305
    KEY_BYTES = 32
    
    def __init__(
        self,
        session_key: bytes,
        stream_id: Optional[bytes] = None,
        gpu: bool = True,
        device_id: int = 0,
    ):
        if len(session_key) != self.KEY_BYTES:
            raise ValueError(f"Session key must be {self.KEY_BYTES} bytes")
        
        self.session_key = session_key
        self.stream_id = stream_id or os.urandom(16)
        self.gpu = gpu and GPU_AVAILABLE
        self.device_id = device_id
        
        # Derive sub-keys
        self.enc_key = _sha256(b"stream-enc", session_key)
        self.auth_key = _sha256(b"stream-auth", session_key)
        
        # Sequence counter
        self._seq = 0
        
        if self.gpu:
            cp.cuda.Device(device_id).use()
            self._cipher = GPUChaCha20Poly1305(self.enc_key, device_id)
    
    def _make_nonce(self, seq: int) -> bytes:
        """Generate 192-bit nonce from stream_id + seq."""
        # nonce = stream_id(128-bit) || seq(64-bit)
        return self.stream_id + struct.pack("<Q", seq)
    
    def _make_aad(self, header: StreamHeader) -> bytes:
        """Build AAD from header."""
        return (
            header.stream_id +
            struct.pack("<Q", header.seq) +
            struct.pack("<I", header.chunk_len) +
            struct.pack("<I", header.flags)
        )
    
    def encrypt_chunk(
        self,
        plaintext: bytes,
        seq: Optional[int] = None,
        flags: int = 0,
    ) -> EncryptedChunk:
        """
        Encrypt a single chunk.
        
        Args:
            plaintext: Data to encrypt
            seq: Sequence number (auto-increment if None)
            flags: Optional flags for codec/container
            
        Returns:
            EncryptedChunk with header, ciphertext, and tag
        """
        if seq is None:
            seq = self._seq
            self._seq += 1
        
        header = StreamHeader(
            stream_id=self.stream_id,
            seq=seq,
            chunk_len=len(plaintext),
            flags=flags,
        )
        
        nonce = self._make_nonce(seq)
        aad = self._make_aad(header)
        
        if self.gpu:
            ct, tag = self._cipher.encrypt(plaintext, nonce, aad)
        else:
            ct, tag = self._encrypt_cpu(plaintext, nonce, aad)
        
        return EncryptedChunk(header=header, ciphertext=ct, tag=tag)
    
    def decrypt_chunk(
        self,
        chunk: EncryptedChunk,
    ) -> bytes:
        """
        Decrypt and verify a chunk.
        
        Raises:
            ValueError: If authentication fails
        """
        nonce = self._make_nonce(chunk.header.seq)
        aad = self._make_aad(chunk.header)
        
        if self.gpu:
            plaintext = self._cipher.decrypt(
                chunk.ciphertext, chunk.tag, nonce, aad
            )
        else:
            plaintext = self._decrypt_cpu(
                chunk.ciphertext, chunk.tag, nonce, aad
            )
        
        return plaintext
    
    def encrypt_batch(
        self,
        chunks: list[bytes],
        start_seq: Optional[int] = None,
    ) -> list[EncryptedChunk]:
        """Encrypt multiple chunks in parallel (GPU batch)."""
        if start_seq is None:
            start_seq = self._seq
            self._seq += len(chunks)
        
        # TODO: Implement batch GPU encryption
        return [
            self.encrypt_chunk(pt, seq=start_seq + i)
            for i, pt in enumerate(chunks)
        ]
    
    def _encrypt_cpu(self, plaintext: bytes, nonce: bytes, aad: bytes) -> Tuple[bytes, bytes]:
        """CPU fallback using cryptography library."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        
        # XChaCha20 = HChaCha20(key, nonce[:16]) -> ChaCha20(subkey, nonce[16:])
        subkey = self._hchacha20(self.enc_key, nonce[:16])
        chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:]  # 12-byte nonce
        
        cipher = ChaCha20Poly1305(subkey)
        ct_with_tag = cipher.encrypt(chacha_nonce, plaintext, aad)
        
        return ct_with_tag[:-16], ct_with_tag[-16:]
    
    def _decrypt_cpu(self, ciphertext: bytes, tag: bytes, nonce: bytes, aad: bytes) -> bytes:
        """CPU fallback decryption."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        
        subkey = self._hchacha20(self.enc_key, nonce[:16])
        chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:]
        
        cipher = ChaCha20Poly1305(subkey)
        return cipher.decrypt(chacha_nonce, ciphertext + tag, aad)
    
    @staticmethod
    def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
        """HChaCha20: key derivation for XChaCha20."""
        # Constants
        constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        
        # Key words
        k = struct.unpack("<8I", key)
        
        # Nonce words
        n = struct.unpack("<4I", nonce16)
        
        # Initial state
        state = list(constants) + list(k) + list(n)
        
        # 20 rounds (10 double-rounds)
        def quarter_round(a, b, c, d):
            state[a] = (state[a] + state[b]) & 0xFFFFFFFF
            state[d] ^= state[a]
            state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF
            
            state[c] = (state[c] + state[d]) & 0xFFFFFFFF
            state[b] ^= state[c]
            state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF
            
            state[a] = (state[a] + state[b]) & 0xFFFFFFFF
            state[d] ^= state[a]
            state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF
            
            state[c] = (state[c] + state[d]) & 0xFFFFFFFF
            state[b] ^= state[c]
            state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF
        
        for _ in range(10):
            # Column rounds
            quarter_round(0, 4, 8, 12)
            quarter_round(1, 5, 9, 13)
            quarter_round(2, 6, 10, 14)
            quarter_round(3, 7, 11, 15)
            # Diagonal rounds
            quarter_round(0, 5, 10, 15)
            quarter_round(1, 6, 11, 12)
            quarter_round(2, 7, 8, 13)
            quarter_round(3, 4, 9, 14)
        
        # Output: state[0..3] and state[12..15]
        out = state[0:4] + state[12:16]
        return struct.pack("<8I", *out)


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute StreamDEM tests."""
    print("=" * 70)
    print("Meteor-NC StreamDEM Test Suite")
    print("=" * 70)
    
    import secrets
    
    results = {}
    
    # Test 1: Basic encrypt/decrypt
    print("\n[Test 1] Basic Encrypt/Decrypt")
    print("-" * 40)
    
    session_key = secrets.token_bytes(32)
    stream = StreamDEM(session_key, gpu=False)  # CPU first
    
    test_sizes = [0, 1, 15, 16, 17, 64, 1000, 10000]
    basic_ok = True
    
    for size in test_sizes:
        pt = secrets.token_bytes(size) if size > 0 else b""
        chunk = stream.encrypt_chunk(pt)
        recovered = stream.decrypt_chunk(chunk)
        ok = (pt == recovered)
        basic_ok = basic_ok and ok
        print(f"  Size {size:5d}: {'PASS' if ok else 'FAIL'}")
    
    results["basic"] = basic_ok
    
    # Test 2: Sequence integrity
    print("\n[Test 2] Sequence Integrity")
    print("-" * 40)
    
    stream2 = StreamDEM(session_key, gpu=False)
    chunks = [stream2.encrypt_chunk(f"msg{i}".encode()) for i in range(5)]
    
    seq_ok = all(chunks[i].header.seq == i for i in range(5))
    results["sequence"] = seq_ok
    print(f"  Auto-increment seq: {'PASS' if seq_ok else 'FAIL'}")
    
    # Test 3: Tamper detection
    print("\n[Test 3] Tamper Detection")
    print("-" * 40)
    
    stream3 = StreamDEM(session_key, gpu=False)
    chunk = stream3.encrypt_chunk(b"secret data")
    
    # Tamper with ciphertext
    bad_ct = bytes([chunk.ciphertext[0] ^ 1]) + chunk.ciphertext[1:]
    bad_chunk = EncryptedChunk(
        header=chunk.header,
        ciphertext=bad_ct,
        tag=chunk.tag,
    )
    
    try:
        stream3.decrypt_chunk(bad_chunk)
        tamper_ok = False
    except Exception:
        tamper_ok = True
    
    results["tamper"] = tamper_ok
    print(f"  Ciphertext tamper: {'PASS' if tamper_ok else 'FAIL'}")
    
    # Test 4: AAD verification
    print("\n[Test 4] AAD Verification")  
    print("-" * 40)
    
    stream4 = StreamDEM(session_key, gpu=False)
    chunk = stream4.encrypt_chunk(b"aad test")
    
    # Modify seq in header (breaks AAD)
    bad_header = StreamHeader(
        stream_id=chunk.header.stream_id,
        seq=chunk.header.seq + 1,  # Wrong seq!
        chunk_len=chunk.header.chunk_len,
        flags=chunk.header.flags,
    )
    bad_chunk = EncryptedChunk(
        header=bad_header,
        ciphertext=chunk.ciphertext,
        tag=chunk.tag,
    )
    
    try:
        stream4.decrypt_chunk(bad_chunk)
        aad_ok = False
    except Exception:
        aad_ok = True
    
    results["aad"] = aad_ok
    print(f"  AAD integrity: {'PASS' if aad_ok else 'FAIL'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
