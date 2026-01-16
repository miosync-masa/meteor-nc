# meteor_nc/cryptography/stream.py
"""
Meteor-NC Stream Hybrid KEM

Streaming Hybrid PKE with correct design:
  - First: KEM encaps with recipient's public key → K
  - Then: All chunks encrypted with K-derived session key (XChaCha20-Poly1305)

This ensures:
  - Anyone with recipient's public key CAN encrypt stream
  - Only recipient with secret key CAN decrypt stream
  - Post-Quantum secure (LWE-KEM)
  - Efficient streaming (KEM only once, AEAD for all chunks)

Wire Format:
  Stream = KEMCiphertext + [EncryptedChunk, EncryptedChunk, ...]
  
  KEMCiphertext:
    | u (n*4B) | v (msg_bits*4B) |
  
  EncryptedChunk (per chunk):
    | header (32B) | ciphertext (variable) | tag (16B) |
  
  StreamHeader (32B):
    | stream_id (16B) | seq (8B) | chunk_len (4B) | flags (4B) |
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from typing import Optional, List, Tuple, Iterator, Union

import numpy as np

from .common import (
    GPU_AVAILABLE, 
    CRYPTO_AVAILABLE, 
    _sha256,
    LWECiphertext,
)
from .core import LWEKEM

if CRYPTO_AVAILABLE:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class StreamHeader:
    """
    Stream chunk header (32 bytes).
    
    Attributes:
        stream_id: 16-byte stream identifier
        seq: 8-byte sequence number (u64)
        chunk_len: 4-byte chunk length (u32)
        flags: 4-byte flags (u32)
            - bit 0: is_final (last chunk in stream)
            - bit 1: has_kem (first chunk contains KEM ciphertext)
    """
    stream_id: bytes      # 16B
    seq: int              # u64
    chunk_len: int        # u32
    flags: int = 0        # u32
    
    HEADER_SIZE = 32
    
    FLAG_FINAL = 0x01
    FLAG_HAS_KEM = 0x02
    
    def __post_init__(self):
        if len(self.stream_id) != 16:
            raise ValueError(f"stream_id must be 16 bytes, got {len(self.stream_id)}")
    
    def to_bytes(self) -> bytes:
        """Serialize header to 32 bytes."""
        return (
            self.stream_id +
            struct.pack(">Q", self.seq) +
            struct.pack(">I", self.chunk_len) +
            struct.pack(">I", self.flags)
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'StreamHeader':
        """Deserialize header from bytes."""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Header too short: {len(data)} < {cls.HEADER_SIZE}")
        
        return cls(
            stream_id=data[:16],
            seq=struct.unpack(">Q", data[16:24])[0],
            chunk_len=struct.unpack(">I", data[24:28])[0],
            flags=struct.unpack(">I", data[28:32])[0],
        )
    
    @property
    def is_final(self) -> bool:
        return bool(self.flags & self.FLAG_FINAL)
    
    @property
    def has_kem(self) -> bool:
        return bool(self.flags & self.FLAG_HAS_KEM)


@dataclass
class EncryptedChunk:
    """Encrypted stream chunk with authentication tag."""
    header: StreamHeader
    ciphertext: bytes
    tag: bytes            # 16 bytes
    
    TAG_SIZE = 16
    
    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        return self.header.to_bytes() + self.ciphertext + self.tag
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptedChunk':
        """Deserialize from wire format."""
        header = StreamHeader.from_bytes(data[:StreamHeader.HEADER_SIZE])
        ct_start = StreamHeader.HEADER_SIZE
        ct_end = ct_start + header.chunk_len
        
        return cls(
            header=header,
            ciphertext=data[ct_start:ct_end],
            tag=data[ct_end:ct_end + cls.TAG_SIZE],
        )
    
    @property
    def wire_size(self) -> int:
        return StreamHeader.HEADER_SIZE + len(self.ciphertext) + self.TAG_SIZE


@dataclass
class EncryptedStream:
    """
    Complete encrypted stream container.
    
    Contains KEM ciphertext + all encrypted chunks.
    """
    kem_u: np.ndarray           # KEM ciphertext u
    kem_v: np.ndarray           # KEM ciphertext v
    stream_id: bytes            # 16 bytes
    chunks: List[EncryptedChunk]
    
    def to_bytes(self) -> bytes:
        """Serialize entire stream."""
        # KEM ciphertext
        kem_bytes = (
            struct.pack(">I", len(self.kem_u)) +
            self.kem_u.astype("<i8").tobytes() +
            struct.pack(">I", len(self.kem_v)) +
            self.kem_v.astype("<i8").tobytes()
        )
        
        # Stream ID
        stream_bytes = self.stream_id
        
        # Chunk count
        chunk_count = struct.pack(">I", len(self.chunks))
        
        # All chunks
        chunk_bytes = b"".join(c.to_bytes() for c in self.chunks)
        
        return kem_bytes + stream_bytes + chunk_count + chunk_bytes


# =============================================================================
# Stream Hybrid KEM
# =============================================================================

class StreamHybridKEM:
    """
    Streaming Hybrid PKE with correct design.
    
    ENCRYPTION:
      1. KEM encaps with recipient's PUBLIC KEY → K
      2. Derive session_key from K
      3. Encrypt all chunks with session_key (XChaCha20-Poly1305)
    
    DECRYPTION:
      1. KEM decaps with own SECRET KEY → K
      2. Derive session_key from K
      3. Decrypt all chunks with session_key
    
    Example (Encryption - Sender):
        >>> sender = StreamHybridKEM(n=256)
        >>> sender.load_recipient_public_key(bob_pk)
        >>> encrypted = sender.encrypt_stream(large_data, chunk_size=64*1024)
        >>> # Send encrypted to Bob
    
    Example (Decryption - Receiver):
        >>> receiver = StreamHybridKEM(n=256, seed=bob_seed)
        >>> receiver.key_gen()  # Regenerate Bob's keys
        >>> decrypted = receiver.decrypt_stream(encrypted)
    """
    
    TAG_SIZE = 16
    
    def __init__(
        self,
        n: int = 256,
        gpu: bool = True,
        device_id: int = 0,
        seed: Optional[bytes] = None,
    ):
        """
        Initialize StreamHybridKEM.
        
        Args:
            n: LWE dimension (256, 512, 1024)
            gpu: Enable GPU acceleration
            device_id: GPU device ID
            seed: Optional seed for deterministic key generation
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required")
        
        self.n = n
        self.gpu = gpu and GPU_AVAILABLE
        self.device_id = device_id
        self.seed = seed
        
        # Initialize KEM
        self._kem = LWEKEM(
            n=n,
            gpu=self.gpu,
            device_id=device_id,
            seed=seed,
        )
        
        # Keys (generated or loaded)
        self._pk_bytes: Optional[bytes] = None
        self._sk_bytes: Optional[bytes] = None
        
        # Recipient's public key (for encryption)
        self._recipient_pk: Optional[bytes] = None
        
        # Session state
        self._session_key: Optional[bytes] = None
        self._stream_id: Optional[bytes] = None
        self._cipher: Optional[ChaCha20Poly1305] = None
        self._seq: int = 0
    
    # =========================================================================
    # Key Management
    # =========================================================================
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """Generate own key pair."""
        self._pk_bytes, self._sk_bytes = self._kem.key_gen()
        return self._pk_bytes, self._sk_bytes
    
    def get_public_key(self) -> bytes:
        """Get own public key."""
        if self._pk_bytes is None:
            raise ValueError("Keys not generated. Call key_gen() first.")
        return self._pk_bytes
    
    def load_recipient_public_key(self, pk_bytes: bytes) -> None:
        """Load recipient's public key for encryption."""
        self._recipient_pk = pk_bytes
    
    # =========================================================================
    # Internal Helpers
    # =========================================================================
    
    def _derive_nonce(self, seq: int) -> bytes:
        """Derive 12-byte nonce from stream_id and sequence."""
        seq_bytes = struct.pack(">Q", seq)
        return _sha256(self._stream_id, seq_bytes)[:12]
    
    def _encrypt_chunk_internal(
        self,
        plaintext: bytes,
        seq: int,
        is_final: bool = False,
    ) -> EncryptedChunk:
        """Encrypt a single chunk with current session key."""
        header = StreamHeader(
            stream_id=self._stream_id,
            seq=seq,
            chunk_len=len(plaintext),
            flags=StreamHeader.FLAG_FINAL if is_final else 0,
        )
        
        nonce = self._derive_nonce(seq)
        aad = header.to_bytes()
        
        ct_with_tag = self._cipher.encrypt(nonce, plaintext, aad)
        
        return EncryptedChunk(
            header=header,
            ciphertext=ct_with_tag[:-self.TAG_SIZE],
            tag=ct_with_tag[-self.TAG_SIZE:],
        )
    
    def _decrypt_chunk_internal(self, chunk: EncryptedChunk) -> bytes:
        """Decrypt a single chunk with current session key."""
        if chunk.header.stream_id != self._stream_id:
            raise ValueError("Stream ID mismatch")
        
        nonce = self._derive_nonce(chunk.header.seq)
        aad = chunk.header.to_bytes()
        ct_with_tag = chunk.ciphertext + chunk.tag
        
        try:
            return self._cipher.decrypt(nonce, ct_with_tag, aad)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    # =========================================================================
    # Stream Encryption (using recipient's PUBLIC key)
    # =========================================================================
    
    def encrypt_stream(
        self,
        data: bytes,
        chunk_size: int = 64 * 1024,
    ) -> EncryptedStream:
        """
        Encrypt data as a stream.
        
        Uses recipient's PUBLIC KEY for KEM encapsulation.
        Only the recipient can decrypt (with their secret key).
        
        Args:
            data: Data to encrypt
            chunk_size: Size of each chunk (default 64KB)
            
        Returns:
            EncryptedStream containing KEM ciphertext + encrypted chunks
        """
        if self._recipient_pk is None:
            raise ValueError("Recipient public key not loaded. Call load_recipient_public_key() first.")
        
        # 1. KEM encapsulation with RECIPIENT'S public key
        enc_kem = LWEKEM(n=self.n, gpu=self.gpu, device_id=self.device_id)
        enc_kem.load_public_key(self._recipient_pk)
        
        K, kem_ct = enc_kem.encaps()
        
        # 2. Derive session key from K
        self._stream_id = secrets.token_bytes(16)
        self._session_key = _sha256(b"stream-session-v2", K)
        self._cipher = ChaCha20Poly1305(self._session_key)
        
        # 3. Encrypt all chunks
        chunks = []
        offset = 0
        seq = 0
        
        while offset < len(data):
            end = min(offset + chunk_size, len(data))
            is_final = (end >= len(data))
            
            chunk_data = data[offset:end]
            chunk = self._encrypt_chunk_internal(chunk_data, seq, is_final)
            chunks.append(chunk)
            
            offset = end
            seq += 1
        
        # Handle empty data
        if not chunks:
            chunks.append(self._encrypt_chunk_internal(b"", 0, is_final=True))
        
        return EncryptedStream(
            kem_u=kem_ct.u,
            kem_v=kem_ct.v,
            stream_id=self._stream_id,
            chunks=chunks,
        )
    
    def encrypt_stream_iter(
        self,
        data_iter: Iterator[bytes],
        recipient_pk: Optional[bytes] = None,
    ) -> Iterator[Union[Tuple[np.ndarray, np.ndarray, bytes], EncryptedChunk]]:
        """
        Encrypt data stream iteratively (memory efficient).
        
        First yield: (kem_u, kem_v, stream_id) - KEM ciphertext
        Subsequent yields: EncryptedChunk objects
        
        Args:
            data_iter: Iterator of data chunks
            recipient_pk: Recipient's public key (optional if already loaded)
        """
        if recipient_pk:
            self._recipient_pk = recipient_pk
        
        if self._recipient_pk is None:
            raise ValueError("Recipient public key not loaded")
        
        # 1. KEM encapsulation
        enc_kem = LWEKEM(n=self.n, gpu=self.gpu, device_id=self.device_id)
        enc_kem.load_public_key(self._recipient_pk)
        
        K, kem_ct = enc_kem.encaps()
        
        # 2. Setup session
        self._stream_id = secrets.token_bytes(16)
        self._session_key = _sha256(b"stream-session-v2", K)
        self._cipher = ChaCha20Poly1305(self._session_key)
        
        # Yield KEM ciphertext first
        yield (kem_ct.u, kem_ct.v, self._stream_id)
        
        # 3. Encrypt and yield chunks (with lookahead for final detection)
        seq = 0
        pending_data = None
        
        for chunk_data in data_iter:
            if pending_data is not None:
                # Previous chunk is not final (we have more data)
                yield self._encrypt_chunk_internal(pending_data, seq, is_final=False)
                seq += 1
            pending_data = chunk_data
        
        # Encrypt final chunk (or empty stream)
        if pending_data is not None:
            yield self._encrypt_chunk_internal(pending_data, seq, is_final=True)
        else:
            # Empty stream
            yield self._encrypt_chunk_internal(b"", 0, is_final=True)
    
    # =========================================================================
    # Stream Decryption (using own SECRET key)
    # =========================================================================
    
    def decrypt_stream(self, encrypted: EncryptedStream) -> bytes:
        """
        Decrypt an encrypted stream.
        
        Uses own SECRET KEY for KEM decapsulation.
        
        Args:
            encrypted: EncryptedStream from encrypt_stream()
            
        Returns:
            Decrypted data
        """
        if self._sk_bytes is None:
            raise ValueError("Secret key not available. Call key_gen() first.")
        
        # 1. KEM decapsulation with OWN secret key
        kem_ct = LWECiphertext(u=encrypted.kem_u, v=encrypted.kem_v)
        K = self._kem.decaps(kem_ct)
        
        # 2. Derive session key
        self._stream_id = encrypted.stream_id
        self._session_key = _sha256(b"stream-session-v2", K)
        self._cipher = ChaCha20Poly1305(self._session_key)
        
        # 3. Decrypt all chunks
        parts = []
        for chunk in encrypted.chunks:
            parts.append(self._decrypt_chunk_internal(chunk))
        
        return b"".join(parts)
    
    def decrypt_stream_iter(
        self,
        kem_u: np.ndarray,
        kem_v: np.ndarray,
        stream_id: bytes,
        chunk_iter: Iterator[EncryptedChunk],
    ) -> Iterator[bytes]:
        """
        Decrypt stream iteratively (memory efficient).
        
        Args:
            kem_u, kem_v: KEM ciphertext
            stream_id: Stream identifier
            chunk_iter: Iterator of EncryptedChunks
            
        Yields:
            Decrypted data chunks
        """
        if self._sk_bytes is None:
            raise ValueError("Secret key not available")
        
        # 1. KEM decapsulation
        kem_ct = LWECiphertext(u=kem_u, v=kem_v)
        K = self._kem.decaps(kem_ct)
        
        # 2. Setup session
        self._stream_id = stream_id
        self._session_key = _sha256(b"stream-session-v2", K)
        self._cipher = ChaCha20Poly1305(self._session_key)
        
        # 3. Decrypt and yield chunks
        for chunk in chunk_iter:
            yield self._decrypt_chunk_internal(chunk)


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute StreamHybridKEM tests."""
    print("=" * 70)
    print("Meteor-NC StreamHybridKEM Test Suite (Correct PKE Design)")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Basic encrypt/decrypt
    print("\n[Test 1] Basic Stream Encrypt/Decrypt")
    print("-" * 40)
    
    # Bob generates keys
    bob = StreamHybridKEM(n=256)
    bob_pk, bob_sk = bob.key_gen()
    
    # Alice encrypts FOR Bob
    alice = StreamHybridKEM(n=256)
    alice.load_recipient_public_key(bob_pk)
    
    test_data = b"Hello Bob! This is a streaming message. " * 100
    encrypted = alice.encrypt_stream(test_data, chunk_size=1024)
    
    # Bob decrypts
    decrypted = bob.decrypt_stream(encrypted)
    
    basic_ok = (test_data == decrypted)
    results['basic'] = basic_ok
    print(f"  Data size: {len(test_data)} bytes")
    print(f"  Chunks: {len(encrypted.chunks)}")
    print(f"  Result: {'PASS' if basic_ok else 'FAIL'}")
    
    # Test 2: Large data
    print("\n[Test 2] Large Data (1MB)")
    print("-" * 40)
    
    large_data = secrets.token_bytes(1024 * 1024)  # 1MB
    
    alice2 = StreamHybridKEM(n=256)
    alice2.load_recipient_public_key(bob_pk)
    encrypted2 = alice2.encrypt_stream(large_data, chunk_size=64 * 1024)
    
    decrypted2 = bob.decrypt_stream(encrypted2)
    
    large_ok = (large_data == decrypted2)
    results['large'] = large_ok
    print(f"  Chunks: {len(encrypted2.chunks)}")
    print(f"  Result: {'PASS' if large_ok else 'FAIL'}")
    
    # Test 3: Empty data
    print("\n[Test 3] Empty Data")
    print("-" * 40)
    
    alice3 = StreamHybridKEM(n=256)
    alice3.load_recipient_public_key(bob_pk)
    encrypted3 = alice3.encrypt_stream(b"")
    
    decrypted3 = bob.decrypt_stream(encrypted3)
    
    empty_ok = (decrypted3 == b"")
    results['empty'] = empty_ok
    print(f"  Result: {'PASS' if empty_ok else 'FAIL'}")
    
    # Test 4: Wrong recipient cannot decrypt
    print("\n[Test 4] Security: Wrong Recipient Cannot Decrypt")
    print("-" * 40)
    
    eve = StreamHybridKEM(n=256)
    eve.key_gen()  # Eve has different keys
    
    alice4 = StreamHybridKEM(n=256)
    alice4.load_recipient_public_key(bob_pk)
    encrypted4 = alice4.encrypt_stream(b"Secret for Bob only!")
    
    security_ok = False
    try:
        eve.decrypt_stream(encrypted4)
        print("  Eve decrypted! SECURITY BREACH!")
    except Exception as e:
        security_ok = True
        print(f"  Eve blocked: decryption failed")
    
    results['security'] = security_ok
    print(f"  Result: {'PASS' if security_ok else 'FAIL'}")
    
    # Test 5: Seed reproducibility
    print("\n[Test 5] Seed Reproducibility")
    print("-" * 40)
    
    seed = b"test_seed_for_streaming_12345678"
    
    bob1 = StreamHybridKEM(n=256, seed=seed)
    bob1.key_gen()
    
    bob2 = StreamHybridKEM(n=256, seed=seed)
    bob2.key_gen()
    
    seed_ok = (bob1.get_public_key() == bob2.get_public_key())
    results['seed'] = seed_ok
    print(f"  Same seed → Same PK: {'PASS' if seed_ok else 'FAIL'}")
    
    # Test 6: Iterator API
    print("\n[Test 6] Iterator API (Memory Efficient)")
    print("-" * 40)
    
    # Pre-generate data to avoid regeneration
    original_chunks = [f"Chunk {i}: ".encode() + secrets.token_bytes(100) for i in range(10)]
    
    def data_generator():
        for chunk in original_chunks:
            yield chunk
    
    alice5 = StreamHybridKEM(n=256)
    alice5.load_recipient_public_key(bob_pk)
    
    # Collect encrypted stream
    enc_iter = alice5.encrypt_stream_iter(data_generator())
    kem_u, kem_v, stream_id = next(enc_iter)
    chunks = list(enc_iter)
    
    # Decrypt with iterator
    decrypted_parts = list(bob.decrypt_stream_iter(kem_u, kem_v, stream_id, iter(chunks)))
    
    # Compare
    iter_ok = (original_chunks == decrypted_parts)
    results['iterator'] = iter_ok
    print(f"  Chunks processed: {len(chunks)}")
    print(f"  Result: {'PASS' if iter_ok else 'FAIL'}")
    
    # Test 7: Tamper detection
    print("\n[Test 7] Tamper Detection")
    print("-" * 40)
    
    alice6 = StreamHybridKEM(n=256)
    alice6.load_recipient_public_key(bob_pk)
    encrypted6 = alice6.encrypt_stream(b"Authentic data")
    
    # Tamper with first chunk's ciphertext
    if len(encrypted6.chunks[0].ciphertext) > 0:
        tampered_ct = bytearray(encrypted6.chunks[0].ciphertext)
        tampered_ct[0] ^= 0xFF
        encrypted6.chunks[0] = EncryptedChunk(
            header=encrypted6.chunks[0].header,
            ciphertext=bytes(tampered_ct),
            tag=encrypted6.chunks[0].tag,
        )
    
    tamper_ok = False
    try:
        bob.decrypt_stream(encrypted6)
    except ValueError:
        tamper_ok = True
    
    results['tamper'] = tamper_ok
    print(f"  Result: {'PASS' if tamper_ok else 'FAIL'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    passed = sum(results.values())
    total = len(results)
    
    print(f"Result: {passed}/{total} tests passed")
    
    if all_pass:
        print("\n✓ ALL TESTS PASSED")
        print("\n✓ Security properties verified:")
        print("  - KEM encaps with recipient's PUBLIC key")
        print("  - All chunks encrypted with derived session key")
        print("  - Only recipient can decrypt with SECRET key")
        print("  - Wrong recipient CANNOT decrypt")
        print("  - Tamper detection works")
    else:
        print("\n✗ SOME TESTS FAILED")
        for name, ok in results.items():
            if not ok:
                print(f"  - {name}: FAILED")
    
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
