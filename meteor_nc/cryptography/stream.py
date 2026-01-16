# meteor_nc/cryptography/stream.py
"""
Meteor-NC Stream Hybrid Encryption

Chunked authenticated encryption combining:
- LWEKEM: Post-quantum key encapsulation (from core.py)
- StreamDEM: GPU-accelerated XChaCha20-Poly1305 stream cipher

Features:
- Per-chunk authentication tags
- Sequence number tracking
- Replay attack prevention
- GPU acceleration for ChaCha20 (when available)
- CPU fallback for compatibility

Wire Format:
  StreamHeader (32B):
    | stream_id  | seq    | chunk_len | flags  |
    | 16B        | 8B     | 4B        | 4B     |
  
  EncryptedChunk:
    | header (32B) | ciphertext (variable) | tag (16B) |
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
    HKDF,
)

# Import LWEKEM from core (CPU version)
from .core import LWEKEM

# GPU DEM (if available)
if GPU_AVAILABLE:
    from .kernels.chacha_poly_kernel import GPUChaCha20Poly1305

# CPU DEM fallback
if CRYPTO_AVAILABLE:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# =============================================================================
# Constants
# =============================================================================

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64KB default chunk size


# =============================================================================
# Data Classes
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
            - bit 1: is_compressed
            - bits 2-31: reserved
    """
    stream_id: bytes      # 16B
    seq: int              # u64
    chunk_len: int        # u32
    flags: int = 0        # u32
    
    HEADER_SIZE = 32
    
    FLAG_FINAL = 0x01
    FLAG_COMPRESSED = 0x02
    
    def __post_init__(self):
        if len(self.stream_id) != 16:
            raise ValueError(f"stream_id must be 16 bytes, got {len(self.stream_id)}")
        if self.seq < 0:
            raise ValueError("seq must be non-negative")
        if self.chunk_len < 0:
            raise ValueError("chunk_len must be non-negative")
    
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
        
        stream_id = data[:16]
        seq = struct.unpack(">Q", data[16:24])[0]
        chunk_len = struct.unpack(">I", data[24:28])[0]
        flags = struct.unpack(">I", data[28:32])[0]
        
        return cls(stream_id=stream_id, seq=seq, chunk_len=chunk_len, flags=flags)
    
    @property
    def is_final(self) -> bool:
        return bool(self.flags & self.FLAG_FINAL)
    
    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & self.FLAG_COMPRESSED)


@dataclass
class EncryptedChunk:
    """
    Encrypted stream chunk.
    
    Attributes:
        header: Stream header with metadata
        ciphertext: Encrypted data
        tag: 16-byte authentication tag
    """
    header: StreamHeader
    ciphertext: bytes
    tag: bytes
    
    TAG_SIZE = 16
    
    def __post_init__(self):
        if len(self.tag) != self.TAG_SIZE:
            raise ValueError(f"tag must be {self.TAG_SIZE} bytes, got {len(self.tag)}")
    
    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        return self.header.to_bytes() + self.ciphertext + self.tag
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptedChunk':
        """Deserialize from wire format."""
        if len(data) < StreamHeader.HEADER_SIZE + cls.TAG_SIZE:
            raise ValueError("Data too short for encrypted chunk")
        
        header = StreamHeader.from_bytes(data[:StreamHeader.HEADER_SIZE])
        
        expected_size = StreamHeader.HEADER_SIZE + header.chunk_len + cls.TAG_SIZE
        if len(data) < expected_size:
            raise ValueError(f"Data truncated: {len(data)} < {expected_size}")
        
        ciphertext = data[StreamHeader.HEADER_SIZE:StreamHeader.HEADER_SIZE + header.chunk_len]
        tag = data[StreamHeader.HEADER_SIZE + header.chunk_len:
                   StreamHeader.HEADER_SIZE + header.chunk_len + cls.TAG_SIZE]
        
        return cls(header=header, ciphertext=ciphertext, tag=tag)
    
    @property
    def wire_size(self) -> int:
        return StreamHeader.HEADER_SIZE + len(self.ciphertext) + self.TAG_SIZE


@dataclass
class StreamCiphertext:
    """
    Complete stream ciphertext including KEM header.
    
    Wire format:
        | kem_ct_len (4B) | kem_ciphertext | chunks... |
    """
    kem_ciphertext: bytes       # KEM encapsulation result
    chunks: List[EncryptedChunk]  # Encrypted chunks
    
    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        result = struct.pack(">I", len(self.kem_ciphertext))
        result += self.kem_ciphertext
        for chunk in self.chunks:
            result += chunk.to_bytes()
        return result
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'StreamCiphertext':
        """Deserialize from wire format."""
        if len(data) < 4:
            raise ValueError("Data too short")
        
        kem_ct_len = struct.unpack(">I", data[:4])[0]
        offset = 4
        
        if len(data) < offset + kem_ct_len:
            raise ValueError("KEM ciphertext truncated")
        
        kem_ciphertext = data[offset:offset + kem_ct_len]
        offset += kem_ct_len
        
        chunks = []
        while offset < len(data):
            if len(data) - offset < StreamHeader.HEADER_SIZE:
                break
            
            header = StreamHeader.from_bytes(data[offset:offset + StreamHeader.HEADER_SIZE])
            chunk_total = StreamHeader.HEADER_SIZE + header.chunk_len + EncryptedChunk.TAG_SIZE
            
            if len(data) < offset + chunk_total:
                raise ValueError("Chunk truncated")
            
            chunk = EncryptedChunk.from_bytes(data[offset:offset + chunk_total])
            chunks.append(chunk)
            offset += chunk_total
        
        return cls(kem_ciphertext=kem_ciphertext, chunks=chunks)


# =============================================================================
# Stream DEM (Data Encapsulation Mechanism)
# =============================================================================

class StreamDEM:
    """
    Stream Data Encapsulation Mechanism with GPU acceleration.
    
    Uses XChaCha20-Poly1305 for authenticated encryption with:
    - 256-bit key
    - 192-bit nonce (derived from stream_id + seq)
    - Per-chunk authentication
    - GPU acceleration when available
    """
    
    def __init__(
        self,
        session_key: bytes,
        stream_id: Optional[bytes] = None,
        gpu: bool = True,
        device_id: int = 0,
    ):
        """
        Initialize StreamDEM.
        
        Args:
            session_key: 32-byte session key
            stream_id: 16-byte stream identifier (generated if None)
            gpu: Enable GPU acceleration
            device_id: GPU device ID
        """
        if len(session_key) != 32:
            raise ValueError(f"session_key must be 32 bytes, got {len(session_key)}")
        
        self.session_key = session_key
        self.stream_id = stream_id or secrets.token_bytes(16)
        self.device_id = device_id
        
        # Use GPU if available and requested
        self.use_gpu = gpu and GPU_AVAILABLE
        
        if self.use_gpu:
            self._gpu_cipher = GPUChaCha20Poly1305(session_key, device_id=device_id)
        elif CRYPTO_AVAILABLE:
            self._cpu_cipher = ChaCha20Poly1305(session_key)
        else:
            raise ImportError("No crypto backend available (need CuPy or cryptography)")
        
        # Sequence counters
        self._encrypt_seq = 0
        self._decrypt_seq = 0
        
        # Replay protection
        self._seen_seqs: set = set()
    
    def _derive_nonce(self, seq: int) -> bytes:
        """Derive 24-byte nonce for XChaCha20."""
        seq_bytes = struct.pack(">Q", seq)
        # Use full 24 bytes for XChaCha20
        return _sha256(self.stream_id, seq_bytes)[:24]
    
    def encrypt_chunk(
        self,
        plaintext: bytes,
        is_final: bool = False,
        aad: Optional[bytes] = None,
    ) -> EncryptedChunk:
        """Encrypt a chunk of data."""
        seq = self._encrypt_seq
        self._encrypt_seq += 1
        
        # Build header
        flags = StreamHeader.FLAG_FINAL if is_final else 0
        header = StreamHeader(
            stream_id=self.stream_id,
            seq=seq,
            chunk_len=len(plaintext),
            flags=flags,
        )
        
        # Derive nonce
        nonce = self._derive_nonce(seq)
        
        # Build AAD
        full_aad = header.to_bytes()
        if aad:
            full_aad += aad
        
        # Encrypt
        if self.use_gpu:
            ciphertext, tag = self._gpu_cipher.encrypt(plaintext, nonce, full_aad)
        else:
            # CPU fallback (uses 12-byte nonce)
            nonce_12 = nonce[:12]
            ct_with_tag = self._cpu_cipher.encrypt(nonce_12, plaintext, full_aad)
            tag = ct_with_tag[-16:]
            ciphertext = ct_with_tag[:-16]
        
        return EncryptedChunk(header=header, ciphertext=ciphertext, tag=tag)
    
    def decrypt_chunk(
        self,
        chunk: EncryptedChunk,
        aad: Optional[bytes] = None,
        check_replay: bool = True,
    ) -> bytes:
        """Decrypt an encrypted chunk."""
        # Verify stream_id
        if chunk.header.stream_id != self.stream_id:
            raise ValueError("Stream ID mismatch")
        
        # Replay protection
        seq = chunk.header.seq
        if check_replay:
            if seq in self._seen_seqs:
                raise ValueError(f"Replay attack detected: seq {seq} already seen")
            self._seen_seqs.add(seq)
        
        # Derive nonce
        nonce = self._derive_nonce(seq)
        
        # Build AAD
        full_aad = chunk.header.to_bytes()
        if aad:
            full_aad += aad
        
        # Decrypt
        if self.use_gpu:
            plaintext = self._gpu_cipher.decrypt(
                chunk.ciphertext, chunk.tag, nonce, full_aad
            )
        else:
            # CPU fallback
            nonce_12 = nonce[:12]
            ct_with_tag = chunk.ciphertext + chunk.tag
            plaintext = self._cpu_cipher.decrypt(nonce_12, ct_with_tag, full_aad)
        
        return plaintext
    
    def reset_counters(self) -> None:
        """Reset sequence counters (for new stream)."""
        self._encrypt_seq = 0
        self._decrypt_seq = 0
        self._seen_seqs.clear()


# =============================================================================
# Stream Hybrid KEM (KEM + DEM Integration)
# =============================================================================

class StreamHybridKEM:
    """
    Stream Hybrid KEM combining:
    - LWEKEM for key encapsulation (post-quantum)
    - StreamDEM for chunked authenticated encryption
    
    Provides streaming interface for large data encryption.
    """
    
    def __init__(
        self,
        n: int = 256,
        q: int = 65537,
        eta: int = 3,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        gpu: bool = True,
        device_id: int = 0,
    ):
        """
        Initialize StreamHybridKEM.
        
        Args:
            n: LWE dimension
            q: LWE modulus
            eta: Error parameter
            chunk_size: Size of each chunk in bytes
            gpu: Enable GPU acceleration for DEM
            device_id: GPU device ID
        """
        self.n = n
        self.q = q
        self.eta = eta
        self.chunk_size = chunk_size
        self.gpu = gpu
        self.device_id = device_id
        
        # Initialize KEM
        self.kem = LWEKEM(n=n, q=q, eta=eta)
        
        # Keys
        self._pk: Optional[bytes] = None
        self._sk: Optional[bytes] = None
    
    def key_gen(self) -> Tuple[bytes, bytes]:
        """Generate key pair."""
        pk, sk = self.kem.key_gen()
        self._pk = pk
        self._sk = sk
        return pk, sk
    
    def load_public_key(self, pk: bytes) -> None:
        """Load public key (for encryption)."""
        self._pk = pk
    
    def load_secret_key(self, sk: bytes) -> None:
        """Load secret key (for decryption)."""
        self._sk = sk
    
    def load_keys(self, pk: bytes, sk: bytes) -> None:
        """Load both keys."""
        self._pk = pk
        self._sk = sk
    
    # =========================================================================
    # Simple Interface (core.py compatible)
    # =========================================================================
    
    def encrypt(self, plaintext: bytes) -> StreamCiphertext:
        """
        Encrypt data using stream encryption.
        
        Automatically chunks large data.
        """
        if self._pk is None:
            raise ValueError("Public key not loaded")
        
        # 1. KEM: Encapsulate to get session key
        self.kem.load_public_key(self._pk)
        shared_key, kem_ct_obj = self.kem.encaps()
        kem_ct = kem_ct_obj.to_bytes()
        
        # 2. DEM: Initialize stream
        stream_id = secrets.token_bytes(16)
        dem = StreamDEM(
            session_key=shared_key,
            stream_id=stream_id,
            gpu=self.gpu,
            device_id=self.device_id,
        )
        
        # 3. Chunk and encrypt
        chunks = []
        offset = 0
        while offset < len(plaintext):
            chunk_data = plaintext[offset:offset + self.chunk_size]
            is_final = (offset + len(chunk_data) >= len(plaintext))
            
            encrypted_chunk = dem.encrypt_chunk(chunk_data, is_final=is_final)
            chunks.append(encrypted_chunk)
            
            offset += len(chunk_data)
        
        # Handle empty plaintext
        if not chunks:
            chunks.append(dem.encrypt_chunk(b"", is_final=True))
        
        return StreamCiphertext(kem_ciphertext=kem_ct, chunks=chunks)
    
    def decrypt(self, ct: Union[StreamCiphertext, bytes]) -> bytes:
        """
        Decrypt stream ciphertext.
        """
        if self._sk is None:
            raise ValueError("Secret key not loaded")
        
        if isinstance(ct, bytes):
            ct = StreamCiphertext.from_bytes(ct)
        
        # 1. KEM: Decapsulate to get session key
        # Import LWECiphertext for parsing
        from .core import LWECiphertext
        kem_ct_obj = LWECiphertext.from_bytes(ct.kem_ciphertext)
        
        # Load keys and decaps
        self.kem.load_secret_key(self._sk)
        if self._pk is not None:
            self.kem.load_public_key(self._pk)
        shared_key = self.kem.decaps(kem_ct_obj)
        
        # 2. DEM: Initialize stream
        if not ct.chunks:
            return b""
        
        stream_id = ct.chunks[0].header.stream_id
        dem = StreamDEM(
            session_key=shared_key,
            stream_id=stream_id,
            gpu=self.gpu,
            device_id=self.device_id,
        )
        
        # 3. Decrypt all chunks
        plaintext_parts = []
        for chunk in ct.chunks:
            pt = dem.decrypt_chunk(chunk, check_replay=True)
            plaintext_parts.append(pt)
        
        return b"".join(plaintext_parts)
    
    # =========================================================================
    # Streaming Interface (for large data)
    # =========================================================================
    
    def encrypt_stream(
        self,
        data_iterator: Iterator[bytes],
    ) -> Iterator[bytes]:
        """
        Encrypt data from an iterator, yielding encrypted chunks.
        
        First yield is the KEM ciphertext header.
        Subsequent yields are encrypted chunks.
        """
        if self._pk is None:
            raise ValueError("Public key not loaded")
        
        # 1. KEM
        self.kem.load_public_key(self._pk)
        shared_key, kem_ct_obj = self.kem.encaps()
        kem_ct = kem_ct_obj.to_bytes()
        
        # Yield KEM header
        yield struct.pack(">I", len(kem_ct)) + kem_ct
        
        # 2. DEM
        stream_id = secrets.token_bytes(16)
        dem = StreamDEM(
            session_key=shared_key,
            stream_id=stream_id,
            gpu=self.gpu,
            device_id=self.device_id,
        )
        
        # 3. Encrypt and yield chunks
        buffer = b""
        final_sent = False
        
        for data in data_iterator:
            buffer += data
            
            while len(buffer) >= self.chunk_size:
                chunk_data = buffer[:self.chunk_size]
                buffer = buffer[self.chunk_size:]
                
                encrypted = dem.encrypt_chunk(chunk_data, is_final=False)
                yield encrypted.to_bytes()
        
        # Final chunk
        encrypted = dem.encrypt_chunk(buffer, is_final=True)
        yield encrypted.to_bytes()
    
    def decrypt_stream(
        self,
        chunk_iterator: Iterator[bytes],
    ) -> Iterator[bytes]:
        """
        Decrypt chunks from an iterator, yielding plaintext.
        
        First input should be the KEM ciphertext header.
        """
        if self._sk is None:
            raise ValueError("Secret key not loaded")
        
        # 1. Read KEM header
        first_chunk = next(chunk_iterator)
        if len(first_chunk) < 4:
            raise ValueError("Invalid stream header")
        
        kem_ct_len = struct.unpack(">I", first_chunk[:4])[0]
        kem_ct = first_chunk[4:4 + kem_ct_len]
        
        if len(kem_ct) < kem_ct_len:
            raise ValueError("KEM ciphertext truncated")
        
        # 2. Decapsulate
        from .core import LWECiphertext
        kem_ct_obj = LWECiphertext.from_bytes(kem_ct)
        self.kem.load_secret_key(self._sk)
        if self._pk is not None:
            self.kem.load_public_key(self._pk)
        shared_key = self.kem.decaps(kem_ct_obj)
        
        # Initialize DEM (stream_id will be set from first chunk)
        dem = None
        
        # Process any remaining data in first chunk
        remaining = first_chunk[4 + kem_ct_len:]
        
        # 3. Decrypt chunks
        def process_data(data: bytes):
            nonlocal dem
            offset = 0
            
            while offset < len(data):
                if len(data) - offset < StreamHeader.HEADER_SIZE:
                    return data[offset:]  # Incomplete header
                
                header = StreamHeader.from_bytes(data[offset:offset + StreamHeader.HEADER_SIZE])
                chunk_total = StreamHeader.HEADER_SIZE + header.chunk_len + EncryptedChunk.TAG_SIZE
                
                if len(data) - offset < chunk_total:
                    return data[offset:]  # Incomplete chunk
                
                chunk = EncryptedChunk.from_bytes(data[offset:offset + chunk_total])
                
                # Initialize DEM with stream_id from first chunk
                if dem is None:
                    dem = StreamDEM(
                        session_key=shared_key,
                        stream_id=chunk.header.stream_id,
                        gpu=self.gpu,
                        device_id=self.device_id,
                    )
                
                pt = dem.decrypt_chunk(chunk)
                yield pt
                
                offset += chunk_total
            
            return b""
        
        # Process remaining from header
        buffer = remaining
        for pt in process_data(buffer):
            yield pt
            buffer = b""
        
        # Process subsequent chunks
        for chunk_data in chunk_iterator:
            buffer += chunk_data
            for pt in process_data(buffer):
                yield pt
                buffer = b""


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute stream hybrid KEM tests."""
    import time
    
    print("=" * 70)
    print("Meteor-NC Stream Hybrid KEM")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Basic Encrypt/Decrypt
    print("\n[Test 1] Basic Stream Encrypt/Decrypt")
    print("-" * 40)
    
    stream = StreamHybridKEM()
    pk, sk = stream.key_gen()
    
    print(f"  PK size: {len(pk)} bytes")
    print(f"  SK size: {len(sk)} bytes")
    
    plaintext = b"Hello, Meteor-NC Stream Hybrid KEM!"
    ct = stream.encrypt(plaintext)
    recovered = stream.decrypt(ct)
    
    basic_ok = (plaintext == recovered)
    results["basic"] = basic_ok
    print(f"  Basic encrypt/decrypt: {'PASS' if basic_ok else 'FAIL'}")
    
    # Test 2: Large Data (multi-chunk)
    print("\n[Test 2] Large Data (Multi-Chunk)")
    print("-" * 40)
    
    stream = StreamHybridKEM(chunk_size=1024)  # 1KB chunks
    pk, sk = stream.key_gen()
    
    large_data = secrets.token_bytes(10 * 1024)  # 10KB
    ct = stream.encrypt(large_data)
    recovered = stream.decrypt(ct)
    
    large_ok = (large_data == recovered)
    results["large"] = large_ok
    print(f"  Chunks: {len(ct.chunks)}")
    print(f"  Large data: {'PASS' if large_ok else 'FAIL'}")
    
    # Test 3: Serialization
    print("\n[Test 3] Ciphertext Serialization")
    print("-" * 40)
    
    ct_bytes = ct.to_bytes()
    ct_recovered = StreamCiphertext.from_bytes(ct_bytes)
    recovered2 = stream.decrypt(ct_recovered)
    
    serial_ok = (large_data == recovered2)
    results["serialization"] = serial_ok
    print(f"  Ciphertext size: {len(ct_bytes)} bytes")
    print(f"  Serialization: {'PASS' if serial_ok else 'FAIL'}")
    
    # Test 4: Sender/Receiver Separation
    print("\n[Test 4] Sender/Receiver Separation")
    print("-" * 40)
    
    receiver = StreamHybridKEM()
    pk, sk = receiver.key_gen()
    
    sender = StreamHybridKEM()
    sender.load_public_key(pk)
    
    ct = sender.encrypt(b"Secret stream data")
    
    try:
        _ = sender.decrypt(ct)
        sender_blocked = False
    except (ValueError, Exception):
        sender_blocked = True
    
    receiver.load_secret_key(sk)
    recovered = receiver.decrypt(ct)
    
    sep_ok = sender_blocked and (recovered == b"Secret stream data")
    results["separation"] = sep_ok
    print(f"  Sender blocked: {'PASS' if sender_blocked else 'FAIL'}")
    print(f"  Receiver decrypts: {'PASS' if recovered == b'Secret stream data' else 'FAIL'}")
    
    # Test 5: Empty Data
    print("\n[Test 5] Empty Data")
    print("-" * 40)
    
    stream = StreamHybridKEM()
    pk, sk = stream.key_gen()
    
    ct = stream.encrypt(b"")
    recovered = stream.decrypt(ct)
    
    empty_ok = (recovered == b"")
    results["empty"] = empty_ok
    print(f"  Empty data: {'PASS' if empty_ok else 'FAIL'}")
    
    # Test 6: Throughput
    print("\n[Test 6] Throughput")
    print("-" * 40)
    
    stream = StreamHybridKEM(chunk_size=64*1024)  # 64KB chunks
    pk, sk = stream.key_gen()
    
    for size_mb in [1, 10]:
        data = secrets.token_bytes(size_mb * 1024 * 1024)
        
        start = time.perf_counter()
        ct = stream.encrypt(data)
        enc_time = time.perf_counter() - start
        
        start = time.perf_counter()
        _ = stream.decrypt(ct)
        dec_time = time.perf_counter() - start
        
        enc_rate = size_mb / enc_time
        dec_rate = size_mb / dec_time
        
        print(f"  {size_mb} MB:")
        print(f"    Encrypt: {enc_rate:.1f} MB/s ({enc_time*1000:.1f} ms)")
        print(f"    Decrypt: {dec_rate:.1f} MB/s ({dec_time*1000:.1f} ms)")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    print(f"GPU acceleration: {'Enabled' if GPU_AVAILABLE else 'Disabled (CPU fallback)'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
