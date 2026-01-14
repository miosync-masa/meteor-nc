# meteor_nc/cryptography/stream.py
"""
Meteor-NC Stream DEM (Data Encapsulation Mechanism)

GPU-accelerated XChaCha20-Poly1305 for streaming encryption.
Designed for high-throughput media delivery (GB/s target).

v2: Fixed-chunk batch API for video streaming
"""

from __future__ import annotations

import os
import time
import struct
from dataclasses import dataclass
from typing import Optional, Tuple, List, Union

import numpy as np

from .common import GPU_AVAILABLE, _sha256

if GPU_AVAILABLE:
    import cupy as cp
    try:
        from .kernels.chacha_poly_kernel import GPUChaCha20Poly1305
        STREAM_GPU_AVAILABLE = True
    except ImportError:
        STREAM_GPU_AVAILABLE = False
else:
    STREAM_GPU_AVAILABLE = False


# =========================
# Data structures
# =========================

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


# Fixed header format (streaming-friendly)
_HEADER_AAD_LEN = 16 + 8 + 4 + 4  # 32 bytes
HEADER_DTYPE = np.dtype([
    ("stream_id", "S16"),
    ("seq", "<u8"),
    ("chunk_len", "<u4"),
    ("flags", "<u4"),
])


def _headers_to_aad_bytes(headers: np.ndarray) -> bytes:
    """Convert HEADER_DTYPE array to contiguous AAD bytes (batch * 32)."""
    if headers.dtype != HEADER_DTYPE:
        raise TypeError("headers must use HEADER_DTYPE")
    return headers.tobytes(order="C")


# =========================
# Stream DEM
# =========================

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
        self.gpu = bool(gpu and STREAM_GPU_AVAILABLE)
        self.device_id = int(device_id)

        # Derive sub-key (domain separated)
        self.enc_key = _sha256(b"stream-enc", session_key)

        # Sequence counter
        self._seq = 0

        if self.gpu:
            cp.cuda.Device(self.device_id).use()
            self._cipher = GPUChaCha20Poly1305(self.enc_key, self.device_id)

    def _make_nonce(self, seq: int) -> bytes:
        """nonce = stream_id(16) || seq(8)"""
        return self.stream_id + struct.pack("<Q", seq)

    def _make_aad(self, header: StreamHeader) -> bytes:
        return (
            header.stream_id +
            struct.pack("<Q", header.seq) +
            struct.pack("<I", header.chunk_len) +
            struct.pack("<I", header.flags)
        )

    # -----------------------------------------
    # Single-chunk API
    # -----------------------------------------

    def encrypt_chunk(
        self,
        plaintext: bytes,
        seq: Optional[int] = None,
        flags: int = 0,
    ) -> EncryptedChunk:
        """Encrypt a single chunk."""
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

    def decrypt_chunk(self, chunk: EncryptedChunk) -> bytes:
        """Decrypt and verify a single chunk."""
        nonce = self._make_nonce(chunk.header.seq)
        aad = self._make_aad(chunk.header)

        if self.gpu:
            return self._cipher.decrypt(chunk.ciphertext, chunk.tag, nonce, aad)
        return self._decrypt_cpu(chunk.ciphertext, chunk.tag, nonce, aad)

    # -----------------------------------------
    # Fixed-chunk batch API (fast path)
    # -----------------------------------------

    def encrypt_batch_fixed(
        self,
        buf: bytes,
        chunk_size: int,
        start_seq: Optional[int] = None,
        flags: int = 0,
        *,
        return_objects: bool = False,
    ) -> Union[Tuple[np.ndarray, bytes, bytes], List[EncryptedChunk]]:
        """
        Encrypt a contiguous buffer as fixed-size chunks.

        Intended for media streaming:
        - Most chunks are exactly chunk_size
        - Last chunk may be shorter (header.chunk_len carries real size)

        Args:
            buf: Input bytes to encrypt
            chunk_size: Size of each chunk (last may be shorter)
            start_seq: Starting sequence number (auto if None)
            flags: Flags for all chunks
            return_objects: If True, return list of EncryptedChunk (slower)

        Returns (fast form, default):
            headers: np.ndarray[HEADER_DTYPE] shape (batch,)
            ct_concat: bytes (sum of chunk lengths)
            tag_concat: bytes (batch * 16)

        If return_objects=True:
            list[EncryptedChunk] (slower but convenient)
        """
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

        total = len(buf)
        if total == 0:
            headers = np.zeros((0,), dtype=HEADER_DTYPE)
            if return_objects:
                return []
            return headers, b"", b""

        batch = (total + chunk_size - 1) // chunk_size

        if start_seq is None:
            start_seq = self._seq
            self._seq += batch

        # Build headers (vectorized)
        headers = np.zeros((batch,), dtype=HEADER_DTYPE)
        headers["stream_id"] = np.frombuffer(self.stream_id, dtype="S16")[0]
        headers["seq"] = np.arange(start_seq, start_seq + batch, dtype=np.uint64)

        # Chunk lengths
        lens = np.full((batch,), chunk_size, dtype=np.uint32)
        last_len = total - (batch - 1) * chunk_size
        lens[-1] = np.uint32(last_len)
        headers["chunk_len"] = lens
        headers["flags"] = np.uint32(flags)

        # Nonces: (batch, 24)
        seq_le = headers["seq"].view(np.uint8).reshape(batch, 8).copy()
        nonces = np.empty((batch, self.NONCE_BYTES), dtype=np.uint8)
        nonces[:, :16] = np.frombuffer(self.stream_id, dtype=np.uint8)[None, :]
        nonces[:, 16:] = seq_le

        # AAD: (batch, 32)
        aad_bytes = _headers_to_aad_bytes(headers)
        aad = np.frombuffer(aad_bytes, dtype=np.uint8).reshape(batch, _HEADER_AAD_LEN)

        # Plaintext to 2D with padding
        pt_padded = np.zeros((batch * chunk_size,), dtype=np.uint8)
        pt_padded[:total] = np.frombuffer(buf, dtype=np.uint8)
        pt2 = pt_padded.reshape(batch, chunk_size)

        if self.gpu:
            cp.cuda.Device(self.device_id).use()

            pt_gpu = cp.asarray(pt2, dtype=cp.uint8)
            nonce_gpu = cp.asarray(nonces, dtype=cp.uint8)
            aad_gpu = cp.asarray(aad, dtype=cp.uint8)
            lens_gpu = cp.asarray(lens, dtype=cp.uint32)

            ct_gpu, tag_gpu = self._cipher.encrypt_batch_fixed(
                pt_gpu, nonce_gpu, aad_gpu, lens_gpu
            )
            cp.cuda.Stream.null.synchronize()

            ct_host = cp.asnumpy(ct_gpu)
            tag_host = cp.asnumpy(tag_gpu)

        else:
            # CPU fallback
            ct_host = np.empty_like(pt2, dtype=np.uint8)
            tag_host = np.empty((batch, self.TAG_BYTES), dtype=np.uint8)

            for i in range(batch):
                clen = int(lens[i])
                nonce_i = nonces[i].tobytes()
                aad_i = aad[i].tobytes()
                pt_i = pt2[i, :clen].tobytes()
                ct_i, tag_i = self._encrypt_cpu(pt_i, nonce_i, aad_i)

                ct_host[i, :clen] = np.frombuffer(ct_i, dtype=np.uint8)
                if clen < chunk_size:
                    ct_host[i, clen:] = 0
                tag_host[i, :] = np.frombuffer(tag_i, dtype=np.uint8)

        # Pack outputs
        if batch == 1:
            ct_concat = ct_host[0, :int(lens[0])].tobytes()
        else:
            full_part = ct_host[:-1, :].reshape((batch - 1) * chunk_size).tobytes()
            last_part = ct_host[-1, :int(lens[-1])].tobytes()
            ct_concat = full_part + last_part

        tag_concat = tag_host.reshape(batch * self.TAG_BYTES).tobytes()

        if not return_objects:
            return headers, ct_concat, tag_concat

        # Slower convenience form
        out = []
        offset = 0
        for i in range(batch):
            clen = int(lens[i])
            h = StreamHeader(
                stream_id=self.stream_id,
                seq=int(headers["seq"][i]),
                chunk_len=clen,
                flags=int(headers["flags"][i]),
            )
            ct_i = ct_concat[offset:offset + clen]
            offset += clen
            tag_i = tag_host[i].tobytes()
            out.append(EncryptedChunk(header=h, ciphertext=ct_i, tag=tag_i))
        return out

    # -----------------------------------------
    # CPU fallback
    # -----------------------------------------

    def _encrypt_cpu(self, plaintext: bytes, nonce: bytes, aad: bytes) -> Tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        subkey = self._hchacha20(self.enc_key, nonce[:16])
        chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:]

        cipher = ChaCha20Poly1305(subkey)
        ct_with_tag = cipher.encrypt(chacha_nonce, plaintext, aad)
        return ct_with_tag[:-16], ct_with_tag[-16:]

    def _decrypt_cpu(self, ciphertext: bytes, tag: bytes, nonce: bytes, aad: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        subkey = self._hchacha20(self.enc_key, nonce[:16])
        chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:]

        cipher = ChaCha20Poly1305(subkey)
        return cipher.decrypt(chacha_nonce, ciphertext + tag, aad)

    @staticmethod
    def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
        """HChaCha20 key derivation."""
        constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        k = struct.unpack("<8I", key)
        n = struct.unpack("<4I", nonce16)
        state = list(constants) + list(k) + list(n)

        def qr(a, b, c, d):
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
            qr(0, 4, 8, 12); qr(1, 5, 9, 13)
            qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12)
            qr(2, 7, 8, 13); qr(3, 4, 9, 14)

        out = state[0:4] + state[12:16]
        return struct.pack("<8I", *out)


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute StreamDEM tests with benchmarks."""
    print("=" * 70)
    print("Meteor-NC StreamDEM Test Suite")
    print("=" * 70)
    
    import secrets
    import time
    
    results = {}
    
    # Test 1: Basic encrypt/decrypt
    print("\n[Test 1] Basic Encrypt/Decrypt")
    print("-" * 40)
    
    session_key = secrets.token_bytes(32)
    stream = StreamDEM(session_key, gpu=False)
    
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
    
    # Test 4: Batch fixed
    print("\n[Test 4] Batch Fixed (Streaming)")
    print("-" * 40)
    
    stream4 = StreamDEM(session_key, gpu=False)
    
    data = secrets.token_bytes(10240)
    headers, ct_concat, tag_concat = stream4.encrypt_batch_fixed(data, chunk_size=1024)
    
    batch_ok = (len(headers) == 10) and (len(ct_concat) == 10240) and (len(tag_concat) == 160)
    results["batch_fixed"] = batch_ok
    print(f"  10KB / 1KB chunks: {'PASS' if batch_ok else 'FAIL'}")
    
    stream5 = StreamDEM(session_key, gpu=False)
    chunks = stream5.encrypt_batch_fixed(data, chunk_size=1024, return_objects=True)
    
    recovered = b""
    for c in chunks:
        recovered += stream5.decrypt_chunk(c)
    
    roundtrip_ok = (data == recovered)
    results["batch_roundtrip"] = roundtrip_ok
    print(f"  Batch round-trip: {'PASS' if roundtrip_ok else 'FAIL'}")
    
    # Test 5: Performance Benchmark
    print("\n[Test 5] Performance Benchmark")
    print("-" * 40)
    
    bench_sizes = [
        (1 * 1024 * 1024, 64 * 1024, "1MB / 64KB chunks"),
        (10 * 1024 * 1024, 256 * 1024, "10MB / 256KB chunks"),
        (100 * 1024 * 1024, 1024 * 1024, "100MB / 1MB chunks"),
    ]
    
    print("\n  [CPU Mode]")
    for total_size, chunk_size, desc in bench_sizes:
        data = secrets.token_bytes(total_size)
        stream_bench = StreamDEM(session_key, gpu=False)
        
        start = time.perf_counter()
        headers, ct, tags = stream_bench.encrypt_batch_fixed(data, chunk_size)
        elapsed = time.perf_counter() - start
        
        throughput = total_size / elapsed / (1024 * 1024)
        print(f"    {desc}: {throughput:.1f} MB/s ({elapsed*1000:.1f} ms)")
    
    if STREAM_GPU_AVAILABLE:
        print("\n  [GPU Mode]")
        for total_size, chunk_size, desc in bench_sizes:
            data = secrets.token_bytes(total_size)
            stream_bench = StreamDEM(session_key, gpu=True)
            
            # Warmup
            _ = stream_bench.encrypt_batch_fixed(data[:chunk_size], chunk_size)
            
            start = time.perf_counter()
            headers, ct, tags = stream_bench.encrypt_batch_fixed(data, chunk_size)
            elapsed = time.perf_counter() - start
            
            throughput = total_size / elapsed / (1024 * 1024)
            print(f"    {desc}: {throughput:.1f} MB/s ({elapsed*1000:.1f} ms)")
    else:
        print("\n  [GPU Mode] Not available")
    
    results["benchmark"] = True
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
