# meteor_nc/cryptography/compression.py
"""
Meteor-NC Coefficient Compression

Kyber-style coefficient compression for wire format size reduction.
Internal computation remains uint32, compression only for transmission.

Compression parameters:
  - D_U = 11 bits for u coefficients
  - D_V = 5 bits for v coefficients (message recovery needs only MSBs)

Size reduction:
  - Before: u(n×4B) + v(n×4B) = 8n bytes
  - After:  u(n×11bit) + v(n×5bit) = 2n bytes (75% reduction!)
"""

import struct
from typing import Tuple

import numpy as np


# =============================================================================
# Compression Parameters
# =============================================================================

D_U = 11  # bits for u coefficients
D_V = 5   # bits for v coefficients (message recovery needs only MSBs)


# =============================================================================
# Core Compression Functions
# =============================================================================

def compress(x: np.ndarray, q: int, d: int) -> np.ndarray:
    """
    Compress coefficients from Z_q to Z_{2^d}.
    
    Formula: round((2^d / q) * x) mod 2^d
    
    Args:
        x: Coefficient array (0 <= x < q), can be int64
        q: Modulus
        d: Target bit width
    
    Returns:
        Compressed coefficients (0 <= y < 2^d) as uint16
    """
    # Ensure positive values in [0, q)
    x_pos = x.astype(np.int64) % q
    
    # Scale and round
    # Use float64 for precision, then convert
    scale = (1 << d) / q
    compressed = np.round(x_pos.astype(np.float64) * scale).astype(np.uint32)
    
    # Mod 2^d
    return (compressed % (1 << d)).astype(np.uint16)


def decompress(y: np.ndarray, q: int, d: int) -> np.ndarray:
    """
    Decompress coefficients from Z_{2^d} back to Z_q.
    
    Formula: round((q / 2^d) * y)
    
    Args:
        y: Compressed coefficients (0 <= y < 2^d)
        q: Target modulus
        d: Source bit width
    
    Returns:
        Decompressed coefficients (0 <= x < q) as int64
    """
    scale = q / (1 << d)
    return np.round(y.astype(np.float64) * scale).astype(np.int64)


# =============================================================================
# Bit Packing Functions
# =============================================================================

def pack_bits(values: np.ndarray, d: int) -> bytes:
    """
    Pack array of d-bit values into byte stream.
    
    Args:
        values: Array of values (each < 2^d)
        d: Bits per value
    
    Returns:
        Packed bytes
    """
    n = len(values)
    total_bits = n * d
    total_bytes = (total_bits + 7) // 8
    
    result = bytearray(total_bytes)
    
    bit_pos = 0
    for val in values:
        val = int(val)
        # Write d bits
        for i in range(d):
            if val & (1 << i):
                byte_idx = bit_pos // 8
                bit_idx = bit_pos % 8
                result[byte_idx] |= (1 << bit_idx)
            bit_pos += 1
    
    return bytes(result)


def unpack_bits(data: bytes, n: int, d: int) -> np.ndarray:
    """
    Unpack byte stream into array of d-bit values.
    
    Args:
        data: Packed bytes
        n: Number of values to extract
        d: Bits per value
    
    Returns:
        Array of unpacked values
    """
    result = np.zeros(n, dtype=np.uint16)
    
    bit_pos = 0
    for i in range(n):
        val = 0
        for j in range(d):
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            if byte_idx < len(data) and data[byte_idx] & (1 << bit_idx):
                val |= (1 << j)
            bit_pos += 1
        result[i] = val
    
    return result


# =============================================================================
# High-Level Ciphertext Compression
# =============================================================================

def compress_ciphertext(
    u: np.ndarray,
    v: np.ndarray,
    q: int,
    d_u: int = D_U,
    d_v: int = D_V,
) -> bytes:
    """
    Compress LWE ciphertext (u, v) to wire format.
    
    Wire format:
        | n (2B) | msg_bits (2B) | u_packed | v_packed |
    
    Args:
        u: (n,) array of coefficients
        v: (msg_bits,) array of coefficients
        q: Modulus
        d_u: Bits for u compression
        d_v: Bits for v compression
    
    Returns:
        Compressed bytes
    """
    n = len(u)
    msg_bits = len(v)
    
    # Compress
    u_compressed = compress(u, q, d_u)
    v_compressed = compress(v, q, d_v)
    
    # Pack bits
    u_packed = pack_bits(u_compressed, d_u)
    v_packed = pack_bits(v_compressed, d_v)
    
    # Header + data
    header = struct.pack(">HH", n, msg_bits)
    
    return header + u_packed + v_packed


def decompress_ciphertext(
    data: bytes,
    q: int,
    d_u: int = D_U,
    d_v: int = D_V,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Decompress wire format back to (u, v).
    
    Args:
        data: Compressed bytes
        q: Modulus
        d_u: Bits for u compression
        d_v: Bits for v compression
    
    Returns:
        (u, v) as int64 arrays
    """
    # Parse header
    n, msg_bits = struct.unpack(">HH", data[:4])
    
    # Calculate byte sizes
    u_bytes = (n * d_u + 7) // 8
    v_bytes = (msg_bits * d_v + 7) // 8
    
    # Unpack
    offset = 4
    u_compressed = unpack_bits(data[offset:offset + u_bytes], n, d_u)
    offset += u_bytes
    v_compressed = unpack_bits(data[offset:offset + v_bytes], msg_bits, d_v)
    
    # Decompress
    u = decompress(u_compressed, q, d_u)
    v = decompress(v_compressed, q, d_v)
    
    return u, v


def compressed_size(n: int, msg_bits: int, d_u: int = D_U, d_v: int = D_V) -> int:
    """Calculate compressed ciphertext size in bytes."""
    header = 4
    u_bytes = (n * d_u + 7) // 8
    v_bytes = (msg_bits * d_v + 7) // 8
    return header + u_bytes + v_bytes


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Test compression/decompression."""
    print("=" * 70)
    print("Meteor-NC Compression Test")
    print("=" * 70)
    
    Q = 4294967291  # 2^32 - 5
    results = {}
    
    # Test 1: Basic compress/decompress roundtrip
    print("\n[Test 1] Compress/Decompress Roundtrip")
    print("-" * 40)
    
    for d in [5, 11, 16]:
        # Random coefficients
        x = np.random.randint(0, Q, size=256, dtype=np.int64)
        
        # Compress and decompress
        y = compress(x, Q, d)
        x_recovered = decompress(y, Q, d)
        
        # Check error (compression is lossy!)
        error = np.abs(x - x_recovered)
        max_error = np.max(error)
        expected_max_error = Q / (1 << d) / 2  # Quantization error bound
        
        ok = max_error <= expected_max_error * 1.1  # 10% margin
        results[f"roundtrip_d{d}"] = ok
        
        print(f"  d={d:2d}: max_error={max_error:,.0f}, "
              f"expected<{expected_max_error:,.0f} -> {'PASS' if ok else 'FAIL'}")
    
    # Test 2: Bit packing
    print("\n[Test 2] Bit Packing/Unpacking")
    print("-" * 40)
    
    for d in [5, 11]:
        values = np.random.randint(0, 1 << d, size=256, dtype=np.uint16)
        
        packed = pack_bits(values, d)
        unpacked = unpack_bits(packed, 256, d)
        
        ok = np.array_equal(values, unpacked)
        results[f"packing_d{d}"] = ok
        
        expected_bytes = (256 * d + 7) // 8
        print(f"  d={d:2d}: {len(packed)} bytes (expected {expected_bytes}), "
              f"roundtrip {'PASS' if ok else 'FAIL'}")
    
    # Test 3: Full ciphertext compression
    print("\n[Test 3] Ciphertext Compression")
    print("-" * 40)
    
    for n in [256, 512, 1024]:
        msg_bits = n
        
        u = np.random.randint(0, Q, size=n, dtype=np.int64)
        v = np.random.randint(0, Q, size=msg_bits, dtype=np.int64)
        
        # Compress
        compressed = compress_ciphertext(u, v, Q)
        
        # Decompress
        u_rec, v_rec = decompress_ciphertext(compressed, Q)
        
        # Check size
        old_size = 8 + n * 4 + msg_bits * 4  # Original wire format
        new_size = len(compressed)
        reduction = (1 - new_size / old_size) * 100
        
        # Check error bounds (for decryption to work)
        u_error = np.max(np.abs(u - u_rec))
        v_error = np.max(np.abs(v - v_rec))
        
        # v needs to preserve top bit for message decoding
        # delta = Q // 2, threshold = Q // 4
        # So v_error < Q // 4 is required
        v_threshold = Q // 4
        v_ok = v_error < v_threshold
        
        results[f"ct_n{n}"] = v_ok
        
        print(f"  n={n:4d}: {old_size:5d}B -> {new_size:4d}B "
              f"({reduction:.0f}% reduction)")
        print(f"          u_err={u_error:,.0f}, v_err={v_error:,.0f} "
              f"(need <{v_threshold:,}) -> {'PASS' if v_ok else 'FAIL'}")
    
    # Test 4: Size comparison with Kyber
    print("\n[Test 4] Size Comparison")
    print("-" * 40)
    
    kyber_ct = {256: 768, 512: 1088, 1024: 1568}
    
    print(f"  {'Level':<12} {'Old CT':<10} {'New CT':<10} {'Kyber':<10} {'vs Kyber':<12}")
    print(f"  {'-'*12} {'-'*10} {'-'*10} {'-'*10} {'-'*12}")
    
    for n, kyber in kyber_ct.items():
        msg_bits = n
        old = 8 + n * 4 + msg_bits * 4
        new = compressed_size(n, msg_bits)
        vs_kyber = (new / kyber - 1) * 100
        
        print(f"  n={n:<8} {old:<10} {new:<10} {kyber:<10} "
              f"{vs_kyber:+.0f}%")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
