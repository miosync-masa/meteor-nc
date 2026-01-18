# meteor_nc/cryptography/compression.py
"""
Meteor-NC Coefficient Compression v2.0

Kyber-style coefficient compression for wire format size reduction.
Internal computation remains uint32, compression only for transmission.

Key Design Decisions:
  1. FO verification uses compressed wire format as canonical form
  2. Level-specific d_u parameters for safety margin
  3. Integer-only arithmetic (no float rounding for determinism)

Compression parameters by security level:
  - n=256  (128-bit): d_u=11, d_v=5
  - n=512  (192-bit): d_u=12, d_v=5
  - n=1024 (256-bit): d_u=13, d_v=5

Error Analysis (worst-case):
  - Decryption computes: v - s^T u
  - Compression error: ε_v - s^T ε_u
  - Must satisfy: |ε_v - s^T ε_u| < Q/4 ≈ 1.07×10^9

  n=256, η=2, d_u=11:
    |s^T ε_u| ≤ 256×2×2^20 = 5.4×10^8 < Q/4 ✅

  n=512, η=2, d_u=12:
    |s^T ε_u| ≤ 512×2×2^19 = 5.4×10^8 < Q/4 ✅

  n=1024, η=3, d_u=13:
    |s^T ε_u| ≤ 1024×3×2^18 = 8.1×10^8 < Q/4 ✅
"""

import struct
from typing import Tuple, Dict

import numpy as np


# =============================================================================
# Compression Parameters (Level-specific)
# =============================================================================

# d_v is same for all levels (message bits only need MSB)
D_V = 5

# d_u varies by n to maintain safety margin
D_U_BY_N: Dict[int, int] = {
    256: 11,   # 128-bit security
    512: 12,   # 192-bit security
    1024: 13,  # 256-bit security
}

# Default for backward compatibility
D_U_DEFAULT = 11


def get_compression_params(n: int) -> Tuple[int, int]:
    """
    Get compression parameters for given dimension.
    
    Args:
        n: LWE dimension (256, 512, or 1024)
    
    Returns:
        (d_u, d_v) tuple
    """
    d_u = D_U_BY_N.get(n, D_U_DEFAULT)
    return d_u, D_V


# =============================================================================
# Core Compression Functions (Integer Arithmetic)
# =============================================================================

def compress(x: np.ndarray, q: int, d: int) -> np.ndarray:
    """
    Compress coefficients from Z_q to Z_{2^d}.
    
    Formula (integer): y = ((x << d) + q//2) // q  mod 2^d
    
    This is equivalent to round(x * 2^d / q) but uses only integer ops
    for deterministic behavior across platforms.
    
    Args:
        x: Coefficient array (0 <= x < q), any integer dtype
        q: Modulus
        d: Target bit width
    
    Returns:
        Compressed coefficients (0 <= y < 2^d) as uint16
    """
    # Ensure positive values in [0, q) as int64
    x_pos = x.astype(np.int64) % q
    
    # Integer rounding: (x * 2^d + q/2) // q
    # This is equivalent to round(x * 2^d / q)
    shifted = x_pos << d  # x * 2^d (fits in int64 for d <= 13)
    rounded = (shifted + (q >> 1)) // q  # Add q/2 for rounding, then divide
    
    # Mod 2^d
    return (rounded & ((1 << d) - 1)).astype(np.uint16)


def decompress(y: np.ndarray, q: int, d: int) -> np.ndarray:
    """
    Decompress coefficients from Z_{2^d} back to Z_q.
    
    Formula (integer): x = (y * q + 2^(d-1)) >> d
    
    This is equivalent to round(y * q / 2^d) but uses only integer ops.
    
    Args:
        y: Compressed coefficients (0 <= y < 2^d)
        q: Target modulus
        d: Source bit width
    
    Returns:
        Decompressed coefficients (0 <= x < q) as int64
    """
    y_64 = y.astype(np.int64)
    
    # Integer rounding: (y * q + 2^(d-1)) >> d
    # This is equivalent to round(y * q / 2^d)
    scaled = y_64 * q  # y * q (fits in int64)
    rounded = (scaled + (1 << (d - 1))) >> d  # Add 2^(d-1) for rounding, then shift
    
    return rounded


# =============================================================================
# Bit Packing Functions
# =============================================================================

def pack_bits(values: np.ndarray, d: int) -> bytes:
    """
    Pack array of d-bit values into byte stream (little-endian bit order).
    
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
        # Write d bits (LSB first)
        for i in range(d):
            if val & (1 << i):
                byte_idx = bit_pos >> 3  # bit_pos // 8
                bit_idx = bit_pos & 7     # bit_pos % 8
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
        Array of unpacked values as uint16
    """
    result = np.zeros(n, dtype=np.uint16)
    
    bit_pos = 0
    for i in range(n):
        val = 0
        for j in range(d):
            byte_idx = bit_pos >> 3
            bit_idx = bit_pos & 7
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
    d_u: int = None,
    d_v: int = None,
) -> bytes:
    """
    Compress LWE ciphertext (u, v) to wire format.
    
    Wire format:
        | n (2B) | msg_bits (2B) | d_u (1B) | d_v (1B) | u_packed | v_packed |
    
    Note: d_u and d_v are included in header for self-describing format.
    
    Args:
        u: (n,) array of coefficients
        v: (msg_bits,) array of coefficients
        q: Modulus
        d_u: Bits for u compression (auto-select if None)
        d_v: Bits for v compression (default D_V if None)
    
    Returns:
        Compressed bytes (canonical wire format for FO)
    """
    n = len(u)
    msg_bits = len(v)
    
    # Auto-select parameters if not provided
    if d_u is None or d_v is None:
        auto_d_u, auto_d_v = get_compression_params(n)
        d_u = d_u if d_u is not None else auto_d_u
        d_v = d_v if d_v is not None else auto_d_v
    
    # Compress using integer arithmetic
    u_compressed = compress(u, q, d_u)
    v_compressed = compress(v, q, d_v)
    
    # Pack bits
    u_packed = pack_bits(u_compressed, d_u)
    v_packed = pack_bits(v_compressed, d_v)
    
    # Header: n(2B) + msg_bits(2B) + d_u(1B) + d_v(1B) = 6B
    header = struct.pack(">HHBB", n, msg_bits, d_u, d_v)
    
    return header + u_packed + v_packed


def decompress_ciphertext(
    data: bytes,
    q: int,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Decompress wire format back to (u, v).
    
    Reads d_u, d_v from header (self-describing format).
    
    Args:
        data: Compressed bytes
        q: Modulus
    
    Returns:
        (u, v) as int64 arrays
    """
    if len(data) < 6:
        raise ValueError(f"Compressed data too short: {len(data)} < 6")
    
    # Parse header
    n, msg_bits, d_u, d_v = struct.unpack(">HHBB", data[:6])
    
    # Calculate byte sizes
    u_bytes = (n * d_u + 7) // 8
    v_bytes = (msg_bits * d_v + 7) // 8
    
    expected_size = 6 + u_bytes + v_bytes
    if len(data) < expected_size:
        raise ValueError(f"Compressed data truncated: {len(data)} < {expected_size}")
    
    # Unpack
    offset = 6
    u_compressed = unpack_bits(data[offset:offset + u_bytes], n, d_u)
    offset += u_bytes
    v_compressed = unpack_bits(data[offset:offset + v_bytes], msg_bits, d_v)
    
    # Decompress using integer arithmetic
    u = decompress(u_compressed, q, d_u)
    v = decompress(v_compressed, q, d_v)
    
    return u, v


def compressed_size(n: int, msg_bits: int, d_u: int = None, d_v: int = None) -> int:
    """
    Calculate compressed ciphertext size in bytes.
    
    Args:
        n: LWE dimension
        msg_bits: Message bits (usually == n)
        d_u: Bits for u (auto-select if None)
        d_v: Bits for v (default D_V if None)
    
    Returns:
        Size in bytes
    """
    if d_u is None or d_v is None:
        auto_d_u, auto_d_v = get_compression_params(n)
        d_u = d_u if d_u is not None else auto_d_u
        d_v = d_v if d_v is not None else auto_d_v
    
    header = 6  # n(2) + msg_bits(2) + d_u(1) + d_v(1)
    u_bytes = (n * d_u + 7) // 8
    v_bytes = (msg_bits * d_v + 7) // 8
    return header + u_bytes + v_bytes


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Test compression/decompression with integer arithmetic."""
    print("=" * 70)
    print("Meteor-NC Compression v2.0 Test (Integer Arithmetic)")
    print("=" * 70)
    
    Q = 4294967291  # 2^32 - 5
    results = {}
    
    # Test 1: Integer arithmetic determinism
    print("\n[Test 1] Integer Arithmetic Determinism")
    print("-" * 40)
    
    determinism_ok = True
    for d in [5, 11, 12, 13]:
        x = np.array([0, 1, Q//2, Q-1, 12345678, 3987654321], dtype=np.int64)
        
        y1 = compress(x, Q, d)
        y2 = compress(x, Q, d)
        
        if not np.array_equal(y1, y2):
            determinism_ok = False
            print(f"  d={d}: FAIL (non-deterministic)")
        else:
            print(f"  d={d}: PASS (deterministic)")
    
    results["determinism"] = determinism_ok
    
    # Test 2: Compress/decompress roundtrip error bounds
    print("\n[Test 2] Roundtrip Error Bounds")
    print("-" * 40)
    
    for n, d_u in D_U_BY_N.items():
        d_v = D_V
        
        # Random coefficients
        x_u = np.random.randint(0, Q, size=n, dtype=np.int64)
        x_v = np.random.randint(0, Q, size=n, dtype=np.int64)
        
        # Compress and decompress
        y_u = compress(x_u, Q, d_u)
        y_v = compress(x_v, Q, d_v)
        x_u_rec = decompress(y_u, Q, d_u)
        x_v_rec = decompress(y_v, Q, d_v)
        
        # Calculate errors (handle wrap-around)
        err_u = np.abs(x_u - x_u_rec)
        err_u = np.minimum(err_u, Q - err_u)
        err_v = np.abs(x_v - x_v_rec)
        err_v = np.minimum(err_v, Q - err_v)
        
        max_err_u = np.max(err_u)
        max_err_v = np.max(err_v)
        
        # Expected max error: Q / 2^d / 2 (half step)
        expected_max_u = Q // (1 << d_u) // 2 + 1
        expected_max_v = Q // (1 << d_v) // 2 + 1
        
        ok_u = max_err_u <= expected_max_u
        ok_v = max_err_v <= expected_max_v
        
        results[f"roundtrip_n{n}"] = ok_u and ok_v
        
        print(f"  n={n}, d_u={d_u}, d_v={d_v}:")
        print(f"    u: max_err={max_err_u:,} (bound={expected_max_u:,}) {'✓' if ok_u else '✗'}")
        print(f"    v: max_err={max_err_v:,} (bound={expected_max_v:,}) {'✓' if ok_v else '✗'}")
    
    # Test 3: Bit packing roundtrip
    print("\n[Test 3] Bit Packing Roundtrip")
    print("-" * 40)
    
    packing_ok = True
    for d in [5, 11, 12, 13]:
        values = np.random.randint(0, 1 << d, size=256, dtype=np.uint16)
        
        packed = pack_bits(values, d)
        unpacked = unpack_bits(packed, 256, d)
        
        if not np.array_equal(values, unpacked):
            packing_ok = False
            print(f"  d={d}: FAIL")
        else:
            expected_bytes = (256 * d + 7) // 8
            print(f"  d={d}: PASS ({len(packed)} bytes)")
    
    results["packing"] = packing_ok
    
    # Test 4: Full ciphertext compression (self-describing)
    print("\n[Test 4] Ciphertext Compression (Self-Describing)")
    print("-" * 40)
    
    for n in [256, 512, 1024]:
        msg_bits = n
        d_u, d_v = get_compression_params(n)
        
        u = np.random.randint(0, Q, size=n, dtype=np.int64)
        v = np.random.randint(0, Q, size=msg_bits, dtype=np.int64)
        
        # Compress (auto-selects d_u, d_v)
        wire = compress_ciphertext(u, v, Q)
        
        # Decompress (reads d_u, d_v from header)
        u_rec, v_rec = decompress_ciphertext(wire, Q)
        
        # Re-compress should give identical wire
        wire2 = compress_ciphertext(u_rec, v_rec, Q)
        
        wire_match = (wire == wire2)
        results[f"wire_determinism_n{n}"] = wire_match
        
        # Size
        old_size = 8 + n * 4 + msg_bits * 4
        new_size = len(wire)
        reduction = (1 - new_size / old_size) * 100
        
        print(f"  n={n} (d_u={d_u}, d_v={d_v}):")
        print(f"    Size: {old_size}B -> {new_size}B ({reduction:.0f}% reduction)")
        print(f"    Wire determinism: {'PASS ✓' if wire_match else 'FAIL ✗'}")
    
    # Test 5: Error analysis for decryption
    print("\n[Test 5] Decryption Error Analysis (Worst-Case)")
    print("-" * 40)
    
    eta_by_n = {256: 2, 512: 2, 1024: 3}
    
    for n, eta in eta_by_n.items():
        d_u, d_v = get_compression_params(n)
        
        # Worst-case error bounds
        eps_u = Q // (1 << d_u) // 2  # Per-coefficient error
        eps_v = Q // (1 << d_v) // 2
        
        # |s^T ε_u| ≤ n * η * ε_u (worst case: all same sign)
        worst_s_eps_u = n * eta * eps_u
        
        # Total error in decryption
        total_worst = worst_s_eps_u + eps_v
        
        # Threshold
        threshold = Q // 4
        
        margin = threshold - total_worst
        ok = margin > 0
        
        results[f"error_margin_n{n}"] = ok
        
        print(f"  n={n}, η={eta}, d_u={d_u}:")
        print(f"    |s^T ε_u| ≤ {worst_s_eps_u:,}")
        print(f"    |ε_v| ≤ {eps_v:,}")
        print(f"    Total ≤ {total_worst:,}")
        print(f"    Threshold = {threshold:,}")
        print(f"    Margin = {margin:,} {'✓' if ok else '✗'}")
    
    # Test 6: Size comparison with Kyber
    print("\n[Test 6] Size Comparison")
    print("-" * 40)
    
    kyber_ct = {256: 768, 512: 1088, 1024: 1568}
    
    print(f"  {'Level':<12} {'Old CT':<10} {'New CT':<10} {'Kyber':<10} {'vs Kyber':<12}")
    print(f"  {'-'*12} {'-'*10} {'-'*10} {'-'*10} {'-'*12}")
    
    for n, kyber in kyber_ct.items():
        msg_bits = n
        old = 8 + n * 4 + msg_bits * 4
        new = compressed_size(n, msg_bits)
        vs_kyber = (new / kyber - 1) * 100
        winner = "🏆" if vs_kyber < 0 else ""
        
        print(f"  n={n:<8} {old:<10} {new:<10} {kyber:<10} {vs_kyber:+.0f}% {winner}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
