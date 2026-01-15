# meteor_nc/cryptography/kernels/batch_kernels_v2.py
"""
BatchKEM Kernels v2 - Multi-Security Level Support

New kernels for n=512, n=1024.
Original n=256 kernels remain untouched in batch_kernels.py.
"""

import cupy as cp
import numpy as np


# =============================================================================
# GPU Unpack v2: (batch, msg_bytes) uint8 → (msg_bits, batch) uint32 * delta
# =============================================================================

_UNPACK_TO_ENCODED_V2 = cp.RawKernel(r'''
extern "C" __global__
void unpack_to_encoded_v2(
    const unsigned char* __restrict__ M_bytes,
    unsigned int* __restrict__ M_encoded,
    const unsigned int delta,
    const int batch,
    const int msg_bits,
    const int msg_bytes
) {
    int idx = blockDim.x * blockIdx.x + threadIdx.x;
    int total = batch * msg_bits;
    if (idx >= total) return;
    
    int b = idx / msg_bits;
    int bit_idx = idx % msg_bits;
    int byte_idx = bit_idx / 8;
    int bit_in_byte = 7 - (bit_idx % 8);  // MSB first
    
    unsigned char byte_val = M_bytes[b * msg_bytes + byte_idx];
    unsigned int bit = (byte_val >> bit_in_byte) & 1;
    
    // Output: F-contiguous (bit_idx, b)
    M_encoded[bit_idx + msg_bits * b] = bit * delta;
}
''', 'unpack_to_encoded_v2')


# =============================================================================
# GPU Pack v2: (batch, msg_bits) uint8 bits → (batch, msg_bytes) uint8 bytes
# =============================================================================

_PACK_BITS_V2 = cp.RawKernel(r'''
extern "C" __global__
void pack_bits_v2(
    const unsigned char* __restrict__ bits,
    unsigned char* __restrict__ bytes,
    const int batch,
    const int msg_bits,
    const int msg_bytes
) {
    int idx = blockDim.x * blockIdx.x + threadIdx.x;
    int total = batch * msg_bytes;
    if (idx >= total) return;
    
    int b = idx / msg_bytes;
    int byte_idx = idx % msg_bytes;
    
    unsigned char result = 0;
    for (int i = 0; i < 8; i++) {
        int bit_idx = byte_idx * 8 + i;
        unsigned char bit = bits[b * msg_bits + bit_idx];
        result |= (bit << (7 - i));
    }
    bytes[b * msg_bytes + byte_idx] = result;
}
''', 'pack_bits_v2')


# =============================================================================
# Helper Functions
# =============================================================================

def unpack_to_encoded_v2(
    M_gpu: cp.ndarray,
    delta: int,
    msg_bits: int,
    msg_bytes: int
) -> cp.ndarray:
    """
    (batch, msg_bytes) uint8 → (msg_bits, batch) uint32 * delta
    F-contiguous output for matrix ops
    
    Supports: msg_bits=256/512/1024, msg_bytes=32/64/128
    """
    batch = M_gpu.shape[0]
    M_encoded = cp.empty((msg_bits, batch), dtype=cp.uint32, order='F')
    
    total = batch * msg_bits
    threads = 256
    blocks = (total + threads - 1) // threads
    
    _UNPACK_TO_ENCODED_V2((blocks,), (threads,), (
        M_gpu, M_encoded,
        np.uint32(delta),
        np.int32(batch),
        np.int32(msg_bits),
        np.int32(msg_bytes)
    ))
    return M_encoded


def pack_bits_v2(
    bits: cp.ndarray,
    msg_bits: int,
    msg_bytes: int
) -> cp.ndarray:
    """
    (batch, msg_bits) uint8 → (batch, msg_bytes) uint8
    
    Supports: msg_bits=256/512/1024, msg_bytes=32/64/128
    """
    batch = bits.shape[0]
    bytes_out = cp.empty((batch, msg_bytes), dtype=cp.uint8)
    
    total = batch * msg_bytes
    threads = 256
    blocks = (total + threads - 1) // threads
    
    _PACK_BITS_V2((blocks,), (threads,), (
        bits, bytes_out,
        np.int32(batch),
        np.int32(msg_bits),
        np.int32(msg_bytes)
    ))
    return bytes_out


# =============================================================================
# Test
# =============================================================================

def test_v2_kernels():
    """Test v2 kernels for multiple security levels."""
    print("=" * 60)
    print("Batch Kernels v2 Test (Multi-Level)")
    print("=" * 60)
    
    results = {}
    
    for n, msg_bits, msg_bytes in [(256, 256, 32), (512, 512, 64), (1024, 1024, 128)]:
        print(f"\n[n={n}] msg_bits={msg_bits}, msg_bytes={msg_bytes}")
        print("-" * 40)
        
        # Test unpack → pack roundtrip
        batch = 100
        M_orig = cp.random.randint(0, 256, (batch, msg_bytes), dtype=cp.uint8)
        
        # Unpack to encoded
        delta = 2**31
        M_encoded = unpack_to_encoded_v2(M_orig, delta, msg_bits, msg_bytes)
        
        print(f"  M_encoded shape: {M_encoded.shape}")  # (msg_bits, batch)
        
        # Decode (simulate)
        M_bits = (M_encoded > 0).astype(cp.uint8).T  # (batch, msg_bits)
        
        # Pack back
        M_recovered = pack_bits_v2(M_bits, msg_bits, msg_bytes)
        
        print(f"  M_recovered shape: {M_recovered.shape}")  # (batch, msg_bytes)
        
        # Compare
        match = cp.all(M_orig == M_recovered)
        results[f"n={n}"] = bool(match)
        print(f"  Roundtrip: {'PASS ✓' if match else 'FAIL ✗'}")
    
    print("\n" + "=" * 60)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED ✓' if all_pass else 'SOME TESTS FAILED ✗'}")
    print("=" * 60)
    
    return all_pass


if __name__ == "__main__":
    test_v2_kernels()
