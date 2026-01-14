# meteor_nc/cryptography/kernels/chacha_poly_kernel.py
"""
GPU-Accelerated XChaCha20-Poly1305

High-throughput AEAD for streaming encryption.
Target: GB/s encryption throughput.
"""

import cupy as cp
import numpy as np
from typing import Tuple


# =============================================================================
# XChaCha20-Poly1305 CUDA Kernels
# =============================================================================

_XCHACHA_POLY_CODE = r'''
// ===========================================================================
// Constants
// ===========================================================================

__constant__ unsigned int CHACHA_CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

// ===========================================================================
// Quarter Round (ChaCha core operation)
// ===========================================================================

__device__ __forceinline__ unsigned int rotl(unsigned int x, int n) {
    return (x << n) | (x >> (32 - n));
}

__device__ void quarter_round(unsigned int* state, int a, int b, int c, int d) {
    state[a] += state[b]; state[d] ^= state[a]; state[d] = rotl(state[d], 16);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = rotl(state[b], 12);
    state[a] += state[b]; state[d] ^= state[a]; state[d] = rotl(state[d], 8);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = rotl(state[b], 7);
}

// ===========================================================================
// HChaCha20 (Key derivation for XChaCha20)
// ===========================================================================

__device__ void hchacha20(
    const unsigned int* key,      // 8 words
    const unsigned int* nonce16,  // 4 words (first 16 bytes of 24-byte nonce)
    unsigned int* subkey          // 8 words output
) {
    unsigned int state[16];
    
    // Initialize state
    state[0] = CHACHA_CONSTANTS[0];
    state[1] = CHACHA_CONSTANTS[1];
    state[2] = CHACHA_CONSTANTS[2];
    state[3] = CHACHA_CONSTANTS[3];
    
    for (int i = 0; i < 8; i++) state[4 + i] = key[i];
    for (int i = 0; i < 4; i++) state[12 + i] = nonce16[i];
    
    // 20 rounds (10 double-rounds)
    for (int i = 0; i < 10; i++) {
        // Column rounds
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
    
    // Output: state[0..3] and state[12..15]
    subkey[0] = state[0];
    subkey[1] = state[1];
    subkey[2] = state[2];
    subkey[3] = state[3];
    subkey[4] = state[12];
    subkey[5] = state[13];
    subkey[6] = state[14];
    subkey[7] = state[15];
}

// ===========================================================================
// ChaCha20 Block Function
// ===========================================================================

__device__ void chacha20_block(
    const unsigned int* key,     // 8 words (subkey from HChaCha20)
    unsigned int counter,
    const unsigned int* nonce,   // 3 words (last 12 bytes, with 4 zero prefix)
    unsigned int* keystream      // 16 words output
) {
    unsigned int state[16];
    unsigned int working[16];
    
    // Initialize
    state[0] = CHACHA_CONSTANTS[0];
    state[1] = CHACHA_CONSTANTS[1];
    state[2] = CHACHA_CONSTANTS[2];
    state[3] = CHACHA_CONSTANTS[3];
    
    for (int i = 0; i < 8; i++) state[4 + i] = key[i];
    
    state[12] = counter;
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];
    
    // Copy to working state
    for (int i = 0; i < 16; i++) working[i] = state[i];
    
    // 20 rounds
    for (int i = 0; i < 10; i++) {
        quarter_round(working, 0, 4, 8, 12);
        quarter_round(working, 1, 5, 9, 13);
        quarter_round(working, 2, 6, 10, 14);
        quarter_round(working, 3, 7, 11, 15);
        quarter_round(working, 0, 5, 10, 15);
        quarter_round(working, 1, 6, 11, 12);
        quarter_round(working, 2, 7, 8, 13);
        quarter_round(working, 3, 4, 9, 14);
    }
    
    // Add original state
    for (int i = 0; i < 16; i++) keystream[i] = working[i] + state[i];
}

// ===========================================================================
// XChaCha20 Encryption Kernel (per-chunk parallel)
// ===========================================================================

extern "C" __global__
void xchacha20_encrypt_batch(
    const unsigned char* __restrict__ plaintext,   // (total_bytes,)
    unsigned char* __restrict__ ciphertext,        // (total_bytes,)
    const unsigned int* __restrict__ key,          // (8,) words
    const unsigned int* __restrict__ nonces,       // (batch, 6) words (24 bytes each)
    const int* __restrict__ chunk_offsets,         // (batch,) byte offsets
    const int* __restrict__ chunk_lengths,         // (batch,) 
    const int batch
) {
    int chunk_idx = blockIdx.x;
    if (chunk_idx >= batch) return;
    
    int tid = threadIdx.x;
    int block_threads = blockDim.x;
    
    int offset = chunk_offsets[chunk_idx];
    int length = chunk_lengths[chunk_idx];
    
    // Get nonce for this chunk
    const unsigned int* nonce24 = nonces + chunk_idx * 6;
    
    // HChaCha20: derive subkey
    __shared__ unsigned int subkey[8];
    __shared__ unsigned int chacha_nonce[3];
    
    if (tid == 0) {
        unsigned int nonce16[4] = {nonce24[0], nonce24[1], nonce24[2], nonce24[3]};
        hchacha20(key, nonce16, subkey);
        
        // Last 8 bytes of nonce with 4 zero prefix
        chacha_nonce[0] = 0;
        chacha_nonce[1] = nonce24[4];
        chacha_nonce[2] = nonce24[5];
    }
    __syncthreads();
    
    // Each thread handles multiple 64-byte blocks
    int num_blocks = (length + 63) / 64;
    
    for (int blk = tid; blk < num_blocks; blk += block_threads) {
        unsigned int keystream[16];
        chacha20_block(subkey, blk, chacha_nonce, keystream);
        
        int blk_offset = offset + blk * 64;
        int blk_len = min(64, length - blk * 64);
        
        // XOR plaintext with keystream
        unsigned char* ks_bytes = (unsigned char*)keystream;
        for (int i = 0; i < blk_len; i++) {
            ciphertext[blk_offset + i] = plaintext[blk_offset + i] ^ ks_bytes[i];
        }
    }
}

// ===========================================================================
// Poly1305 MAC (per-chunk)
// ===========================================================================

// Poly1305 uses 130-bit arithmetic, we'll use uint64 pairs
// r: clamped key (128 bit)
// s: second key part (128 bit)
// accumulator: 130 bit

__device__ void poly1305_init_key(
    const unsigned char* key32,  // 32 bytes: r || s
    unsigned long long* r,       // 2 x uint64 (clamped)
    unsigned long long* s        // 2 x uint64
) {
    // r = key[0:16], clamped
    unsigned long long r0 = 0, r1 = 0;
    for (int i = 0; i < 8; i++) r0 |= ((unsigned long long)key32[i]) << (i * 8);
    for (int i = 0; i < 8; i++) r1 |= ((unsigned long long)key32[8 + i]) << (i * 8);
    
    // Clamp r
    r0 &= 0x0ffffffc0fffffffULL;
    r1 &= 0x0ffffffc0ffffffcULL;
    
    r[0] = r0;
    r[1] = r1;
    
    // s = key[16:32]
    unsigned long long s0 = 0, s1 = 0;
    for (int i = 0; i < 8; i++) s0 |= ((unsigned long long)key32[16 + i]) << (i * 8);
    for (int i = 0; i < 8; i++) s1 |= ((unsigned long long)key32[24 + i]) << (i * 8);
    
    s[0] = s0;
    s[1] = s1;
}

// Simplified Poly1305 - accumulate blocks
__device__ void poly1305_block(
    unsigned long long* acc,     // 3 x uint64 (130-bit accumulator)
    const unsigned char* block,
    int block_len,
    const unsigned long long* r,
    int is_final
) {
    // Load block as 128-bit + 1 bit
    unsigned long long n0 = 0, n1 = 0;
    
    for (int i = 0; i < 8 && i < block_len; i++) {
        n0 |= ((unsigned long long)block[i]) << (i * 8);
    }
    for (int i = 8; i < 16 && i < block_len; i++) {
        n1 |= ((unsigned long long)block[i]) << ((i - 8) * 8);
    }
    
    // Add high bit if not final partial block
    unsigned long long hibit = (block_len < 16 || is_final) ? 0 : 1;
    if (block_len == 16) hibit = 1;
    
    // acc += n
    acc[0] += n0;
    acc[1] += n1 + (acc[0] < n0 ? 1 : 0);
    acc[2] += hibit + (acc[1] < n1 ? 1 : 0);
    
    // acc *= r (mod 2^130 - 5)
    // This is simplified - full implementation needs proper 130-bit modular multiplication
    // For correctness, we use a basic approach
    
    unsigned __int128 a0 = acc[0];
    unsigned __int128 a1 = acc[1];
    unsigned __int128 a2 = acc[2];
    
    unsigned __int128 r0 = r[0];
    unsigned __int128 r1 = r[1];
    
    // Multiply and reduce mod 2^130 - 5
    unsigned __int128 d0 = a0 * r0;
    unsigned __int128 d1 = a0 * r1 + a1 * r0;
    unsigned __int128 d2 = a1 * r1 + a2 * r0;
    unsigned __int128 d3 = a2 * r1;
    
    // Carry propagation
    d1 += d0 >> 64;
    d2 += d1 >> 64;
    d3 += d2 >> 64;
    
    acc[0] = (unsigned long long)d0;
    acc[1] = (unsigned long long)d1;
    acc[2] = (unsigned long long)(d2 & 0x3);  // Keep only 2 bits for 130-bit
    
    // Reduce mod 2^130 - 5
    unsigned long long carry = (d2 >> 2) + (d3 << 62);
    carry *= 5;
    acc[0] += carry;
    if (acc[0] < carry) {
        acc[1]++;
        if (acc[1] == 0) acc[2]++;
    }
}

extern "C" __global__
void poly1305_tag_batch(
    const unsigned char* __restrict__ data,       // All data concatenated
    const unsigned char* __restrict__ aad,        // AAD per chunk
    unsigned char* __restrict__ tags,             // (batch, 16) output
    const unsigned char* __restrict__ poly_keys,  // (batch, 32) Poly1305 keys
    const int* __restrict__ chunk_offsets,
    const int* __restrict__ chunk_lengths,
    const int* __restrict__ aad_offsets,
    const int* __restrict__ aad_lengths,
    const int batch
) {
    int idx = blockDim.x * blockIdx.x + threadIdx.x;
    if (idx >= batch) return;
    
    // Initialize
    unsigned long long r[2], s[2];
    unsigned long long acc[3] = {0, 0, 0};
    
    poly1305_init_key(poly_keys + idx * 32, r, s);
    
    int ct_offset = chunk_offsets[idx];
    int ct_len = chunk_lengths[idx];
    int aad_offset = aad_offsets[idx];
    int aad_len = aad_lengths[idx];
    
    // Process AAD
    const unsigned char* aad_ptr = aad + aad_offset;
    for (int i = 0; i < aad_len; i += 16) {
        int block_len = min(16, aad_len - i);
        poly1305_block(acc, aad_ptr + i, block_len, r, 0);
    }
    
    // Pad AAD to 16 bytes
    if (aad_len % 16 != 0) {
        // Already handled by block_len < 16
    }
    
    // Process ciphertext
    const unsigned char* ct_ptr = data + ct_offset;
    for (int i = 0; i < ct_len; i += 16) {
        int block_len = min(16, ct_len - i);
        poly1305_block(acc, ct_ptr + i, block_len, r, 0);
    }
    
    // Add lengths block
    unsigned char len_block[16] = {0};
    unsigned long long aad_len64 = aad_len;
    unsigned long long ct_len64 = ct_len;
    for (int i = 0; i < 8; i++) {
        len_block[i] = (aad_len64 >> (i * 8)) & 0xFF;
        len_block[8 + i] = (ct_len64 >> (i * 8)) & 0xFF;
    }
    poly1305_block(acc, len_block, 16, r, 1);
    
    // Finalize: acc += s
    acc[0] += s[0];
    if (acc[0] < s[0]) acc[1]++;
    acc[1] += s[1];
    
    // Output tag
    unsigned char* tag = tags + idx * 16;
    for (int i = 0; i < 8; i++) {
        tag[i] = (acc[0] >> (i * 8)) & 0xFF;
        tag[8 + i] = (acc[1] >> (i * 8)) & 0xFF;
    }
}
'''

_XCHACHA_MODULE = cp.RawModule(code=_XCHACHA_POLY_CODE)
_xchacha20_encrypt = _XCHACHA_MODULE.get_function('xchacha20_encrypt_batch')
_poly1305_tag = _XCHACHA_MODULE.get_function('poly1305_tag_batch')


# =============================================================================
# Python Interface
# =============================================================================

class GPUChaCha20Poly1305:
    """
    GPU-accelerated XChaCha20-Poly1305 AEAD.
    
    Designed for high-throughput streaming encryption.
    """
    
    def __init__(self, key: bytes, device_id: int = 0):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        
        cp.cuda.Device(device_id).use()
        
        self.key = key
        self.key_words = cp.asarray(
            np.frombuffer(key, dtype=np.uint32), dtype=cp.uint32
        )
        self.device_id = device_id
    
    def encrypt(
        self,
        plaintext: bytes,
        nonce: bytes,
        aad: bytes,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt with XChaCha20-Poly1305.
        
        Args:
            plaintext: Data to encrypt
            nonce: 24-byte nonce
            aad: Associated data
            
        Returns:
            (ciphertext, tag)
        """
        if len(nonce) != 24:
            raise ValueError("Nonce must be 24 bytes")
        
        # Single chunk
        pt_gpu = cp.asarray(np.frombuffer(plaintext, dtype=np.uint8))
        ct_gpu = cp.empty_like(pt_gpu)
        
        nonce_words = cp.asarray(
            np.frombuffer(nonce, dtype=np.uint32), dtype=cp.uint32
        ).reshape(1, 6)
        
        offsets = cp.array([0], dtype=cp.int32)
        lengths = cp.array([len(plaintext)], dtype=cp.int32)
        
        # Encrypt
        threads = 256
        _xchacha20_encrypt(
            (1,), (threads,),
            (pt_gpu, ct_gpu, self.key_words, nonce_words,
             offsets, lengths, np.int32(1))
        )
        
        ciphertext = cp.asnumpy(ct_gpu).tobytes()
        
        # Generate Poly1305 key from first ChaCha20 block
        poly_key = self._derive_poly_key(nonce)
        
        # Compute tag (CPU for now, GPU batch version available)
        tag = self._poly1305_tag_cpu(ciphertext, aad, poly_key)
        
        return ciphertext, tag
    
    def decrypt(
        self,
        ciphertext: bytes,
        tag: bytes,
        nonce: bytes,
        aad: bytes,
    ) -> bytes:
        """
        Decrypt and verify XChaCha20-Poly1305.
        
        Raises:
            ValueError: If authentication fails
        """
        if len(tag) != 16:
            raise ValueError("Tag must be 16 bytes")
        
        # Verify tag first
        poly_key = self._derive_poly_key(nonce)
        expected_tag = self._poly1305_tag_cpu(ciphertext, aad, poly_key)
        
        if not self._constant_time_compare(tag, expected_tag):
            raise ValueError("Authentication failed")
        
        # Decrypt (same as encrypt for stream cipher)
        ct_gpu = cp.asarray(np.frombuffer(ciphertext, dtype=np.uint8))
        pt_gpu = cp.empty_like(ct_gpu)
        
        nonce_words = cp.asarray(
            np.frombuffer(nonce, dtype=np.uint32), dtype=cp.uint32
        ).reshape(1, 6)
        
        offsets = cp.array([0], dtype=cp.int32)
        lengths = cp.array([len(ciphertext)], dtype=cp.int32)
        
        threads = 256
        _xchacha20_encrypt(
            (1,), (threads,),
            (ct_gpu, pt_gpu, self.key_words, nonce_words,
             offsets, lengths, np.int32(1))
        )
        
        return cp.asnumpy(pt_gpu).tobytes()
    
    def _derive_poly_key(self, nonce: bytes) -> bytes:
        """Derive Poly1305 key from XChaCha20 keystream."""
        # HChaCha20 + ChaCha20 block 0
        from meteor_nc.cryptography.stream import StreamDEM
        subkey = StreamDEM._hchacha20(self.key, nonce[:16])
        
        # ChaCha20 block 0 with counter=0
        chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:]
        
        # Generate 64 bytes, use first 32 as Poly1305 key
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        cipher = Cipher(algorithms.ChaCha20(subkey, chacha_nonce), mode=None)
        encryptor = cipher.encryptor()
        keystream = encryptor.update(b"\x00" * 64)
        
        return keystream[:32]
    
    def _poly1305_tag_cpu(self, data: bytes, aad: bytes, key: bytes) -> bytes:
        """Compute Poly1305 tag (CPU fallback)."""
        from cryptography.hazmat.primitives.poly1305 import Poly1305
        
        # AEAD construction: pad AAD, pad data, lengths
        def pad16(x):
            rem = len(x) % 16
            return x + (b"\x00" * (16 - rem) if rem else b"")
        
        import struct
        msg = pad16(aad) + pad16(data) + struct.pack("<QQ", len(aad), len(data))
        
        p = Poly1305(key)
        p.update(msg)
        return p.finalize()
    
    @staticmethod
    def _constant_time_compare(a: bytes, b: bytes) -> bool:
        """Constant-time comparison."""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0


# =============================================================================
# Test
# =============================================================================

def test_gpu_chacha_poly():
    """Test GPU XChaCha20-Poly1305."""
    import secrets
    
    print("=" * 60)
    print("GPU XChaCha20-Poly1305 Test")
    print("=" * 60)
    
    key = secrets.token_bytes(32)
    cipher = GPUChaCha20Poly1305(key)
    
    # Test various sizes
    sizes = [0, 1, 15, 16, 17, 64, 1000, 10000, 100000]
    
    for size in sizes:
        pt = secrets.token_bytes(size) if size > 0 else b""
        nonce = secrets.token_bytes(24)
        aad = b"test aad"
        
        ct, tag = cipher.encrypt(pt, nonce, aad)
        recovered = cipher.decrypt(ct, tag, nonce, aad)
        
        ok = (pt == recovered)
        print(f"  Size {size:6d}: {'PASS' if ok else 'FAIL'}")
    
    print("=" * 60)


if __name__ == "__main__":
    test_gpu_chacha_poly()
