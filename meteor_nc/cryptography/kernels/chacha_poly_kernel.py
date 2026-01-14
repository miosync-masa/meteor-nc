# meteor_nc/cryptography/kernels/chacha_poly_kernel.py
"""
GPU-Accelerated XChaCha20-Poly1305

XChaCha20: GPU (high throughput)
Poly1305: CPU (cryptography library, correctness優先)
"""

import cupy as cp
import numpy as np
from typing import Tuple


# =============================================================================
# XChaCha20 CUDA Kernel (Poly1305 は CPU)
# =============================================================================

_XCHACHA_CODE = r'''
// ===========================================================================
// Constants
// ===========================================================================

__constant__ unsigned int CHACHA_CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

// ===========================================================================
// Quarter Round
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
    const unsigned int* key,
    const unsigned int* nonce16,
    unsigned int* subkey
) {
    unsigned int state[16];
    
    state[0] = CHACHA_CONSTANTS[0];
    state[1] = CHACHA_CONSTANTS[1];
    state[2] = CHACHA_CONSTANTS[2];
    state[3] = CHACHA_CONSTANTS[3];
    
    for (int i = 0; i < 8; i++) state[4 + i] = key[i];
    for (int i = 0; i < 4; i++) state[12 + i] = nonce16[i];
    
    for (int i = 0; i < 10; i++) {
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
    
    subkey[0] = state[0];  subkey[1] = state[1];
    subkey[2] = state[2];  subkey[3] = state[3];
    subkey[4] = state[12]; subkey[5] = state[13];
    subkey[6] = state[14]; subkey[7] = state[15];
}

// ===========================================================================
// ChaCha20 Block
// ===========================================================================

__device__ void chacha20_block(
    const unsigned int* key,
    unsigned int counter,
    const unsigned int* nonce,
    unsigned int* keystream
) {
    unsigned int state[16];
    unsigned int working[16];
    
    state[0] = CHACHA_CONSTANTS[0];
    state[1] = CHACHA_CONSTANTS[1];
    state[2] = CHACHA_CONSTANTS[2];
    state[3] = CHACHA_CONSTANTS[3];
    
    for (int i = 0; i < 8; i++) state[4 + i] = key[i];
    
    state[12] = counter;
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];
    
    for (int i = 0; i < 16; i++) working[i] = state[i];
    
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
    
    for (int i = 0; i < 16; i++) keystream[i] = working[i] + state[i];
}

// ===========================================================================
// XChaCha20 Encrypt (Single chunk, multi-block parallel)
// ===========================================================================

extern "C" __global__
void xchacha20_crypt(
    const unsigned char* __restrict__ input,
    unsigned char* __restrict__ output,
    const unsigned int* __restrict__ key,
    const unsigned int* __restrict__ nonce24,  // 6 words (24 bytes)
    const int length
) {
    int tid = blockDim.x * blockIdx.x + threadIdx.x;
    
    // Each thread handles one 64-byte block
    int block_idx = tid;
    int num_blocks = (length + 63) / 64;
    
    if (block_idx >= num_blocks) return;
    
    // HChaCha20: derive subkey (all threads do this, could optimize with shared mem)
    unsigned int subkey[8];
    unsigned int nonce16[4] = {nonce24[0], nonce24[1], nonce24[2], nonce24[3]};
    hchacha20(key, nonce16, subkey);
    
    // ChaCha20 nonce: 0 || nonce24[4:6]
    unsigned int chacha_nonce[3] = {0, nonce24[4], nonce24[5]};
    
    // Generate keystream for this block
    // Block 0 is reserved for Poly1305 key, so start from block 1
    unsigned int keystream[16];
    chacha20_block(subkey, block_idx + 1, chacha_nonce, keystream);
    
    // XOR with input
    int offset = block_idx * 64;
    int blk_len = min(64, length - offset);
    unsigned char* ks_bytes = (unsigned char*)keystream;
    
    for (int i = 0; i < blk_len; i++) {
        output[offset + i] = input[offset + i] ^ ks_bytes[i];
    }
}
'''

_XCHACHA_MODULE = cp.RawModule(code=_XCHACHA_CODE)
_xchacha20_crypt = _XCHACHA_MODULE.get_function('xchacha20_crypt')


# =============================================================================
# Python Interface
# =============================================================================

class GPUChaCha20Poly1305:
    """
    GPU-accelerated XChaCha20-Poly1305 AEAD.
    
    - XChaCha20: GPU (parallel block generation)
    - Poly1305: CPU (cryptography library)
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
        """Encrypt with XChaCha20-Poly1305."""
        if len(nonce) != 24:
            raise ValueError("Nonce must be 24 bytes")
        
        if len(plaintext) == 0:
            # Empty plaintext special case
            poly_key = self._derive_poly_key(nonce)
            tag = self._poly1305_tag(b"", aad, poly_key)
            return b"", tag
        
        # GPU encrypt
        pt_gpu = cp.asarray(np.frombuffer(plaintext, dtype=np.uint8))
        ct_gpu = cp.empty_like(pt_gpu)
        
        nonce_words = cp.asarray(
            np.frombuffer(nonce, dtype=np.uint32), dtype=cp.uint32
        )
        
        num_blocks = (len(plaintext) + 63) // 64
        threads = min(256, num_blocks)
        blocks = (num_blocks + threads - 1) // threads
        
        _xchacha20_crypt(
            (blocks,), (threads,),
            (pt_gpu, ct_gpu, self.key_words, nonce_words, np.int32(len(plaintext)))
        )
        
        ciphertext = cp.asnumpy(ct_gpu).tobytes()
        
        # CPU Poly1305
        poly_key = self._derive_poly_key(nonce)
        tag = self._poly1305_tag(ciphertext, aad, poly_key)
        
        return ciphertext, tag
    
    def decrypt(
        self,
        ciphertext: bytes,
        tag: bytes,
        nonce: bytes,
        aad: bytes,
    ) -> bytes:
        """Decrypt and verify."""
        if len(tag) != 16:
            raise ValueError("Tag must be 16 bytes")
        
        # Verify tag first
        poly_key = self._derive_poly_key(nonce)
        expected_tag = self._poly1305_tag(ciphertext, aad, poly_key)
        
        if not self._constant_time_compare(tag, expected_tag):
            raise ValueError("Authentication failed")
        
        if len(ciphertext) == 0:
            return b""
        
        # GPU decrypt (same as encrypt)
        ct_gpu = cp.asarray(np.frombuffer(ciphertext, dtype=np.uint8))
        pt_gpu = cp.empty_like(ct_gpu)
        
        nonce_words = cp.asarray(
            np.frombuffer(nonce, dtype=np.uint32), dtype=cp.uint32
        )
        
        num_blocks = (len(ciphertext) + 63) // 64
        threads = min(256, num_blocks)
        blocks = (num_blocks + threads - 1) // threads
        
        _xchacha20_crypt(
            (blocks,), (threads,),
            (ct_gpu, pt_gpu, self.key_words, nonce_words, np.int32(len(ciphertext)))
        )
        
        return cp.asnumpy(pt_gpu).tobytes()
    
    def _derive_poly_key(self, nonce: bytes) -> bytes:
        """Derive Poly1305 key via HChaCha20 + ChaCha20 block 0."""
        # HChaCha20
        subkey = self._hchacha20(self.key, nonce[:16])
        
        # ChaCha20 nonce: cryptography expects 16 bytes (counter + nonce)
        # Format: 4-byte counter (0) + 12-byte nonce
        # nonce[16:24] is 8 bytes, so we need to pad
        chacha_nonce = b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + nonce[16:24]  # 16 bytes total
        
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        cipher = Cipher(algorithms.ChaCha20(subkey, chacha_nonce), mode=None)
        encryptor = cipher.encryptor()
        keystream = encryptor.update(b"\x00" * 64)
        
        return keystream[:32]
    
    @staticmethod
    def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
        """HChaCha20 key derivation."""
        import struct
        
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
    
    def _poly1305_tag(self, data: bytes, aad: bytes, key: bytes) -> bytes:
        """Compute Poly1305 tag."""
        from cryptography.hazmat.primitives.poly1305 import Poly1305
        import struct
        
        def pad16(x):
            rem = len(x) % 16
            return x + (b"\x00" * (16 - rem) if rem else b"")
        
        msg = pad16(aad) + pad16(data) + struct.pack("<QQ", len(aad), len(data))
        
        p = Poly1305(key)
        p.update(msg)
        return p.finalize()

    def encrypt_batch_fixed(
        self,
        pt: cp.ndarray,
        nonces: cp.ndarray,
        aad: cp.ndarray,
        lens: cp.ndarray,
    ) -> Tuple[cp.ndarray, cp.ndarray]:
        """
        Batch encrypt fixed-size chunks.
        
        Args:
            pt:     (batch, chunk_size) uint8 (padded)
            nonces: (batch, 24) uint8
            aad:    (batch, 32) uint8
            lens:   (batch,) uint32 (real length per chunk)
        
        Returns:
            ct:  (batch, chunk_size) uint8
            tag: (batch, 16) uint8
        """
        batch, chunk_size = pt.shape
        ct = cp.empty_like(pt)
        tag = cp.empty((batch, 16), dtype=cp.uint8)
        
        # 暫定実装（ループ）- 後でカーネル統合で高速化
        for i in range(int(batch)):
            clen = int(lens[i].get())
            pt_i = cp.asnumpy(pt[i, :clen]).tobytes()
            nonce_i = cp.asnumpy(nonces[i]).tobytes()
            aad_i = cp.asnumpy(aad[i]).tobytes()
            
            ct_i, tag_i = self.encrypt(pt_i, nonce_i, aad_i)
            
            ct[i, :clen] = cp.asarray(np.frombuffer(ct_i, dtype=np.uint8))
            if clen < chunk_size:
                ct[i, clen:] = 0
            tag[i] = cp.asarray(np.frombuffer(tag_i, dtype=np.uint8))
        
        return ct, tag
    
    @staticmethod
    def _constant_time_compare(a: bytes, b: bytes) -> bool:
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
    
    sizes = [0, 1, 15, 16, 17, 64, 1000, 10000, 100000]
    all_pass = True
    
    for size in sizes:
        pt = secrets.token_bytes(size) if size > 0 else b""
        nonce = secrets.token_bytes(24)
        aad = b"test aad"
        
        ct, tag = cipher.encrypt(pt, nonce, aad)
        recovered = cipher.decrypt(ct, tag, nonce, aad)
        
        ok = (pt == recovered)
        all_pass = all_pass and ok
        print(f"  Size {size:6d}: {'PASS' if ok else 'FAIL'}")
    
    # Tamper test
    ct, tag = cipher.encrypt(b"secret", secrets.token_bytes(24), b"aad")
    try:
        cipher.decrypt(ct, bytes([tag[0] ^ 1]) + tag[1:], secrets.token_bytes(24), b"aad")
        tamper_ok = False
    except ValueError:
        tamper_ok = True
    
    print(f"  Tamper detect: {'PASS' if tamper_ok else 'FAIL'}")
    all_pass = all_pass and tamper_ok
    
    print("=" * 60)
    print(f"Result: {'ALL PASS' if all_pass else 'SOME FAILED'}")
    print("=" * 60)
    
    return all_pass


if __name__ == "__main__":
    test_gpu_chacha_poly()
