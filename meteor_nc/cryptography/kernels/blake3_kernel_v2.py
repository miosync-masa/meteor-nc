# meteor_nc/cryptography/kernels/blake3_kernel_v2.py
"""
GPU BLAKE3 v2 - Multi-Security Level Support

Extended for variable message sizes (32/64/128 bytes).
Original 32-byte kernels remain untouched in blake3_kernel.py.
"""

import cupy as cp
import numpy as np

# =============================================================================
# CUDA Code: Seed/Key Derivation (Variable Message Size)
# =============================================================================

_BLAKE3_V2_CODE = r'''
// BLAKE3 IV
__constant__ unsigned int IV_V2[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

__constant__ int MSG_PERM_V2[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

__device__ __forceinline__ unsigned int rotr_v2(unsigned int x, int n) {
    return (x >> n) | (x << (32 - n));
}

__device__ void g_v2(unsigned int* state, int a, int b, int c, int d,
                     unsigned int mx, unsigned int my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr_v2(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr_v2(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr_v2(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr_v2(state[b] ^ state[c], 7);
}

__device__ void round_fn_v2(unsigned int* state, unsigned int* m) {
    g_v2(state, 0, 4,  8, 12, m[0],  m[1]);
    g_v2(state, 1, 5,  9, 13, m[2],  m[3]);
    g_v2(state, 2, 6, 10, 14, m[4],  m[5]);
    g_v2(state, 3, 7, 11, 15, m[6],  m[7]);
    g_v2(state, 0, 5, 10, 15, m[8],  m[9]);
    g_v2(state, 1, 6, 11, 12, m[10], m[11]);
    g_v2(state, 2, 7,  8, 13, m[12], m[13]);
    g_v2(state, 3, 4,  9, 14, m[14], m[15]);
}

__device__ void permute_v2(unsigned int* m) {
    unsigned int tmp[16];
    for (int i = 0; i < 16; i++) tmp[i] = m[MSG_PERM_V2[i]];
    for (int i = 0; i < 16; i++) m[i] = tmp[i];
}

__device__ void compress_block_v2(unsigned int* cv, const unsigned int* block, 
                                   int block_len, unsigned int flags) {
    unsigned int state[16];
    for (int i = 0; i < 8; i++) state[i] = cv[i];
    state[8]  = IV_V2[0]; state[9]  = IV_V2[1];
    state[10] = IV_V2[2]; state[11] = IV_V2[3];
    state[12] = 0;        state[13] = 0;
    state[14] = block_len; state[15] = flags;

    unsigned int m[16];
    for (int i = 0; i < 16; i++) m[i] = block[i];

    for (int r = 0; r < 7; r++) {
        round_fn_v2(state, m);
        if (r < 6) permute_v2(m);
    }

    for (int i = 0; i < 8; i++) cv[i] = state[i] ^ state[i + 8];
}

// Variable-length message seed derivation
extern "C" __global__
void blake3_derive_seeds_v2(
    const unsigned char* __restrict__ messages,
    const unsigned char* __restrict__ pk_hash,
    unsigned long long* __restrict__ seeds_r,
    unsigned long long* __restrict__ seeds_e1,
    unsigned long long* __restrict__ seeds_e2,
    const int batch,
    const int msg_bytes
) {
    int tid = blockDim.x * blockIdx.x + threadIdx.x;
    if (tid >= batch) return;

    const unsigned char* m_ptr = messages + tid * msg_bytes;
    
    unsigned int cv[8];
    for (int i = 0; i < 8; i++) cv[i] = IV_V2[i];
    
    int total_bytes = msg_bytes + 32;
    int num_blocks = (total_bytes + 63) / 64;
    
    unsigned int block[16];
    int byte_idx = 0;
    
    for (int blk = 0; blk < num_blocks; blk++) {
        for (int i = 0; i < 16; i++) {
            unsigned int word = 0;
            for (int j = 0; j < 4; j++) {
                int pos = byte_idx + i * 4 + j;
                unsigned char b = 0;
                if (pos < msg_bytes) {
                    b = m_ptr[pos];
                } else if (pos < total_bytes) {
                    b = pk_hash[pos - msg_bytes];
                }
                word |= ((unsigned int)b) << (j * 8);
            }
            block[i] = word;
        }
        byte_idx += 64;
        
        unsigned int flags = 0;
        if (blk == 0) flags |= 0x01;
        if (blk == num_blocks - 1) flags |= 0x02;
        if (blk == num_blocks - 1) flags |= 0x08;
        
        int block_len = 64;
        if (blk == num_blocks - 1) {
            int remaining = total_bytes - (blk * 64);
            if (remaining < 64) block_len = remaining;
        }
        
        compress_block_v2(cv, block, block_len, flags);
    }
    
    seeds_r[tid]  = ((unsigned long long)cv[0]) | ((unsigned long long)cv[1] << 32);
    seeds_e1[tid] = ((unsigned long long)cv[2]) | ((unsigned long long)cv[3] << 32);
    seeds_e2[tid] = ((unsigned long long)cv[4]) | ((unsigned long long)cv[5] << 32);
}

// Variable-length key derivation with implicit rejection
extern "C" __global__
void blake3_derive_keys_v2(
    const unsigned char* __restrict__ messages,
    const unsigned char* __restrict__ ct_hashes,
    const unsigned char* __restrict__ z,
    const unsigned char* __restrict__ ok_mask,
    unsigned char* __restrict__ keys,
    const int batch,
    const int msg_bytes
) {
    int tid = blockDim.x * blockIdx.x + threadIdx.x;
    if (tid >= batch) return;

    const unsigned char* m_ptr = messages + tid * msg_bytes;
    const unsigned char* ct_ptr = ct_hashes + tid * 32;
    unsigned char is_ok = ok_mask[tid];

    unsigned int cv[8];
    for (int i = 0; i < 8; i++) cv[i] = IV_V2[i];
    
    int input_bytes = is_ok ? msg_bytes : 32;
    int total_bytes = input_bytes + 32;
    int num_blocks = (total_bytes + 63) / 64;
    
    unsigned int block[16];
    int byte_idx = 0;
    
    for (int blk = 0; blk < num_blocks; blk++) {
        for (int i = 0; i < 16; i++) {
            unsigned int word = 0;
            for (int j = 0; j < 4; j++) {
                int pos = byte_idx + i * 4 + j;
                unsigned char b = 0;
                if (pos < input_bytes) {
                    if (is_ok) {
                        b = m_ptr[pos];
                    } else {
                        b = z[pos];
                    }
                } else if (pos < total_bytes) {
                    b = ct_ptr[pos - input_bytes];
                }
                word |= ((unsigned int)b) << (j * 8);
            }
            block[i] = word;
        }
        byte_idx += 64;
        
        unsigned int flags = 0;
        if (blk == 0) flags |= 0x01;
        if (blk == num_blocks - 1) flags |= 0x02;
        if (blk == num_blocks - 1) flags |= 0x08;
        
        int block_len = 64;
        if (blk == num_blocks - 1) {
            int remaining = total_bytes - (blk * 64);
            if (remaining < 64) block_len = remaining;
        }
        
        compress_block_v2(cv, block, block_len, flags);
    }
    
    unsigned char* out_ptr = keys + tid * 32;
    for (int i = 0; i < 8; i++) {
        out_ptr[i*4 + 0] = (unsigned char)(cv[i]);
        out_ptr[i*4 + 1] = (unsigned char)(cv[i] >> 8);
        out_ptr[i*4 + 2] = (unsigned char)(cv[i] >> 16);
        out_ptr[i*4 + 3] = (unsigned char)(cv[i] >> 24);
    }
}

// U||V concat hash (variable sizes)
extern "C" __global__
void blake3_hash_uv_concat_v2(
    const unsigned int* __restrict__ U,
    const unsigned int* __restrict__ V,
    unsigned char* __restrict__ out,
    const int batch,
    const int n,
    const int msg_bits
) {
    int tid = blockDim.x * blockIdx.x + threadIdx.x;
    if (tid >= batch) return;

    const unsigned int* u_ptr = U + tid * n;
    const unsigned int* v_ptr = V + tid * msg_bits;

    unsigned int cv[8];
    for (int i = 0; i < 8; i++) cv[i] = IV_V2[i];

    int total_words = n + msg_bits;
    int num_blocks = (total_words + 15) / 16;

    unsigned int block[16];
    int word_idx = 0;

    for (int blk = 0; blk < num_blocks; blk++) {
        for (int i = 0; i < 16; i++) {
            if (word_idx < n) {
                block[i] = u_ptr[word_idx];
            } else if (word_idx < total_words) {
                block[i] = v_ptr[word_idx - n];
            } else {
                block[i] = 0;
            }
            word_idx++;
        }

        unsigned int flags = 0;
        if (blk == 0) flags |= 0x01;
        if (blk == num_blocks - 1) flags |= 0x02;
        if (blk == num_blocks - 1) flags |= 0x08;

        int block_len = 64;
        if (blk == num_blocks - 1) {
            int remaining = (total_words * 4) - (blk * 64);
            if (remaining < 64) block_len = remaining;
        }

        compress_block_v2(cv, block, block_len, flags);
    }

    unsigned char* out_ptr = out + tid * 32;
    for (int i = 0; i < 8; i++) {
        out_ptr[i*4 + 0] = (unsigned char)(cv[i]);
        out_ptr[i*4 + 1] = (unsigned char)(cv[i] >> 8);
        out_ptr[i*4 + 2] = (unsigned char)(cv[i] >> 16);
        out_ptr[i*4 + 3] = (unsigned char)(cv[i] >> 24);
    }
}
'''

_BLAKE3_V2_MODULE = cp.RawModule(code=_BLAKE3_V2_CODE)
_blake3_derive_seeds_v2_kernel = _BLAKE3_V2_MODULE.get_function('blake3_derive_seeds_v2')
_blake3_derive_keys_v2_kernel = _BLAKE3_V2_MODULE.get_function('blake3_derive_keys_v2')
_blake3_hash_uv_v2_kernel = _BLAKE3_V2_MODULE.get_function('blake3_hash_uv_concat_v2')


# =============================================================================
# Python Class
# =============================================================================

class GPUBlake3V2:
    """GPU BLAKE3 v2 for variable message sizes (32/64/128 bytes)."""
    
    def __init__(self, device_id: int = 0):
        cp.cuda.Device(device_id).use()
        self._threads = 256
    
    def hash_u32_concat_batch(
        self,
        U: cp.ndarray,
        V: cp.ndarray,
        n: int = 256,
        msg_bits: int = 256,
    ) -> cp.ndarray:
        """
        Hash U||V concatenation for batch.
        
        Args:
            U: (batch, n) uint32
            V: (batch, msg_bits) uint32
            n: LWE dimension (256, 512, 1024)
            msg_bits: message bits (256, 512, 1024)
            
        Returns:
            (batch, 32) uint8 hashes
        """
        batch = U.shape[0]
        out = cp.empty((batch, 32), dtype=cp.uint8)
        
        U_c = cp.ascontiguousarray(U)
        V_c = cp.ascontiguousarray(V)
        
        blocks = (batch + self._threads - 1) // self._threads
        _blake3_hash_uv_v2_kernel(
            (blocks,), (self._threads,),
            (U_c, V_c, out, batch, n, msg_bits)
        )
        
        return out
    
    def derive_seeds_batch(
        self,
        messages: cp.ndarray,
        pk_hash: bytes,
        msg_bytes: int = 32,
    ) -> tuple:
        """
        Derive FO seeds for variable-length messages.
        
        Args:
            messages: (batch, msg_bytes) uint8 on GPU
            pk_hash: 32 bytes
            msg_bytes: 32, 64, or 128
        """
        batch = messages.shape[0]
        
        pk_hash_gpu = cp.asarray(np.frombuffer(pk_hash, dtype=np.uint8))
        
        seeds_r = cp.empty(batch, dtype=cp.uint64)
        seeds_e1 = cp.empty(batch, dtype=cp.uint64)
        seeds_e2 = cp.empty(batch, dtype=cp.uint64)
        
        blocks = (batch + self._threads - 1) // self._threads
        _blake3_derive_seeds_v2_kernel(
            (blocks,), (self._threads,),
            (messages, pk_hash_gpu, seeds_r, seeds_e1, seeds_e2, batch, msg_bytes)
        )
        
        return seeds_r, seeds_e1, seeds_e2
    
    def derive_keys_batch(
        self,
        messages: cp.ndarray,
        ct_hashes: cp.ndarray,
        z: bytes,
        ok_mask: cp.ndarray,
        msg_bytes: int = 32,
    ) -> cp.ndarray:
        """
        Derive shared keys with implicit rejection.
        
        Args:
            messages: (batch, msg_bytes) uint8
            ct_hashes: (batch, 32) uint8
            z: 32 bytes
            ok_mask: (batch,) uint8
            msg_bytes: 32, 64, or 128
        """
        batch = messages.shape[0]
        
        z_gpu = cp.asarray(np.frombuffer(z, dtype=np.uint8))
        keys = cp.empty((batch, 32), dtype=cp.uint8)
        
        blocks = (batch + self._threads - 1) // self._threads
        _blake3_derive_keys_v2_kernel(
            (blocks,), (self._threads,),
            (messages, ct_hashes, z_gpu, ok_mask, keys, batch, msg_bytes)
        )
        
        return keys
