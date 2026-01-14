# meteor_nc/cryptography/kernels/batch_kernels.py
"""
BatchKEM専用CUDAカーネル群 (1D grid版)
"""

import cupy as cp
import numpy as np


_STRIDE_SEED = np.uint64(0xD1B54A32D192ED03)


# =============================================================================
# CBD Kernel (int32 output)
# =============================================================================

_CBD_KERNEL_I32 = cp.RawKernel(r'''
extern "C" __global__
void cbd_from_seeds_i32(
    const unsigned long long* __restrict__ seeds,
    int* __restrict__ out,
    const int dim,
    const int batch,
    const int eta,
    const unsigned long long stride_seed
) {
    int tid = blockDim.x * blockIdx.x + threadIdx.x;
    int total = dim * batch;
    if (tid >= total) return;

    int i = tid % dim;
    int b = tid / dim;

    unsigned long long x = seeds[b] + (unsigned long long)i * stride_seed;
    x += 0x9e3779b97f4a7c15ULL;
    unsigned long long z = x;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    z = z ^ (z >> 31);

    int a = 0, c = 0;
    for (int t = 0; t < eta; t++) {
        a += (int)((z >> t) & 1ULL);
        c += (int)((z >> (t + eta)) & 1ULL);
    }
    
    // F-contiguous output: out[i, b] = out[i + dim * b]
    out[i + dim * b] = a - c;
}
''', 'cbd_from_seeds_i32')


# =============================================================================
# U = A.T @ R + E1 (1D grid)
# =============================================================================

_MATMUL_AT_R_1D = cp.RawKernel(r'''
extern "C" __global__
void matmul_at_r_u32_1d(
    const unsigned int* __restrict__ A,
    const int* __restrict__ R,
    const int* __restrict__ E1,
    unsigned int* __restrict__ U,
    const int k,
    const int n,
    const int batch
) {
    int idx = blockDim.x * blockIdx.x + threadIdx.x;
    int total = n * batch;
    if (idx >= total) return;
    
    int col = idx % n;
    int b = idx / n;
    
    unsigned long long acc = 0ULL;
    for (int i = 0; i < k; i++) {
        unsigned int a_val = A[i * n + col];
        int r_val = R[i + k * b];
        acc += (unsigned long long)((long long)a_val * (long long)r_val);
    }
    
    unsigned int sum32 = (unsigned int)(acc & 0xFFFFFFFFULL);
    int e = E1[col + n * b];
    U[col + n * b] = sum32 + (unsigned int)e;
}
''', 'matmul_at_r_u32_1d')


# =============================================================================
# B_dot_R = b @ R (1D grid)
# =============================================================================

_BDOTR_1D = cp.RawKernel(r'''
extern "C" __global__
void bdotr_u32_1d(
    const unsigned int* __restrict__ b,
    const int* __restrict__ R,
    unsigned int* __restrict__ out,
    const int k,
    const int batch
) {
    int idx = blockDim.x * blockIdx.x + threadIdx.x;
    if (idx >= batch) return;
    
    unsigned long long acc = 0ULL;
    for (int i = 0; i < k; i++) {
        unsigned int bi = b[i];
        int ri = R[i + k * idx];
        acc += (unsigned long long)((long long)bi * (long long)ri);
    }
    out[idx] = (unsigned int)(acc & 0xFFFFFFFFULL);
}
''', 'bdotr_u32_1d')


# =============================================================================
# b = A @ s + e (1D grid)
# =============================================================================

_B_FROM_AS_1D = cp.RawKernel(r'''
extern "C" __global__
void b_from_As_u32_1d(
    const unsigned int* __restrict__ A,
    const int* __restrict__ s,
    const int* __restrict__ e,
    unsigned int* __restrict__ b,
    const int k,
    const int n
) {
    int row = blockDim.x * blockIdx.x + threadIdx.x;
    if (row >= k) return;
    
    unsigned long long acc = 0ULL;
    for (int j = 0; j < n; j++) {
        unsigned int a_val = A[row * n + j];
        int s_val = s[j];
        acc += (unsigned long long)((long long)a_val * (long long)s_val);
    }
    unsigned int sum32 = (unsigned int)(acc & 0xFFFFFFFFULL);
    b[row] = sum32 + (unsigned int)e[row];
}
''', 'b_from_As_u32_1d')


# =============================================================================
# S_dot_U = s @ U.T (1D grid)
# U is (batch, n), s is (n,), output is (batch,)
# =============================================================================

_SDOTU_1D = cp.RawKernel(r'''
extern "C" __global__
void sdotu_u32_1d(
    const int* __restrict__ s,
    const unsigned int* __restrict__ U,
    unsigned int* __restrict__ out,
    const int n,
    const int batch
) {
    int idx = blockDim.x * blockIdx.x + threadIdx.x;
    if (idx >= batch) return;
    
    unsigned long long acc = 0ULL;
    for (int i = 0; i < n; i++) {
        int si = s[i];
        unsigned int ui = U[idx * n + i];
        acc += (unsigned long long)((long long)si * (long long)ui);
    }
    out[idx] = (unsigned int)(acc & 0xFFFFFFFFULL);
}
''', 'sdotu_u32_1d')


# =============================================================================
# Helper Functions
# =============================================================================

def cbd_i32(seeds: cp.ndarray, dim: int, eta: int) -> cp.ndarray:
    """CBD samples as int32, shape (dim, batch), F-contiguous"""
    batch = int(seeds.size)
    total = dim * batch
    out = cp.empty((dim, batch), dtype=cp.int32, order='F')
    
    threads = 256
    blocks = (total + threads - 1) // threads
    _CBD_KERNEL_I32(
        (blocks,), (threads,),
        (seeds, out, np.int32(dim), np.int32(batch), np.int32(eta), _STRIDE_SEED)
    )
    return out


def matmul_AT_R(A: cp.ndarray, R: cp.ndarray, E1: cp.ndarray) -> cp.ndarray:
    """U = A.T @ R + E1 (mod 2^32)"""
    k, n = A.shape
    batch = R.shape[1]
    U = cp.empty((n, batch), dtype=cp.uint32, order='F')
    
    total = n * batch
    threads = 256
    blocks = (total + threads - 1) // threads
    
    _MATMUL_AT_R_1D((blocks,), (threads,), (
        A, R, E1, U,
        np.int32(k), np.int32(n), np.int32(batch)
    ))
    return U


def bdot_R(b: cp.ndarray, R: cp.ndarray) -> cp.ndarray:
    """B_dot_R = b @ R (mod 2^32)"""
    k = b.shape[0]
    batch = R.shape[1]
    out = cp.empty(batch, dtype=cp.uint32)
    
    threads = 256
    blocks = (batch + threads - 1) // threads
    _BDOTR_1D((blocks,), (threads,), (
        b, R, out,
        np.int32(k), np.int32(batch)
    ))
    return out


def b_from_As(A: cp.ndarray, s: cp.ndarray, e: cp.ndarray) -> cp.ndarray:
    """b = A @ s + e (mod 2^32)"""
    k, n = A.shape
    b = cp.empty(k, dtype=cp.uint32)
    
    threads = 256
    blocks = (k + threads - 1) // threads
    _B_FROM_AS_1D((blocks,), (threads,), (
        A, s, e, b,
        np.int32(k), np.int32(n)
    ))
    return b


def sdot_U(s: cp.ndarray, U: cp.ndarray) -> cp.ndarray:
    """S_dot_U = s @ U.T (mod 2^32), U is (batch, n) C-contiguous"""
    n = s.shape[0]
    batch = U.shape[0]
    out = cp.empty(batch, dtype=cp.uint32)
    
    threads = 256
    blocks = (batch + threads - 1) // threads
    _SDOTU_1D((blocks,), (threads,), (
        s, U, out,
        np.int32(n), np.int32(batch)
    ))
    return out
