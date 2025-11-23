"""
Meteor-NC GPU Parallel Implementation
Google Colab + A100 Optimized

Features:
- CuPy-based GPU acceleration
- Batch processing (data parallelism)
- Key generation parallelization
- Memory-efficient design
- Colab session management
"""

import numpy as np
import cupy as cp
from cupy.linalg import lstsq as cp_lstsq
from scipy.stats import ortho_group, special_ortho_group
import time
from typing import List, Dict, Tuple
import json
from datetime import datetime

# =============================================================================
# GPU-Accelerated Meteor-NC
# =============================================================================

class MeteorNC_GPU:
    """
    GPU-accelerated Meteor-NC with batch processing support
    """

    def __init__(self, n=256, m=8, noise_std=1e-10,
                 rank_reduction=0.3, name="", device_id=0):
        """
        Parameters:
        -----------
        n : int
            Dimension
        m : int
            Number of layers
        noise_std : float
            Noise standard deviation
        rank_reduction : float
            Rank reduction ratio (0 < rank_reduction < 1)
        name : str
            Configuration name
        device_id : int
            GPU device ID
        """
        # Set GPU device
        cp.cuda.Device(device_id).use()

        self.n = n
        self.m = m
        self.noise_std = noise_std
        self.rank_reduction = rank_reduction
        self.name = name or f"Meteor-NC-{n}-GPU"
        self.device_id = device_id

        # Keys (stored on GPU)
        self.S_gpu = None
        self.S_inv_gpu = None
        self.public_keys_gpu = []  # List of CuPy arrays

        # Private structures (kept on CPU for key generation)
        self.private_P = []
        self.private_D = []
        self.private_R = []

        # Metrics
        self.metrics = {
            'keygen_time': 0,
            'encrypt_times': [],
            'decrypt_times': [],
            'batch_throughputs': {},
            'memory_usage': {}
        }

        # Memory tracking
        self._track_memory("init")

    def _track_memory(self, stage: str):
        """Track GPU memory usage"""
        mempool = cp.get_default_memory_pool()
        used = mempool.used_bytes() / 1024**2  # MB
        total = mempool.total_bytes() / 1024**2
        self.metrics['memory_usage'][stage] = {
            'used_mb': used,
            'total_mb': total
        }

    def _generate_S_orthogonal_cpu(self):
        """Generate orthogonal S on CPU, then transfer to GPU"""
        S_cpu = ortho_group.rvs(dim=self.n)
        return S_cpu

    def _generate_projection_gpu(self):
        """Generate projection matrix on GPU"""
        target_rank = int(self.n * (1 - self.rank_reduction))

        # Generate on GPU
        A = cp.random.randn(self.n, target_rank, dtype=cp.float64)
        Q, _ = cp.linalg.qr(A)
        P = Q @ Q.T

        return P

    def _generate_diagonal_gpu(self, num_blocks=8):
        """Generate block-diagonal dominant matrix on GPU"""
        block_size = self.n // num_blocks
        blocks = []

        for _ in range(num_blocks):
            block = cp.random.randn(block_size, block_size, dtype=cp.float64) * 0.1
            block += cp.eye(block_size, dtype=cp.float64) * 10.0
            blocks.append(block)

        # Construct block diagonal
        D = cp.zeros((self.n, self.n), dtype=cp.float64)
        for i, block in enumerate(blocks):
            start = i * block_size
            end = start + block_size
            D[start:end, start:end] = block

        return D

    def _generate_rotation_gpu(self, layer_idx):
        """Generate small rotation matrix on GPU"""
        scale = 0.01
        group_type = layer_idx % 3

        if group_type == 0:
            # Special orthogonal (generate on CPU, transfer)
            R_cpu = special_ortho_group.rvs(self.n)
            R = cp.asarray(R_cpu, dtype=cp.float64)
            R = (R - cp.eye(self.n)) * scale
        elif group_type == 1:
            # Skew-symmetric
            A = cp.random.randn(self.n, self.n, dtype=cp.float64)
            R = (A - A.T) / 2 * scale
        else:
            # Random
            R = cp.random.randn(self.n, self.n, dtype=cp.float64) * scale

        return R

    def key_gen(self, verbose=True):
        """
        Generate keys with GPU acceleration
        """
        if verbose:
            print(f"[*] Generating Keys: {self.name} on GPU {self.device_id}")

        start_time = time.time()

        # Generate S on CPU (scipy only supports CPU)
        S_cpu = self._generate_S_orthogonal_cpu()

        # Transfer to GPU
        self.S_gpu = cp.asarray(S_cpu, dtype=cp.float64)
        self.S_inv_gpu = self.S_gpu.T

        # Generate layers on GPU
        self.public_keys_gpu = []
        self.private_P = []
        self.private_D = []
        self.private_R = []

        for i in range(self.m):
            # All operations on GPU
            P = self._generate_projection_gpu()
            D = self._generate_diagonal_gpu()
            R = self._generate_rotation_gpu(i)
            E = cp.random.normal(0, self.noise_std, (self.n, self.n), dtype=cp.float64)

            # Compute public key on GPU
            inner = P + D
            pi_tilde = self.S_gpu @ inner @ self.S_inv_gpu + R + E

            self.public_keys_gpu.append(pi_tilde)

            # Keep private structures (transfer to CPU for storage)
            self.private_P.append(cp.asnumpy(P))
            self.private_D.append(cp.asnumpy(D))
            self.private_R.append(cp.asnumpy(R))

        self.metrics['keygen_time'] = time.time() - start_time
        self._track_memory("keygen_complete")

        if verbose:
            print(f"[+] KeyGen Complete: {self.metrics['keygen_time']:.3f}s")
            mem = self.metrics['memory_usage']['keygen_complete']
            print(f"    GPU Memory: {mem['used_mb']:.1f} MB / {mem['total_mb']:.1f} MB")

        return self.metrics['keygen_time']

    def encrypt_single(self, message_cpu):
        """
        Encrypt single message (for compatibility)
        """
        start_time = time.time()

        # Transfer to GPU
        M = cp.asarray(message_cpu, dtype=cp.float64)

        # Apply transformations on GPU
        C = M.copy()
        for pi in self.public_keys_gpu:
            C = pi @ C

        # Add noise
        eta = cp.random.normal(0, self.noise_std, self.n, dtype=cp.float64)
        C = C + eta

        # Transfer back to CPU
        C_cpu = cp.asnumpy(C)

        elapsed = time.time() - start_time
        self.metrics['encrypt_times'].append(elapsed)

        return C_cpu

    def encrypt_batch(self, messages_cpu, return_gpu=False):
        """
        Batch encryption (data parallelism)

        Parameters:
        -----------
        messages_cpu : ndarray, shape (batch_size, n)
            Messages to encrypt
        return_gpu : bool
            If True, return GPU arrays (for chaining operations)

        Returns:
        --------
        ciphertexts : ndarray or cp.ndarray, shape (batch_size, n)
        """
        start_time = time.time()

        batch_size = messages_cpu.shape[0]

        # Transfer entire batch to GPU
        M = cp.asarray(messages_cpu, dtype=cp.float64)  # [batch, n]

        # Apply transformations (matrix @ batch)
        C = M.copy()
        for pi in self.public_keys_gpu:
            # Batch matrix multiplication
            C = C @ pi.T  # [batch, n] @ [n, n] = [batch, n]

        # Add noise to entire batch
        eta = cp.random.normal(0, self.noise_std, (batch_size, self.n), dtype=cp.float64)
        C = C + eta

        elapsed = time.time() - start_time

        # Calculate throughput
        throughput = batch_size / elapsed
        if batch_size not in self.metrics['batch_throughputs']:
            self.metrics['batch_throughputs'][batch_size] = []
        self.metrics['batch_throughputs'][batch_size].append(throughput)

        if return_gpu:
            return C
        else:
            # Transfer back to CPU
            return cp.asnumpy(C)

    def decrypt_single(self, ciphertext_cpu):
        """
        Decrypt single ciphertext
        """
        start_time = time.time()

        # Transfer to GPU
        C = cp.asarray(ciphertext_cpu, dtype=cp.float64)

        # Build composite on GPU
        composite = cp.eye(self.n, dtype=cp.float64)
        for pi in self.public_keys_gpu:
            composite = pi @ composite

        # Solve least-squares on GPU
        M_recovered, _, _, _ = cp_lstsq(composite, C)

        # Transfer back to CPU
        M_cpu = cp.asnumpy(M_recovered)

        elapsed = time.time() - start_time
        self.metrics['decrypt_times'].append(elapsed)

        return M_cpu

    def decrypt_batch(self, ciphertexts_cpu):
        """
        Batch decryption

        Parameters:
        -----------
        ciphertexts_cpu : ndarray, shape (batch_size, n)

        Returns:
        --------
        messages : ndarray, shape (batch_size, n)
        """
        start_time = time.time()

        batch_size = ciphertexts_cpu.shape[0]

        # Transfer to GPU
        C = cp.asarray(ciphertexts_cpu, dtype=cp.float64)  # [batch, n]

        # Build composite on GPU (only once!)
        composite = cp.eye(self.n, dtype=cp.float64)
        for pi in self.public_keys_gpu:
            composite = pi @ composite

        # Solve for all ciphertexts
        # C = [batch, n], composite = [n, n]
        # We want: M = composite^{-1} @ C.T
        M_batch = cp.linalg.lstsq(composite, C.T, rcond=None)[0].T  # [batch, n]

        # Transfer back to CPU
        M_cpu = cp.asnumpy(M_batch)

        elapsed = time.time() - start_time

        return M_cpu, elapsed

    def verify_security_gpu(self, verbose=True):
        """
        Security verification on GPU (dimension-scaled thresholds)
        """
        results = {}

        # Λ-IPP: Rank deficiency (on CPU for now)
        rank_deficits = [self.n - np.linalg.matrix_rank(P) for P in self.private_P]
        results['IPP_deficit'] = np.mean(rank_deficits)
        ipp_threshold = self.n * 0.2
        results['IPP_threshold'] = ipp_threshold
        results['IPP_secure'] = results['IPP_deficit'] > ipp_threshold

        # Λ-CP: Non-commutativity (on GPU, dimension-scaled)
        commutators = []
        for i in range(len(self.public_keys_gpu) - 1):
            pi_i = self.public_keys_gpu[i]
            pi_j = self.public_keys_gpu[i+1]
            comm = pi_i @ pi_j - pi_j @ pi_i
            comm_norm = float(cp.linalg.norm(comm, 'fro'))
            commutators.append(comm_norm)
        results['CP_commutator'] = np.mean(commutators)
        
        # ★ 修正：dimension-scaled threshold
        cp_threshold = 8.0 * np.sqrt(self.n / 256.0)
        results['CP_threshold'] = cp_threshold
        results['CP_secure'] = results['CP_commutator'] > cp_threshold

        # Λ-RRP: Rotation norms (on CPU, dimension-scaled range)
        rotation_norms = [np.linalg.norm(R, 'fro') for R in self.private_R]
        results['RRP_rotation'] = np.mean(rotation_norms)
        
        # ★ 修正：dimension-scaled bounds
        rrp_lower = 0.01
        rrp_upper = 10.0 * np.sqrt(self.n / 256.0)
        results['RRP_lower'] = rrp_lower
        results['RRP_upper'] = rrp_upper
        results['RRP_secure'] = rrp_lower < results['RRP_rotation'] < rrp_upper

        results['overall_secure'] = all([
            results['IPP_secure'],
            results['CP_secure'],
            results['RRP_secure']
        ])

        if verbose:
            print(f"\n[Security] {self.name}")
            print(f"  Λ-IPP: {results['IPP_deficit']:.1f} "
                  f"(threshold: {ipp_threshold:.0f}) "
                  f"{'✅' if results['IPP_secure'] else '⚠️'}")
            print(f"  Λ-CP:  {results['CP_commutator']:.2f} "
                  f"(threshold: {cp_threshold:.2f}) "
                  f"{'✅' if results['CP_secure'] else '⚠️'}")
            print(f"  Λ-RRP: {results['RRP_rotation']:.4f} "
                  f"(range: [{rrp_lower:.2f}, {rrp_upper:.2f}]) "
                  f"{'✅' if results['RRP_secure'] else '⚠️'}")
            print(f"  Overall: {'✅ SECURE' if results['overall_secure'] else '⚠️ WEAK'}")

        return results

    def cleanup_gpu(self):
        """Free GPU memory"""
        self.public_keys_gpu = []
        self.S_gpu = None
        self.S_inv_gpu = None
        mempool = cp.get_default_memory_pool()
        mempool.free_all_blocks()
        print(f"[+] GPU memory freed")

# =============================================================================
# GPU Benchmarking Suite
# =============================================================================

class MeteorNC_GPU_Benchmark:
    """
    Comprehensive GPU benchmarking
    """

    def __init__(self):
        self.results = []
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def benchmark_batch_sizes(self, config: Dict,
                              batch_sizes=[1, 10, 100, 1000, 10000],
                              num_warmup=5):
        """
        Benchmark different batch sizes
        """
        print("\n" + "="*70)
        print(f"Benchmarking: {config['name']}")
        print(f"Batch sizes: {batch_sizes}")
        print("="*70)

        # Create instance
        meteor = MeteorNC_GPU(
            n=config['n'],
            m=config['m'],
            noise_std=config.get('noise_std', 1e-10),
            rank_reduction=config.get('rank_reduction', 0.3),
            name=config['name']
        )

        # Key generation
        keygen_time = meteor.key_gen(verbose=True)

        # Security check
        security = meteor.verify_security_gpu(verbose=True)

        print(f"\n[*] Batch Processing Benchmark")
        print(f"{'Batch':<10} {'Encrypt (ms)':<15} {'Decrypt (ms)':<15} {'Throughput (msg/s)':<20} {'Speedup':<10}")
        print("-"*70)

        batch_results = {}
        baseline_time = None

        for batch_size in batch_sizes:
            # Generate test data
            messages = np.random.randn(batch_size, config['n'])

            # Warmup
            for _ in range(num_warmup):
                _ = meteor.encrypt_batch(messages[:min(10, batch_size)])

            # Encryption benchmark
            start = time.time()
            C_batch = meteor.encrypt_batch(messages)
            encrypt_time = time.time() - start

            # Decryption benchmark
            start = time.time()
            M_recovered, decrypt_time = meteor.decrypt_batch(C_batch)

            # Calculate metrics
            throughput = batch_size / encrypt_time
            total_time = encrypt_time + decrypt_time

            if baseline_time is None:
                baseline_time = total_time
                speedup = 1.0
            else:
                expected_time = baseline_time * batch_size
                speedup = expected_time / total_time

            # Verify correctness
            error = np.linalg.norm(messages - M_recovered) / np.linalg.norm(messages)

            batch_results[batch_size] = {
                'encrypt_time': encrypt_time,
                'decrypt_time': decrypt_time,
                'total_time': total_time,
                'throughput': throughput,
                'speedup': speedup,
                'error': error
            }

            print(f"{batch_size:<10} {encrypt_time*1000:<15.2f} {decrypt_time*1000:<15.2f} "
                  f"{throughput:<20.0f} {speedup:<10.1f}x")

        # Cleanup
        meteor.cleanup_gpu()

        result = {
            'config': config,
            'keygen_time': keygen_time,
            'security': security,
            'batch_results': batch_results
        }

        self.results.append(result)
        return result

    def compare_cpu_gpu(self, config: Dict, batch_size=100):
        """
        Compare CPU vs GPU performance
        """
        print("\n" + "="*70)
        print(f"CPU vs GPU Comparison: {config['name']}")
        print("="*70)

        from meteor_nc_production import MeteorNC_Production  # Assuming original CPU code

        # CPU version
        print("\n[*] CPU Baseline...")
        meteor_cpu = MeteorNC_Production(
            n=config['n'],
            m=config['m'],
            noise_std=config.get('noise_std', 1e-10),
            rank_reduction=config.get('rank_reduction', 0.3)
        )
        meteor_cpu.key_gen(verbose=False)

        messages = np.random.randn(batch_size, config['n'])

        # CPU encryption
        start = time.time()
        C_cpu = np.array([meteor_cpu.encrypt(m) for m in messages])
        cpu_encrypt_time = time.time() - start

        # GPU version
        print("[*] GPU Accelerated...")
        meteor_gpu = MeteorNC_GPU(
            n=config['n'],
            m=config['m'],
            noise_std=config.get('noise_std', 1e-10),
            rank_reduction=config.get('rank_reduction', 0.3)
        )
        meteor_gpu.key_gen(verbose=False)

        # GPU encryption (with warmup)
        _ = meteor_gpu.encrypt_batch(messages[:10])

        start = time.time()
        C_gpu = meteor_gpu.encrypt_batch(messages)
        gpu_encrypt_time = time.time() - start

        speedup = cpu_encrypt_time / gpu_encrypt_time

        print(f"\n[+] Results (batch_size={batch_size}):")
        print(f"  CPU Time:  {cpu_encrypt_time*1000:.2f} ms")
        print(f"  GPU Time:  {gpu_encrypt_time*1000:.2f} ms")
        print(f"  Speedup:   {speedup:.1f}x 🚀")

        meteor_gpu.cleanup_gpu()

        return {
            'cpu_time': cpu_encrypt_time,
            'gpu_time': gpu_encrypt_time,
            'speedup': speedup
        }

# =============================================================================
# Colab Helper Functions
# =============================================================================

def setup_colab_environment():
    """
    Setup Google Colab environment
    """
    try:
        from google.colab import drive
        drive.mount('/content/drive', force_remount=False)
        print("[+] Google Drive mounted")
    except:
        print("[!] Not running in Colab or Drive already mounted")

    # Check GPU
    print(f"\n[*] GPU Information:")
    print(f"  CuPy available: {cp.is_available()}")
    if cp.is_available():
        device = cp.cuda.Device()
        print(f"  Device: {device.id}")
        print(f"  Name: {cp.cuda.runtime.getDeviceProperties(device.id)['name'].decode()}")
        print(f"  Compute Capability: {device.compute_capability}")

        meminfo = cp.cuda.runtime.memGetInfo()
        print(f"  Total Memory: {meminfo[1] / 1024**3:.1f} GB")
        print(f"  Free Memory: {meminfo[0] / 1024**3:.1f} GB")

    return cp.is_available()

def keep_colab_alive():
    """
    Keep Colab session alive
    """
    from IPython.display import Javascript, display
    display(Javascript('''
    function KeepAlive() {
        console.log("Keeping Colab session alive...");
        document.querySelector("colab-connect-button").click();
    }
    setInterval(KeepAlive, 60000);  // Every 60 seconds
    '''))
    print("[+] Session keep-alive activated")

# =============================================================================
# Example Usage
# =============================================================================

if __name__ == "__main__":
    # Setup
    print("🌠"*35)
    print("Meteor-NC GPU Parallel Implementation")
    print("🌠"*35)

    if not setup_colab_environment():
        print("[!] GPU not available! Exiting...")
        exit(1)

    # Configuration
    config = {
        'name': 'METEOR-256-GPU',
        'n': 256,
        'm': 10,
        'noise_std': 1e-10,
        'rank_reduction': 0.3
    }

    # Run benchmark
    benchmark = MeteorNC_GPU_Benchmark()
    results = benchmark.benchmark_batch_sizes(
        config,
        batch_sizes=[1, 10, 100, 1000, 5000]
    )

    print("\n" + "🌠"*35)
    print("Benchmark Complete!")
    print("🌠"*35)
