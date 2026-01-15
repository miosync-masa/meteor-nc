# Meteor-NC: High-Performance Post-Quantum KEM

**GPU-Accelerated Lattice-Based Key Encapsulation Mechanism**

> This repository accompanies the TCHES 2026 submission

---

## Overview

Meteor-NC is a practical implementation of a post-quantum key encapsulation mechanism (KEM) achieving **4M+ encapsulations/second** on modern GPUs. The cryptographic security relies entirely on well-established primitives:

| Component | Foundation | Reference |
|-----------|------------|-----------|
| KEM | LWE Problem | Regev 2005, NIST PQC |
| IND-CCA2 | Fujisaki-Okamoto Transform | ePrint 2017/604 |
| Key Derivation | HKDF | RFC 5869 |
| Authenticated Encryption | AES-GCM | RFC 5116 |

**No novel cryptographic assumptions are introduced.** The contribution is a high-throughput implementation suitable for server-side batch operations and real-time applications.

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Meteor-NC System                         │
├─────────────────────────────────────────────────────────────┤
│  Security Layer (Established Primitives)                    │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │   LWE   │  │   F-O   │  │  HKDF   │  │ AES-GCM │        │
│  │ Problem │  │Transform│  │RFC 5869 │  │  AEAD   │        │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘        │
├─────────────────────────────────────────────────────────────┤
│  Implementation Layer (This Work)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ GPU Batch   │  │   32-byte   │  │  Protocol   │         │
│  │ Processing  │  │ Seed KDF    │  │   Layers    │         │
│  │ (4M ops/s)  │  │ (Compact)   │  │ (P2P/Stream)│         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

---

## Performance Results

Tested on NVIDIA RTX 4090, all security levels pass 100% correctness tests.

### Batch KEM Throughput

| Security Level | n | Peak Throughput | Latency (100K batch) |
|----------------|-----|-----------------|----------------------|
| NIST Level 1 | 256 | **4,175,900 ops/sec** | 23.9 ms |
| NIST Level 3 | 512 | **2,379,398 ops/sec** | 21.0 ms |
| NIST Level 5 | 1024 | **1,017,945 ops/sec** | 9.8 ms |

### Test Results Summary

```
======================================================================
FINAL SUMMARY - ALL SECURITY LEVELS
======================================================================
  n=256:  ✅ PASS  |  Peak: 4,175,900 ops/sec
  n=512:  ✅ PASS  |  Peak: 2,379,398 ops/sec
  n=1024: ✅ PASS  |  Peak: 1,017,945 ops/sec

RESULT: ✅ ALL LEVELS PASSED
======================================================================
```

---

## Parameter Sets

| Level | n | k | q | η | Shared Secret |
|-------|-----|-----|----------|-----|---------------|
| 128-bit (NIST L1) | 256 | 256 | 2³²−5 | 2 | 32 bytes |
| 192-bit (NIST L3) | 512 | 512 | 2³²−5 | 2 | 32 bytes |
| 256-bit (NIST L5) | 1024 | 1024 | 2³²−5 | 3 | 32 bytes |

Concrete security should be assessed with standard LWE estimators (e.g., lattice-estimator).

---

## Cryptographic Construction

### MeteorNC-Core-KEM

The KEM follows a standard LWE-based construction with FO transform:

**Key Generation:**
1. Derive matrix A ∈ Z_q^(k×n) from seeded RNG
2. Sample s ← χ_η^n, e ← χ_η^k (Centered Binomial Distribution)
3. Compute b = As + e
4. Output pk = (A, b, pk_hash), sk = (s, z)

**Encapsulation:**
1. Sample random message m ← {0,1}^256
2. Derive deterministic randomness r = H("random" ‖ m ‖ pk_hash)
3. Compute ciphertext ct = (u, v) using hash-derived errors
4. Output K = H("shared" ‖ m ‖ ct), ct

**Decapsulation (with Implicit Rejection):**
1. Decrypt to obtain m'
2. Re-encrypt to verify ct' = ct
3. If valid: K = H("shared" ‖ m' ‖ ct)
4. If invalid: K = H("fail" ‖ z ‖ ct) ← **implicit rejection**

### HybridKEM (KEM-DEM)

```
K_kem → HKDF("aead-key") → k_aead → AES-GCM
```

Domain separation ensures KEM and DEM key spaces are independent.

---

## Implementation Highlights

### 1. GPU Batch Processing

Custom CUDA kernels for parallel encapsulation:
- CBD sampling (Centered Binomial Distribution)
- Matrix-vector multiplication
- BLAKE3 hashing for key derivation

```python
from meteor_nc.cryptography.batch import BatchLWEKEM

kem = BatchLWEKEM(n=256, device_id=0)
kem.key_gen()

# 100,000 parallel encapsulations
K_batch, ct_batch, _ = kem.encaps_batch(100000)
# → 4M+ ops/sec on RTX 4090
```

### 2. Compact Key Storage

Full key pairs derived from 32-byte master seed via HKDF:

```python
from meteor_nc.cryptography import create_kdf_meteor

kdf = create_kdf_meteor(security_level=256)
kdf.key_gen()

seed = kdf.export_seed()  # 32 bytes only!
# Later: restore full keys from seed
```

### 3. CPU/GPU Interoperability

FO transform requires byte-exact ciphertext reconstruction. Hash-derived randomness (not backend RNG) ensures NumPy and CuPy produce identical ciphertexts:

```python
# Works identically on CPU and GPU
r_vec = small_error_from_seed(H("r" ‖ r), k)
e1 = small_error_from_seed(H("e1" ‖ r), n)
e2 = small_error_from_seed(H("e2" ‖ r), 8μ)
```

---

## Module Structure

```
meteor_nc/
├── cryptography/
│   ├── core.py          # LWEKEM, HybridKEM
│   ├── common.py        # HKDF, CBD, constants
│   ├── batch.py         # BatchLWEKEM (GPU)
│   ├── stream.py        # StreamDEM (chunked AEAD)
│   └── kernels/         # CUDA kernels
├── protocols/
│   ├── basic.py         # P2P messaging
│   └── advanced.py      # Network simulation
└── tests/
    ├── test_core.py     # Correctness tests
    ├── test_batch.py    # Batch tests
    └── test_stream.py   # Stream tests
```

---

## Installation

```bash
# Basic (CPU)
pip install .

# With GPU support (CUDA 12.x)
pip install ".[gpu]"

# Development
pip install -e ".[dev]"
```

### Requirements

- Python ≥ 3.8
- NumPy ≥ 1.20
- SciPy ≥ 1.7
- cryptography ≥ 3.4 (AEAD)
- CuPy ≥ 12.0 (optional, GPU)

---

## Usage

### Basic KEM

```python
from meteor_nc.cryptography import LWEKEM

alice = LWEKEM(n=256)
alice.key_gen()

bob = LWEKEM(n=256)
bob.key_gen()

K, ct = bob.encaps()
K_dec = alice.decaps(ct)

assert K == K_dec
```

### Hybrid Encryption

```python
from meteor_nc.cryptography import HybridKEM

kem = HybridKEM(n=256)
kem.key_gen()

ciphertext = kem.encrypt(b"Secret message", aad=b"metadata")
plaintext = kem.decrypt(ciphertext, aad=b"metadata")
```

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Individual suites
python -m tests.test_core   # KEM correctness
python -m tests.test_batch  # Batch operations
python -m tests.test_stream # Stream DEM
```

### Test Coverage

| Test | Description | Status |
|------|-------------|--------|
| B1 | Encaps/Decaps consistency | ✅ |
| B2 | Implicit rejection isolation | ✅ |
| B3 | GPU≡CPU consistency | ✅ |
| B4 | Dtype/shape handling | ✅ |
| B5 | Determinism | ✅ |
| B6 | Performance benchmark | ✅ |

---

## Security Considerations

### What We Claim

- **IND-CCA2 security** under LWE assumption (via FO transform)
- **Implicit rejection** prevents chosen-ciphertext attacks
- **Domain-separated hashing** isolates key derivation contexts

### What We Do NOT Claim

- Novel hardness assumptions
- Formal proofs beyond standard LWE reduction
- Side-channel resistance beyond implicit rejection

### Limitations

1. Ciphertext size larger than ML-KEM for equivalent security
2. GPU memory constraints for large batches at n=1024
3. Single-threaded CPU performance slower than optimized C

---

## License

MIT License. See [LICENSE](LICENSE).

---

## References

1. O. Regev. "On lattices, learning with errors, random linear codes, and cryptography." STOC 2005.
2. D. Hofheinz, K. Hövelmanns, E. Kiltz. "A Modular Analysis of the Fujisaki-Okamoto Transformation." TCC 2017. [ePrint 2017/604](https://eprint.iacr.org/2017/604)
3. H. Krawczyk, P. Eronen. "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." [RFC 5869](https://tools.ietf.org/html/rfc5869)
4. NIST Post-Quantum Cryptography Standardization. [csrc.nist.gov](https://csrc.nist.gov/projects/post-quantum-cryptography)
