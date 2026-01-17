# Meteor-NC: High-Performance Post-Quantum KEM

**GPU-Accelerated Lattice-Based Key Encapsulation Mechanism**

> This repository accompanies the TCHES 2026 submission

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Meteor-NC is a practical implementation of a post-quantum lattice-based key encapsulation mechanism (KEM). The cryptographic security relies entirely on **well-established primitives**:

| Component | Foundation | Reference |
|-----------|------------|-----------|
| KEM | LWE Problem | Regev 2005, NIST PQC |
| IND-CCA2 | Fujisaki–Okamoto (FO) Transform | ePrint 2017/604 |
| Key Derivation | HKDF (Extract-and-Expand) | RFC 5869 |
| Authenticated Encryption | (X)ChaCha20-Poly1305 / AES-GCM | RFC 8439 / RFC 5116 |

**No novel cryptographic assumptions are introduced.** The contribution is an implementation-first, throughput-oriented design with byte-exact FO behavior across CPU/GPU backends.

---

## ✨ Key Features

- **🚀 High Throughput**: 4M+ ops/sec on RTX 4090 (batch backend)
- **🔐 Post-Quantum Security**: Based on LWE with FO transform (IND-CCA2)
- **📦 Compact Keys**: 32-byte seed-based key storage
- **🔄 CPU/GPU Interop**: Byte-exact FO across backends
- **🌐 Protocol Ready**: P2P, streaming, and auth layers included

---

## Performance Results

Measured on NVIDIA RTX 4090 (batch backend). All security levels pass correctness tests.

### Batch KEM Throughput

| Security Level | n | Peak Throughput | Latency (100K batch) |
|----------------|-----|-----------------|----------------------|
| NIST Level 1 | 256 | **4,175,900 ops/sec** | 23.9 ms |
| NIST Level 3 | 512 | **2,379,398 ops/sec** | 21.0 ms |
| NIST Level 5 | 1024 | **1,017,945 ops/sec** | 9.8 ms |

```
======================================================================
FINAL SUMMARY - ALL SECURITY LEVELS
----------------------------------------------------------------------
n=256:  ✅ PASS  |  Peak: 4,175,900 ops/sec
n=512:  ✅ PASS  |  Peak: 2,379,398 ops/sec
n=1024: ✅ PASS  |  Peak: 1,017,945 ops/sec

RESULT: ✅ ALL LEVELS PASSED
======================================================================
```

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Meteor-NC System                            │
├─────────────────────────────────────────────────────────────────────┤
│  Security Layer (Established Primitives)                            │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌─────────────────┐    │
│  │   LWE    │  │    FO     │  │   HKDF   │  │ (X)ChaCha/AEAD  │    │
│  │ Problem  │  │ Transform │  │ RFC 5869 │  │   (DEM layer)   │    │
│  └──────────┘  └───────────┘  └──────────┘  └─────────────────┘    │
├─────────────────────────────────────────────────────────────────────┤
│  Implementation Layer (This Work)                                   │
│  ┌──────────────┐  ┌───────────────┐  ┌────────────────────┐       │
│  │  GPU Batch   │  │ 32-byte Seed  │  │  Protocol Layers   │       │
│  │  Processing  │  │  Key Restore  │  │   (P2P / Stream)   │       │
│  │  (4M ops/s)  │  │ (auth/repro)  │  │                    │       │
│  └──────────────┘  └───────────────┘  └────────────────────┘       │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Basic KEM Usage

```python
from meteor_nc.cryptography.core import LWEKEM

# Create KEM instance (NIST Level 1)
kem = LWEKEM(n=256)

# Generate keypair
pk, sk = kem.key_gen()

# Encapsulation (anyone with pk)
K1, ct = kem.encaps()

# Decapsulation (only sk holder)
K2 = kem.decaps(ct)

assert K1 == K2  # Shared secret matches!
```

### GPU Batch Processing

```python
from meteor_nc.cryptography.batch import BatchLWEKEM

kem = BatchLWEKEM(n=256, device_id=0)
kem.key_gen()

# 100,000 parallel encapsulations
K_batch, U_batch, V_batch = kem.encaps_batch(100000)
# → 4M+ ops/sec on RTX-class GPUs
```

### Compact Key Storage (32-byte seed)

```python
import secrets
from meteor_nc.cryptography.core import LWEKEM

master_seed = secrets.token_bytes(32)

# Generate keypair from seed
kem1 = LWEKEM(n=256)
pk1, sk1 = kem1.key_gen(seed=master_seed)

# Later: restore deterministically
kem2 = LWEKEM(n=256)
pk2, sk2 = kem2.key_gen(seed=master_seed)

assert pk1 == pk2 and sk1 == sk2  # Identical!
```

> ⚠️ **Security note**: Deterministic mode is for device-bound auth/recovery. If `master_seed` leaks, the secret key leaks. For standard encryption, use `seed=None`.

---

## Parameter Sets

| Level | n | k | q (default) | η | Shared Secret |
|-------|-----|-----|-------------|-----|---------------|
| 128-bit (NIST L1) | 256 | 256 | 2³²−5 | 2 | 32 bytes |
| 192-bit (NIST L3) | 512 | 512 | 2³²−5 | 2 | 32 bytes |
| 256-bit (NIST L5) | 1024 | 1024 | 2³²−5 | 3 | 32 bytes |

**Backend note**: GPU batch uses `q = 2³²` via native `uint32` wrap-around for fast modular arithmetic.

---

## Cryptographic Construction

### Key Generation

```
1. Sample pk_seed (32B) → reconstruct A ∈ Z_q^{k×n}
2. Sample s ← χ_η^n (secret), e ← χ_η^k (error)
3. Compute b = A·s + e (mod q)
4. Compute pk_hash = H(pk_seed || b)
5. Sample z ← {0,1}^256 (implicit rejection key)
6. Output: pk = (params, pk_seed, b, pk_hash), sk = (s, z)
```

### Encapsulation (FO-style)

```
1. Sample m ← {0,1}^n
2. Derive (seed_r, seed_e1, seed_e2) ← G(m, pk_hash)
3. Sample r, e1, e2 from seeds
4. Compute: u = A^T·r + e1, v = b^T·r + e2 + Encode(m)
5. K = HKDF(m || H(ct), info="shared-secret")
6. Output: (K, ct=(u,v))
```

### Decapsulation with Implicit Rejection

```
1. Recover m' = Decode(v − s^T·u)
2. Re-encrypt m' → (u', v')
3. If (u,v) == (u',v'):
     K = HKDF(m' || H(ct), info="shared-secret")
   Else:
     K = HKDF(z || H(ct), info="implicit-reject")  ← IND-CCA2
```

---

## HybridKEM (KEM-DEM)

```
K_kem
├─ HKDF(info="aead-key")  → k_aead  → AEAD (XChaCha20-Poly1305)
└─ HKDF(info="mixer-key") → k_mix   → protocol binding (optional)
```
---

## Design Goals

Meteor-NC targets deployments where:

- 🔒 Long-lived credentials must be **post-quantum**
- 💾 Endpoints store only a **small secret** (32 bytes)
- 🌐 Sessions established over untrusted networks with **IND-CCA2**
- ⚡ Throughput matters more than single-shot latency

Three compatible backends:

| Backend | Use Case | Performance |
|---------|----------|-------------|
| **Core** | Portability, correctness | Baseline |
| **Batch** | High-throughput (GPU) | 4M+ ops/sec |
| **Stream** | Chunked AEAD transport | Real-time |

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
│   ├── meteor_protocols.py         # P2P messaging
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

MIT License. See [LICENSE](License).

---

## References

1. O. Regev. "On lattices, learning with errors, random linear codes, and cryptography." STOC 2005.
2. D. Hofheinz, K. Hövelmanns, E. Kiltz. "A Modular Analysis of the Fujisaki-Okamoto Transformation." TCC 2017. [ePrint 2017/604](https://eprint.iacr.org/2017/604)
3. H. Krawczyk, P. Eronen. "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." [RFC 5869](https://tools.ietf.org/html/rfc5869)
4. NIST Post-Quantum Cryptography Standardization. [csrc.nist.gov](https://csrc.nist.gov/projects/post-quantum-cryptography)
