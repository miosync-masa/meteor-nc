# Meteor-NC: High-Performance Post-Quantum KEM

**GPU-Accelerated Lattice-Based Key Encapsulation Mechanism**


[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18309744.svg)](https://doi.org/10.5281/zenodo.18309744)

> [!CAUTION]
> **Meteor-NC v2.x is broken; do not use it.** Its encryption hid every
> message bit under one shared scalar mask, so a passive attacker recovers
> the shared secret from the public key and a single ciphertext. Its
> parameters were also far below the claimed security levels.
> **v3 replaces the KEM core with FrodoKEM-640/976/1344-SHAKE** (verified
> byte-exact against the official KATs). The batch backend was rebuilt on the
> same core for GPU (CuPy) and CPU (NumPy). The performance and size tables
> further below describe **v2** and are kept for history only.
> See [SECURITY.md](SECURITY.md).
>
> | v3 level (`n=`) | Core | PK (B) | CT (B) | CPU keygen / encaps / decaps |
> |---|---|---|---|---|
> | L1 (`256`) | FrodoKEM-640-SHAKE | 9,628 | 9,764 | 8.5 / 7.6 / 7.2 ms |
> | L3 (`512`) | FrodoKEM-976-SHAKE | 15,644 | 15,804 | 14.9 / 12.3 / 9.8 ms |
> | L5 (`1024`) | FrodoKEM-1344-SHAKE | 21,532 | 21,708 | 28.3 / 19.7 / 25.8 ms |
>
> Sizes include a 12-byte Meteor header. Timings: single-threaded NumPy, cloud VM.
>
> **Batch (v3).** `BatchLWEKEM(n=...)` batches encaps/decaps on the GPU when
> CuPy and a CUDA device are present: SHAKE, noise sampling and 15-bit packing
> run in CUDA kernels, and the LWE products run on tensor cores (float16
> inputs, float32 accumulation), split so that every result is exact. The
> GPU path passes the official KATs and matches the CPU implementation
> (`benchmarks/bench_v3_gpu.py` checks this before benchmarking).
>
> Measured on an A100-SXM4-80GB (Colab), batch 100,000, operations per second:
>
> | Level | encaps (GPU-resident) | decaps (GPU-resident) | encaps (to host, with K) | decaps (to host, with K) |
> |---|---|---|---|---|
> | L1 FrodoKEM-640 | **1,244,275** | 947,686 | 197,161 | 193,103 |
> | L3 FrodoKEM-976 | 719,645 | 534,176 | 119,816 | 109,634 |
> | L5 FrodoKEM-1344 | 518,477 | 386,120 | 87,535 | 69,293 |
>
> "GPU-resident" leaves the FrodoKEM shared secrets and wires on the GPU;
> "to host" also derives K and moves the ~10-22 KB wires between host and
> GPU, which currently limits it (host-transfer bound, not compute bound).
> CPU (NumPy, batch 256): about 1,800 / 1,600 (L1) encaps / decaps per second.

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

- **🚀 High Throughput**: 4M+ ops/sec on Colab A100(40G) (batch backend)
- **🔐 Post-Quantum Security**: Based on LWE with FO transform (IND-CCA2)
- **📦 Compact Keys**: 32-byte seed-based key storage
- **🔄 CPU/GPU Interop**: Byte-exact FO across backends
- **🌐 Protocol Ready**: P2P, streaming, and auth layers included

---

## Performance Results

Measured on Colab A100（40G）(batch backend). All security levels pass correctness tests.

### Batch KEM Throughput

| Security Level | n | Peak Throughput | Latency (100K batch) |
|----------------|-----|-----------------|----------------------|
| NIST Level 1 | 256 | **4,175,900 ops/sec** | 23.9 ms |
| NIST Level 3 | 512 | **2,379,398 ops/sec** | 21.0 ms |
| NIST Level 5 | 1024 | **1,017,945 ops/sec** | 9.8 ms |

### Batch KEM Throughput　compressed

| Security Level | n    | Encaps (ops/sec) | Decaps (ops/sec) |
|----------------|------|------------------|------------------|
| NIST Level 1   | 256  | 1,344,648        | 1,377,240        |
| NIST Level 3   | 512  | 1,238,124        | 1,572,161        |
| NIST Level 5   | 1024 |   973,204        | 1,519,720        |

| Scheme     | Security Level | PK (B) | CT (B) | CT Compressed (B) | SS (B) |
|------------|----------------|--------|--------|-------------------|--------|
| Meteor-NC | n=256 (L1)     | 1100   | 2056   | **518**           | 32     |
| Meteor-NC | n=512 (L3)     | 2124   | 4104   | **1094**          | 32     |
| Meteor-NC | n=1024 (L5)    | 4172   | 8200   | **2310**          | 32     |

```
======================================================================
FINAL SUMMARY - ALL SECURITY LEVELS
----------------------------------------------------------------------
n=256:  ✅ PASS  |  Peak: 4,175,900 ops/sec
n=512:  ✅ PASS  |  Peak: 2,379,398 ops/sec
n=1024: ✅ PASS  |  Peak: 1,017,945 ops/sec

RESULT: ✅ ALL LEVELS PASSED
======================================================================

======================================================================
COMPRESSED FINAL SUMMARY - ALL SECURITY LEVELS
----------------------------------------------------------------------
n=256:  ✅ PASS  |  Peak: 1,344,648 ops/sec
n=512:  ✅ PASS  |  Peak: 1,238,124 ops/sec
n=1024: ✅ PASS  |  Peak: 973,204   ops/sec

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

kem = BatchLWEKEM(n=256, device_id=0)   # CuPy if a GPU is present, else NumPy
pk, sk = kem.key_gen()

K, wires = kem.encaps_batch(100_000)      # K: (B, 32) uint8, wires: (B, wire_len) uint8
assert (kem.decaps_batch(wires) == K).all()
# wires are ordinary v3 KEM ciphertexts: LWEKEM.decaps(wires[i].tobytes()) works too
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
│   ├── compression.py   # Compression
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

## License

MIT License. See [LICENSE](License).

---

## References

1. O. Regev. "On lattices, learning with errors, random linear codes, and cryptography." STOC 2005.
2. D. Hofheinz, K. Hövelmanns, E. Kiltz. "A Modular Analysis of the Fujisaki-Okamoto Transformation." TCC 2017. [ePrint 2017/604](https://eprint.iacr.org/2017/604)
3. H. Krawczyk, P. Eronen. "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." [RFC 5869](https://tools.ietf.org/html/rfc5869)
4. NIST Post-Quantum Cryptography Standardization. [csrc.nist.gov](https://csrc.nist.gov/projects/post-quantum-cryptography)
