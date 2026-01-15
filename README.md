# Meteor-NC: PQC with 32-Byte Identities
  
**A Post-Quantum KEM Stack with 32-Byte Identities for High-Throughput and P2P Systems**

> This repository accompanies the TCHES submission "Meteor-NC: A Lattice-Based Cryptosystem with Non-Commutative Structure"

---

## Abstract

Meteor-NC is a post-quantum hybrid key encapsulation mechanism (KEM) designed for practical deployment. The system combines LWE-based cryptography with GPU acceleration to achieve high throughput while maintaining strong security guarantees. Key features include:

- **Extreme key compression**: 32-byte master seeds generate full key pairs
- **GPU-accelerated batch operations**: 4M+ encapsulations/second
- **Adaptive Precision Noise (APN)**: Dynamic noise scaling for IND-CPA security
- **Fujisaki-Okamoto transform**: IND-CCA2 security
- **Practical protocol layers**: P2P messaging, streaming encryption, authentication

---

## Security Parameters

| Parameter | n=256 | n=512 | n=1024 |
|-----------|-------|-------|--------|
| **NIST Level** | 1 | 3 | 5 |
| **Classical Security** | 128-bit | 192-bit | 256-bit |
| **Quantum Security** | ~64-bit | ~96-bit | ~128-bit |
| **Message Bytes** | 32 | 64 | 128 |
| **Public Key** | 32 bytes (seed) | 32 bytes (seed) | 32 bytes (seed) |
| **Ciphertext** | ~66 KB | ~264 KB | ~1 MB |
| **Layer Count (m)** | 10 | 18 | 34 |

### Layer Count Formula
```
m = max(8, floor(n/32) + 2)
```

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Master Seed (32 bytes)                      │
│                            │                                    │
│                     ┌──────┴──────┐                             │
│                     │    HKDF     │  RFC 5869                   │
│                     │ (HMAC-SHA256)│                            │
│                     └──────┬──────┘                             │
│                            │                                    │
│              ┌─────────────┼─────────────┐                      │
│              │             │             │                      │
│              ▼             ▼             ▼                      │
│         LWE Keys     APN Params    Stream Keys                  │
│         (A, s, e)    (κ, σ_eff)    (session)                   │
│              │             │             │                      │
│              └─────────────┴─────────────┘                      │
│                            │                                    │
│                            ▼                                    │
│              ┌─────────────────────────────┐                    │
│              │       Meteor-NC KEM         │                    │
│              │   (IND-CCA2 via FO)         │                    │
│              └─────────────────────────────┘                    │
│                            │                                    │
│              ┌─────────────┴─────────────┐                      │
│              │                           │                      │
│              ▼                           ▼                      │
│        Single KEM               Batch KEM (GPU)                 │
│        (CPU/GPU)               (CUDA Kernels)                   │
│                                          │                      │
│                            ┌─────────────┴─────────────┐        │
│                            │                           │        │
│                            ▼                           ▼        │
│                    Stream DEM                  P2P Protocol     │
│                 (XChaCha20-Poly1305)         (Web 4.0 Ready)   │
└─────────────────────────────────────────────────────────────────┘
```

### Module Structure

```
meteor_nc/
├── cryptography/
│   ├── core.py          # LWE-KEM + Hybrid KEM + APN
│   ├── batch.py         # GPU batch operations (CUDA)
│   ├── stream.py        # StreamDEM (XChaCha20-Poly1305)
│   ├── practical.py     # String/file encryption API
│   ├── common.py        # HKDF, CBD, constants
│   └── kernels/         # Custom CUDA kernels
│       ├── cbd.cu       # Centered Binomial Distribution
│       ├── matrix.cu    # Matrix operations
│       └── blake3.cu    # BLAKE3 hashing
├── protocols/
│   ├── basic.py         # MeteorNode, P2P messaging
│   ├── advanced.py      # Network simulation, testing
│   └── web4.py          # libp2p, DHT, PubSub, IPFS
├── auth/
│   └── core.py          # Device-bound authentication
└── tests/
    ├── test_core.py     # KEM correctness tests
    ├── test_batch.py    # Batch operation tests
    └── test_stream.py   # Stream DEM tests
```

---

## Installation

### Requirements

- Python 3.8+
- NumPy
- CuPy (optional, for GPU acceleration)
- cryptography (for XChaCha20-Poly1305)

### Basic Installation

```bash
pip install numpy cryptography
```

### GPU Support (Recommended)

```bash
pip install cupy-cuda12x  # For CUDA 12.x
# or
pip install cupy-cuda11x  # For CUDA 11.x
```

### Development Installation

```bash
git clone <anonymous-repository-url>
cd meteor-nc
pip install -e .
```

---

## Usage

### Basic KEM Operations

```python
from meteor_nc.cryptography import LWEKEM

# Key generation (NIST Level 1)
alice = LWEKEM(n=256)
alice.key_gen()

bob = LWEKEM(n=256)
bob.key_gen()

# Encapsulation (Bob → Alice)
K, ct = bob.encaps()

# Decapsulation (Alice)
K_dec = alice.decaps(ct)

assert K == K_dec  # Shared secret established
```

### Seed-Based Key Derivation

```python
from meteor_nc.cryptography import create_kdf_meteor

# Generate from master seed (32 bytes → full keys)
kdf = create_kdf_meteor(security_level=256)
kdf.key_gen()

# Export seed for storage (only 32 bytes!)
seed = kdf.export_seed()
print(f"Seed: {seed.hex()}")

# Restore from seed
kdf_restored = create_kdf_meteor(security_level=256, seed=seed)
kdf_restored.key_gen()
```

### Batch Operations (GPU)

```python
from meteor_nc.cryptography.batch import BatchLWEKEM
import cupy as cp

# Initialize batch KEM
kem = BatchLWEKEM(n=256, device_id=0)
kem.key_gen()

# Batch encapsulation (100,000 keys in parallel)
K_batch, ct_batch, _ = kem.encaps_batch(100000)
cp.cuda.Stream.null.synchronize()

print(f"Generated {len(K_batch)} shared secrets")
```

### P2P Protocol

```python
from meteor_nc.protocols import MeteorNode

# Create nodes
alice = MeteorNode("Alice", security_level=256)
bob = MeteorNode("Bob", security_level=256)

# Exchange MeteorIDs (32 bytes each)
alice.add_peer("Bob", bob.get_meteor_id())
bob.add_peer("Alice", alice.get_meteor_id())

# Send encrypted message
message = b"Hello, quantum-resistant world!"
encrypted = alice.send("Bob", message)

# Receive and decrypt
decrypted = bob.receive(encrypted)
assert message == decrypted
```

### Streaming Encryption

```python
from meteor_nc.cryptography.stream import StreamDEM
import secrets

# Establish session keys (from KEM)
session_key = secrets.token_bytes(32)
stream_id = secrets.token_bytes(16)

# Create stream encryptors
enc = StreamDEM(session_key=session_key, stream_id=stream_id)
dec = StreamDEM(session_key=session_key, stream_id=stream_id)

# Encrypt chunks
chunk1 = enc.encrypt_chunk(b"First chunk")
chunk2 = enc.encrypt_chunk(b"Second chunk")

# Decrypt chunks (order-sensitive)
plain1 = dec.decrypt_chunk(chunk1)
plain2 = dec.decrypt_chunk(chunk2)
```

---

## Performance

### Batch KEM Throughput (RTX 4090)

| Operation | n=256 | n=512 | n=1024 |
|-----------|-------|-------|--------|
| **Encapsulation** | 4.2M ops/sec | 1.1M ops/sec | 280K ops/sec |
| **Key Generation** | 850K ops/sec | 220K ops/sec | 55K ops/sec |

### Single Operation Latency

| Operation | CPU (n=256) | GPU (n=256) |
|-----------|-------------|-------------|
| Key Generation | 12.5 ms | 0.8 ms |
| Encapsulation | 8.2 ms | 0.3 ms |
| Decapsulation | 15.1 ms | 0.5 ms |

### Memory Usage

| Security Level | Key Memory | Batch (100K) Memory |
|----------------|------------|---------------------|
| n=256 | ~520 KB | ~6.5 GB |
| n=512 | ~2.1 MB | ~26 GB |
| n=1024 | ~8.4 MB | ~104 GB |

---

## Testing

### Run All Tests

```bash
# Core KEM tests
python -m tests.test_core

# Batch operation tests
python -m tests.test_batch

# Stream DEM tests
python -m tests.test_stream
```

### Test Categories

1. **Correctness Tests** (A1-A2)
   - Key generation determinism
   - Encapsulation/decapsulation roundtrip
   - Multi-level security (n=256, 512, 1024)

2. **Security Tests** (A3, B, E)
   - IND-CPA verification
   - IND-CCA2 (implicit rejection)
   - AEAD integrity
   - K_fail uniformity

3. **Reproducibility Tests** (A4)
   - Seed determinism
   - Cross-platform consistency

4. **Performance Tests** (A5, B6)
   - Throughput benchmarks
   - Latency measurements

### Example Test Output

```
[A1.1] Determinism Test
    Same seed → same keys: PASS ✓
    Different seed → different keys: PASS ✓

[A2.1] LWE-KEM Roundtrip
    n=256: PASS ✓ (1000 iterations)
    n=512: PASS ✓ (1000 iterations)
    n=1024: PASS ✓ (1000 iterations)

[B6] Batch Performance (n=256)
    batch_size=1000: 3,847,291 ops/sec
    batch_size=10000: 4,128,459 ops/sec
    batch_size=100000: 4,215,832 ops/sec
```

---

## Security Considerations

### Adaptive Precision Noise (APN)

The system employs APN (Algorithm 5 in the paper) to achieve IND-CPA security:

```
σ_eff = max(σ_0, ||C|| · ε · κ / √n)

where:
  σ_0    = Base noise (1e-10)
  ||C||  = Ciphertext norm
  ε      = Machine epsilon (2.22e-16 for FP64)
  κ      = Safety factor (default: 10000)
  n      = Dimension
```

### Fujisaki-Okamoto Transform

IND-CCA2 security is achieved via implicit rejection:

```python
# Decapsulation with implicit rejection
K' = H(m', ct)  # Re-derive key
if ct' != ct:   # Implicit check
    return K_fail = PRF(sk, ct)  # Pseudorandom rejection
else:
    return K'
```

### Side-Channel Resistance

- Constant-time CBD sampling
- Implicit rejection (no branching on secret data)
- APN prevents precision-based attacks

---

## Limitations

1. **GPU Memory**: Large batch sizes at high security levels (n=1024) require significant VRAM
2. **CPU Performance**: Single-threaded CPU operations are slower than optimized libraries like liboqs
3. **Ciphertext Size**: Larger than lattice-based schemes like Kyber/ML-KEM

---

## Directory Structure

```
.
├── README.md              # This file
├── meteor_nc/             # Main library
└── tests/                 # Test suite
```

---

## License

This software is provided for academic review purposes. See LICENSE file for details.

---

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [LWE Problem](https://en.wikipedia.org/wiki/Learning_with_errors)
- [Fujisaki-Okamoto Transform](https://eprint.iacr.org/2017/604)
- [RFC 5869 - HKDF](https://tools.ietf.org/html/rfc5869)
- [XChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
