# Meteor-NC: A Lattice-Based Key Encapsulation Mechanism

**Post-Quantum Hybrid KEM with GPU Acceleration**

> This repository accompanies the TCHES submission  
> "Meteor-NC: A Lattice-Based Cryptosystem with P2P"

---

## Overview

Meteor-NC is a post-quantum key encapsulation mechanism (KEM) based on the Learning With Errors (LWE) problem. The system consists of:

1. **MeteorNC-Core-KEM**: An LWE-based KEM with Fujisaki-Okamoto transform and implicit rejection (`class LWEKEM`)
2. **HybridKEM**: A KEM-DEM hybrid encryption scheme combining the KEM with an AEAD (`class HybridKEM`)
3. **Throughput Interfaces**: Batch encapsulation/decapsulation and streaming chunk encryption (optional)

### High-Level Data Flow

```
KeyGen → Encaps → K → KDF → k_aead → AEAD.Enc/Dec
```

The KEM shared secret K is never used directly as an AEAD key; a domain-separated hash derives the final symmetric key.

---

## Parameter Sets

The implementation provides three parameter bundles:

| Level | n | k | q | η | Message Size |
|-------|-----|-----|----------|-----|--------------|
| 128 | 256 | 256 | 2³²−5 | 2 | 32 bytes |
| 192 | 512 | 512 | 2³²−5 | 2 | 64 bytes |
| 256 | 1024 | 1024 | 2³²−5 | 3 | 128 bytes |

**Note**: Concrete security should be assessed with standard LWE estimators. The numeric labels (128/192/256) expose a tunable dimension/modulus/error interface and do not constitute formal security claims.

### Representation

- Ring elements: signed 64-bit integers (Python/NumPy/CuPy)
- Reduction: modulo q after additions and matrix products
- Intermediate values remain within 2⁶³ signed range for the above parameters

---

## Cryptographic Construction

### Message Encoding/Decoding

The KEM encrypts a uniformly random m ∈ {0,1}^(8μ), where μ = 32 bytes.

**Encoding**: Let δ = ⌊q/2⌋. The message is encoded bitwise as:
```
EncBits(m) := δ · bits(m) ∈ Z_q^(8μ)
```

**Decoding** (threshold at q/4): Each coordinate is centered into (−q/2, q/2] and outputs bit 1 iff |v| > q/4.

### MeteorNC-Core-KEM

#### Key Generation (`KeyGen`)

Starting from a 32-byte master seed, using HKDF with parameter-derived salt:

1. Sample A ← Z_q^(k×n) uniformly using seeded backend RNG
2. Sample s ← χ_η^n and e ← χ_η^k using seeded CBD sampling
3. Compute b = As + e ∈ Z_q^k
4. Compute pk_hash = H("pk_hash" ‖ enc(A) ‖ enc(b))
5. Derive implicit-rejection seed z ← {0,1}²⁵⁶ via HKDF label "implicit_reject"

**Output**: 
- Public key: pk = (A, b, pk_hash)
- Secret key: sk = (s, z)

#### Encapsulation (`Encaps(pk)`)

1. Sample m ← {0,1}^(8μ) uniformly (32 random bytes)
2. Compute r = H("random" ‖ m ‖ pk_hash)
3. Deterministically sample from hash-derived seeds:
   - r_vec ← D_small^k (label "r")
   - e₁ ← D_small^n (label "e1")
   - e₂ ← D_small^(8μ) (label "e2")
4. Compute encoded message: m_enc = δ · bits(m) ∈ Z_q^(8μ)
5. Compute ciphertext:
   - u = Aᵀr_vec + e₁ ∈ Z_q^n
   - v = bᵀr_vec + e₂ + m_enc ∈ Z_q^(8μ)
6. Compute shared secret: K = H("shared" ‖ m ‖ enc(u) ‖ enc(v))

**Output**: (K, ct) where ct = (u, v)

#### Decapsulation (`Decaps(pk, sk, ct)`)

Given ct = (u, v):

1. Compute v_dec = v − sᵀu ∈ Z_q^(8μ), then decode m' = DecBits(v_dec)
2. Compute r' = H("random" ‖ m' ‖ pk_hash) and re-encrypt to obtain ct' = (u', v')
3. Let ok = CTEq(enc(ct), enc(ct'))
4. **Implicit rejection**:
   ```
   K = H("shared" ‖ m' ‖ enc(ct))   if ok = 1
   K = H("fail" ‖ z ‖ enc(ct))      if ok = 0
   ```

**Output**: K

#### Backend Independence

NumPy and CuPy RNGs are not output-equivalent under the same seed. The FO check requires byte-for-byte equality of ct and ct'. Therefore, encryption-time vectors (r_vec, e₁, e₂) are sampled deterministically from hash-derived seeds (not from backend RNGs), ensuring CPU/GPU interoperability.

### HybridKEM

The hybrid scheme uses KEM-DEM with an AEAD data encapsulation mechanism.

#### Key Derivation

Given KEM shared secret K ∈ {0,1}²⁵⁶, derive the AEAD key:
```
k_aead := H("aead-key" ‖ K) ∈ {0,1}²⁵⁶
```

This domain separation prevents cross-protocol interactions between KEM and DEM hashing.

#### Optional Reversible Mixer

The implementation includes a reversible "mixer" (`SymmetricMixer`) implemented as a Feistel network over 32-bit words. Security is **not** claimed from this mixer; confidentiality and integrity are provided by AEAD. The mixer is deterministic and invertible, so it does not weaken AEAD security.

#### Hybrid Ciphertext Structure

```python
FullCiphertext = (u, v, nonce, ct, tag)
```

Where (u, v) is the KEM ciphertext and (nonce, ct, tag) is the AEAD output.

#### Pluggable AEAD

The reference `HybridKEM` instantiates AEAD as AES-GCM (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`). Other AEADs (e.g., XChaCha20-Poly1305) can be substituted without affecting the KEM analysis.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Master Seed (32 bytes)                      │
│                            │                                    │
│                     ┌──────┴──────┐                             │
│                     │    HKDF     │  RFC 5869 (HMAC-SHA256)     │
│                     └──────┬──────┘                             │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                 │
│         │                  │                  │                 │
│         ▼                  ▼                  ▼                 │
│    Matrix A           Secrets (s,e)      Rejection z           │
│   (seeded RNG)        (CBD sampling)     (implicit)            │
│         │                  │                  │                 │
│         └────────┬─────────┘                  │                 │
│                  ▼                            │                 │
│         ┌────────────────┐                    │                 │
│         │  pk = (A,b,h)  │                    │                 │
│         │  sk = (s,z)    │◄───────────────────┘                 │
│         └────────┬───────┘                                      │
│                  │                                              │
│         ┌────────┴────────┐                                     │
│         │                 │                                     │
│         ▼                 ▼                                     │
│   ┌──────────┐     ┌──────────┐                                 │
│   │  Encaps  │     │  Decaps  │                                 │
│   │ (m→K,ct) │     │(ct→K/K_f)│  ← Implicit Rejection           │
│   └────┬─────┘     └────┬─────┘                                 │
│        │                │                                       │
│        └───────┬────────┘                                       │
│                ▼                                                │
│        ┌───────────────┐                                        │
│        │   HybridKEM   │                                        │
│        │  (KEM + AEAD) │                                        │
│        └───────┬───────┘                                        │
│                │                                                │
│     ┌──────────┴──────────┐                                     │
│     │                     │                                     │
│     ▼                     ▼                                     │
│ ┌─────────┐         ┌──────────┐                                │
│ │  Batch  │         │ Stream   │                                │
│ │   KEM   │         │   DEM    │                                │
│ │  (GPU)  │         │ (chunks) │                                │
│ └─────────┘         └──────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Structure

```
meteor_nc/
├── cryptography/
│   ├── core.py          # LWEKEM, HybridKEM, SymmetricMixer
│   ├── common.py        # HKDF, CBD, constants (Q_DEFAULT, etc.)
│   ├── batch.py         # BatchLWEKEM (GPU parallel)
│   ├── stream.py        # StreamDEM (chunked AEAD)
│   ├── practical.py     # High-level string/file API
│   └── kernels/         # Custom CUDA kernels
├── protocols/
│   ├── basic.py         # MeteorNode, P2P messaging
│   ├── advanced.py      # Network simulation
│   └── web4.py          # libp2p, DHT, PubSub integration
├── auth/
│   └── core.py          # Device-bound authentication
└── tests/
    ├── test_core.py     # KEM correctness & security tests
    ├── test_batch.py    # Batch operation tests
    └── test_stream.py   # Stream DEM tests
```

---

## Installation

### Requirements

- Python 3.8+
- NumPy ≥ 1.20.0
- SciPy ≥ 1.7.0
- cryptography ≥ 3.4.0 (for AEAD)
- CuPy (optional, for GPU acceleration)

### Basic Installation

```bash
pip install .
```

### With GPU Support

```bash
pip install ".[gpu]"        # CUDA 12.x
pip install ".[gpu-cuda11]" # CUDA 11.x
```

### Development

```bash
pip install -e ".[dev]"
```

---

## Usage

### Basic KEM Operations

```python
from meteor_nc.cryptography import LWEKEM

# Key generation (Level-128: n=256)
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

### Hybrid Encryption

```python
from meteor_nc.cryptography import HybridKEM

# Setup
kem = HybridKEM(n=256)
kem.key_gen()

# Encrypt with optional AAD
plaintext = b"Quantum-resistant message"
aad = b"authenticated metadata"
ciphertext = kem.encrypt(plaintext, aad=aad)

# Decrypt
recovered = kem.decrypt(ciphertext, aad=aad)
assert plaintext == recovered
```

### Seed-Based Key Derivation

```python
from meteor_nc.cryptography import create_kdf_meteor

# Generate from 32-byte master seed
kdf = create_kdf_meteor(security_level=256)
kdf.key_gen()

# Export seed for compact storage
seed = kdf.export_seed()  # Only 32 bytes!

# Restore from seed
kdf_restored = create_kdf_meteor(security_level=256, seed=seed)
kdf_restored.key_gen()
```

### Batch Operations (GPU)

```python
from meteor_nc.cryptography.batch import BatchLWEKEM

# Initialize
kem = BatchLWEKEM(n=256, device_id=0)
kem.key_gen()

# Batch encapsulation (100,000 parallel)
K_batch, ct_batch, _ = kem.encaps_batch(100000)
```

### Streaming Encryption

```python
from meteor_nc.cryptography.stream import StreamDEM

# Establish session (from KEM shared secret)
session_key = K  # From KEM
stream_id = secrets.token_bytes(16)

enc = StreamDEM(session_key=session_key, stream_id=stream_id)
dec = StreamDEM(session_key=session_key, stream_id=stream_id)

# Encrypt/decrypt chunks
chunk = enc.encrypt_chunk(b"Video frame data")
plaintext = dec.decrypt_chunk(chunk)
```

---

## Performance

### Batch KEM Throughput (RTX 4090)

| Level | n | Encaps (ops/sec) | KeyGen (ops/sec) |
|-------|-----|------------------|------------------|
| 128 | 256 | 4.2M | 850K |
| 192 | 512 | 1.1M | 220K |
| 256 | 1024 | 280K | 55K |

### Single Operation Latency (n=256)

| Operation | CPU | GPU |
|-----------|-----|-----|
| KeyGen | 12.5 ms | 0.8 ms |
| Encaps | 8.2 ms | 0.3 ms |
| Decaps | 15.1 ms | 0.5 ms |

---

## Testing

```bash
# All tests
python -m pytest tests/ -v

# Individual suites
python -m tests.test_core    # KEM correctness
python -m tests.test_batch   # Batch operations
python -m tests.test_stream  # Stream DEM
```

### Test Categories

| Category | Tests | Description |
|----------|-------|-------------|
| A1-A2 | Correctness | KeyGen determinism, Encaps/Decaps roundtrip |
| A3, B | Security | IND-CPA, IND-CCA2 (implicit rejection), AEAD |
| A4 | Reproducibility | Seed determinism, cross-platform |
| A5, B6 | Performance | Throughput, latency benchmarks |
| E | Extended | K_fail uniformity, negative tests |

---

## Security Considerations

### IND-CCA2 via Fujisaki-Okamoto

The implementation achieves IND-CCA2 security through:

1. **Deterministic re-encryption**: Hash-derived randomness ensures ct' reconstruction
2. **Implicit rejection**: Invalid ciphertexts produce pseudorandom K_fail = H("fail" ‖ z ‖ ct)
3. **Constant-time comparison**: CTEq prevents timing side-channels

### Domain Separation

All hash operations use distinct domain labels:
- `"pk_hash"`: Public key commitment
- `"random"`: Encryption randomness derivation
- `"shared"`: Valid shared secret
- `"fail"`: Implicit rejection key
- `"aead-key"`: KEM→DEM key derivation

### Side-Channel Resistance

- Constant-time CBD sampling
- Implicit rejection (no branching on secret data)
- Backend-independent re-encryption

---

## Limitations

1. **Ciphertext size**: Larger than ML-KEM/Kyber for equivalent security
2. **GPU memory**: Large batches at n=1024 require significant VRAM
3. **Single-threaded CPU**: Slower than optimized C implementations

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## References

- Learning With Errors: Regev (2005), Peikert (2016)
- Fujisaki-Okamoto Transform: [ePrint 2017/604](https://eprint.iacr.org/2017/604)
- HKDF: [RFC 5869](https://tools.ietf.org/html/rfc5869)
- AEAD: [RFC 5116](https://tools.ietf.org/html/rfc5116)
