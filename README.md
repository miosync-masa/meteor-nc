# Meteor-NC: High-Performance Post-Quantum Cryptosystem

**A post-quantum public-key cryptosystem from non-commutative matrix groups, achieving 700,000 msg/s on GPU with IND-CPA security.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![CUDA](https://img.shields.io/badge/CUDA-11%2F12-green.svg)](https://developer.nvidia.com/cuda-downloads)

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔐 **Quantum-Resistant** | Three-fold hardness: LTDF + NCSP + Procrustes |
| ⚡ **700K msg/s** | GPU-accelerated decryption (NVIDIA A100) |
| 📦 **32-byte Keys** | KDF compresses keys from MB to 32 bytes |
| 🛡️ **IND-CPA Secure** | Adaptive Precision Noise (APN) ensures semantic security |
| 🚀 **140× Faster** | Than NIST Kyber-768 |

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/anonymous/meteor-nc.git
cd meteor-nc

# Install
pip install .

# With GPU support
pip install ".[gpu]"
```

### Basic Usage

```python
from meteor_nc import MeteorKDF

# Create and generate keys
crypto = MeteorKDF(n=256, m=10)
crypto.key_gen()

# Save seed (only 32 bytes!)
seed = crypto.export_seed()

# Encrypt/Decrypt
ciphertext = crypto.encrypt(message)
plaintext = crypto.decrypt(ciphertext)
```

### String Encryption

```python
from meteor_nc.cryptography.string import MeteorPractical

# High-level API
crypto = MeteorPractical(n=256)
crypto.key_gen()
crypto.expand_keys()

# Encrypt string
encrypted = crypto.encrypt_string("Hello, quantum-resistant world!")
decrypted = crypto.decrypt_string(encrypted)
```

### P2P Communication

```python
from meteor_nc import MeteorNode

# Create nodes
alice = MeteorNode("Alice", security_level=256)
bob = MeteorNode("Bob", security_level=256)

# Exchange 32-byte IDs
alice.add_peer("Bob", bob.get_meteor_id())
bob.add_peer("Alice", alice.get_meteor_id())

# Send encrypted message
encrypted = alice.send("Bob", b"Hello Bob!")
plaintext = bob.receive(encrypted)
```

---

## 📊 Performance

### Benchmark Results (NVIDIA A100)

| Variant | n | m | Enc (K/s) | Dec (K/s) | Error | NCSP |
|---------|---|---|-----------|-----------|-------|------|
| METEOR-128 | 128 | 8 | 1,307 | 1,513 | 2.5×10⁻¹² | 23.9 |
| METEOR-256 | 256 | 10 | 828 | 700 | 2.9×10⁻¹² | 63.1 |
| METEOR-512 | 512 | 18 | 367 | 269 | 5.3×10⁻¹² | 171.1 |
| METEOR-1024 | 1024 | 34 | 98 | 128 | 5.5×10⁻¹¹ | 475.3 |

### Comparison with Standards

| System | Throughput | Quantum-Safe | Key Size |
|--------|------------|--------------|----------|
| RSA-2048 | ~1K/s | ❌ | 256 bytes |
| AES-256-GCM | ~100K/s | ❌ | 32 bytes |
| NIST Kyber-768 | ~5K/s | ✅ | 1.6 KB |
| **Meteor-NC (256)** | **700K/s** | ✅ | **32 bytes** |

**140× faster than Kyber-768** with smaller keys.

---

## 🔒 Security

### Three-Fold Hardness

Meteor-NC security relies on three independent hard problems:

1. **LTDF (Lossy Trapdoor Functions)**: Rank-deficient projections destroy information unconditionally
2. **NCSP (Non-Commutative Security Parameter)**: Non-abelian group structure resists Shor's algorithm
3. **Noisy Procrustes**: Geometric recovery hardness from skew-symmetric perturbations

### Quantum Resistance

| Property | Result |
|----------|--------|
| Non-commutativity | ‖[πᵢ,πⱼ]‖ = 63.1 (threshold: 8.0) ✅ |
| Periodic structure | None detected (k ≤ 15) ✅ |
| Grover complexity | 2^1,015,808 operations ✅ |
| Shor applicability | Structurally immune ✅ |

### Security Levels

| Level | Lossiness | Classical | Quantum (Grover) |
|-------|-----------|-----------|------------------|
| METEOR-128 | 307 dim | 2^507,904 | 2^253,952 |
| METEOR-256 | 768 dim | 2^2,031,616 | 2^1,015,808 |
| METEOR-512 | 2,765 dim | 2^8,126,464 | 2^4,063,232 |
| METEOR-1024 | 10,444 dim | 2^32,505,856 | 2^16,252,928 |

---

## 📁 Project Structure

```
meteor-nc/
├── meteor_nc/
│   ├── __init__.py           # Package exports
│   ├── cryptography/
│   │   ├── core.py           # MeteorNC base implementation
│   │   ├── kdf.py            # MeteorKDF with GPU acceleration
│   │   ├── gpu.py            # MeteorGPU optimized implementation
│   │   └── string.py         # MeteorPractical string encryption
│   ├── protocols/
│   │   ├── basic.py          # MeteorNode, MeteorProtocol
│   │   ├── advanced.py       # MeteorNetwork, LatencySimulator
│   │   └── web4.py           # MeteorIdentity, MeteorIPFS
│   └── auth/
│       └── auth.py           # MeteorAuth passwordless authentication
├── tests/
│   ├── test_security_validation.py
│   ├── test_basic_protocol.py
│   ├── test_string_encryption.py
│   ├── test_advanced_web4.py
│   ├── test_integrated.py
│   └── test_gpu_scaling.py
├── pyproject.toml
├── LICENSE
├── CHANGELOG.md
└── README.md
```

---

## 🧪 Testing

### Basic Tests
```bash
python tests/test_security_validation.py
python tests/test_basic_protocol.py
python tests/test_string_encryption.py
python tests/test_integrated.py
```

### Paper Claims Verification

Verifies claims from the TCHES paper (Section 6).

```bash
# Quick test (~3 min)
python tests/test_paper_claims.py

# Full test - matches paper parameters (~40 min)
python tests/test_paper_claims.py -f

# Different security levels
python tests/test_paper_claims.py -n 128
python tests/test_paper_claims.py -n 512
```

### Verification Results (NVIDIA A100, n=256, Full Mode)

| Test | Result | Paper Claim |
|------|--------|-------------|
| APN IND-CPA | 4950/4950 unique ✅ | 100% unique ciphertexts |
| Numerical Stability | 9/9 passed ✅ | All extreme inputs |
| Ciphertext Distribution | 89.5% normal ✅ | >80% normality |
| Long-Term Stability | drift=0.05% ✅ | No drift (10K cycles) |
| Million Messages | 0 failures ✅ | 0 failures / 10⁶ |
| Max Decryption Error | 2.70×10⁻¹² ✅ | < 10⁻¹⁰ |

---

## 🔧 API Reference

### MeteorKDF (GPU)

```python
class MeteorKDF:
    def __init__(self, n=256, m=None, seed=None)
    def key_gen(self) -> float  # Returns time
    def expand_keys(self, verbose=False) -> float
    def encrypt(self, message: np.ndarray) -> np.ndarray
    def decrypt(self, ciphertext: np.ndarray) -> np.ndarray
    def export_seed(self) -> bytes  # 32 bytes
    def cleanup(self)
```

### MeteorPractical (String/File)

```python
class MeteorPractical:
    def __init__(self, n=256, seed=None)
    def key_gen(self)
    def expand_keys(self)
    def encrypt_string(self, text: str) -> dict
    def decrypt_string(self, encrypted: dict) -> str
    def encrypt_bytes(self, data: bytes) -> dict
    def decrypt_bytes(self, encrypted: dict) -> bytes
    def export_seed(self) -> bytes
```

### MeteorNode (P2P)

```python
class MeteorNode:
    def __init__(self, name: str, security_level=256, seed=None)
    def get_meteor_id(self) -> bytes  # 32 bytes
    def add_peer(self, name: str, meteor_id: bytes)
    def send(self, peer: str, message: bytes) -> bytes
    def receive(self, encrypted: bytes) -> bytes
    def cleanup(self)
```

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 📖 Citation

```bibtex
@inproceedings{meteor_nc_2025,
  title={Meteor-NC: A High-Performance Post-Quantum Cryptosystem 
         from Non-Commutative Matrix Groups},
  author={Anonymous},
  booktitle={IACR Transactions on Cryptographic Hardware 
             and Embedded Systems},
  year={2025},
  note={Under review}
}
```

---

<div align="center">

**⚡ Meteor-NC: 700K msg/s. Quantum-Resistant. 32-byte Keys.**

</div>
