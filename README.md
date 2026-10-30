# Meteor-NC: Post-Quantum KEM with a GPU Batch Backend

**FrodoKEM in Python, verified against the official KATs, batched on CUDA at over a million encapsulations per second**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18309744.svg)](https://doi.org/10.5281/zenodo.18309744)

> [!CAUTION]
> **Meteor-NC v2.x was broken; do not use it.** Its KEM hid all message bits
> under one shared mask (a passive attacker recovered the shared secret from
> the public key and one ciphertext), its parameters were far below their
> claimed levels, and the protocol and auth layers had independent breaks.
> v3 replaces all of them. Details in [SECURITY.md](SECURITY.md).

## Overview

Meteor-NC is a research implementation of a post-quantum key encapsulation
mechanism and the layers around it (hybrid encryption, P2P messaging,
device-bound authentication). It introduces **no new cryptographic
assumptions or parameters**: the KEM is FrodoKEM, and every other primitive
is a standard one.

| Component | Primitive | Reference |
|---|---|---|
| KEM | FrodoKEM-640/976/1344-SHAKE (plain LWE) | FrodoKEM specification |
| Shared secret | SHAKE256(domain ‖ FrodoKEM shared secret) | FIPS 202 |
| Message encryption | ChaCha20-Poly1305 | RFC 8439 |
| Signatures (protocols) | Ed25519 + ML-DSA-65, both must verify | RFC 8032, FIPS 204 |

What this project adds is engineering: a NumPy implementation that is
byte-identical to the FrodoKEM reference, and a CUDA batch backend whose
outputs are byte-identical too.

## Features

- **Verified KEM**: all 300 official NIST KAT vectors (100 per level) match
  byte for byte, on CPU and on GPU.
- **GPU batch**: SHAKE, noise sampling and packing in CUDA kernels; the LWE
  products on tensor cores, split so the float arithmetic is exact.
- **Protocols**: self-certifying identities (MeteorID = hash of the public
  keys), signed and encrypted envelopes, replay protection, TCP transport.
- **Auth**: user seed + per-device secret, challenge-response login.

## Performance

**Single operations** (CPU, NumPy, one thread, cloud VM):

| Level (`n=`) | Core | Public key | Ciphertext | keygen / encaps / decaps |
|---|---|---|---|---|
| L1 (`256`) | FrodoKEM-640-SHAKE | 9,628 B | 9,764 B | 8.5 / 7.6 / 7.2 ms |
| L3 (`512`) | FrodoKEM-976-SHAKE | 15,644 B | 15,804 B | 14.9 / 12.3 / 9.8 ms |
| L5 (`1024`) | FrodoKEM-1344-SHAKE | 21,532 B | 21,708 B | 28.3 / 19.7 / 25.8 ms |

Sizes include a 12-byte Meteor header. Shared secrets are 32 bytes.

**Batch on GPU** (A100-SXM4-80GB on Colab, batch 100,000, operations per second):

| Level | encaps (GPU-resident) | decaps (GPU-resident) | encaps (to host, with K) | decaps (to host, with K) |
|---|---|---|---|---|
| L1 FrodoKEM-640 | **1,244,275** | 947,686 | 197,161 | 193,103 |
| L3 FrodoKEM-976 | 719,645 | 534,176 | 119,816 | 109,634 |
| L5 FrodoKEM-1344 | 518,477 | 386,120 | 87,535 | 69,293 |

"GPU-resident" leaves shared secrets and ciphertexts on the GPU. "To host"
also derives K and copies the 10–22 KB ciphertexts to and from host memory,
which is the current limit there. On CPU the batch backend does about
1,800 / 1,600 L1 encaps / decaps per second.

Reproduce (checks KATs and CPU equality first, aborts on any mismatch):

```bash
git clone --depth 1 https://github.com/microsoft/PQCrypto-LWEKE /content/LWEKE
python benchmarks/bench_v3_gpu.py --kat /content/LWEKE/FrodoKEM/KAT
python benchmarks/bench_v3_gpu.py --skip-checks --profile 50000   # per-stage breakdown
```

## Quick Start

```bash
pip install numpy scipy "cryptography>=49"
pip install cupy-cuda12x      # optional, for the GPU batch backend (match your CUDA)
```

### KEM

```python
from meteor_nc.cryptography.core import LWEKEM

alice = LWEKEM(n=256)               # 256 -> FrodoKEM-640 (L1); 512 -> 976; 1024 -> 1344
pk, sk = alice.key_gen()

bob = LWEKEM(n=256)
bob.load_public_key(pk)
K1, ct = bob.encaps()               # 32-byte key, ciphertext bytes

assert alice.decaps(ct) == K1
```

### Batch (GPU if available, else CPU)

```python
from meteor_nc.cryptography.batch import BatchLWEKEM

kem = BatchLWEKEM(n=256)
pk, sk = kem.key_gen()
K, wires = kem.encaps_batch(100_000)            # (B, 32) and (B, wire_len) uint8
assert (kem.decaps_batch(wires) == K).all()     # wires also open with LWEKEM.decaps
```

### Deterministic keys from a seed

```python
import secrets
from meteor_nc.cryptography.core import LWEKEM

seed = secrets.token_bytes(32)
assert LWEKEM(n=256, seed=seed).key_gen() == LWEKEM(n=256, seed=seed).key_gen()
```

Whoever has the seed has the secret key. Use `seed=None` (default) unless
you need to restore keys.

### Hybrid encryption

```python
from meteor_nc.cryptography.core import HybridKEM

recv = HybridKEM(security_level=128)
pk, sk = recv.key_gen()
send = HybridKEM(security_level=128)
send.load_public_key(pk)
ct = send.encrypt(b"hello", aad=b"header")
assert recv.decrypt(ct, aad=b"header") == b"hello"
```

### P2P messages

```python
from meteor_nc.protocols.meteor_protocol import MeteorNode

alice, bob = MeteorNode("Alice"), MeteorNode("Bob")
alice.add_peer("Bob", bob.get_meteor_id(), bob.get_public_key())     # rejected if they don't match
bob.add_peer("Alice", alice.get_meteor_id(), alice.get_public_key())

msg = alice.send("Bob", b"Hello Bob!")       # encrypted, signed (Ed25519 + ML-DSA-65)
assert bob.receive(msg) == b"Hello Bob!"     # unknown senders, tampering, replays: ValueError
```

Over TCP between processes, with signed address records:

```python
node = MeteorWeb4Node("Alice", local_delivery=False)    # from meteor_nc.protocols.web4
await node.start_tcp("0.0.0.0", 9000)
record = node.get_address_record()                       # give this to peers
node.add_peer_from_record("Bob", bob_record)             # verified before use
await node.send_text("Bob", "hi")
```

### Device-bound login

```python
from meteor_nc.auth import MeteorAuth, MeteorAuthServer, answer_challenge

auth = MeteorAuth()                    # device secret in ~/.meteor_nc/device_key (0600)
user_seed = auth.generate_seed()       # knowledge factor: keep it safe
node = auth.login(user_seed)           # same seed + same device -> same MeteorID

server = MeteorAuthServer()
node.add_peer("Server", server.get_server_id(), server.get_server_public_key())
token = server.register(node.get_meteor_id(), node.get_public_key())
challenge = server.create_challenge(token)
assert server.authenticate(token, answer_challenge(node, "Server", challenge))
```

Biometric checks (`require_biometric=True`) are an application-level gate in
pure Python; they become a real factor only with a hardware keystore behind
`DeviceKeyStore` (see the class docstring).

## Construction

**KEM**: FrodoKEM as specified (Gen with SHAKE128, error sampling by CDF
table, packing, FO transform with implicit rejection and salt). The Meteor
layer wraps it with a 12-byte header (`version, level, n`) and derives
`K = SHAKE256("meteor-nc-v3-K" ‖ ss)`.

**GPU batch**: products have one small factor (|x| ≤ 12) and one factor
below 2¹⁶. Splitting the latter into bytes keeps every partial sum below
2²⁴, so float16 inputs with float32 accumulation (tensor cores) or float32
GEMM are exact. A self-test at start-up falls back to another mode if the
device does not compute them exactly.

**Envelopes** (`protocols/envelope.py`): header (type, sender, recipient,
time, random id, hash of the KEM ciphertext, metadata) as AEAD associated
data, ChaCha20-Poly1305 under a fresh KEM key, and a hybrid signature over
header and ciphertext. Receivers check the sender's MeteorID against their
bundle, verify the signature, reject stale or repeated ids, then decrypt.

## Module Structure

```
meteor_nc/
├── cryptography/
│   ├── frodo.py          # FrodoKEM-SHAKE (single), KAT-exact
│   ├── frodo_batch.py    # batched FrodoKEM for NumPy / CuPy
│   ├── core.py           # LWEKEM, HybridKEM
│   ├── batch.py          # BatchLWEKEM, BatchHybridKEM
│   ├── stream.py         # StreamDEM (chunked AEAD)
│   └── kernels/          # CUDA: shake_kernel.py, pack_kernel.py
├── protocols/
│   ├── envelope.py       # identities, signed envelopes, replay guard
│   ├── meteor_protocol.py# MeteorNode
│   ├── transport.py      # TCP transport, signed address records
│   ├── web4.py           # MeteorWeb4Node (TCP, PubSub, IPFS, optional libp2p)
│   └── advanced.py       # network simulators
├── auth/                 # MeteorAuth, MeteorAuthServer, DeviceKeyStore
└── block/                # wallet / mempool / registry integration
benchmarks/bench_v3_gpu.py
tests/
```

## Testing

```bash
git clone --depth 1 https://github.com/microsoft/PQCrypto-LWEKE /tmp/LWEKE
FRODO_KAT_DIR=/tmp/LWEKE/FrodoKEM/KAT METEOR_SC_SAMPLES=600 \
  python -m pytest -q -o asyncio_mode=auto tests meteor_nc/block/tests
```

Without a GPU, GPU-only tests are skipped. The CUDA kernels' C source is
still compiled with the host compiler and checked against hashlib and the
reference implementation. With a GPU all tests run (186 on an A100).

## Limitations

- Research implementation in Python: no constant-time guarantees.
- libp2p transport is not wired up (py-libp2p is trio-based); TCP is.
- `block/` has not yet been reviewed for v3.

## License

MIT License. See [LICENSE](License).

## References

1. E. Alkim et al. *FrodoKEM: Learning With Errors Key Encapsulation.* [frodokem.org](https://frodokem.org/); reference code and KATs: [microsoft/PQCrypto-LWEKE](https://github.com/microsoft/PQCrypto-LWEKE)
2. O. Regev. "On lattices, learning with errors, random linear codes, and cryptography." STOC 2005.
3. D. Hofheinz, K. Hövelmanns, E. Kiltz. "A Modular Analysis of the Fujisaki-Okamoto Transformation." TCC 2017. [ePrint 2017/604](https://eprint.iacr.org/2017/604)
4. NIST. FIPS 202 (SHA-3/SHAKE), FIPS 204 (ML-DSA).
5. Y. Nir, A. Langley. ChaCha20 and Poly1305 for IETF Protocols. [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
