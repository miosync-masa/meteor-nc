# Meteor-NC Block: Post-Quantum Blockchain Integration

**Version**: 0.3.0  
**Status**: Production Ready ✅ (93/93 tests passing)

---

## Overview

The `block/` module provides post-quantum cryptographic primitives for EVM-compatible blockchains. Built on top of Meteor-NC's LWE-based KEM, it enables:

- **Encrypted P2P Communication**: Wallet-to-wallet messaging with forward secrecy
- **MEV Protection**: Transaction encryption and commit-reveal schemes
- **On-Chain Key Registry**: Decentralized public key management via smart contracts
- **Wallet Integration**: MetaMask Snap and WalletConnect v2 support

---

## Key Design Principles

### 1. Signatures Are Not Replaced

Meteor-NC excels at **encryption and key distribution**, but **transaction authorization still requires signatures**.

| Layer | Role | Technology |
|-------|------|------------|
| **Signature (Authorization)** | Proof of sender's authority | ECDSA/EdDSA → Future: Dilithium |
| **Encryption (Confidentiality)** | Communication & data protection | **Meteor-NC KEM** |

> **Conclusion**: Meteor-NC enhances the blockchain experience through confidentiality, bandwidth efficiency, and batch processing—not by replacing signatures.

### 2. Registry Trust Model

The `PKRegistry.sol` contract implements a complete trust model:

- ✅ **Key Rotation & Revocation**: Update, rotate, and revoke keys
- ✅ **Multiple Key Types**: Separate encryption and signing keys via `KeyType` enum
- ✅ **Version Control**: Suite ID, expiration, and Key-ID for backward compatibility
- ✅ **Authentication**: Registration requires `msg.sender` signature

### 3. Domain Separation & Replay Protection

The `SecureEnvelope` includes comprehensive security fields:

| Field | Purpose |
|-------|---------|
| `chain_id` | Prevents cross-chain replay |
| `sender_id` | Sender's Key-ID (registry reference) |
| `recipient_id` | Recipient's Key-ID |
| `nonce` | DEM nonce |
| `sequence` | Replay protection |
| `sender_auth` | Mutual authentication (optional) |

**AAD Construction**:
```
aad = H(domain || chain_id || header || kem_wire)
```

### 4. Transport Authentication Options

KEM alone provides:
- ✅ Encryption to a known public key
- ❌ Proof of sender identity

**Use Case Guidance**:
- **Confidentiality only**: KEM + AEAD is sufficient
- **Mutual authentication**: Add signature in handshake (EIP-712 supported)

### 5. MEV Protection Architecture

Mempool encryption requires a designated decryptor:

- Encrypted transactions are sent to **builders/sequencers/relays**
- Works best with **L2/Rollups** and **private relays**
- Commit-reveal scheme provides additional protection

### 6. Target Chain

**EVM-compatible chains** (Solidity) are the primary target.

---

## Architecture

```
meteor_nc/
├── cryptography/          # Existing crypto primitives
├── auth/                  # Existing authentication
├── protocols/             # Existing P2P protocols
│
└── block/                 # 🆕 Blockchain Integration
    │
    ├── wire/              # 📦 Wire Format
    │   ├── envelope.py    # SecureEnvelope v0.3
    │   └── __init__.py
    │
    ├── suites.py          # 🔧 Cryptographic Suites
    │
    ├── transport/         # 📡 Off-Chain Communication
    │   ├── channel.py     # SecureChannel (encrypted P2P)
    │   ├── wallet.py      # WalletChannel (wallet-to-wallet)
    │   └── rpc.py         # SecureRPCClient (MEV protection)
    │
    ├── registry/          # 🔑 On-Chain Registry
    │   ├── pk_store.py    # PKStore (Web3 interface)
    │   ├── resolver.py    # KeyResolver (caching, batching)
    │   └── contracts/     # Solidity Contracts
    │       ├── PKRegistry.sol
    │       └── abi/PKRegistry.json
    │
    ├── mempool/           # 🔒 MEV Protection
    │   ├── encrypt.py     # TxEncryptor/TxDecryptor
    │   └── shield.py      # CommitReveal scheme
    │
    ├── adapters/          # 💼 Wallet Integration
    │   ├── base.py        # WalletAdapter (abstract)
    │   ├── metamask.py    # MetaMaskAdapter (Snap)
    │   └── walletconnect.py # WalletConnectAdapter (v2)
    │
    └── tests/
        └── test_integration.py  # E2E tests
```

---

## Dependency Graph

```
              ┌──────────────────────┐
              │   block/adapters/    │  ← Wallet Integration
              │   (MetaMask, WC)     │
              └──────────┬───────────┘
                         │
              ┌──────────▼───────────┐
              │   block/transport/   │  ← Off-Chain Communication
              │   (channel, wallet)  │
              └──────────┬───────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
┌────────────────┐ ┌───────────┐ ┌────────────────┐
│ block/wire/    │ │ block/    │ │ block/mempool/ │
│ (envelope)     │ │ registry/ │ │ (MEV shield)   │
└────────┬───────┘ └─────┬─────┘ └────────┬───────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
              ┌──────────▼───────────┐
              │   protocols/web4.py  │  ← Existing P2P
              │   (libp2p/DHT/IPFS)  │
              └──────────┬───────────┘
                         │
              ┌──────────▼───────────┐
              │  cryptography/       │  ← Existing Crypto
              │  (LWEKEM, StreamDEM) │
              └──────────────────────┘
```

---

## Wire Format

### SecureEnvelope v0.3

```
┌─────────────────────────────────────────────────────────────────────┐
│ Header (90B fixed)                                                   │
├─────────────────────────────────────────────────────────────────────┤
│  version (1B)     │  type (1B)       │  flags (2B)                  │
│  suite_id (1B)    │  auth_scheme (1B)│  chain_id (4B)               │
│  sender_id (32B)                     │  recipient_id (32B)          │
│  session_id (8B)                     │  sequence (8B)               │
├─────────────────────────────────────────────────────────────────────┤
│  [pk_blob: 64B]      ← optional (flags.INCLUDE_PK_BLOB)             │
│  kem_ct (variable)   ← determined by suite_id                       │
│  tag (16B)           ← AEAD authentication tag                      │
│  payload (NB)        ← encrypted data                               │
│  [sender_auth: var]  ← optional, determined by auth_scheme          │
└─────────────────────────────────────────────────────────────────────┘
```

### Cryptographic Suites

| Suite ID | Name | Security Level | n | kem_ct Size |
|----------|------|----------------|---|-------------|
| 0x01 | meteor-nc-level1 | NIST Level 1 (128-bit) | 256 | 518B |
| 0x02 | meteor-nc-level3 | NIST Level 3 (192-bit) | 512 | 1094B |
| 0x03 | meteor-nc-level5 | NIST Level 5 (256-bit) | 1024 | 2310B |

### Authentication Schemes

| Auth ID | Name | Size | Description |
|---------|------|------|-------------|
| 0x00 | none | 0B | No sender authentication |
| 0x01 | ed25519 | 64B | Ed25519 signature |
| 0x02 | secp256k1 | 65B | secp256k1 ECDSA (r‖s‖v) |
| 0x03 | eip712 | 65B | EIP-712 typed data signature |

### PK Blob Format (64B)

```
pk_blob = pk_seed (32B) || b_hash (32B)
```

- `pk_seed`: Matrix A reconstruction seed
- `b_hash`: SHA-256 hash of public key vector b

### Envelope Types

| Value | Name | Description |
|-------|------|-------------|
| 0x00 | HANDSHAKE | Initial key exchange |
| 0x01 | DATA | Regular data message |
| 0x02 | ACK | Acknowledgment |
| 0x03 | CLOSE | Channel close |
| 0x10 | TX_ENCRYPTED | Encrypted transaction (MEV) |
| 0x11 | TX_COMMIT | Commit phase |
| 0x12 | TX_REVEAL | Reveal phase |
| 0x20 | STREAM_START | Stream start |
| 0x21 | STREAM_DATA | Stream data chunk |
| 0x22 | STREAM_END | Stream end |
| 0xF0 | ERROR | Error message |
| 0xF1 | PING | Keep-alive ping |
| 0xF2 | PONG | Keep-alive pong |

### Wire Sizes

| Configuration | Header | pk_blob | kem_ct (L1) | tag | auth | Total + payload |
|---------------|--------|---------|-------------|-----|------|-----------------|
| DATA (minimal) | 90B | - | 518B | 16B | - | 624B + N |
| HANDSHAKE | 90B | 64B | 518B | 16B | - | 688B + N |
| DATA + Ed25519 | 90B | - | 518B | 16B | 64B | 688B + N |
| HANDSHAKE + secp256k1 | 90B | 64B | 518B | 16B | 65B | 753B + N |
| HANDSHAKE (L5) | 90B | 64B | 2310B | 16B | - | 2480B + N |

---

## Quick Start

### 1. P2P Encrypted Channel

```python
from meteor_nc.block import SecureChannel

# Create channels
alice = SecureChannel.create(chain_id=1)
bob = SecureChannel.create(chain_id=1)

# Handshake
handshake = alice.connect(bob.pk_blob)
response = bob.accept(handshake)
alice.finalize(response)

# Exchange messages
env = alice.send(b"Hello Bob!")
data = bob.receive(env)  # b"Hello Bob!"
```

### 2. Wallet-to-Wallet Messaging

```python
from meteor_nc.block import WalletChannel

# Create wallet channels
wallet = WalletChannel.create(address="0x...", chain_id=1)
session, handshake = wallet.initiate_handshake(peer_addr, peer_pk_blob)

# After handshake completion...
env = session.send_message("Hello!")
```

### 3. MEV-Protected Transactions

```python
from meteor_nc.block import TxEncryptor

# Encrypt transaction for builder
encryptor = TxEncryptor(builder_pk_bytes=pk_bytes, chain_id=1)
encrypted = encryptor.encrypt(raw_tx)
# Send encrypted.wire to private relay
```

### 4. MetaMask Integration

```python
from meteor_nc.block import MetaMaskAdapter

adapter = MetaMaskAdapter()
await adapter.connect()

# Generate Meteor identity
pk_blob = await adapter.get_meteor_pk_blob()

# Initiate encrypted session
session, handshake = await adapter.initiate_session(peer_addr, peer_pk_blob)
```

---

## Module Reference

### wire/

| Class | Description |
|-------|-------------|
| `SecureEnvelope` | Wire format with encryption, authentication, replay protection |
| `EnvelopeType` | Message type enumeration |
| `EnvelopeFlags` | Feature flags (pk_blob, compression, auth) |
| `compute_aad` | AAD computation for AEAD |
| `compute_commit` | Commit hash for commit-reveal |

### transport/

| Class | Description |
|-------|-------------|
| `SecureChannel` | Encrypted P2P channel with state machine |
| `WalletChannel` | Ethereum address-based messaging |
| `WalletSession` | Active wallet communication session |
| `SecureRPCClient` | Encrypted RPC for private transactions |
| `SecureRPCHandler` | Server-side decryption handler |

### registry/

| Class | Description |
|-------|-------------|
| `PKStore` | Web3 interface to PKRegistry.sol |
| `KeyResolver` | High-level resolver with caching |
| `KeyType` | Key type enumeration (ENCRYPTION, SIGNING) |
| `MeteorKeyInfo` | Key metadata container |

### mempool/

| Class | Description |
|-------|-------------|
| `TxEncryptor` | Transaction encryption for builders |
| `TxDecryptor` | Transaction decryption (builder-side) |
| `CommitReveal` | Two-phase commit-reveal manager |
| `ShieldedTx` | Shielded transaction container |

### adapters/

| Class | Description |
|-------|-------------|
| `WalletAdapter` | Abstract wallet adapter interface |
| `MockWalletAdapter` | Testing adapter |
| `MetaMaskAdapter` | MetaMask Snap integration |
| `WalletConnectAdapter` | WalletConnect v2 protocol |
| `WalletState` | Connection state enumeration |
| `WalletCapability` | Capability flags |

---

## Test Results

### Unit Tests (88/88 ✅)

| Module | Tests | Status |
|--------|-------|--------|
| wire/envelope | 12/12 | ✅ |
| transport/channel | 5/5 | ✅ |
| transport/wallet | 7/7 | ✅ |
| transport/rpc | 7/7 | ✅ |
| registry/pk_store | 8/8 | ✅ |
| registry/resolver | 7/7 | ✅ |
| mempool/encrypt | 7/7 | ✅ |
| mempool/shield | 9/9 | ✅ |
| adapters/base | 8/8 | ✅ |
| adapters/metamask | 9/9 | ✅ |
| adapters/walletconnect | 9/9 | ✅ |

### Integration Tests (5/5 ✅)

| Test | Description |
|------|-------------|
| Wallet-to-Wallet Messaging | MetaMask ↔ WalletConnect |
| Registry-Based Key Discovery | PKStore → KeyResolver → Communication |
| MEV-Protected Transaction | TxEncryptor → SecureRPCClient → Builder |
| Commit-Reveal Flow | Create → Commit → Reveal → Verify |
| Multi-Party Communication | 3-party mesh network |

---

## Existing Module Integration

| Existing Module | Usage in Block |
|-----------------|----------------|
| `cryptography/core.py` → LWEKEM | Core KEM primitive |
| `cryptography/stream.py` → StreamDEM | AEAD encryption |
| `cryptography/compression.py` | 518B ciphertext compression |
| `cryptography/practical.py` → MeteorPractical | Channel foundation |
| `protocols/web4.py` → MeteorWeb4Node | P2P networking |

---

## Security Considerations

1. **Forward Secrecy**: Each session uses ephemeral keys
2. **Replay Protection**: Sequence numbers and session IDs
3. **Domain Separation**: Chain ID in AAD prevents cross-chain attacks
4. **Key Expiration**: On-chain registry enforces key validity
5. **Mutual Authentication**: Optional EIP-712 signatures

---

## Future Work

- [ ] `mempool/contracts/CommitReveal.sol` - On-chain commit-reveal
- [ ] Dilithium signature integration
- [ ] Multi-chain registry synchronization
- [ ] Hardware wallet support (Ledger, Trezor)

---

## Links

- [Meteor-NC Repository](https://github.com/miosync-masa/meteor-nc)
- [TCHES 2026 Submission](https://anonymous.4open.science/r/meteor-nc-F73C/)

---

## License

MIT License - See repository for details.
