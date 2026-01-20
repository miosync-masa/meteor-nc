# meteor_nc/block/__init__.py
"""
Meteor-NC Block: Blockchain Integration Layer v0.3

Post-quantum cryptography for blockchain applications.
Provides MEV protection, encrypted P2P communication, and on-chain key registry.

Submodules:
    wire/       - Wire formats (SecureEnvelope v0.3)
    suites/     - Cryptographic suite definitions (LWE-256/512/1024)
    transport/  - Off-chain communication
                  - SecureChannel: P2P encrypted channel
                  - WalletChannel: Ethereum wallet-to-wallet messaging
                  - SecureRPCClient: Encrypted RPC for MEV protection
    registry/   - On-chain PK registry
                  - PKStore: Store/retrieve keys from PKRegistry.sol
                  - KeyResolver: Resolve address → pk_blob
    mempool/    - MEV protection
                  - TxEncryptor: Encrypt transactions for builder
                  - CommitReveal: Two-phase commit-reveal scheme
    adapters/   - Wallet integration
                  - WalletAdapter: Abstract base for wallet adapters
                  - MetaMaskAdapter: MetaMask Snap integration
                  - WalletConnectAdapter: WalletConnect v2 protocol

Quick Start:
    # 1. P2P Encrypted Channel
    from meteor_nc.block import SecureChannel
    
    alice = SecureChannel.create(chain_id=1)
    bob = SecureChannel.create(chain_id=1)
    
    handshake = alice.connect(bob.pk_blob)
    response = bob.accept(handshake)
    alice.finalize(response)
    
    env = alice.send(b"Hello Bob!")
    data = bob.receive(env)  # b"Hello Bob!"
    
    # 2. Wallet-to-Wallet Messaging
    from meteor_nc.block import WalletChannel, WalletMessage
    
    wallet = WalletChannel.create(address="0x...", chain_id=1)
    session, handshake = wallet.initiate_handshake(peer_addr, peer_pk_blob)
    # ... complete handshake ...
    env = session.send_message("Hello!")
    
    # 3. MEV-Protected Transactions
    from meteor_nc.block import TxEncryptor
    
    encryptor = TxEncryptor(builder_pk_bytes=pk, chain_id=1)
    encrypted = encryptor.encrypt(raw_tx)
    # Send encrypted.wire to private relay
    
    # 4. Secure RPC
    from meteor_nc.block import SecureRPCClient
    
    client = SecureRPCClient(
        endpoint="https://private-relay.example.com",
        builder_pk_bytes=builder_pk,
        chain_id=1,
    )
    tx_hash = await client.send_private_transaction(signed_tx)

Test Results (88/88 pass):
    - wire/envelope: 12/12
    - transport/channel: 5/5
    - transport/wallet: 7/7
    - transport/rpc: 7/7
    - registry/pk_store: 8/8
    - registry/resolver: 7/7
    - mempool/encrypt: 7/7
    - mempool/shield: 9/9
    - adapters/base: 8/8
    - adapters/metamask: 9/9
    - adapters/walletconnect: 9/9

See ARCHITECTURE.md for design details.

Updated: 2025-01-20
Version: 0.3.0
"""

# =============================================================================
# Suites Module - Cryptographic parameters
# =============================================================================
from .suites import (
    # Suite definitions (LWE-256/512/1024)
    SUITES,
    Suite,
    get_suite,
    get_kem_ct_size,
    get_pk_blob_size,
    DEFAULT_SUITE_ID,
    
    # Auth scheme definitions (NONE, ECDSA, EdDSA, Dilithium)
    AUTH_SCHEMES,
    AuthScheme,
    get_auth_scheme,
    get_auth_size,
    DEFAULT_AUTH_SCHEME_ID,
    
    # Session ID generation
    generate_session_id_random,
    generate_session_id_deterministic,
    
    # PK Blob helpers (64B: pk_seed + b_hash)
    PK_BLOB_SIZE,
    create_pk_blob,
    parse_pk_blob,
)

# =============================================================================
# Wire Module - SecureEnvelope v0.3
# =============================================================================
from .wire import (
    # Main envelope class
    SecureEnvelope,
    EnvelopeType,
    EnvelopeFlags,
    
    # Protocol constants
    PROTOCOL_VERSION,
    DOMAIN_SEPARATOR,
    
    # AAD/Auth computation
    compute_aad,
    compute_auth_message,
    compute_aad_from_envelope,
)

# =============================================================================
# Transport Module - Off-chain communication
# =============================================================================
from .transport import (
    # SecureChannel: P2P encrypted channel
    SecureChannel,
    ChannelState,
    ChannelError,
    HandshakeError,
    DecryptionError,
    
    # WalletChannel: Ethereum wallet messaging
    WalletChannel,
    WalletSession,
    WalletMessage,
    MessageType,
    WalletError,
    AddressError,
    
    # SecureRPCClient: Encrypted RPC
    SecureRPCClient,
    SecureRPCHandler,
    RPCRequest,
    RPCResponse,
    RPCError,
)

# =============================================================================
# Registry Module - On-chain key management
# =============================================================================
from .registry import (
    # PKStore: Interact with PKRegistry.sol
    PKStore,
    KeyType,
    MeteorKeyInfo,
    RegistryError,
    KeyNotFoundError,
    
    # KeyResolver: Address → pk_blob resolution
    KeyResolver,
    ResolverError,
)

# =============================================================================
# Mempool Module - MEV protection
# =============================================================================
from .mempool import (
    # Transaction encryption
    TxEncryptor,
    TxDecryptor,
    EncryptedTx,
    
    # Commit-Reveal scheme
    CommitReveal,
    ShieldedTx,
    CommitPhase,
)

# =============================================================================
# Adapters Module - Wallet integration
# =============================================================================
from .adapters import (
    # Base adapter
    WalletAdapter,
    MockWalletAdapter,
    WalletState,
    WalletCapability,
    WalletInfo,
    WalletEvent,
    SignResult,
    EIP712Domain,
    WalletAdapterError,
    
    # MetaMask
    MetaMaskAdapter,
    
    # WalletConnect
    WalletConnectAdapter,
)

# =============================================================================
# Adapters Module - Wallet integration
# =============================================================================
from .adapters import (
    # Abstract adapter
    WalletAdapter,
    MockWalletAdapter,
    
    # MetaMask
    MetaMaskAdapter,
    
    # WalletConnect
    WalletConnectAdapter,
    
    # Types
    WalletState,
    WalletCapability,
    WalletInfo,
    MeteorIdentity,
    SignResult,
    EIP712Domain,
    WalletAdapterError,
)

# =============================================================================
# Public API
# =============================================================================
__all__ = [
    # === Wire ===
    "SecureEnvelope",
    "EnvelopeType",
    "EnvelopeFlags",
    "PROTOCOL_VERSION",
    "DOMAIN_SEPARATOR",
    "compute_aad",
    "compute_auth_message",
    "compute_aad_from_envelope",
    
    # === Suites ===
    "SUITES",
    "Suite",
    "get_suite",
    "get_kem_ct_size",
    "get_pk_blob_size",
    "DEFAULT_SUITE_ID",
    "AUTH_SCHEMES",
    "AuthScheme",
    "get_auth_scheme",
    "get_auth_size",
    "DEFAULT_AUTH_SCHEME_ID",
    "generate_session_id_random",
    "generate_session_id_deterministic",
    "PK_BLOB_SIZE",
    "create_pk_blob",
    "parse_pk_blob",
    
    # === Transport: Channel ===
    "SecureChannel",
    "ChannelState",
    "ChannelError",
    "HandshakeError",
    "DecryptionError",
    
    # === Transport: Wallet ===
    "WalletChannel",
    "WalletSession",
    "WalletMessage",
    "MessageType",
    "WalletError",
    "AddressError",
    
    # === Transport: RPC ===
    "SecureRPCClient",
    "SecureRPCHandler",
    "RPCRequest",
    "RPCResponse",
    "RPCError",
    
    # === Registry ===
    "PKStore",
    "KeyType",
    "MeteorKeyInfo",
    "KeyResolver",
    "RegistryError",
    "KeyNotFoundError",
    "ResolverError",
    
    # === Mempool ===
    "TxEncryptor",
    "TxDecryptor",
    "EncryptedTx",
    "CommitReveal",
    "ShieldedTx",
    "CommitPhase",
    
    # === Adapters ===
    "WalletAdapter",
    "MockWalletAdapter",
    "MetaMaskAdapter",
    "WalletConnectAdapter",
    "WalletState",
    "WalletCapability",
    "WalletInfo",
    "MeteorIdentity",
    "SignResult",
    "EIP712Domain",
    "WalletAdapterError",
]

__version__ = "0.3.0"
