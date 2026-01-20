# meteor_nc/block/__init__.py
"""
Meteor-NC Block: Blockchain Integration Layer v0.3

Post-quantum cryptography for blockchain applications.
Supports multiple security levels, auth schemes, and session management.

Submodules:
    suites/     - Cryptographic suite definitions
    wire/       - Wire formats (SecureEnvelope v0.3)
    transport/  - Off-chain communication (SecureChannel)
    registry/   - On-chain PK registry (PKStore, KeyResolver)
    mempool/    - MEV protection (TODO)
    adapters/   - Wallet integration (TODO)

Usage:
    from meteor_nc.block import SecureEnvelope, EnvelopeType
    from meteor_nc.block import SUITES, AUTH_SCHEMES, generate_session_id_random
    
    # Create envelope
    session_id = generate_session_id_random()
    env = SecureEnvelope.create_data(
        chain_id=1,
        sender_id=my_key_id,
        recipient_id=peer_key_id,
        session_id=session_id,
        sequence=42,
        kem_ct=kem_ct,
        tag=tag,
        payload=encrypted_data,
        suite_id=0x01,  # Level 1
    )
    wire = env.to_bytes()
    
    # Use SecureChannel for P2P communication
    from meteor_nc.block.transport import SecureChannel
    alice = SecureChannel.create(chain_id=1)
    
    # Use registry for key management
    from meteor_nc.block.registry import PKStore, KeyResolver, KeyType

See ARCHITECTURE.md for design details.
"""

# Import from suites module
from .suites import (
    # Suite definitions
    SUITES,
    Suite,
    get_suite,
    get_kem_ct_size,
    get_pk_blob_size,
    DEFAULT_SUITE_ID,
    
    # Auth scheme definitions
    AUTH_SCHEMES,
    AuthScheme,
    get_auth_scheme,
    get_auth_size,
    DEFAULT_AUTH_SCHEME_ID,
    
    # Session ID generation
    generate_session_id_random,
    generate_session_id_deterministic,
    
    # PK Blob helpers
    PK_BLOB_SIZE,
    create_pk_blob,
    parse_pk_blob,
)

# Import from wire module
from .wire import (
    SecureEnvelope,
    EnvelopeType,
    EnvelopeFlags,
    PROTOCOL_VERSION,
    DOMAIN_SEPARATOR,
    compute_aad,
    compute_auth_message,
)

# Import from transport module
from .transport import (
    SecureChannel,
    ChannelState,
    ChannelError,
    HandshakeError,
    DecryptionError,
)

# Import from registry module
from .registry import (
    PKStore,
    KeyType,
    MeteorKeyInfo,
    KeyResolver,
    RegistryError,
    KeyNotFoundError,
)

# Import from mempool module
from .mempool import (
    TxEncryptor,
    TxDecryptor,
    EncryptedTx,
    CommitReveal,
    ShieldedTx,
    CommitPhase,
)

__all__ = [
    # Main class
    "SecureEnvelope",
    "EnvelopeType",
    "EnvelopeFlags",
    
    # Protocol
    "PROTOCOL_VERSION",
    "DOMAIN_SEPARATOR",
    
    # Suite/Auth
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
    
    # Session ID
    "generate_session_id_random",
    "generate_session_id_deterministic",
    
    # PK Blob
    "PK_BLOB_SIZE",
    "create_pk_blob",
    "parse_pk_blob",
    
    # Helpers
    "compute_aad",
    "compute_auth_message",
    
    # Transport
    "SecureChannel",
    "ChannelState",
    "ChannelError",
    "HandshakeError",
    "DecryptionError",
    
    # Registry
    "PKStore",
    "KeyType",
    "MeteorKeyInfo",
    "KeyResolver",
    "RegistryError",
    "KeyNotFoundError",
    
    # Mempool (MEV Protection)
    "TxEncryptor",
    "TxDecryptor",
    "EncryptedTx",
    "CommitReveal",
    "ShieldedTx",
    "CommitPhase",
]

__version__ = "0.3.0"
