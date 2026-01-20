# meteor_nc/block/wire/__init__.py
"""
Meteor-NC Block Wire Format v0.3

Compact wire formats for blockchain-integrated post-quantum messaging.
Supports multiple suites (Level 1/3/5), auth schemes, and session management.

Modules:
    envelope: SecureEnvelope for P2P and blockchain communication

Usage:
    from meteor_nc.block.wire import SecureEnvelope, EnvelopeType, EnvelopeFlags
    from meteor_nc.block.suites import SUITES, AUTH_SCHEMES, generate_session_id_random
    
    # Create handshake (with pk_blob)
    session_id = generate_session_id_random()
    env = SecureEnvelope.create_handshake(
        chain_id=1,
        sender_id=my_key_id,
        recipient_id=peer_key_id,
        session_id=session_id,
        pk_blob=my_pk_seed + my_b_hash,  # 64B
        kem_ct=kem_ct,
        tag=tag,
        payload=encrypted_data,
        suite_id=0x01,  # Level 1
    )
    
    # Create data message
    env = SecureEnvelope.create_data(
        chain_id=1,
        sender_id=my_key_id,
        recipient_id=peer_key_id,
        session_id=session_id,
        sequence=42,
        kem_ct=kem_ct,
        tag=tag,
        payload=encrypted_data,
    )
    
    # Serialize / Deserialize
    wire = env.to_bytes()
    env = SecureEnvelope.from_bytes(wire)
"""

from .envelope import (
    # Main class
    SecureEnvelope,
    
    # Enums
    EnvelopeType,
    EnvelopeFlags,
    
    # Constants
    PROTOCOL_VERSION,
    DOMAIN_SEPARATOR,
    HEADER_SIZE,
    TAG_SIZE,
    KEY_ID_SIZE,
    SESSION_ID_SIZE,
    
    # Helpers
    compute_aad,
    compute_auth_message,
    compute_commit,
    compute_aad_from_envelope,
)

# Re-export from suites for convenience
from ..suites import (
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

__all__ = [
    # Main class
    "SecureEnvelope",
    
    # Enums
    "EnvelopeType",
    "EnvelopeFlags",
    
    # Constants
    "PROTOCOL_VERSION",
    "DOMAIN_SEPARATOR",
    "HEADER_SIZE",
    "TAG_SIZE",
    "KEY_ID_SIZE",
    "SESSION_ID_SIZE",
    "PK_BLOB_SIZE",
    "DEFAULT_SUITE_ID",
    "DEFAULT_AUTH_SCHEME_ID",
    
    # Suite/Auth
    "SUITES",
    "Suite",
    "get_suite",
    "get_kem_ct_size",
    "get_pk_blob_size",
    "AUTH_SCHEMES",
    "AuthScheme",
    "get_auth_scheme",
    "get_auth_size",
    
    # Session ID
    "generate_session_id_random",
    "generate_session_id_deterministic",
    
    # PK Blob
    "create_pk_blob",
    "parse_pk_blob",
    
    # Helpers
    "compute_aad",
    "compute_auth_message",
    "compute_commit",
    "compute_aad_from_envelope",
]

__version__ = "0.3.0"
