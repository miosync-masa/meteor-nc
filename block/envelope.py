# meteor_nc/block/wire/envelope.py
"""
Meteor-NC Block Wire Format: SecureEnvelope v0.3

Compact wire format for blockchain-integrated post-quantum messaging.
Includes domain separation, replay protection, multi-suite support, and sender authentication.

Wire Format v0.3:
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

Suite Support (kem_ct sizes):
    - Suite 0x01: n=256  (NIST Level 1) - 518B
    - Suite 0x02: n=512  (NIST Level 3) - 1094B
    - Suite 0x03: n=1024 (NIST Level 5) - 2310B

Auth Schemes (sender_auth sizes):
    - 0x00: None (0B)
    - 0x01: Ed25519 (64B)
    - 0x02: secp256k1 ECDSA (65B)
    - 0x03: EIP-712 (65B)

Session ID (8B):
    - Random: generate_session_id_random()
    - Deterministic: generate_session_id_deterministic(sender, recipient, ts, nonce)

PK Blob (64B):
    - pk_seed (32B): Seed for matrix A reconstruction
    - b_hash (32B): Hash of public key vector b

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import Optional

# Import from suites module
from ..suites import (
    SUITES,
    AUTH_SCHEMES,
    get_suite,
    get_auth_scheme,
    get_kem_ct_size,
    get_pk_blob_size,
    get_auth_size,
    generate_session_id_random,
    generate_session_id_deterministic,
    create_pk_blob,
    parse_pk_blob,
    DEFAULT_SUITE_ID,
    DEFAULT_AUTH_SCHEME_ID,
    PK_BLOB_SIZE,
)


# =============================================================================
# Constants
# =============================================================================

PROTOCOL_VERSION = 3

# Fixed sizes
TAG_SIZE = 16
KEY_ID_SIZE = 32
SESSION_ID_SIZE = 8
SEQUENCE_SIZE = 8

# Header: version(1) + type(1) + flags(2) + suite_id(1) + auth_scheme(1) + 
#         chain_id(4) + sender_id(32) + recipient_id(32) + session_id(8) + sequence(8) = 90
HEADER_SIZE = 1 + 1 + 2 + 1 + 1 + 4 + 32 + 32 + 8 + 8  # 90 bytes

# Domain separator
DOMAIN_SEPARATOR = b"meteor-nc-block-v3"


# =============================================================================
# Enums
# =============================================================================

class EnvelopeType(IntEnum):
    """Envelope message types."""
    
    # Standard messages
    HANDSHAKE = 0x00       # Initial key exchange (includes pk_blob)
    DATA = 0x01            # Regular data message
    ACK = 0x02             # Acknowledgment
    CLOSE = 0x03           # Channel close
    
    # MEV protection messages
    TX_ENCRYPTED = 0x10    # Encrypted transaction
    TX_COMMIT = 0x11       # Commit phase (commit-reveal)
    TX_REVEAL = 0x12       # Reveal phase
    
    # Streaming messages
    STREAM_START = 0x20    # Stream start
    STREAM_DATA = 0x21     # Stream data chunk
    STREAM_END = 0x22      # Stream end
    
    # Error / Control
    ERROR = 0xF0           # Error message
    PING = 0xF1            # Keep-alive ping
    PONG = 0xF2            # Keep-alive pong


class EnvelopeFlags(IntFlag):
    """Envelope flags (2 bytes = 16 bits)."""
    
    NONE = 0x0000
    
    # Bit 0: Include pk_blob in envelope
    INCLUDE_PK_BLOB = 0x0001
    
    # Bit 1: Payload is compressed
    COMPRESSED_PAYLOAD = 0x0002
    
    # Bit 2: Request acknowledgment
    REQUEST_ACK = 0x0004
    
    # Bit 3: Final message in sequence/stream
    FINAL = 0x0008
    
    # Bit 4: Has sender authentication (redundant with auth_scheme, but fast check)
    HAS_AUTH = 0x0010
    
    # Bit 5-7: Reserved
    # Bit 8-15: Application-specific


# =============================================================================
# SecureEnvelope
# =============================================================================

@dataclass
class SecureEnvelope:
    """
    Secure envelope for Meteor-NC Block protocol v0.3.
    
    Attributes:
        version: Protocol version (3)
        env_type: Message type
        flags: Envelope flags
        suite_id: Cryptographic suite (determines kem_ct size)
        auth_scheme: Authentication scheme (determines sender_auth size)
        chain_id: EVM chain ID
        sender_id: Sender's Key-ID (32B)
        recipient_id: Recipient's Key-ID (32B)
        session_id: Session identifier (8B)
        sequence: Sequence number within session
        pk_blob: Optional public key blob (64B: pk_seed + b_hash)
        kem_ct: KEM ciphertext (size varies by suite)
        tag: AEAD authentication tag (16B)
        payload: Encrypted payload
        sender_auth: Optional sender authentication signature
    """
    
    version: int
    env_type: EnvelopeType
    flags: EnvelopeFlags
    suite_id: int
    auth_scheme: int
    chain_id: int
    sender_id: bytes
    recipient_id: bytes
    session_id: bytes        # 8 bytes
    sequence: int
    pk_blob: Optional[bytes]  # 64B or None
    kem_ct: bytes             # Variable by suite
    tag: bytes                # 16B
    payload: bytes
    sender_auth: Optional[bytes] = None  # Variable by auth_scheme
    
    def __post_init__(self):
        """Validate envelope fields."""
        # Version
        if self.version != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported version: {self.version}, expected {PROTOCOL_VERSION}")
        
        # Suite
        suite = get_suite(self.suite_id)
        expected_kem_ct_size = suite.kem_ct_size
        
        # Auth scheme
        auth = get_auth_scheme(self.auth_scheme)
        expected_auth_size = auth.size
        
        # chain_id (uint32)
        if not (0 <= self.chain_id <= 0xFFFFFFFF):
            raise ValueError(f"chain_id must be uint32, got {self.chain_id}")
        
        # sender_id
        if len(self.sender_id) != KEY_ID_SIZE:
            raise ValueError(f"sender_id must be {KEY_ID_SIZE}B, got {len(self.sender_id)}")
        
        # recipient_id
        if len(self.recipient_id) != KEY_ID_SIZE:
            raise ValueError(f"recipient_id must be {KEY_ID_SIZE}B, got {len(self.recipient_id)}")
        
        # session_id
        if len(self.session_id) != SESSION_ID_SIZE:
            raise ValueError(f"session_id must be {SESSION_ID_SIZE}B, got {len(self.session_id)}")
        
        # sequence (uint64)
        if not (0 <= self.sequence <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError(f"sequence must be uint64, got {self.sequence}")
        
        # pk_blob consistency
        has_pk_blob = self.pk_blob is not None
        flag_set = bool(self.flags & EnvelopeFlags.INCLUDE_PK_BLOB)
        
        if has_pk_blob != flag_set:
            raise ValueError("pk_blob presence must match INCLUDE_PK_BLOB flag")
        
        if has_pk_blob and len(self.pk_blob) != PK_BLOB_SIZE:
            raise ValueError(f"pk_blob must be {PK_BLOB_SIZE}B, got {len(self.pk_blob)}")
        
        # kem_ct size
        if len(self.kem_ct) != expected_kem_ct_size:
            raise ValueError(f"kem_ct must be {expected_kem_ct_size}B for suite 0x{self.suite_id:02x}, got {len(self.kem_ct)}")
        
        # tag
        if len(self.tag) != TAG_SIZE:
            raise ValueError(f"tag must be {TAG_SIZE}B, got {len(self.tag)}")
        
        # sender_auth consistency
        has_auth = self.sender_auth is not None
        auth_flag_set = bool(self.flags & EnvelopeFlags.HAS_AUTH)
        
        if has_auth != auth_flag_set:
            raise ValueError("sender_auth presence must match HAS_AUTH flag")
        
        if has_auth:
            if expected_auth_size == 0:
                raise ValueError("sender_auth provided but auth_scheme is NONE")
            if len(self.sender_auth) != expected_auth_size:
                raise ValueError(f"sender_auth must be {expected_auth_size}B for auth 0x{self.auth_scheme:02x}, got {len(self.sender_auth)}")
    
    # =========================================================================
    # Factory Methods
    # =========================================================================
    
    @classmethod
    def create_handshake(
        cls,
        chain_id: int,
        sender_id: bytes,
        recipient_id: bytes,
        session_id: bytes,
        pk_blob: bytes,
        kem_ct: bytes,
        tag: bytes,
        payload: bytes = b"",
        suite_id: int = DEFAULT_SUITE_ID,
        auth_scheme: int = DEFAULT_AUTH_SCHEME_ID,
        sender_auth: Optional[bytes] = None,
    ) -> SecureEnvelope:
        """
        Create HANDSHAKE envelope (includes pk_blob).
        
        Use for initial key exchange when recipient doesn't have sender's PK.
        """
        flags = EnvelopeFlags.INCLUDE_PK_BLOB
        if sender_auth is not None:
            flags |= EnvelopeFlags.HAS_AUTH
        
        return cls(
            version=PROTOCOL_VERSION,
            env_type=EnvelopeType.HANDSHAKE,
            flags=flags,
            suite_id=suite_id,
            auth_scheme=auth_scheme,
            chain_id=chain_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            sequence=0,
            pk_blob=pk_blob,
            kem_ct=kem_ct,
            tag=tag,
            payload=payload,
            sender_auth=sender_auth,
        )
    
    @classmethod
    def create_data(
        cls,
        chain_id: int,
        sender_id: bytes,
        recipient_id: bytes,
        session_id: bytes,
        sequence: int,
        kem_ct: bytes,
        tag: bytes,
        payload: bytes,
        suite_id: int = DEFAULT_SUITE_ID,
        auth_scheme: int = DEFAULT_AUTH_SCHEME_ID,
        sender_auth: Optional[bytes] = None,
        request_ack: bool = False,
    ) -> SecureEnvelope:
        """
        Create DATA envelope (pk_blob omitted).
        
        Use for subsequent messages after handshake.
        """
        flags = EnvelopeFlags.NONE
        if request_ack:
            flags |= EnvelopeFlags.REQUEST_ACK
        if sender_auth is not None:
            flags |= EnvelopeFlags.HAS_AUTH
        
        return cls(
            version=PROTOCOL_VERSION,
            env_type=EnvelopeType.DATA,
            flags=flags,
            suite_id=suite_id,
            auth_scheme=auth_scheme,
            chain_id=chain_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            sequence=sequence,
            pk_blob=None,
            kem_ct=kem_ct,
            tag=tag,
            payload=payload,
            sender_auth=sender_auth,
        )
    
    @classmethod
    def create_tx_encrypted(
        cls,
        chain_id: int,
        sender_id: bytes,
        recipient_id: bytes,  # Builder/Sequencer Key-ID
        session_id: bytes,
        sequence: int,
        kem_ct: bytes,
        tag: bytes,
        encrypted_tx: bytes,
        suite_id: int = DEFAULT_SUITE_ID,
        auth_scheme: int = DEFAULT_AUTH_SCHEME_ID,
        sender_auth: Optional[bytes] = None,
        include_pk_blob: bool = False,
        pk_blob: Optional[bytes] = None,
    ) -> SecureEnvelope:
        """
        Create TX_ENCRYPTED envelope for MEV protection.
        """
        flags = EnvelopeFlags.NONE
        if include_pk_blob:
            flags |= EnvelopeFlags.INCLUDE_PK_BLOB
        if sender_auth is not None:
            flags |= EnvelopeFlags.HAS_AUTH
        
        return cls(
            version=PROTOCOL_VERSION,
            env_type=EnvelopeType.TX_ENCRYPTED,
            flags=flags,
            suite_id=suite_id,
            auth_scheme=auth_scheme,
            chain_id=chain_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            sequence=sequence,
            pk_blob=pk_blob if include_pk_blob else None,
            kem_ct=kem_ct,
            tag=tag,
            payload=encrypted_tx,
            sender_auth=sender_auth,
        )
    
    @classmethod
    def create_ack(
        cls,
        chain_id: int,
        sender_id: bytes,
        recipient_id: bytes,
        session_id: bytes,
        sequence: int,
        kem_ct: bytes,
        tag: bytes,
        suite_id: int = DEFAULT_SUITE_ID,
    ) -> SecureEnvelope:
        """Create ACK envelope."""
        return cls(
            version=PROTOCOL_VERSION,
            env_type=EnvelopeType.ACK,
            flags=EnvelopeFlags.NONE,
            suite_id=suite_id,
            auth_scheme=0x00,
            chain_id=chain_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            sequence=sequence,
            pk_blob=None,
            kem_ct=kem_ct,
            tag=tag,
            payload=b"",
            sender_auth=None,
        )
    
    @classmethod
    def create_close(
        cls,
        chain_id: int,
        sender_id: bytes,
        recipient_id: bytes,
        session_id: bytes,
        sequence: int,
        kem_ct: bytes,
        tag: bytes,
        suite_id: int = DEFAULT_SUITE_ID,
    ) -> SecureEnvelope:
        """Create CLOSE envelope."""
        return cls(
            version=PROTOCOL_VERSION,
            env_type=EnvelopeType.CLOSE,
            flags=EnvelopeFlags.FINAL,
            suite_id=suite_id,
            auth_scheme=0x00,
            chain_id=chain_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            sequence=sequence,
            pk_blob=None,
            kem_ct=kem_ct,
            tag=tag,
            payload=b"",
            sender_auth=None,
        )
    
    # =========================================================================
    # Serialization
    # =========================================================================
    
    def to_bytes(self) -> bytes:
        """
        Serialize envelope to wire format.
        
        Wire: [header:90][pk_blob:64?][kem_ct:var][tag:16][payload:N][sender_auth:var?]
        """
        # Header (90 bytes)
        # Format: >BBHBBI32s32s8sQ
        #   B: version (1)
        #   B: type (1)
        #   H: flags (2)
        #   B: suite_id (1)
        #   B: auth_scheme (1)
        #   I: chain_id (4)
        #   32s: sender_id (32)
        #   32s: recipient_id (32)
        #   8s: session_id (8)
        #   Q: sequence (8)
        header = struct.pack(
            ">BBHBBI32s32s8sQ",
            self.version,
            self.env_type,
            self.flags,
            self.suite_id,
            self.auth_scheme,
            self.chain_id,
            self.sender_id,
            self.recipient_id,
            self.session_id,
            self.sequence,
        )
        
        parts = [header]
        
        # Optional pk_blob
        if self.flags & EnvelopeFlags.INCLUDE_PK_BLOB:
            parts.append(self.pk_blob)
        
        # kem_ct, tag, payload
        parts.append(self.kem_ct)
        parts.append(self.tag)
        parts.append(self.payload)
        
        # Optional sender_auth
        if self.flags & EnvelopeFlags.HAS_AUTH:
            parts.append(self.sender_auth)
        
        return b"".join(parts)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> SecureEnvelope:
        """
        Deserialize envelope from wire format.
        """
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Data too short for header: {len(data)} < {HEADER_SIZE}")
        
        # Parse header
        header_fmt = ">BBHBBI32s32s8sQ"
        (
            version, env_type_raw, flags_raw, suite_id, auth_scheme_id,
            chain_id, sender_id, recipient_id, session_id, sequence
        ) = struct.unpack(header_fmt, data[:HEADER_SIZE])
        
        # Validate and convert
        try:
            env_type = EnvelopeType(env_type_raw)
        except ValueError:
            raise ValueError(f"Unknown envelope type: 0x{env_type_raw:02x}")
        
        flags = EnvelopeFlags(flags_raw)
        
        # Get sizes from suite/auth
        suite = get_suite(suite_id)
        auth = get_auth_scheme(auth_scheme_id)
        
        kem_ct_size = suite.kem_ct_size
        auth_size = auth.size if (flags & EnvelopeFlags.HAS_AUTH) else 0
        
        has_pk_blob = bool(flags & EnvelopeFlags.INCLUDE_PK_BLOB)
        pk_blob_size = PK_BLOB_SIZE if has_pk_blob else 0
        
        # Calculate minimum size
        min_size = HEADER_SIZE + pk_blob_size + kem_ct_size + TAG_SIZE + auth_size
        
        if len(data) < min_size:
            raise ValueError(f"Data too short: {len(data)} < {min_size}")
        
        # Parse body
        offset = HEADER_SIZE
        
        # pk_blob
        pk_blob = None
        if has_pk_blob:
            pk_blob = data[offset:offset + PK_BLOB_SIZE]
            offset += PK_BLOB_SIZE
        
        # kem_ct
        kem_ct = data[offset:offset + kem_ct_size]
        offset += kem_ct_size
        
        # tag
        tag = data[offset:offset + TAG_SIZE]
        offset += TAG_SIZE
        
        # payload (variable) and optional sender_auth at end
        if auth_size > 0:
            payload = data[offset:-auth_size]
            sender_auth = data[-auth_size:]
        else:
            payload = data[offset:]
            sender_auth = None
        
        return cls(
            version=version,
            env_type=env_type,
            flags=flags,
            suite_id=suite_id,
            auth_scheme=auth_scheme_id,
            chain_id=chain_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            sequence=sequence,
            pk_blob=pk_blob,
            kem_ct=kem_ct,
            tag=tag,
            payload=payload,
            sender_auth=sender_auth,
        )
    
    # =========================================================================
    # Properties
    # =========================================================================
    
    @property
    def suite(self):
        """Get suite configuration."""
        return get_suite(self.suite_id)
    
    @property
    def auth(self):
        """Get auth scheme configuration."""
        return get_auth_scheme(self.auth_scheme)
    
    @property
    def total_size(self) -> int:
        """Total wire size in bytes."""
        size = HEADER_SIZE + len(self.kem_ct) + TAG_SIZE + len(self.payload)
        if self.pk_blob:
            size += len(self.pk_blob)
        if self.sender_auth:
            size += len(self.sender_auth)
        return size
    
    @property
    def has_pk_blob(self) -> bool:
        return bool(self.flags & EnvelopeFlags.INCLUDE_PK_BLOB)
    
    @property
    def has_auth(self) -> bool:
        return bool(self.flags & EnvelopeFlags.HAS_AUTH)
    
    @property
    def is_handshake(self) -> bool:
        return self.env_type == EnvelopeType.HANDSHAKE
    
    @property
    def is_mev_protected(self) -> bool:
        return self.env_type in (
            EnvelopeType.TX_ENCRYPTED,
            EnvelopeType.TX_COMMIT,
            EnvelopeType.TX_REVEAL,
        )
    
    def __repr__(self) -> str:
        pk_info = "pk=✓" if self.pk_blob else "pk=None"
        auth_info = f"auth={self.auth.name}" if self.has_auth else "auth=None"
        return (
            f"SecureEnvelope(v={self.version}, "
            f"type={self.env_type.name}, "
            f"suite=0x{self.suite_id:02x}, "
            f"chain={self.chain_id}, "
            f"session={self.session_id.hex()[:8]}..., "
            f"seq={self.sequence}, "
            f"{pk_info}, {auth_info}, "
            f"payload={len(self.payload)}B)"
        )


# =============================================================================
# AAD Helper
# =============================================================================

def compute_aad(
    env_type: EnvelopeType,
    suite_id: int,
    chain_id: int,
    sender_id: bytes,
    recipient_id: bytes,
    session_id: bytes,
    sequence: int,
    kem_ct: bytes,
    flags: EnvelopeFlags = EnvelopeFlags.NONE,
    pk_blob: Optional[bytes] = None,
) -> bytes:
    """
    Compute AAD for AEAD encryption.
    
    AAD binds: domain, suite, chain, type, sender, recipient, session, sequence, flags, kem_ct, pk_blob
    """
    h = hashlib.sha256()
    h.update(DOMAIN_SEPARATOR)
    h.update(struct.pack(">B", suite_id))
    h.update(struct.pack(">I", chain_id))
    h.update(struct.pack(">B", env_type))
    h.update(struct.pack(">H", flags))  # Include flags in AAD
    h.update(sender_id)
    h.update(recipient_id)
    h.update(session_id)
    h.update(struct.pack(">Q", sequence))
    h.update(kem_ct)
    if pk_blob:
        h.update(pk_blob)
    
    return h.digest()


def compute_auth_message(envelope: SecureEnvelope) -> bytes:
    """
    Compute message to be signed for sender authentication.
    """
    h = hashlib.sha256()
    h.update(b"meteor-nc-block-auth-v3")
    h.update(struct.pack(">B", envelope.suite_id))
    h.update(struct.pack(">I", envelope.chain_id))
    h.update(struct.pack(">B", envelope.env_type))
    h.update(envelope.sender_id)
    h.update(envelope.recipient_id)
    h.update(envelope.session_id)
    h.update(struct.pack(">Q", envelope.sequence))
    h.update(envelope.kem_ct)
    h.update(envelope.tag)
    h.update(hashlib.sha256(envelope.payload).digest())
    
    return h.digest()


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test SecureEnvelope v0.3."""
    print("=" * 70)
    print("Meteor-NC Block Wire: SecureEnvelope v0.3 Test")
    print("=" * 70)
    
    import secrets
    
    results = {}
    
    # Common test data
    chain_id = 1
    sender_id = secrets.token_bytes(32)
    recipient_id = secrets.token_bytes(32)
    session_id = generate_session_id_random()
    pk_blob = secrets.token_bytes(64)  # pk_seed(32) + b_hash(32)
    tag = secrets.token_bytes(16)
    payload = b"Hello, v0.3!"
    
    # Test each suite
    for suite_id, suite in SUITES.items():
        print(f"\n[Suite 0x{suite_id:02x}] {suite.name}")
        print("-" * 40)
        
        kem_ct = secrets.token_bytes(suite.kem_ct_size)
        
        # Test 1: Handshake
        env = SecureEnvelope.create_handshake(
            chain_id=chain_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            pk_blob=pk_blob,
            kem_ct=kem_ct,
            tag=tag,
            payload=payload,
            suite_id=suite_id,
        )
        
        wire = env.to_bytes()
        restored = SecureEnvelope.from_bytes(wire)
        
        handshake_ok = (
            restored.version == PROTOCOL_VERSION and
            restored.suite_id == suite_id and
            restored.chain_id == chain_id and
            restored.session_id == session_id and
            restored.has_pk_blob and
            restored.pk_blob == pk_blob and
            restored.kem_ct == kem_ct and
            restored.payload == payload
        )
        
        print(f"  Handshake wire: {len(wire)}B (kem_ct={suite.kem_ct_size}B)")
        print(f"  Round-trip: {'PASS ✓' if handshake_ok else 'FAIL ✗'}")
        
        results[f"suite_{suite_id:02x}_handshake"] = handshake_ok
        
        # Test 2: Data
        env_data = SecureEnvelope.create_data(
            chain_id=chain_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            sequence=42,
            kem_ct=kem_ct,
            tag=tag,
            payload=payload,
            suite_id=suite_id,
        )
        
        wire_data = env_data.to_bytes()
        restored_data = SecureEnvelope.from_bytes(wire_data)
        
        data_ok = (
            restored_data.sequence == 42 and
            not restored_data.has_pk_blob and
            restored_data.payload == payload
        )
        
        print(f"  Data wire: {len(wire_data)}B (saves {len(wire) - len(wire_data)}B)")
        print(f"  Round-trip: {'PASS ✓' if data_ok else 'FAIL ✗'}")
        
        results[f"suite_{suite_id:02x}_data"] = data_ok
    
    # Test auth schemes
    print("\n[Auth Schemes]")
    print("-" * 40)
    
    kem_ct = secrets.token_bytes(518)  # Default suite
    
    for auth_id, auth in AUTH_SCHEMES.items():
        if auth_id == 0x00:
            continue  # Skip NONE
        
        sender_auth = secrets.token_bytes(auth.size)
        
        env = SecureEnvelope.create_data(
            chain_id=chain_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=session_id,
            sequence=1,
            kem_ct=kem_ct,
            tag=tag,
            payload=payload,
            auth_scheme=auth_id,
            sender_auth=sender_auth,
        )
        
        wire = env.to_bytes()
        restored = SecureEnvelope.from_bytes(wire)
        
        auth_ok = (
            restored.has_auth and
            restored.auth_scheme == auth_id and
            restored.sender_auth == sender_auth
        )
        
        print(f"  {auth.name} ({auth.size}B): {'PASS ✓' if auth_ok else 'FAIL ✗'}")
        results[f"auth_{auth_id:02x}"] = auth_ok
    
    # Test session_id generation
    print("\n[Session ID]")
    print("-" * 40)
    
    sid_random = generate_session_id_random()
    sid_det1 = generate_session_id_deterministic(sender_id, recipient_id, 1000.0, b"nonce123")
    sid_det2 = generate_session_id_deterministic(sender_id, recipient_id, 1000.0, b"nonce123")
    
    session_ok = len(sid_random) == 8 and sid_det1 == sid_det2
    print(f"  Random: {sid_random.hex()}")
    print(f"  Deterministic: {sid_det1.hex()} (reproducible: {sid_det1 == sid_det2})")
    results["session_id"] = session_ok
    
    # Test AAD
    print("\n[AAD Computation]")
    print("-" * 40)
    
    aad1 = compute_aad(
        EnvelopeType.DATA, 0x01, chain_id, sender_id, recipient_id,
        session_id, 1, kem_ct, EnvelopeFlags.NONE
    )
    aad2 = compute_aad(
        EnvelopeType.DATA, 0x01, chain_id, sender_id, recipient_id,
        session_id, 2, kem_ct, EnvelopeFlags.NONE
    )
    
    aad_ok = len(aad1) == 32 and aad1 != aad2
    print(f"  AAD size: {len(aad1)}B")
    print(f"  AAD varies with sequence: {'PASS ✓' if aad_ok else 'FAIL ✗'}")
    results["aad"] = aad_ok
    
    # Test error handling
    print("\n[Error Handling]")
    print("-" * 40)
    
    error_ok = True
    
    try:
        SecureEnvelope.from_bytes(b"short")
        error_ok = False
        print("  Short data: FAIL")
    except ValueError:
        print("  Short data: PASS ✓")
    
    try:
        SecureEnvelope.create_data(
            chain_id=chain_id,
            sender_id=b"short",  # Wrong size
            recipient_id=recipient_id,
            session_id=session_id,
            sequence=0,
            kem_ct=kem_ct,
            tag=tag,
            payload=b"",
        )
        error_ok = False
        print("  Invalid sender_id: FAIL")
    except ValueError:
        print("  Invalid sender_id: PASS ✓")
    
    results["error"] = error_ok
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    passed = sum(results.values())
    total = len(results)
    
    print(f"Result: {passed}/{total} tests passed")
    print(f"{'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    
    if all_pass:
        print("\n✓ v0.3 Features Verified:")
        print("  - Multi-suite support (Level 1/3/5)")
        print("  - Multi-auth support (Ed25519/secp256k1/EIP-712)")
        print("  - Session ID (random + deterministic)")
        print("  - pk_blob (pk_seed + b_hash)")
        print("  - Domain-separated AAD with flags")
    
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
