# meteor_nc/block/suites.py
"""
Meteor-NC Block Protocol Suites

Defines cryptographic parameter suites for forward compatibility.
Each suite specifies KEM parameters, compression settings, and sizes.

Suite Selection:
    - Suite 0x01 (Level 1): n=256, 128-bit security, smallest ciphertext
    - Suite 0x02 (Level 3): n=512, 192-bit security, medium
    - Suite 0x03 (Level 5): n=1024, 256-bit security, largest

Auth Scheme Selection:
    - 0x00: None (no sender authentication)
    - 0x01: Ed25519 (64 bytes)
    - 0x02: secp256k1 ECDSA (65 bytes, r||s||v)
    - 0x03: EIP-712 typed data (65 bytes)

Usage:
    from meteor_nc.block.suites import SUITES, AUTH_SCHEMES, get_suite, get_auth_scheme
    
    suite = get_suite(0x01)
    print(suite["kem_ct_size"])  # 518
    
    auth = get_auth_scheme(0x01)
    print(auth["size"])  # 64

Updated: 2025-01-20
Version: 0.3.0
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass


# =============================================================================
# Suite Definitions
# =============================================================================

@dataclass(frozen=True)
class Suite:
    """Cryptographic parameter suite."""
    id: int
    name: str
    security_level: int      # NIST security level (1, 3, 5)
    n: int                   # LWE dimension
    d_u: int                 # Compression parameter for u
    d_v: int                 # Compression parameter for v
    kem_ct_size: int         # Compressed ciphertext size in bytes
    pk_blob_size: int        # Public key blob size (pk_seed + b_hash)
    aead: str                # AEAD algorithm
    hash_domain: str         # Domain separator for hashing


# Defined suites
SUITES: Dict[int, Suite] = {
    0x01: Suite(
        id=0x01,
        name="meteor-nc-level1",
        security_level=1,
        n=256,
        d_u=11,
        d_v=5,
        kem_ct_size=518,        # 6 + ceil(256*11/8) + ceil(256*5/8) = 6 + 352 + 160 = 518
        pk_blob_size=64,        # pk_seed(32) + b_hash(32)
        aead="XChaCha20-Poly1305",
        hash_domain="meteor-nc-block-v3-L1",
    ),
    0x02: Suite(
        id=0x02,
        name="meteor-nc-level3",
        security_level=3,
        n=512,
        d_u=12,
        d_v=5,
        kem_ct_size=1094,       # 6 + ceil(512*12/8) + ceil(512*5/8) = 6 + 768 + 320 = 1094
        pk_blob_size=64,        # pk_seed(32) + b_hash(32)
        aead="XChaCha20-Poly1305",
        hash_domain="meteor-nc-block-v3-L3",
    ),
    0x03: Suite(
        id=0x03,
        name="meteor-nc-level5",
        security_level=5,
        n=1024,
        d_u=13,
        d_v=5,
        kem_ct_size=2310,       # 6 + ceil(1024*13/8) + ceil(1024*5/8) = 6 + 1664 + 640 = 2310
        pk_blob_size=64,        # pk_seed(32) + b_hash(32)
        aead="XChaCha20-Poly1305",
        hash_domain="meteor-nc-block-v3-L5",
    ),
}

# Default suite
DEFAULT_SUITE_ID = 0x01


def get_suite(suite_id: int) -> Suite:
    """
    Get suite by ID.
    
    Args:
        suite_id: Suite identifier (0x01, 0x02, 0x03)
    
    Returns:
        Suite instance
    
    Raises:
        ValueError: If suite_id is unknown
    """
    if suite_id not in SUITES:
        raise ValueError(f"Unknown suite_id: 0x{suite_id:02x}. Valid: {list(SUITES.keys())}")
    return SUITES[suite_id]


def get_kem_ct_size(suite_id: int) -> int:
    """Get KEM ciphertext size for suite."""
    return get_suite(suite_id).kem_ct_size


def get_pk_blob_size(suite_id: int) -> int:
    """Get public key blob size for suite."""
    return get_suite(suite_id).pk_blob_size


# =============================================================================
# Auth Scheme Definitions
# =============================================================================

@dataclass(frozen=True)
class AuthScheme:
    """Authentication scheme definition."""
    id: int
    name: str
    size: int                # Signature size in bytes (0 = no auth)
    description: str


AUTH_SCHEMES: Dict[int, AuthScheme] = {
    0x00: AuthScheme(
        id=0x00,
        name="none",
        size=0,
        description="No sender authentication",
    ),
    0x01: AuthScheme(
        id=0x01,
        name="ed25519",
        size=64,
        description="Ed25519 signature (64 bytes)",
    ),
    0x02: AuthScheme(
        id=0x02,
        name="secp256k1",
        size=65,
        description="secp256k1 ECDSA signature (r:32 + s:32 + v:1 = 65 bytes)",
    ),
    0x03: AuthScheme(
        id=0x03,
        name="eip712",
        size=65,
        description="EIP-712 typed data signature (65 bytes)",
    ),
}

# Default auth scheme
DEFAULT_AUTH_SCHEME_ID = 0x00


def get_auth_scheme(auth_scheme_id: int) -> AuthScheme:
    """
    Get auth scheme by ID.
    
    Args:
        auth_scheme_id: Auth scheme identifier
    
    Returns:
        AuthScheme instance
    
    Raises:
        ValueError: If auth_scheme_id is unknown
    """
    if auth_scheme_id not in AUTH_SCHEMES:
        raise ValueError(f"Unknown auth_scheme_id: 0x{auth_scheme_id:02x}. Valid: {list(AUTH_SCHEMES.keys())}")
    return AUTH_SCHEMES[auth_scheme_id]


def get_auth_size(auth_scheme_id: int) -> int:
    """Get signature size for auth scheme."""
    return get_auth_scheme(auth_scheme_id).size


# =============================================================================
# Session ID Generation
# =============================================================================

import secrets
import hashlib
import struct
import time


def generate_session_id_random() -> bytes:
    """
    Generate random session ID (8 bytes).
    
    Use this for most cases - simple and secure.
    """
    return secrets.token_bytes(8)


def generate_session_id_deterministic(
    sender_id: bytes,
    recipient_id: bytes,
    timestamp: Optional[float] = None,
    nonce: Optional[bytes] = None,
) -> bytes:
    """
    Generate deterministic session ID from inputs.
    
    Useful when both parties need to derive the same session ID
    without explicit exchange.
    
    Args:
        sender_id: Sender's Key-ID (32 bytes)
        recipient_id: Recipient's Key-ID (32 bytes)
        timestamp: Unix timestamp (default: current time)
        nonce: Additional randomness (default: 8 random bytes)
    
    Returns:
        8-byte session ID
    """
    if timestamp is None:
        timestamp = time.time()
    if nonce is None:
        nonce = secrets.token_bytes(8)
    
    h = hashlib.sha256()
    h.update(b"meteor-nc-session-v3")
    h.update(sender_id)
    h.update(recipient_id)
    h.update(struct.pack(">d", timestamp))  # 8 bytes double
    h.update(nonce)
    
    return h.digest()[:8]


# =============================================================================
# PK Blob Helpers
# =============================================================================

PK_SEED_SIZE = 32
B_HASH_SIZE = 32
PK_BLOB_SIZE = PK_SEED_SIZE + B_HASH_SIZE  # 64 bytes


def create_pk_blob(pk_seed: bytes, b_hash: bytes) -> bytes:
    """
    Create public key blob from components.
    
    Args:
        pk_seed: 32-byte seed for matrix A reconstruction
        b_hash: 32-byte hash of public key vector b
    
    Returns:
        64-byte pk_blob
    """
    if len(pk_seed) != PK_SEED_SIZE:
        raise ValueError(f"pk_seed must be {PK_SEED_SIZE} bytes")
    if len(b_hash) != B_HASH_SIZE:
        raise ValueError(f"b_hash must be {B_HASH_SIZE} bytes")
    
    return pk_seed + b_hash


def parse_pk_blob(pk_blob: bytes) -> tuple[bytes, bytes]:
    """
    Parse public key blob into components.
    
    Args:
        pk_blob: 64-byte public key blob
    
    Returns:
        Tuple of (pk_seed, b_hash)
    """
    if len(pk_blob) != PK_BLOB_SIZE:
        raise ValueError(f"pk_blob must be {PK_BLOB_SIZE} bytes")
    
    pk_seed = pk_blob[:PK_SEED_SIZE]
    b_hash = pk_blob[PK_SEED_SIZE:]
    
    return pk_seed, b_hash


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test suite definitions."""
    print("=" * 70)
    print("Meteor-NC Block Suites Test")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Suite lookup
    print("\n[Test 1] Suite Lookup")
    print("-" * 40)
    
    suite_ok = True
    for suite_id, suite in SUITES.items():
        retrieved = get_suite(suite_id)
        if retrieved != suite:
            suite_ok = False
        print(f"  Suite 0x{suite_id:02x}: {suite.name}")
        print(f"    n={suite.n}, kem_ct={suite.kem_ct_size}B, pk_blob={suite.pk_blob_size}B")
    
    results["suite_lookup"] = suite_ok
    print(f"  Result: {'PASS ✓' if suite_ok else 'FAIL ✗'}")
    
    # Test 2: Auth scheme lookup
    print("\n[Test 2] Auth Scheme Lookup")
    print("-" * 40)
    
    auth_ok = True
    for auth_id, auth in AUTH_SCHEMES.items():
        retrieved = get_auth_scheme(auth_id)
        if retrieved != auth:
            auth_ok = False
        print(f"  Auth 0x{auth_id:02x}: {auth.name} ({auth.size}B)")
    
    results["auth_lookup"] = auth_ok
    print(f"  Result: {'PASS ✓' if auth_ok else 'FAIL ✗'}")
    
    # Test 3: Session ID generation
    print("\n[Test 3] Session ID Generation")
    print("-" * 40)
    
    # Random
    sid1 = generate_session_id_random()
    sid2 = generate_session_id_random()
    
    random_ok = len(sid1) == 8 and len(sid2) == 8 and sid1 != sid2
    print(f"  Random 1: {sid1.hex()}")
    print(f"  Random 2: {sid2.hex()}")
    print(f"  Different: {'PASS ✓' if random_ok else 'FAIL ✗'}")
    
    # Deterministic
    sender = secrets.token_bytes(32)
    recipient = secrets.token_bytes(32)
    ts = time.time()
    nonce = secrets.token_bytes(8)
    
    sid3 = generate_session_id_deterministic(sender, recipient, ts, nonce)
    sid4 = generate_session_id_deterministic(sender, recipient, ts, nonce)  # Same inputs
    sid5 = generate_session_id_deterministic(sender, recipient, ts + 1, nonce)  # Different ts
    
    det_ok = len(sid3) == 8 and sid3 == sid4 and sid3 != sid5
    print(f"  Deterministic (same inputs): {sid3.hex()} == {sid4.hex()}: {sid3 == sid4}")
    print(f"  Deterministic (diff ts): {sid3.hex()} != {sid5.hex()}: {sid3 != sid5}")
    
    results["session_id"] = random_ok and det_ok
    print(f"  Result: {'PASS ✓' if results['session_id'] else 'FAIL ✗'}")
    
    # Test 4: PK Blob
    print("\n[Test 4] PK Blob Create/Parse")
    print("-" * 40)
    
    pk_seed = secrets.token_bytes(32)
    b_hash = secrets.token_bytes(32)
    
    blob = create_pk_blob(pk_seed, b_hash)
    parsed_seed, parsed_hash = parse_pk_blob(blob)
    
    blob_ok = (
        len(blob) == 64 and
        parsed_seed == pk_seed and
        parsed_hash == b_hash
    )
    
    results["pk_blob"] = blob_ok
    print(f"  Blob size: {len(blob)}B")
    print(f"  Round-trip: {'PASS ✓' if blob_ok else 'FAIL ✗'}")
    
    # Test 5: Error handling
    print("\n[Test 5] Error Handling")
    print("-" * 40)
    
    error_ok = True
    
    try:
        get_suite(0xFF)
        error_ok = False
        print("  Invalid suite: FAIL (should raise)")
    except ValueError:
        print("  Invalid suite: PASS ✓ (raised ValueError)")
    
    try:
        get_auth_scheme(0xFF)
        error_ok = False
        print("  Invalid auth: FAIL (should raise)")
    except ValueError:
        print("  Invalid auth: PASS ✓ (raised ValueError)")
    
    results["error"] = error_ok
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    passed = sum(results.values())
    total = len(results)
    
    print(f"Result: {passed}/{total} tests passed")
    print(f"{'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
