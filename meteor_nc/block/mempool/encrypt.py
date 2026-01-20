# meteor_nc/block/mempool/encrypt.py
"""
Meteor-NC Block Mempool: Transaction Encryption

Encrypt transactions for builder/sequencer/relay to prevent MEV extraction.
Uses TX_ENCRYPTED envelope type for encrypted transaction submission.

Architecture:
    User Wallet → TxEncryptor → TX_ENCRYPTED envelope → Builder/Sequencer
    
    1. User encrypts raw tx with builder's public key (pk_blob from registry)
    2. Encrypted tx is submitted to mempool/relay
    3. Only designated builder can decrypt and include in block

Security Properties:
    - Post-quantum secure (LWE-KEM)
    - Forward secrecy (fresh KEM per tx)
    - Builder-specific (only intended recipient can decrypt)
    - Tamper-proof (AEAD with AAD binding)

Usage:
    from meteor_nc.block.mempool import TxEncryptor
    
    # Get builder's pk_blob from registry
    builder_pk_blob = resolver.resolve_by_address(builder_address)
    
    # Create encryptor
    encryptor = TxEncryptor(
        builder_pk_blob=builder_pk_blob,
        chain_id=1,
        suite_id=0x01,
    )
    
    # Encrypt transaction
    encrypted = encryptor.encrypt(raw_tx_bytes)
    
    # Get envelope for submission
    envelope = encrypted.envelope
    wire = envelope.to_bytes()

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Tuple, TYPE_CHECKING

# Import from wire module
from ..wire import (
    SecureEnvelope,
    EnvelopeType,
    EnvelopeFlags,
    compute_aad,
    compute_commit,
    generate_session_id_random,
    get_suite,
    DEFAULT_SUITE_ID,
    PK_BLOB_SIZE,
)

# Import from suites
from ..suites import parse_pk_blob

# Conditional imports for cryptography
try:
    from ...cryptography.core import LWEKEM
    from ...cryptography.stream import StreamDEM, EncryptedChunk, StreamHeader
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    LWEKEM = None
    StreamDEM = None


# =============================================================================
# Exceptions
# =============================================================================

class TxEncryptionError(Exception):
    """Base transaction encryption error."""
    pass


class CryptoNotAvailableError(TxEncryptionError):
    """Cryptography modules not available."""
    def __init__(self):
        super().__init__(
            "Cryptography modules not available. "
            "Ensure meteor_nc.cryptography is properly installed."
        )


class InvalidPkBlobError(TxEncryptionError):
    """Invalid pk_blob provided."""
    def __init__(self, reason: str):
        super().__init__(f"Invalid pk_blob: {reason}")


# =============================================================================
# Types
# =============================================================================

@dataclass
class EncryptedTx:
    """
    Encrypted transaction result.
    
    Attributes:
        envelope: TX_ENCRYPTED SecureEnvelope ready for submission
        commit: Commit hash for commit-reveal (if needed)
        session_key: Session key (for debugging, should not be shared)
        timestamp: Encryption timestamp
    """
    envelope: SecureEnvelope
    commit: bytes  # H(envelope) for commit-reveal
    session_key: Optional[bytes] = None  # DEBUG ONLY
    timestamp: float = 0.0
    
    @property
    def wire(self) -> bytes:
        """Serialized envelope for transmission."""
        return self.envelope.to_bytes()
    
    @property
    def tx_id(self) -> bytes:
        """Transaction identifier (first 8 bytes of commit)."""
        return self.commit[:8]


# =============================================================================
# TxEncryptor
# =============================================================================

class TxEncryptor:
    """
    Transaction encryptor for MEV protection.
    
    Encrypts raw transactions using the builder/sequencer's public key.
    Uses TX_ENCRYPTED envelope type.
    
    Note: Requires full pk_bytes (not just pk_blob) because encryption
    needs the complete public key matrix. pk_blob (64B) is used for
    on-chain registry, pk_bytes (~1KB) is distributed off-chain.
    """
    
    def __init__(
        self,
        builder_pk_bytes: bytes,
        chain_id: int,
        suite_id: int = DEFAULT_SUITE_ID,
        sender_key_id: Optional[bytes] = None,
        include_sender_pk: bool = False,
        sender_pk_blob: Optional[bytes] = None,
        gpu: bool = False,
    ):
        """
        Initialize transaction encryptor.
        
        Args:
            builder_pk_bytes: Builder's full public key bytes (from LWEKEM.key_gen())
            chain_id: Chain ID for domain separation
            suite_id: Cryptographic suite (0x01, 0x02, 0x03)
            sender_key_id: Sender's key ID (32 bytes, random if not provided)
            include_sender_pk: Include sender's pk_blob in envelope
            sender_pk_blob: Sender's pk_blob (required if include_sender_pk=True)
            gpu: Use GPU acceleration if available
        """
        if not CRYPTO_AVAILABLE:
            raise CryptoNotAvailableError()
        
        self._chain_id = chain_id
        self._suite_id = suite_id
        self._gpu = gpu
        
        # Get suite parameters
        suite = get_suite(suite_id)
        self._n = suite.n
        
        # Initialize KEM and load builder's public key
        self._kem = LWEKEM(n=self._n, gpu=gpu)
        self._kem.load_public_key(builder_pk_bytes)
        
        # Extract pk_seed and compute b_hash for key_id
        # pk_bytes format: header(12) + pk_seed(32) + b(k*4) + pk_hash(32)
        pk_seed = builder_pk_bytes[12:44]
        k = self._kem.pk.k
        b_bytes = builder_pk_bytes[44:44 + k * 4]
        b_hash = hashlib.sha256(b_bytes).digest()
        
        self._builder_pk_seed = pk_seed
        self._builder_b_hash = b_hash
        self._builder_pk_blob = pk_seed + b_hash
        self._builder_key_id = self._compute_key_id(pk_seed, b_hash)
        
        # Sender identity
        self._sender_key_id = sender_key_id or secrets.token_bytes(32)
        self._include_sender_pk = include_sender_pk
        self._sender_pk_blob = sender_pk_blob
        
        if include_sender_pk and not sender_pk_blob:
            raise TxEncryptionError("sender_pk_blob required when include_sender_pk=True")
        
        # Sequence counter
        self._sequence = 0
    
    @staticmethod
    def _compute_key_id(pk_seed: bytes, b_hash: bytes) -> bytes:
        """Compute key ID from pk_seed and b_hash."""
        return hashlib.sha256(pk_seed + b_hash).digest()
    
    def encrypt(
        self,
        raw_tx: bytes,
        nonce: Optional[bytes] = None,
    ) -> EncryptedTx:
        """
        Encrypt a raw transaction.
        
        Args:
            raw_tx: Raw transaction bytes
            nonce: Optional nonce (random if not provided)
        
        Returns:
            EncryptedTx with envelope and commit
        """
        timestamp = time.time()
        
        # Generate session ID
        session_id = generate_session_id_random()
        
        # Derive 16-byte stream_id from 8-byte session_id (StreamDEM requires 16B)
        stream_id = hashlib.sha256(b"meteor-nc-stream-id" + session_id).digest()[:16]
        
        # Get sequence
        seq = self._sequence
        self._sequence += 1
        
        # KEM: encapsulate to builder's public key
        # LWEKEM.encaps() uses the loaded public key, returns (shared_secret, ciphertext)
        shared_secret, kem_ct = self._kem.encaps()
        
        # Derive session key from shared secret
        session_key = hashlib.sha256(
            b"meteor-nc-tx-session-v3" + shared_secret
        ).digest()
        
        # Initialize StreamDEM for encryption
        dem = StreamDEM(session_key, stream_id=stream_id)
        
        # Prepare flags
        flags = EnvelopeFlags.NONE
        if self._include_sender_pk:
            flags |= EnvelopeFlags.INCLUDE_PK_BLOB
        
        # Compute AAD
        aad = compute_aad(
            env_type=EnvelopeType.TX_ENCRYPTED,
            suite_id=self._suite_id,
            chain_id=self._chain_id,
            sender_id=self._sender_key_id,
            recipient_id=self._builder_key_id,
            session_id=session_id,
            sequence=seq,
            kem_ct=kem_ct,
            flags=flags,
            pk_blob=self._sender_pk_blob if self._include_sender_pk else None,
        )
        
        # Encrypt transaction (single-shot, is_final=True)
        encrypted_chunk = dem.encrypt_chunk(raw_tx, is_final=True, aad=aad)
        
        # Extract ciphertext and tag from EncryptedChunk
        ciphertext = encrypted_chunk.ciphertext
        tag = encrypted_chunk.tag
        
        # Create envelope
        envelope = SecureEnvelope.create_tx_encrypted(
            chain_id=self._chain_id,
            sender_id=self._sender_key_id,
            recipient_id=self._builder_key_id,
            session_id=session_id,
            sequence=seq,
            kem_ct=kem_ct,
            tag=tag,
            encrypted_tx=ciphertext,
            suite_id=self._suite_id,
            include_pk_blob=self._include_sender_pk,
            pk_blob=self._sender_pk_blob,
        )
        
        # Compute commit for commit-reveal
        commit = compute_commit(envelope)
        
        return EncryptedTx(
            envelope=envelope,
            commit=commit,
            session_key=session_key,  # DEBUG: remove in production
            timestamp=timestamp,
        )
    
    def encrypt_batch(
        self,
        raw_txs: list[bytes],
    ) -> list[EncryptedTx]:
        """
        Encrypt multiple transactions.
        
        Args:
            raw_txs: List of raw transaction bytes
        
        Returns:
            List of EncryptedTx
        """
        return [self.encrypt(tx) for tx in raw_txs]


# =============================================================================
# TxDecryptor (for builder/sequencer)
# =============================================================================

class TxDecryptor:
    """
    Transaction decryptor for builder/sequencer.
    
    Decrypts TX_ENCRYPTED envelopes using the builder's secret key.
    """
    
    def __init__(
        self,
        pk_bytes: bytes,
        sk_bytes: bytes,
        chain_id: int,
        suite_id: int = DEFAULT_SUITE_ID,
        gpu: bool = False,
    ):
        """
        Initialize transaction decryptor.
        
        Args:
            pk_bytes: Builder's public key bytes (for FO verification)
            sk_bytes: Builder's secret key bytes
            chain_id: Expected chain ID
            suite_id: Cryptographic suite
            gpu: Use GPU acceleration
        """
        if not CRYPTO_AVAILABLE:
            raise CryptoNotAvailableError()
        
        self._chain_id = chain_id
        self._suite_id = suite_id
        self._gpu = gpu
        
        # Initialize KEM with keys
        suite = get_suite(suite_id)
        self._kem = LWEKEM(n=suite.n, gpu=gpu)
        self._kem.load_public_key(pk_bytes)
        self._kem._import_secret_key(sk_bytes)
        
        # Extract pk_seed and compute key_id
        pk_seed = pk_bytes[12:44]
        k = self._kem.pk.k
        b_bytes = pk_bytes[44:44 + k * 4]
        b_hash = hashlib.sha256(b_bytes).digest()
        self._key_id = hashlib.sha256(pk_seed + b_hash).digest()
    
    def decrypt(self, envelope: SecureEnvelope) -> bytes:
        """
        Decrypt a TX_ENCRYPTED envelope.
        
        Args:
            envelope: TX_ENCRYPTED SecureEnvelope
        
        Returns:
            Decrypted raw transaction bytes
        
        Raises:
            TxEncryptionError: If decryption fails
        """
        # Validate envelope type
        if envelope.env_type != EnvelopeType.TX_ENCRYPTED:
            raise TxEncryptionError(
                f"Expected TX_ENCRYPTED, got {envelope.env_type.name}"
            )
        
        # Validate chain ID
        if envelope.chain_id != self._chain_id:
            raise TxEncryptionError(
                f"Chain ID mismatch: expected {self._chain_id}, got {envelope.chain_id}"
            )
        
        # Validate recipient (should be us)
        if envelope.recipient_id != self._key_id:
            raise TxEncryptionError("Envelope not addressed to this builder")
        
        # Decapsulate KEM
        try:
            shared_secret = self._kem.decaps(envelope.kem_ct)
        except Exception as e:
            raise TxEncryptionError(f"KEM decapsulation failed: {e}")
        
        # Derive session key
        session_key = hashlib.sha256(
            b"meteor-nc-tx-session-v3" + shared_secret
        ).digest()
        
        # Derive 16-byte stream_id from 8-byte session_id (same as encryptor)
        stream_id = hashlib.sha256(b"meteor-nc-stream-id" + envelope.session_id).digest()[:16]
        
        # Initialize StreamDEM for decryption
        dem = StreamDEM(session_key, stream_id=stream_id)
        
        # Compute AAD
        flags = envelope.flags
        aad = compute_aad(
            env_type=envelope.env_type,
            suite_id=envelope.suite_id,
            chain_id=envelope.chain_id,
            sender_id=envelope.sender_id,
            recipient_id=envelope.recipient_id,
            session_id=envelope.session_id,
            sequence=envelope.sequence,
            kem_ct=envelope.kem_ct,
            flags=flags,
            pk_blob=envelope.pk_blob if envelope.pk_blob else None,
        )
        
        # Reconstruct EncryptedChunk from envelope
        # Note: encrypt_chunk uses internal seq=0 for first chunk
        header = StreamHeader(
            stream_id=stream_id,
            seq=0,  # First (and only) chunk, matches encrypt_chunk's seq
            chunk_len=len(envelope.payload),
            flags=StreamHeader.FLAG_FINAL,  # Single-shot encryption
        )
        chunk = EncryptedChunk(
            header=header,
            ciphertext=envelope.payload,
            tag=envelope.tag,
        )
        
        # Decrypt
        try:
            plaintext = dem.decrypt_chunk(chunk, aad=aad, check_replay=False)
        except Exception as e:
            raise TxEncryptionError(f"Decryption failed: {e}")
        
        return plaintext
    
    def verify_commit(self, envelope: SecureEnvelope, commit: bytes) -> bool:
        """
        Verify that envelope matches a commit.
        
        Args:
            envelope: TX_ENCRYPTED envelope
            commit: Expected commit hash
        
        Returns:
            True if commit matches
        """
        computed = compute_commit(envelope)
        return computed == commit


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test TxEncryptor and TxDecryptor with real cryptography."""
    print("=" * 70)
    print("Meteor-NC Block Mempool: TxEncryptor/TxDecryptor Test")
    print("=" * 70)
    
    if not CRYPTO_AVAILABLE:
        print("\n⚠️  Cryptography modules not available, skipping crypto tests")
        return True
    
    results = {}
    
    # Setup: Generate builder keys
    print("\n[Setup] Generate Builder Keys")
    print("-" * 40)
    
    suite = get_suite(DEFAULT_SUITE_ID)
    kem = LWEKEM(n=suite.n, gpu=False)
    pk_bytes, sk_bytes = kem.key_gen()
    
    print(f"  Suite: Level {suite.security_level} (n={suite.n})")
    print(f"  pk_bytes: {len(pk_bytes)}B")
    print(f"  sk_bytes: {len(sk_bytes)}B")
    
    # Test 1: TxEncryptor creation
    print("\n[Test 1] TxEncryptor Creation")
    print("-" * 40)
    
    chain_id = 1
    try:
        encryptor = TxEncryptor(
            builder_pk_bytes=pk_bytes,
            chain_id=chain_id,
            suite_id=DEFAULT_SUITE_ID,
        )
        results["encryptor"] = True
        print(f"  Builder key ID: {encryptor._builder_key_id.hex()[:16]}...")
        print("  Result: PASS ✓")
    except Exception as e:
        results["encryptor"] = False
        print(f"  Error: {e}")
        print("  Result: FAIL ✗")
        return False
    
    # Test 2: Encrypt transaction
    print("\n[Test 2] Encrypt Transaction")
    print("-" * 40)
    
    raw_tx = b"Hello, this is a test transaction! MEV protection enabled."
    
    try:
        encrypted = encryptor.encrypt(raw_tx)
        results["encrypt"] = (
            encrypted.envelope.env_type == EnvelopeType.TX_ENCRYPTED and
            len(encrypted.commit) == 32 and
            len(encrypted.envelope.to_bytes()) > 0
        )
        print(f"  Original tx: {len(raw_tx)}B")
        print(f"  Envelope wire: {len(encrypted.envelope.to_bytes())}B")
        print(f"  Commit: {encrypted.commit.hex()[:16]}...")
        print(f"  Result: {'PASS ✓' if results['encrypt'] else 'FAIL ✗'}")
    except Exception as e:
        results["encrypt"] = False
        print(f"  Error: {e}")
        print("  Result: FAIL ✗")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 3: TxDecryptor creation
    print("\n[Test 3] TxDecryptor Creation")
    print("-" * 40)
    
    try:
        decryptor = TxDecryptor(
            pk_bytes=pk_bytes,
            sk_bytes=sk_bytes,
            chain_id=chain_id,
            suite_id=DEFAULT_SUITE_ID,
        )
        results["decryptor"] = True
        print(f"  Key ID matches: {decryptor._key_id == encryptor._builder_key_id}")
        print("  Result: PASS ✓")
    except Exception as e:
        results["decryptor"] = False
        print(f"  Error: {e}")
        print("  Result: FAIL ✗")
        return False
    
    # Test 4: Decrypt transaction (ROUNDTRIP!)
    print("\n[Test 4] Decrypt Transaction (Roundtrip)")
    print("-" * 40)
    
    try:
        decrypted_tx = decryptor.decrypt(encrypted.envelope)
        results["roundtrip"] = (decrypted_tx == raw_tx)
        print(f"  Decrypted: {decrypted_tx[:40]}...")
        print(f"  Matches original: {decrypted_tx == raw_tx}")
        print(f"  Result: {'PASS ✓' if results['roundtrip'] else 'FAIL ✗'}")
    except Exception as e:
        results["roundtrip"] = False
        print(f"  Error: {e}")
        print("  Result: FAIL ✗")
        import traceback
        traceback.print_exc()
    
    # Test 5: Commit verification
    print("\n[Test 5] Commit Verification")
    print("-" * 40)
    
    commit_ok = decryptor.verify_commit(encrypted.envelope, encrypted.commit)
    wrong_commit = secrets.token_bytes(32)
    commit_fail = not decryptor.verify_commit(encrypted.envelope, wrong_commit)
    
    results["commit"] = commit_ok and commit_fail
    
    print(f"  Valid commit verified: {commit_ok}")
    print(f"  Wrong commit rejected: {commit_fail}")
    print(f"  Result: {'PASS ✓' if results['commit'] else 'FAIL ✗'}")
    
    # Test 6: Multiple transactions
    print("\n[Test 6] Multiple Transactions")
    print("-" * 40)
    
    txs = [
        b"TX1: Transfer 100 ETH",
        b"TX2: Swap USDC for ETH",
        b"TX3: NFT mint",
    ]
    
    all_ok = True
    for i, tx in enumerate(txs):
        encrypted = encryptor.encrypt(tx)
        decrypted = decryptor.decrypt(encrypted.envelope)
        ok = (decrypted == tx)
        all_ok = all_ok and ok
        print(f"  TX{i+1}: {'OK' if ok else 'FAIL'}")
    
    results["multiple"] = all_ok
    print(f"  Result: {'PASS ✓' if results['multiple'] else 'FAIL ✗'}")
    
    # Test 7: Envelope structure
    print("\n[Test 7] Envelope Structure")
    print("-" * 40)
    
    # Serialize and deserialize
    wire = encrypted.envelope.to_bytes()
    parsed = SecureEnvelope.from_bytes(wire)
    
    results["structure"] = (
        parsed.env_type == EnvelopeType.TX_ENCRYPTED and
        parsed.chain_id == chain_id and
        parsed.recipient_id == encryptor._builder_key_id
    )
    
    print(f"  Wire size: {len(wire)}B")
    print(f"  Type: {parsed.env_type.name}")
    print(f"  Chain ID: {parsed.chain_id}")
    print(f"  Result: {'PASS ✓' if results['structure'] else 'FAIL ✗'}")
    
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
