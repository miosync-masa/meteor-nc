# meteor_nc/block/mempool/shield.py
"""
Meteor-NC Block Mempool: Commit-Reveal Shield

Commit-reveal scheme for front-running and MEV protection.
Provides cryptographic binding between commit and reveal phases.

Flow:
    1. COMMIT: User publishes commit = H(encrypted_envelope)
    2. WAIT: Wait for commit to be confirmed on-chain
    3. REVEAL: User publishes full encrypted_envelope
    4. VERIFY: Builder verifies H(envelope) == commit
    5. DECRYPT: Builder decrypts and includes tx

Security Properties:
    - Binding: commit uniquely identifies the envelope
    - Hiding: commit reveals nothing about tx content
    - Non-malleable: envelope cannot be modified after commit
    - Time-locked: reveal only valid after commit confirmed

Usage:
    from meteor_nc.block.mempool import CommitReveal, ShieldedTx
    
    # Create shielded transaction
    shield = CommitReveal(chain_id=1)
    
    # Phase 1: Commit
    shielded = shield.create_shielded(encrypted_envelope)
    commit_data = shielded.commit_data  # Submit to chain
    
    # Phase 2: After commit confirmed
    reveal_data = shielded.reveal_data  # Submit to builder
    
    # Builder verification
    is_valid = shield.verify(commit, envelope)

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Dict, List, Tuple

# Import from wire module
from ..wire import (
    SecureEnvelope,
    EnvelopeType,
    compute_commit,
)


# =============================================================================
# Exceptions
# =============================================================================

class CommitRevealError(Exception):
    """Base commit-reveal error."""
    pass


class CommitMismatchError(CommitRevealError):
    """Commit does not match envelope."""
    def __init__(self, expected: bytes, got: bytes):
        self.expected = expected
        self.got = got
        super().__init__(
            f"Commit mismatch: expected {expected.hex()[:16]}..., "
            f"got {got.hex()[:16]}..."
        )


class InvalidPhaseError(CommitRevealError):
    """Operation not valid in current phase."""
    def __init__(self, current: str, required: str):
        super().__init__(f"Invalid phase: current={current}, required={required}")


class ExpiredCommitError(CommitRevealError):
    """Commit has expired."""
    def __init__(self, commit: bytes, expired_at: float):
        self.commit = commit
        self.expired_at = expired_at
        super().__init__(f"Commit {commit.hex()[:16]}... expired at {expired_at}")


class DuplicateCommitError(CommitRevealError):
    """Commit already exists."""
    def __init__(self, commit: bytes):
        self.commit = commit
        super().__init__(f"Duplicate commit: {commit.hex()[:16]}...")


# =============================================================================
# Types
# =============================================================================

class CommitPhase(IntEnum):
    """Commit-reveal phase."""
    CREATED = 0       # ShieldedTx created, not yet committed
    COMMITTED = 1     # Commit published on-chain
    REVEALED = 2      # Envelope revealed to builder
    EXECUTED = 3      # Transaction executed
    EXPIRED = 4       # Commit expired without reveal
    INVALID = 5       # Verification failed


@dataclass
class ShieldedTx:
    """
    Shielded transaction with commit-reveal data.
    
    Attributes:
        envelope: Encrypted TX_ENCRYPTED envelope
        commit: Commit hash (32 bytes)
        phase: Current phase
        created_at: Creation timestamp
        committed_at: Commit confirmation timestamp
        revealed_at: Reveal timestamp
        ttl: Time-to-live in seconds (0 = no expiry)
        nonce: Random nonce for uniqueness
    """
    envelope: SecureEnvelope
    commit: bytes
    phase: CommitPhase = CommitPhase.CREATED
    created_at: float = field(default_factory=time.time)
    committed_at: Optional[float] = None
    revealed_at: Optional[float] = None
    ttl: float = 300.0  # 5 minutes default
    nonce: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    
    @property
    def commit_data(self) -> bytes:
        """
        Data to submit for commit phase.
        
        Format: commit(32) || nonce(16) || chain_id(4) || ttl(4)
        """
        import struct
        return (
            self.commit +
            self.nonce +
            struct.pack(">I", self.envelope.chain_id) +
            struct.pack(">I", int(self.ttl))
        )
    
    @property
    def reveal_data(self) -> bytes:
        """
        Data to submit for reveal phase.
        
        Format: commit(32) || nonce(16) || envelope_wire
        """
        return self.commit + self.nonce + self.envelope.to_bytes()
    
    @property
    def tx_id(self) -> bytes:
        """Transaction identifier (first 8 bytes of commit)."""
        return self.commit[:8]
    
    @property
    def is_expired(self) -> bool:
        """Check if commit has expired."""
        if self.ttl == 0:
            return False
        return time.time() > self.created_at + self.ttl
    
    def mark_committed(self, timestamp: Optional[float] = None) -> None:
        """Mark as committed."""
        self.phase = CommitPhase.COMMITTED
        self.committed_at = timestamp or time.time()
    
    def mark_revealed(self, timestamp: Optional[float] = None) -> None:
        """Mark as revealed."""
        self.phase = CommitPhase.REVEALED
        self.revealed_at = timestamp or time.time()
    
    def mark_executed(self) -> None:
        """Mark as executed."""
        self.phase = CommitPhase.EXECUTED
    
    def mark_expired(self) -> None:
        """Mark as expired."""
        self.phase = CommitPhase.EXPIRED
    
    def mark_invalid(self) -> None:
        """Mark as invalid."""
        self.phase = CommitPhase.INVALID


# =============================================================================
# CommitReveal
# =============================================================================

class CommitReveal:
    """
    Commit-reveal scheme manager.
    
    Handles creation, tracking, and verification of shielded transactions.
    """
    
    def __init__(
        self,
        chain_id: int,
        default_ttl: float = 300.0,
        max_pending: int = 1000,
    ):
        """
        Initialize commit-reveal manager.
        
        Args:
            chain_id: Chain ID for validation
            default_ttl: Default TTL for commits (seconds)
            max_pending: Maximum pending commits to track
        """
        self._chain_id = chain_id
        self._default_ttl = default_ttl
        self._max_pending = max_pending
        
        # Pending commits: commit -> ShieldedTx
        self._pending: Dict[bytes, ShieldedTx] = {}
        
        # Revealed commits (for duplicate detection)
        self._revealed: Dict[bytes, float] = {}
    
    # =========================================================================
    # Creation
    # =========================================================================
    
    def create_shielded(
        self,
        envelope: SecureEnvelope,
        ttl: Optional[float] = None,
    ) -> ShieldedTx:
        """
        Create a shielded transaction from encrypted envelope.
        
        Args:
            envelope: TX_ENCRYPTED envelope
            ttl: Time-to-live (uses default if None)
        
        Returns:
            ShieldedTx ready for commit phase
        """
        # Validate envelope type
        if envelope.env_type != EnvelopeType.TX_ENCRYPTED:
            raise CommitRevealError(
                f"Expected TX_ENCRYPTED envelope, got {envelope.env_type.name}"
            )
        
        # Validate chain ID
        if envelope.chain_id != self._chain_id:
            raise CommitRevealError(
                f"Chain ID mismatch: expected {self._chain_id}, got {envelope.chain_id}"
            )
        
        # Compute commit
        commit = compute_commit(envelope)
        
        # Check for duplicates
        if commit in self._pending:
            raise DuplicateCommitError(commit)
        
        # Create shielded tx
        shielded = ShieldedTx(
            envelope=envelope,
            commit=commit,
            ttl=ttl or self._default_ttl,
        )
        
        # Track pending
        self._pending[commit] = shielded
        self._cleanup_expired()
        
        return shielded
    
    def create_commit_only(self, envelope: SecureEnvelope) -> bytes:
        """
        Create commit hash without tracking.
        
        Useful for one-off verification.
        """
        return compute_commit(envelope)
    
    # =========================================================================
    # Phase Transitions
    # =========================================================================
    
    def confirm_commit(
        self,
        commit: bytes,
        timestamp: Optional[float] = None,
    ) -> ShieldedTx:
        """
        Confirm that commit has been published on-chain.
        
        Args:
            commit: Commit hash
            timestamp: Confirmation timestamp
        
        Returns:
            Updated ShieldedTx
        """
        if commit not in self._pending:
            raise CommitRevealError(f"Unknown commit: {commit.hex()[:16]}...")
        
        shielded = self._pending[commit]
        
        if shielded.is_expired:
            shielded.mark_expired()
            raise ExpiredCommitError(commit, shielded.created_at + shielded.ttl)
        
        shielded.mark_committed(timestamp)
        return shielded
    
    def reveal(self, commit: bytes) -> Tuple[ShieldedTx, bytes]:
        """
        Get reveal data for a confirmed commit.
        
        Args:
            commit: Commit hash
        
        Returns:
            (ShieldedTx, reveal_data)
        """
        if commit not in self._pending:
            raise CommitRevealError(f"Unknown commit: {commit.hex()[:16]}...")
        
        shielded = self._pending[commit]
        
        if shielded.phase != CommitPhase.COMMITTED:
            raise InvalidPhaseError(shielded.phase.name, "COMMITTED")
        
        if shielded.is_expired:
            shielded.mark_expired()
            raise ExpiredCommitError(commit, shielded.created_at + shielded.ttl)
        
        shielded.mark_revealed()
        self._revealed[commit] = time.time()
        
        return shielded, shielded.reveal_data
    
    def mark_executed(self, commit: bytes) -> None:
        """Mark transaction as executed."""
        if commit in self._pending:
            self._pending[commit].mark_executed()
            del self._pending[commit]
    
    # =========================================================================
    # Verification (for builder/sequencer)
    # =========================================================================
    
    def verify(
        self,
        commit: bytes,
        envelope: SecureEnvelope,
    ) -> bool:
        """
        Verify that envelope matches commit.
        
        Args:
            commit: Published commit hash
            envelope: Revealed envelope
        
        Returns:
            True if valid
        
        Raises:
            CommitMismatchError: If commit doesn't match
        """
        computed = compute_commit(envelope)
        
        if computed != commit:
            raise CommitMismatchError(commit, computed)
        
        return True
    
    def verify_and_extract(
        self,
        commit: bytes,
        reveal_data: bytes,
    ) -> SecureEnvelope:
        """
        Verify reveal data and extract envelope.
        
        Args:
            commit: Published commit hash
            reveal_data: Full reveal data (commit || nonce || envelope_wire)
        
        Returns:
            Verified SecureEnvelope
        """
        # Parse reveal data
        if len(reveal_data) < 48:  # 32 (commit) + 16 (nonce)
            raise CommitRevealError("Reveal data too short")
        
        reveal_commit = reveal_data[:32]
        reveal_nonce = reveal_data[32:48]
        envelope_wire = reveal_data[48:]
        
        # Verify commit matches
        if reveal_commit != commit:
            raise CommitMismatchError(commit, reveal_commit)
        
        # Parse envelope
        envelope = SecureEnvelope.from_bytes(envelope_wire)
        
        # Verify envelope produces same commit
        self.verify(commit, envelope)
        
        return envelope
    
    # =========================================================================
    # Management
    # =========================================================================
    
    def get_pending(self, commit: bytes) -> Optional[ShieldedTx]:
        """Get pending shielded tx by commit."""
        return self._pending.get(commit)
    
    def get_all_pending(self) -> List[ShieldedTx]:
        """Get all pending shielded txs."""
        return list(self._pending.values())
    
    def cancel(self, commit: bytes) -> bool:
        """
        Cancel a pending commit (before reveal).
        
        Returns True if cancelled, False if not found.
        """
        if commit in self._pending:
            del self._pending[commit]
            return True
        return False
    
    def _cleanup_expired(self) -> int:
        """Clean up expired commits. Returns count of cleaned."""
        expired = [
            commit for commit, shielded in self._pending.items()
            if shielded.is_expired
        ]
        
        for commit in expired:
            self._pending[commit].mark_expired()
            del self._pending[commit]
        
        # Also clean old revealed entries (older than 1 hour)
        cutoff = time.time() - 3600
        old_revealed = [c for c, t in self._revealed.items() if t < cutoff]
        for commit in old_revealed:
            del self._revealed[commit]
        
        return len(expired)
    
    def stats(self) -> Dict[str, int]:
        """Get statistics."""
        self._cleanup_expired()
        
        phases = {}
        for shielded in self._pending.values():
            name = shielded.phase.name
            phases[name] = phases.get(name, 0) + 1
        
        return {
            "pending": len(self._pending),
            "revealed_total": len(self._revealed),
            **phases,
        }


# =============================================================================
# Batch Operations
# =============================================================================

class BatchCommitReveal:
    """
    Batch commit-reveal for multiple transactions.
    
    Allows committing multiple txs in a single on-chain operation.
    """
    
    def __init__(self, chain_id: int, default_ttl: float = 300.0):
        self._chain_id = chain_id
        self._default_ttl = default_ttl
        self._manager = CommitReveal(chain_id, default_ttl)
    
    def create_batch_commit(
        self,
        envelopes: List[SecureEnvelope],
        ttl: Optional[float] = None,
    ) -> Tuple[bytes, List[ShieldedTx]]:
        """
        Create a batch commit for multiple envelopes.
        
        Args:
            envelopes: List of TX_ENCRYPTED envelopes
            ttl: Time-to-live
        
        Returns:
            (batch_commit, list of ShieldedTx)
        """
        shielded_txs = []
        individual_commits = []
        
        for envelope in envelopes:
            shielded = self._manager.create_shielded(envelope, ttl)
            shielded_txs.append(shielded)
            individual_commits.append(shielded.commit)
        
        # Batch commit = H(commit_1 || commit_2 || ... || commit_n)
        h = hashlib.sha256()
        h.update(b"meteor-nc-batch-commit-v3")
        for commit in individual_commits:
            h.update(commit)
        batch_commit = h.digest()
        
        return batch_commit, shielded_txs
    
    def verify_batch(
        self,
        batch_commit: bytes,
        envelopes: List[SecureEnvelope],
    ) -> bool:
        """Verify batch commit against envelopes."""
        individual_commits = [compute_commit(env) for env in envelopes]
        
        h = hashlib.sha256()
        h.update(b"meteor-nc-batch-commit-v3")
        for commit in individual_commits:
            h.update(commit)
        computed = h.digest()
        
        return computed == batch_commit


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test CommitReveal and ShieldedTx."""
    print("=" * 70)
    print("Meteor-NC Block Mempool: CommitReveal Test")
    print("=" * 70)
    
    from ..wire import generate_session_id_random, get_suite, DEFAULT_SUITE_ID
    
    results = {}
    
    # Setup
    print("\n[Setup] Create Test Envelopes")
    print("-" * 40)
    
    chain_id = 1
    sender_id = secrets.token_bytes(32)
    recipient_id = secrets.token_bytes(32)
    session_id = generate_session_id_random()
    suite = get_suite(DEFAULT_SUITE_ID)
    kem_ct = secrets.token_bytes(suite.kem_ct_size)
    tag = secrets.token_bytes(16)
    payload = b"test_encrypted_tx_data"
    
    envelope = SecureEnvelope.create_tx_encrypted(
        chain_id=chain_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
        session_id=session_id,
        sequence=0,
        kem_ct=kem_ct,
        tag=tag,
        encrypted_tx=payload,
        suite_id=DEFAULT_SUITE_ID,
    )
    
    print(f"  Envelope type: {envelope.env_type.name}")
    print(f"  Chain ID: {envelope.chain_id}")
    
    # Test 1: Create CommitReveal
    print("\n[Test 1] Create CommitReveal Manager")
    print("-" * 40)
    
    cr = CommitReveal(chain_id=chain_id, default_ttl=300.0)
    results["creation"] = True
    print(f"  Manager created for chain {chain_id}")
    print("  Result: PASS ✓")
    
    # Test 2: Create ShieldedTx
    print("\n[Test 2] Create ShieldedTx")
    print("-" * 40)
    
    shielded = cr.create_shielded(envelope)
    
    results["shielded"] = (
        len(shielded.commit) == 32 and
        shielded.phase == CommitPhase.CREATED and
        shielded.envelope == envelope
    )
    
    print(f"  Commit: {shielded.commit.hex()[:32]}...")
    print(f"  Phase: {shielded.phase.name}")
    print(f"  TTL: {shielded.ttl}s")
    print(f"  Result: {'PASS ✓' if results['shielded'] else 'FAIL ✗'}")
    
    # Test 3: Commit data format
    print("\n[Test 3] Commit Data Format")
    print("-" * 40)
    
    commit_data = shielded.commit_data
    expected_len = 32 + 16 + 4 + 4  # commit + nonce + chain_id + ttl
    
    results["commit_data"] = len(commit_data) == expected_len
    
    print(f"  Commit data length: {len(commit_data)}B (expected {expected_len})")
    print(f"  Result: {'PASS ✓' if results['commit_data'] else 'FAIL ✗'}")
    
    # Test 4: Phase transitions
    print("\n[Test 4] Phase Transitions")
    print("-" * 40)
    
    # Confirm commit
    cr.confirm_commit(shielded.commit)
    phase_ok_1 = shielded.phase == CommitPhase.COMMITTED
    print(f"  After confirm: {shielded.phase.name}")
    
    # Reveal
    _, reveal_data = cr.reveal(shielded.commit)
    phase_ok_2 = shielded.phase == CommitPhase.REVEALED
    print(f"  After reveal: {shielded.phase.name}")
    
    results["phases"] = phase_ok_1 and phase_ok_2
    print(f"  Result: {'PASS ✓' if results['phases'] else 'FAIL ✗'}")
    
    # Test 5: Verification
    print("\n[Test 5] Commit Verification")
    print("-" * 40)
    
    # Create new envelope for verification test
    envelope2 = SecureEnvelope.create_tx_encrypted(
        chain_id=chain_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
        session_id=generate_session_id_random(),
        sequence=1,
        kem_ct=kem_ct,
        tag=tag,
        encrypted_tx=b"another_tx",
        suite_id=DEFAULT_SUITE_ID,
    )
    
    commit2 = compute_commit(envelope2)
    
    # Verify correct commit
    verify_ok = cr.verify(commit2, envelope2)
    print(f"  Valid commit verified: {verify_ok}")
    
    # Verify wrong commit should fail
    wrong_commit_failed = False
    try:
        cr.verify(shielded.commit, envelope2)  # Wrong commit
    except CommitMismatchError:
        wrong_commit_failed = True
        print("  Invalid commit rejected: True")
    
    results["verification"] = verify_ok and wrong_commit_failed
    print(f"  Result: {'PASS ✓' if results['verification'] else 'FAIL ✗'}")
    
    # Test 6: Reveal data verification
    print("\n[Test 6] Reveal Data Verification")
    print("-" * 40)
    
    # Parse and verify reveal data
    reveal_commit = reveal_data[:32]
    reveal_nonce = reveal_data[32:48]
    envelope_wire = reveal_data[48:]
    
    parsed_envelope = SecureEnvelope.from_bytes(envelope_wire)
    verify_reveal = cr.verify(reveal_commit, parsed_envelope)
    
    results["reveal_verify"] = verify_reveal and parsed_envelope.payload == envelope.payload
    
    print(f"  Reveal commit matches: {reveal_commit == shielded.commit}")
    print(f"  Envelope parsed: {parsed_envelope.env_type.name}")
    print(f"  Payload matches: {parsed_envelope.payload == envelope.payload}")
    print(f"  Result: {'PASS ✓' if results['reveal_verify'] else 'FAIL ✗'}")
    
    # Test 7: Duplicate detection
    print("\n[Test 7] Duplicate Detection")
    print("-" * 40)
    
    cr2 = CommitReveal(chain_id=chain_id)
    _ = cr2.create_shielded(envelope2)
    
    duplicate_rejected = False
    try:
        cr2.create_shielded(envelope2)  # Same envelope again
    except DuplicateCommitError:
        duplicate_rejected = True
    
    results["duplicate"] = duplicate_rejected
    print(f"  Duplicate rejected: {duplicate_rejected}")
    print(f"  Result: {'PASS ✓' if results['duplicate'] else 'FAIL ✗'}")
    
    # Test 8: Batch commit
    print("\n[Test 8] Batch Commit")
    print("-" * 40)
    
    envelopes = []
    for i in range(3):
        env = SecureEnvelope.create_tx_encrypted(
            chain_id=chain_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            session_id=generate_session_id_random(),
            sequence=i + 10,
            kem_ct=kem_ct,
            tag=tag,
            encrypted_tx=f"batch_tx_{i}".encode(),
            suite_id=DEFAULT_SUITE_ID,
        )
        envelopes.append(env)
    
    batch_cr = BatchCommitReveal(chain_id)
    batch_commit, batch_shielded = batch_cr.create_batch_commit(envelopes)
    
    batch_verify = batch_cr.verify_batch(batch_commit, envelopes)
    
    results["batch"] = (
        len(batch_commit) == 32 and
        len(batch_shielded) == 3 and
        batch_verify
    )
    
    print(f"  Batch commit: {batch_commit.hex()[:32]}...")
    print(f"  Batch size: {len(batch_shielded)} txs")
    print(f"  Batch verified: {batch_verify}")
    print(f"  Result: {'PASS ✓' if results['batch'] else 'FAIL ✗'}")
    
    # Test 9: Stats
    print("\n[Test 9] Statistics")
    print("-" * 40)
    
    stats = cr.stats()
    results["stats"] = "pending" in stats
    
    print(f"  Stats: {stats}")
    print(f"  Result: {'PASS ✓' if results['stats'] else 'FAIL ✗'}")
    
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
