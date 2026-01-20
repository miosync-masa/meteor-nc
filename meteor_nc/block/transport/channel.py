# meteor_nc/block/transport/channel.py
"""
Meteor-NC Block Transport: SecureChannel

Encrypted P2P communication channel using:
- LWEKEM for post-quantum key exchange
- StreamDEM for authenticated encryption
- SecureEnvelope v0.3 for wire format

Channel Lifecycle:
    1. create() - Generate local identity
    2. connect(peer_pk_blob) - Initiator sends HANDSHAKE
    3. accept(handshake) - Responder receives HANDSHAKE, sends response
    4. finalize(response) - Initiator finalizes handshake
    5. send(data) - Send encrypted DATA
    6. receive(envelope) - Receive and decrypt
    7. close() - Send CLOSE and terminate

State Machine:
    CREATED -> CONNECTING -> CONNECTED -> CLOSED
              (initiator)
    CREATED -> ACCEPTING -> CONNECTED -> CLOSED
              (responder)

Security:
    - Post-quantum secure (LWE-KEM)
    - Forward secrecy (fresh KEM per session)
    - Replay protection (session_id + sequence)
    - Domain separation (chain_id, sender_id, recipient_id)

Usage:
    # Initiator (Alice)
    alice = SecureChannel.create(chain_id=1)
    handshake = alice.connect(bob_pk_blob)
    # send handshake to Bob...
    alice.finalize(bob_response)
    
    # Responder (Bob)
    bob = SecureChannel.create(chain_id=1)
    response = bob.accept(handshake)
    # send response to Alice...
    
    # Encrypted communication
    env = alice.send(b"Hello Bob!")
    data = bob.receive(env)

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import hashlib
import secrets
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Tuple, Dict, Any

import numpy as np

# Cryptography primitives
from ...cryptography.core import LWEKEM
from ...cryptography.stream import StreamDEM, EncryptedChunk, StreamHeader
from ...cryptography.common import _sha256

# Wire format
from ..wire import (
    SecureEnvelope,
    EnvelopeType,
    EnvelopeFlags,
    compute_aad,
    generate_session_id_random,
    create_pk_blob,
    parse_pk_blob,
    SUITES,
    get_suite,
    get_auth_size,
    DEFAULT_SUITE_ID,
    DEFAULT_AUTH_SCHEME_ID,
    PK_BLOB_SIZE,
    TAG_SIZE,
)


# =============================================================================
# Exceptions
# =============================================================================

class ChannelError(Exception):
    """Base exception for channel errors."""
    pass


class HandshakeError(ChannelError):
    """Handshake failed."""
    pass


class DecryptionError(ChannelError):
    """Decryption failed."""
    pass


class StateError(ChannelError):
    """Invalid state for operation."""
    pass


# =============================================================================
# Channel State
# =============================================================================

class ChannelState(Enum):
    """Channel state machine."""
    CREATED = auto()      # Initial state, identity generated
    CONNECTING = auto()   # Initiator: sent HANDSHAKE, awaiting response
    ACCEPTING = auto()    # Responder: received HANDSHAKE, sent response
    CONNECTED = auto()    # Handshake complete, can send/receive
    CLOSED = auto()       # Channel closed


# =============================================================================
# Local Identity
# =============================================================================

@dataclass
class LocalIdentity:
    """Local channel identity."""
    key_id: bytes           # 32B - derived from pk_hash
    pk_seed: bytes          # 32B - for matrix A reconstruction
    b_hash: bytes           # 32B - hash of public key vector b
    pk_bytes: bytes         # Full serialized public key
    sk_bytes: bytes         # Secret key (KEEP SECRET!)
    
    @property
    def pk_blob(self) -> bytes:
        """64B public key blob for sharing."""
        return create_pk_blob(self.pk_seed, self.b_hash)


# =============================================================================
# Secure Channel
# =============================================================================

class SecureChannel:
    """
    Secure communication channel using Meteor-NC KEM.
    
    Thread-safe for single-direction operations (send OR receive).
    Not thread-safe for bidirectional concurrent operations.
    """
    
    def __init__(
        self,
        identity: LocalIdentity,
        kem: LWEKEM,
        chain_id: int,
        suite_id: int,
        auth_scheme: int,
        gpu: bool,
        device_id: int,
    ):
        """
        Internal constructor. Use create() instead.
        """
        self._identity = identity
        self._kem = kem
        self._chain_id = chain_id
        self._suite_id = suite_id
        self._auth_scheme = auth_scheme
        self._gpu = gpu
        self._device_id = device_id
        
        # State
        self._state = ChannelState.CREATED
        
        # Peer info (set during handshake)
        self._peer_key_id: Optional[bytes] = None
        self._peer_pk_blob: Optional[bytes] = None
        self._peer_pk_bytes: Optional[bytes] = None
        
        # Session (established after handshake)
        self._session_id: Optional[bytes] = None
        self._send_sequence: int = 0
        self._recv_sequence: int = 0
        
        # DEM (created after handshake)
        self._send_dem: Optional[StreamDEM] = None
        self._recv_dem: Optional[StreamDEM] = None
        
        # Handshake state
        self._handshake_K: Optional[bytes] = None  # Temporary, cleared after finalize
    
    # =========================================================================
    # Factory
    # =========================================================================
    
    @classmethod
    def create(
        cls,
        chain_id: int = 1,
        suite_id: int = DEFAULT_SUITE_ID,
        auth_scheme: int = DEFAULT_AUTH_SCHEME_ID,
        gpu: bool = True,
        device_id: int = 0,
        seed: Optional[bytes] = None,
    ) -> SecureChannel:
        """
        Create a new secure channel with fresh identity.
        
        Args:
            chain_id: EVM chain ID (default: 1 for mainnet)
            suite_id: Cryptographic suite (0x01=L1, 0x02=L3, 0x03=L5)
            auth_scheme: Authentication scheme
            gpu: Enable GPU acceleration
            device_id: GPU device ID
            seed: Optional seed for deterministic key generation
        
        Returns:
            SecureChannel instance in CREATED state
        """
        # Get suite params
        suite = get_suite(suite_id)
        n = suite.n
        
        # Create KEM
        kem = LWEKEM(
            n=n,
            gpu=gpu,
            device_id=device_id,
            seed=seed,
            use_compression=True,
        )
        
        # Generate keys
        pk_bytes, sk_bytes = kem.key_gen()
        
        # Extract pk_seed and compute b_hash
        # pk_bytes format: header(12) + pk_seed(32) + b(k*4) + pk_hash(32)
        pk_seed = pk_bytes[12:44]
        pk_hash = pk_bytes[-32:]
        
        # Compute b_hash from the b portion
        b_bytes = pk_bytes[44:-32]
        b_hash = _sha256(b"b_hash", b_bytes)
        
        # key_id = H(pk_seed || b_hash)
        key_id = _sha256(b"key_id", pk_seed, b_hash)
        
        identity = LocalIdentity(
            key_id=key_id,
            pk_seed=pk_seed,
            b_hash=b_hash,
            pk_bytes=pk_bytes,
            sk_bytes=sk_bytes,
        )
        
        return cls(
            identity=identity,
            kem=kem,
            chain_id=chain_id,
            suite_id=suite_id,
            auth_scheme=auth_scheme,
            gpu=gpu,
            device_id=device_id,
        )
    
    # =========================================================================
    # Properties
    # =========================================================================
    
    @property
    def state(self) -> ChannelState:
        """Current channel state."""
        return self._state
    
    @property
    def key_id(self) -> bytes:
        """Local 32-byte key ID."""
        return self._identity.key_id
    
    @property
    def pk_blob(self) -> bytes:
        """Local 64-byte public key blob for sharing."""
        return self._identity.pk_blob
    
    @property
    def chain_id(self) -> int:
        return self._chain_id
    
    @property
    def suite_id(self) -> int:
        return self._suite_id
    
    @property
    def session_id(self) -> Optional[bytes]:
        return self._session_id
    
    @property
    def is_connected(self) -> bool:
        return self._state == ChannelState.CONNECTED
    
    # =========================================================================
    # Handshake: Initiator
    # =========================================================================
    
    def connect(self, peer_pk_blob: bytes) -> SecureEnvelope:
        """
        Initiate handshake to peer (INITIATOR side).
        
        Args:
            peer_pk_blob: Peer's 64-byte public key blob
        
        Returns:
            HANDSHAKE envelope to send to peer
        
        Raises:
            StateError: If not in CREATED state
        """
        if self._state != ChannelState.CREATED:
            raise StateError(f"Cannot connect in state {self._state}")
        
        if len(peer_pk_blob) != PK_BLOB_SIZE:
            raise ValueError(f"peer_pk_blob must be {PK_BLOB_SIZE}B")
        
        # Parse peer pk_blob
        peer_pk_seed, peer_b_hash = parse_pk_blob(peer_pk_blob)
        peer_key_id = _sha256(b"key_id", peer_pk_seed, peer_b_hash)
        
        self._peer_pk_blob = peer_pk_blob
        self._peer_key_id = peer_key_id
        
        # Generate session ID
        self._session_id = generate_session_id_random()
        
        # KEM encapsulation with OUR key (will be ignored by peer)
        # Real key exchange happens when peer responds
        suite = get_suite(self._suite_id)
        kem_ct = secrets.token_bytes(suite.kem_ct_size)  # Placeholder
        
        # PROTOCOL: Include full pk_bytes in payload so peer can encaps to us
        payload = self._identity.pk_bytes
        
        # Create handshake envelope
        envelope = SecureEnvelope.create_handshake(
            chain_id=self._chain_id,
            sender_id=self._identity.key_id,
            recipient_id=peer_key_id,
            session_id=self._session_id,
            pk_blob=self._identity.pk_blob,
            kem_ct=kem_ct,
            tag=secrets.token_bytes(TAG_SIZE),  # Placeholder
            payload=payload,  # Full pk_bytes for peer to use
            suite_id=self._suite_id,
            auth_scheme=self._auth_scheme,
        )
        
        self._state = ChannelState.CONNECTING
        return envelope
    
    def finalize(self, response: SecureEnvelope) -> None:
        """
        Finalize handshake after receiving peer's response (INITIATOR side).
        
        Args:
            response: HANDSHAKE response from peer
        
        Raises:
            StateError: If not in CONNECTING state
            HandshakeError: If response is invalid
        """
        if self._state != ChannelState.CONNECTING:
            raise StateError(f"Cannot finalize in state {self._state}")
        
        # Validate response
        if response.env_type != EnvelopeType.HANDSHAKE:
            raise HandshakeError(f"Expected HANDSHAKE, got {response.env_type}")
        
        if response.chain_id != self._chain_id:
            raise HandshakeError(f"Chain ID mismatch: {response.chain_id} != {self._chain_id}")
        
        if response.recipient_id != self._identity.key_id:
            raise HandshakeError("Response not addressed to us")
        
        # Extract peer's pk_blob
        if not response.has_pk_blob:
            raise HandshakeError("Response missing pk_blob")
        
        self._peer_pk_blob = response.pk_blob
        peer_pk_seed, peer_b_hash = parse_pk_blob(response.pk_blob)
        self._peer_key_id = _sha256(b"key_id", peer_pk_seed, peer_b_hash)
        
        # Get peer's full pk_bytes from payload
        self._peer_pk_bytes = response.payload
        
        # Decaps the response KEM with OUR secret key
        # (peer encapped to our public key)
        K = self._kem.decaps(response.kem_ct)
        
        # Derive session keys
        self._setup_session_keys(K)
        
        # Clear handshake state
        self._handshake_K = None
        
        self._state = ChannelState.CONNECTED
    
    # =========================================================================
    # Handshake: Responder
    # =========================================================================
    
    def accept(self, handshake: SecureEnvelope) -> SecureEnvelope:
        """
        Accept incoming handshake (RESPONDER side).
        
        Args:
            handshake: HANDSHAKE envelope from initiator
        
        Returns:
            HANDSHAKE response envelope
        
        Raises:
            StateError: If not in CREATED state
            HandshakeError: If handshake is invalid
        """
        if self._state != ChannelState.CREATED:
            raise StateError(f"Cannot accept in state {self._state}")
        
        # Validate handshake
        if handshake.env_type != EnvelopeType.HANDSHAKE:
            raise HandshakeError(f"Expected HANDSHAKE, got {handshake.env_type}")
        
        if handshake.chain_id != self._chain_id:
            raise HandshakeError(f"Chain ID mismatch: {handshake.chain_id} != {self._chain_id}")
        
        if handshake.recipient_id != self._identity.key_id:
            raise HandshakeError("Handshake not addressed to us")
        
        # Extract peer's pk_blob
        if not handshake.has_pk_blob:
            raise HandshakeError("Handshake missing pk_blob")
        
        self._peer_pk_blob = handshake.pk_blob
        peer_pk_seed, peer_b_hash = parse_pk_blob(handshake.pk_blob)
        self._peer_key_id = _sha256(b"key_id", peer_pk_seed, peer_b_hash)
        
        # PROTOCOL: Get peer's full pk_bytes from payload
        peer_pk_bytes = handshake.payload
        if len(peer_pk_bytes) == 0:
            raise HandshakeError("Handshake missing pk_bytes in payload")
        
        self._peer_pk_bytes = peer_pk_bytes
        
        # Use initiator's session_id
        self._session_id = handshake.session_id
        
        # Create KEM for encapsulation TO PEER (using peer's public key)
        suite = get_suite(self._suite_id)
        peer_kem = LWEKEM(
            n=suite.n,
            gpu=self._gpu,
            device_id=self._device_id,
            use_compression=True,
        )
        peer_kem.load_public_key(peer_pk_bytes)
        
        # Encaps to PEER's public key
        K, kem_ct = peer_kem.encaps()
        
        # Derive session keys
        self._setup_session_keys(K)
        
        # Create response envelope (include our full pk_bytes for peer)
        response = SecureEnvelope.create_handshake(
            chain_id=self._chain_id,
            sender_id=self._identity.key_id,
            recipient_id=self._peer_key_id,
            session_id=self._session_id,
            pk_blob=self._identity.pk_blob,
            kem_ct=kem_ct,
            tag=secrets.token_bytes(TAG_SIZE),
            payload=self._identity.pk_bytes,  # Our full pk_bytes
            suite_id=self._suite_id,
            auth_scheme=self._auth_scheme,
        )
        
        self._state = ChannelState.CONNECTED
        return response
    
    # =========================================================================
    # Session Key Setup
    # =========================================================================
    
    def _setup_session_keys(self, K: bytes) -> None:
        """Derive send/recv DEMs from shared secret K."""
        # Derive session key (same for both directions)
        session_key = _sha256(b"session_key", K, self._session_id)
        
        # Direction is determined by key_id order
        # Lower key_id sends on stream_id_A, receives on stream_id_B
        # Higher key_id sends on stream_id_B, receives on stream_id_A
        key_ids = sorted([self._identity.key_id, self._peer_key_id])
        stream_id_A = _sha256(b"stream_A", self._session_id, key_ids[0])[:16]
        stream_id_B = _sha256(b"stream_B", self._session_id, key_ids[1])[:16]
        
        if self._identity.key_id == key_ids[0]:
            # We have lower key_id
            send_stream_id = stream_id_A
            recv_stream_id = stream_id_B
        else:
            # We have higher key_id
            send_stream_id = stream_id_B
            recv_stream_id = stream_id_A
        
        # Create DEMs with same key, different stream_ids
        self._send_dem = StreamDEM(
            session_key=session_key,
            stream_id=send_stream_id,
            gpu=self._gpu,
            device_id=self._device_id,
        )
        
        self._recv_dem = StreamDEM(
            session_key=session_key,
            stream_id=recv_stream_id,
            gpu=self._gpu,
            device_id=self._device_id,
        )
    
    # =========================================================================
    # Send / Receive
    # =========================================================================
    
    def send(self, data: bytes) -> SecureEnvelope:
        """
        Encrypt and send data.
        
        Args:
            data: Plaintext data to send
        
        Returns:
            DATA envelope containing encrypted data
        
        Raises:
            StateError: If not connected
        """
        if self._state != ChannelState.CONNECTED:
            raise StateError(f"Cannot send in state {self._state}")
        
        # Get next sequence
        seq = self._send_sequence
        self._send_sequence += 1
        
        # Compute AAD
        aad = compute_aad(
            env_type=EnvelopeType.DATA,
            suite_id=self._suite_id,
            chain_id=self._chain_id,
            sender_id=self._identity.key_id,
            recipient_id=self._peer_key_id,
            session_id=self._session_id,
            sequence=seq,
            kem_ct=b"",  # No KEM for data messages
            flags=EnvelopeFlags.NONE,
        )
        
        # Encrypt
        chunk = self._send_dem.encrypt_chunk(data, aad=aad)
        
        # Create KEM ciphertext (placeholder - reuse session)
        # For efficiency, we could reuse the session key
        # But for forward secrecy, we'd generate new KEM per message
        # DECISION: Reuse session key, KEM ciphertext is placeholder
        suite = get_suite(self._suite_id)
        kem_ct = secrets.token_bytes(suite.kem_ct_size)  # Placeholder
        
        # Build envelope
        envelope = SecureEnvelope.create_data(
            chain_id=self._chain_id,
            sender_id=self._identity.key_id,
            recipient_id=self._peer_key_id,
            session_id=self._session_id,
            sequence=seq,
            kem_ct=kem_ct,
            tag=chunk.tag,
            payload=chunk.ciphertext,
            suite_id=self._suite_id,
            auth_scheme=self._auth_scheme,
        )
        
        return envelope
    
    def receive(self, envelope: SecureEnvelope) -> bytes:
        """
        Receive and decrypt data.
        
        Args:
            envelope: Received DATA envelope
        
        Returns:
            Decrypted plaintext
        
        Raises:
            StateError: If not connected
            DecryptionError: If decryption fails
        """
        if self._state != ChannelState.CONNECTED:
            raise StateError(f"Cannot receive in state {self._state}")
        
        # Validate envelope
        if envelope.env_type != EnvelopeType.DATA:
            raise DecryptionError(f"Expected DATA, got {envelope.env_type}")
        
        if envelope.chain_id != self._chain_id:
            raise DecryptionError(f"Chain ID mismatch")
        
        if envelope.recipient_id != self._identity.key_id:
            raise DecryptionError("Message not addressed to us")
        
        if envelope.session_id != self._session_id:
            raise DecryptionError("Session ID mismatch")
        
        # Replay protection
        seq = envelope.sequence
        if seq < self._recv_sequence:
            raise DecryptionError(f"Replay detected: seq {seq} < {self._recv_sequence}")
        
        self._recv_sequence = seq + 1
        
        # Compute AAD
        aad = compute_aad(
            env_type=EnvelopeType.DATA,
            suite_id=self._suite_id,
            chain_id=self._chain_id,
            sender_id=envelope.sender_id,
            recipient_id=self._identity.key_id,
            session_id=self._session_id,
            sequence=seq,
            kem_ct=b"",
            flags=EnvelopeFlags.NONE,
        )
        
        # Build chunk for decryption
        # Note: Use envelope.sequence as StreamDEM derives nonce from seq
        header = StreamHeader(
            stream_id=self._recv_dem.stream_id,
            seq=seq,  # Must match sender's StreamDEM._encrypt_seq
            chunk_len=len(envelope.payload),
            flags=0,
        )
        chunk = EncryptedChunk(
            header=header,
            ciphertext=envelope.payload,
            tag=envelope.tag,
        )
        
        # Decrypt (StreamDEM will verify internally)
        try:
            # Reset recv_dem sequence to match envelope sequence
            self._recv_dem._seen_seqs.clear()  # Allow any sequence
            plaintext = self._recv_dem.decrypt_chunk(chunk, aad=aad, check_replay=False)
            return plaintext
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}")
    
    # =========================================================================
    # Close
    # =========================================================================
    
    def close(self) -> Optional[SecureEnvelope]:
        """
        Close the channel.
        
        Returns:
            CLOSE envelope to send (or None if not connected)
        """
        if self._state == ChannelState.CLOSED:
            return None
        
        envelope = None
        
        if self._state == ChannelState.CONNECTED:
            # Send CLOSE
            suite = get_suite(self._suite_id)
            kem_ct = secrets.token_bytes(suite.kem_ct_size)
            
            envelope = SecureEnvelope.create_close(
                chain_id=self._chain_id,
                sender_id=self._identity.key_id,
                recipient_id=self._peer_key_id,
                session_id=self._session_id,
                sequence=self._send_sequence,
                kem_ct=kem_ct,
                tag=secrets.token_bytes(TAG_SIZE),
                suite_id=self._suite_id,
            )
        
        # Clear sensitive state
        self._handshake_K = None
        self._send_dem = None
        self._recv_dem = None
        
        self._state = ChannelState.CLOSED
        return envelope
    
    def __repr__(self) -> str:
        return (
            f"SecureChannel(state={self._state.name}, "
            f"chain={self._chain_id}, suite=0x{self._suite_id:02x}, "
            f"key_id={self._identity.key_id.hex()[:8]}...)"
        )


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test SecureChannel."""
    print("=" * 70)
    print("Meteor-NC Block Transport: SecureChannel Test")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Channel creation
    print("\n[Test 1] Channel Creation")
    print("-" * 40)
    
    try:
        alice = SecureChannel.create(chain_id=1, suite_id=0x01, gpu=False)
        bob = SecureChannel.create(chain_id=1, suite_id=0x01, gpu=False)
        
        print(f"  Alice: {alice}")
        print(f"  Bob: {bob}")
        print(f"  Alice pk_blob: {len(alice.pk_blob)}B")
        print(f"  Bob pk_blob: {len(bob.pk_blob)}B")
        
        results["creation"] = True
        print("  Result: PASS ✓")
    except Exception as e:
        results["creation"] = False
        print(f"  Result: FAIL ✗ ({e})")
    
    # Test 2: Handshake
    print("\n[Test 2] Handshake")
    print("-" * 40)
    
    try:
        # Alice initiates
        handshake = alice.connect(bob.pk_blob)
        print(f"  Alice -> Bob HANDSHAKE: {handshake.total_size}B")
        print(f"  Alice state: {alice.state}")
        
        # Bob accepts
        response = bob.accept(handshake)
        print(f"  Bob -> Alice RESPONSE: {response.total_size}B")
        print(f"  Bob state: {bob.state}")
        
        # Alice finalizes
        alice.finalize(response)
        print(f"  Alice state: {alice.state}")
        
        results["handshake"] = (
            alice.is_connected and
            bob.is_connected and
            alice.session_id == bob.session_id
        )
        print(f"  Session ID match: {alice.session_id.hex()[:16]}")
        print(f"  Result: {'PASS ✓' if results['handshake'] else 'FAIL ✗'}")
    except Exception as e:
        results["handshake"] = False
        print(f"  Result: FAIL ✗ ({e})")
        import traceback
        traceback.print_exc()
    
    # Test 3: Send/Receive (only if handshake passed)
    if results.get("handshake"):
        print("\n[Test 3] Send/Receive")
        print("-" * 40)
        
        try:
            # Alice sends to Bob
            message = b"Hello Bob! This is a test message."
            env = alice.send(message)
            print(f"  Alice sends: {len(message)}B -> envelope {env.total_size}B")
            
            # Bob receives
            decrypted = bob.receive(env)
            print(f"  Bob receives: {len(decrypted)}B")
            
            results["send_recv"] = decrypted == message
            print(f"  Match: {results['send_recv']}")
            print(f"  Result: {'PASS ✓' if results['send_recv'] else 'FAIL ✗'}")
        except Exception as e:
            results["send_recv"] = False
            print(f"  Result: FAIL ✗ ({e})")
            import traceback
            traceback.print_exc()
    
    # Test 4: Bidirectional
    if results.get("send_recv"):
        print("\n[Test 4] Bidirectional")
        print("-" * 40)
        
        try:
            # Bob sends to Alice
            msg_bob = b"Hello Alice! Got your message."
            env_bob = bob.send(msg_bob)
            decrypted_alice = alice.receive(env_bob)
            
            results["bidirectional"] = decrypted_alice == msg_bob
            print(f"  Bob -> Alice: {results['bidirectional']}")
            print(f"  Result: {'PASS ✓' if results['bidirectional'] else 'FAIL ✗'}")
        except Exception as e:
            results["bidirectional"] = False
            print(f"  Result: FAIL ✗ ({e})")
    
    # Test 5: Close
    print("\n[Test 5] Close")
    print("-" * 40)
    
    try:
        close_env = alice.close()
        print(f"  Alice CLOSE: {close_env.total_size if close_env else 'None'}B")
        print(f"  Alice state: {alice.state}")
        
        bob.close()
        print(f"  Bob state: {bob.state}")
        
        results["close"] = alice.state == ChannelState.CLOSED and bob.state == ChannelState.CLOSED
        print(f"  Result: {'PASS ✓' if results['close'] else 'FAIL ✗'}")
    except Exception as e:
        results["close"] = False
        print(f"  Result: FAIL ✗ ({e})")
    
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
