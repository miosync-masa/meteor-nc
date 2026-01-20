# meteor_nc/block/transport/wallet.py
"""
Meteor-NC Block Transport: Wallet-to-Wallet Communication

Encrypted P2P communication between Ethereum wallets using:
- SecureChannel for encrypted messaging
- PKRegistry for public key resolution
- Ethereum address as identity

Features:
    - Address-based messaging (send to 0x...)
    - Registry-backed key resolution
    - Optional sender authentication
    - Message types (text, binary, structured)

Usage:
    # Create wallet channel
    wallet = WalletChannel.create(
        address="0x1234...",
        chain_id=1,
    )
    
    # Connect to another wallet
    session = await wallet.connect_to("0xABCD...", registry)
    
    # Send encrypted message
    envelope = session.send_message("Hello!")
    
    # Receive and decrypt
    message = session.receive_message(envelope)

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Dict, Any, Union, Callable, Tuple

from .channel import (
    SecureChannel,
    ChannelState,
    ChannelError,
    HandshakeError,
)

from ..wire import (
    SecureEnvelope,
    EnvelopeType,
    EnvelopeFlags,
    DEFAULT_SUITE_ID,
    PK_BLOB_SIZE,
)

# Optional registry integration
try:
    from ..registry import KeyResolver
    REGISTRY_AVAILABLE = True
except ImportError:
    KeyResolver = None
    REGISTRY_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

# Message type identifiers
class MessageType(IntEnum):
    """Message content types."""
    TEXT = 0x01        # UTF-8 text
    BINARY = 0x02      # Raw bytes
    JSON = 0x03        # JSON object
    SIGNED = 0x10      # Signed message
    ENCRYPTED = 0x20   # Double-encrypted (for forwarding)


# =============================================================================
# Exceptions
# =============================================================================

class WalletError(Exception):
    """Base exception for wallet operations."""
    pass


class AddressError(WalletError):
    """Invalid Ethereum address."""
    pass


class ResolutionError(WalletError):
    """Failed to resolve address to public key."""
    pass


class MessageError(WalletError):
    """Message encoding/decoding error."""
    pass


# =============================================================================
# Message Container
# =============================================================================

@dataclass
class WalletMessage:
    """
    Wallet message container.
    
    Attributes:
        msg_type: Message type (TEXT, BINARY, JSON, etc.)
        content: Message content (bytes)
        sender: Sender address (if known)
        timestamp: Message timestamp
        metadata: Optional metadata dict
    """
    msg_type: MessageType
    content: bytes
    sender: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Wire format: type(1) + timestamp(8) + meta_len(2) + meta + content
    
    def to_bytes(self) -> bytes:
        """Serialize message to bytes."""
        import struct
        
        # Encode metadata as JSON
        meta_bytes = json.dumps(self.metadata).encode('utf-8') if self.metadata else b''
        
        # Pack: type(1) + timestamp(8) + meta_len(2) + meta + content
        header = struct.pack(
            '>B d H',
            self.msg_type,
            self.timestamp,
            len(meta_bytes),
        )
        
        return header + meta_bytes + self.content
    
    @classmethod
    def from_bytes(cls, data: bytes, sender: Optional[str] = None) -> 'WalletMessage':
        """Deserialize message from bytes."""
        import struct
        
        if len(data) < 11:  # 1 + 8 + 2
            raise MessageError(f"Message too short: {len(data)}B")
        
        msg_type, timestamp, meta_len = struct.unpack('>B d H', data[:11])
        
        if len(data) < 11 + meta_len:
            raise MessageError(f"Message truncated: expected {11 + meta_len}B, got {len(data)}B")
        
        meta_bytes = data[11:11 + meta_len]
        content = data[11 + meta_len:]
        
        metadata = json.loads(meta_bytes.decode('utf-8')) if meta_bytes else {}
        
        return cls(
            msg_type=MessageType(msg_type),
            content=content,
            sender=sender,
            timestamp=timestamp,
            metadata=metadata,
        )
    
    @classmethod
    def text(cls, text: str, **metadata) -> 'WalletMessage':
        """Create text message."""
        return cls(
            msg_type=MessageType.TEXT,
            content=text.encode('utf-8'),
            metadata=metadata,
        )
    
    @classmethod
    def binary(cls, data: bytes, **metadata) -> 'WalletMessage':
        """Create binary message."""
        return cls(
            msg_type=MessageType.BINARY,
            content=data,
            metadata=metadata,
        )
    
    @classmethod
    def json_msg(cls, obj: Any, **metadata) -> 'WalletMessage':
        """Create JSON message."""
        return cls(
            msg_type=MessageType.JSON,
            content=json.dumps(obj).encode('utf-8'),
            metadata=metadata,
        )
    
    def as_text(self) -> str:
        """Get content as text."""
        if self.msg_type not in (MessageType.TEXT, MessageType.JSON):
            raise MessageError(f"Cannot convert {self.msg_type.name} to text")
        return self.content.decode('utf-8')
    
    def as_json(self) -> Any:
        """Get content as JSON object."""
        if self.msg_type != MessageType.JSON:
            raise MessageError(f"Cannot convert {self.msg_type.name} to JSON")
        return json.loads(self.content.decode('utf-8'))


# =============================================================================
# Wallet Session
# =============================================================================

@dataclass
class WalletSession:
    """
    Active session between two wallets.
    
    Wraps SecureChannel with wallet-specific functionality.
    """
    channel: SecureChannel
    local_address: str
    peer_address: str
    created_at: float = field(default_factory=time.time)
    
    @property
    def is_connected(self) -> bool:
        """Check if session is connected."""
        return self.channel.state == ChannelState.CONNECTED
    
    @property
    def session_id(self) -> bytes:
        """Get session ID."""
        return self.channel.session_id
    
    def send_message(self, message: Union[str, bytes, WalletMessage]) -> SecureEnvelope:
        """
        Send a message to peer.
        
        Args:
            message: Text string, bytes, or WalletMessage
        
        Returns:
            SecureEnvelope ready for transmission
        """
        if not self.is_connected:
            raise WalletError("Session not connected")
        
        # Convert to WalletMessage if needed
        if isinstance(message, str):
            msg = WalletMessage.text(message)
        elif isinstance(message, bytes):
            msg = WalletMessage.binary(message)
        elif isinstance(message, WalletMessage):
            msg = message
        else:
            raise MessageError(f"Unsupported message type: {type(message)}")
        
        # Serialize and send
        return self.channel.send(msg.to_bytes())
    
    def receive_message(self, envelope: SecureEnvelope) -> WalletMessage:
        """
        Receive and decrypt a message.
        
        Args:
            envelope: Received SecureEnvelope
        
        Returns:
            Decrypted WalletMessage
        """
        if not self.is_connected:
            raise WalletError("Session not connected")
        
        # Decrypt
        data = self.channel.receive(envelope)
        
        # Parse message
        return WalletMessage.from_bytes(data, sender=self.peer_address)
    
    def close(self) -> Optional[SecureEnvelope]:
        """Close the session."""
        return self.channel.close()


# =============================================================================
# WalletChannel
# =============================================================================

class WalletChannel:
    """
    Wallet-to-wallet communication channel.
    
    Manages encrypted P2P sessions between Ethereum wallets.
    """
    
    def __init__(
        self,
        address: str,
        chain_id: int,
        seed: bytes,
        pk_blob: bytes,
        suite_id: int = DEFAULT_SUITE_ID,
    ):
        """
        Initialize wallet channel.
        
        Args:
            address: Ethereum address (0x...)
            chain_id: Chain ID
            seed: Deterministic seed for key generation
            pk_blob: 64-byte pk_blob for sharing
            suite_id: Cryptographic suite
        """
        self._address = self._validate_address(address)
        self._chain_id = chain_id
        self._seed = seed
        self._pk_blob = pk_blob
        self._suite_id = suite_id
        
        # Active sessions: peer_address -> WalletSession
        self._sessions: Dict[str, WalletSession] = {}
    
    @staticmethod
    def _validate_address(address: str) -> str:
        """Validate Ethereum address format."""
        if not address.startswith('0x'):
            raise AddressError("Address must start with 0x")
        if len(address) != 42:
            raise AddressError(f"Address must be 42 chars, got {len(address)}")
        try:
            int(address, 16)
        except ValueError:
            raise AddressError("Address must be valid hex")
        return address.lower()
    
    @classmethod
    def create(
        cls,
        address: str,
        chain_id: int,
        suite_id: int = DEFAULT_SUITE_ID,
        seed: Optional[bytes] = None,
    ) -> 'WalletChannel':
        """
        Create a new wallet channel with generated keys.
        
        Args:
            address: Ethereum address
            chain_id: Chain ID
            suite_id: Cryptographic suite
            seed: Optional seed for deterministic key generation
        
        Returns:
            WalletChannel instance
        """
        # Generate seed if not provided
        if seed is None:
            seed = secrets.token_bytes(32)
        
        # Create temporary channel to get pk_blob (uses consistent key derivation)
        temp_channel = SecureChannel.create(
            chain_id=chain_id,
            suite_id=suite_id,
            seed=seed,
            gpu=False,  # CPU for initialization
        )
        pk_blob = temp_channel.pk_blob
        
        return cls(
            address=address,
            chain_id=chain_id,
            seed=seed,
            pk_blob=pk_blob,
            suite_id=suite_id,
        )
    
    @property
    def address(self) -> str:
        """Get wallet address."""
        return self._address
    
    @property
    def pk_blob(self) -> bytes:
        """Get public key blob for sharing."""
        return self._pk_blob
    
    @property
    def chain_id(self) -> int:
        """Get chain ID."""
        return self._chain_id
    
    def get_session(self, peer_address: str) -> Optional[WalletSession]:
        """Get existing session with peer."""
        return self._sessions.get(peer_address.lower())
    
    def initiate_handshake(
        self,
        peer_address: str,
        peer_pk_blob: bytes,
    ) -> Tuple[WalletSession, SecureEnvelope]:
        """
        Initiate handshake with peer wallet.
        
        Args:
            peer_address: Peer's Ethereum address
            peer_pk_blob: Peer's public key blob
        
        Returns:
            Tuple of (WalletSession, HANDSHAKE envelope)
        """
        peer_address = self._validate_address(peer_address)
        
        if len(peer_pk_blob) != PK_BLOB_SIZE:
            raise WalletError(f"Invalid pk_blob size: {len(peer_pk_blob)}")
        
        # Create channel with our seed (generates same keys)
        channel = SecureChannel.create(
            chain_id=self._chain_id,
            suite_id=self._suite_id,
            seed=self._seed,
        )
        
        # Initiate handshake
        handshake = channel.connect(peer_pk_blob)
        
        # Create session (not yet connected)
        session = WalletSession(
            channel=channel,
            local_address=self._address,
            peer_address=peer_address,
        )
        
        self._sessions[peer_address] = session
        
        return session, handshake
    
    def accept_handshake(
        self,
        peer_address: str,
        handshake: SecureEnvelope,
    ) -> Tuple[WalletSession, SecureEnvelope]:
        """
        Accept handshake from peer wallet.
        
        Args:
            peer_address: Peer's Ethereum address
            handshake: HANDSHAKE envelope from peer
        
        Returns:
            Tuple of (WalletSession, response envelope)
        """
        peer_address = self._validate_address(peer_address)
        
        # Create channel with our seed (generates same keys)
        channel = SecureChannel.create(
            chain_id=self._chain_id,
            suite_id=self._suite_id,
            seed=self._seed,
        )
        
        # Accept handshake
        response = channel.accept(handshake)
        
        # Create session (connected!)
        session = WalletSession(
            channel=channel,
            local_address=self._address,
            peer_address=peer_address,
        )
        
        self._sessions[peer_address] = session
        
        return session, response
    
    def finalize_handshake(
        self,
        peer_address: str,
        response: SecureEnvelope,
    ) -> WalletSession:
        """
        Finalize handshake with peer's response.
        
        Args:
            peer_address: Peer's Ethereum address
            response: Response envelope from peer
        
        Returns:
            Connected WalletSession
        """
        peer_address = self._validate_address(peer_address)
        
        session = self._sessions.get(peer_address)
        if session is None:
            raise WalletError(f"No pending session with {peer_address}")
        
        # Finalize
        session.channel.finalize(response)
        
        return session
    
    async def connect_to(
        self,
        peer_address: str,
        resolver: Any,  # KeyResolver
        transport: Optional[Callable] = None,
    ) -> WalletSession:
        """
        Connect to peer wallet using registry resolution.
        
        This is a convenience method that:
        1. Resolves peer's pk_blob from registry
        2. Performs full handshake
        
        Args:
            peer_address: Peer's Ethereum address
            resolver: KeyResolver for key lookup
            transport: Optional async function to send/receive envelopes
        
        Returns:
            Connected WalletSession
        
        Note: If transport is None, returns session after initiating handshake.
              Caller must complete handshake manually.
        """
        if not REGISTRY_AVAILABLE:
            raise WalletError("Registry module not available")
        
        peer_address = self._validate_address(peer_address)
        
        # Resolve peer's public key
        pk_blob = resolver.resolve_by_address(peer_address)
        if pk_blob is None:
            raise ResolutionError(f"Could not resolve pk_blob for {peer_address}")
        
        # Initiate handshake
        session, handshake = self.initiate_handshake(peer_address, pk_blob)
        
        if transport is None:
            # Return pending session
            return session
        
        # Use transport for handshake
        response = await transport(handshake)
        self.finalize_handshake(peer_address, response)
        
        return session
    
    def close_session(self, peer_address: str) -> Optional[SecureEnvelope]:
        """
        Close session with peer.
        
        Args:
            peer_address: Peer's Ethereum address
        
        Returns:
            CLOSE envelope if session existed
        """
        peer_address = peer_address.lower()
        session = self._sessions.pop(peer_address, None)
        
        if session:
            return session.close()
        return None
    
    def close_all(self) -> None:
        """Close all active sessions."""
        for addr in list(self._sessions.keys()):
            self.close_session(addr)


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test WalletChannel."""
    print("=" * 70)
    print("Meteor-NC Block Transport: WalletChannel Test")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Create wallet channel
    print("\n[Test 1] Create WalletChannel")
    print("-" * 40)
    
    alice_addr = "0x" + "A" * 40
    bob_addr = "0x" + "B" * 40
    
    try:
        alice = WalletChannel.create(
            address=alice_addr,
            chain_id=1,
        )
        bob = WalletChannel.create(
            address=bob_addr,
            chain_id=1,
        )
        results["create"] = True
        print(f"  Alice: {alice.address[:10]}...")
        print(f"  Bob: {bob.address[:10]}...")
        print(f"  pk_blob size: {len(alice.pk_blob)}B")
        print("  Result: PASS ✓")
    except Exception as e:
        results["create"] = False
        print(f"  Error: {e}")
        print("  Result: FAIL ✗")
        return False
    
    # Test 2: Handshake
    print("\n[Test 2] Handshake")
    print("-" * 40)
    
    try:
        # Alice initiates
        alice_session, handshake = alice.initiate_handshake(bob_addr, bob.pk_blob)
        
        # Bob accepts
        bob_session, response = bob.accept_handshake(alice_addr, handshake)
        
        # Alice finalizes
        alice.finalize_handshake(bob_addr, response)
        
        results["handshake"] = (
            alice_session.is_connected and
            bob_session.is_connected
        )
        print(f"  Alice connected: {alice_session.is_connected}")
        print(f"  Bob connected: {bob_session.is_connected}")
        print(f"  Result: {'PASS ✓' if results['handshake'] else 'FAIL ✗'}")
    except Exception as e:
        results["handshake"] = False
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()
        print("  Result: FAIL ✗")
        return False
    
    # Test 3: Send/receive text message
    print("\n[Test 3] Text Message")
    print("-" * 40)
    
    try:
        # Alice sends text
        envelope = alice_session.send_message("Hello Bob! 👋")
        
        # Bob receives
        msg = bob_session.receive_message(envelope)
        
        results["text"] = (
            msg.msg_type == MessageType.TEXT and
            msg.as_text() == "Hello Bob! 👋" and
            msg.sender == alice_addr.lower()
        )
        print(f"  Type: {msg.msg_type.name}")
        print(f"  Content: {msg.as_text()}")
        print(f"  Sender: {msg.sender[:10]}...")
        print(f"  Result: {'PASS ✓' if results['text'] else 'FAIL ✗'}")
    except Exception as e:
        results["text"] = False
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()
        print("  Result: FAIL ✗")
    
    # Test 4: Send/receive binary message
    print("\n[Test 4] Binary Message")
    print("-" * 40)
    
    try:
        data = bytes(range(256))
        envelope = bob_session.send_message(data)
        msg = alice_session.receive_message(envelope)
        
        results["binary"] = (
            msg.msg_type == MessageType.BINARY and
            msg.content == data
        )
        print(f"  Type: {msg.msg_type.name}")
        print(f"  Size: {len(msg.content)}B")
        print(f"  Matches: {msg.content == data}")
        print(f"  Result: {'PASS ✓' if results['binary'] else 'FAIL ✗'}")
    except Exception as e:
        results["binary"] = False
        print(f"  Error: {e}")
        print("  Result: FAIL ✗")
    
    # Test 5: JSON message
    print("\n[Test 5] JSON Message")
    print("-" * 40)
    
    try:
        obj = {"action": "transfer", "amount": 100, "token": "ETH"}
        msg_out = WalletMessage.json_msg(obj, priority="high")
        envelope = alice_session.send_message(msg_out)
        msg_in = bob_session.receive_message(envelope)
        
        results["json"] = (
            msg_in.msg_type == MessageType.JSON and
            msg_in.as_json() == obj and
            msg_in.metadata.get("priority") == "high"
        )
        print(f"  Type: {msg_in.msg_type.name}")
        print(f"  Content: {msg_in.as_json()}")
        print(f"  Metadata: {msg_in.metadata}")
        print(f"  Result: {'PASS ✓' if results['json'] else 'FAIL ✗'}")
    except Exception as e:
        results["json"] = False
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()
        print("  Result: FAIL ✗")
    
    # Test 6: Address validation
    print("\n[Test 6] Address Validation")
    print("-" * 40)
    
    try:
        # Valid
        WalletChannel._validate_address("0x" + "a" * 40)
        
        # Invalid - no 0x
        try:
            WalletChannel._validate_address("a" * 40)
            invalid_caught = False
        except AddressError:
            invalid_caught = True
        
        # Invalid - wrong length
        try:
            WalletChannel._validate_address("0x" + "a" * 20)
            length_caught = False
        except AddressError:
            length_caught = True
        
        results["address"] = invalid_caught and length_caught
        print(f"  Missing 0x rejected: {invalid_caught}")
        print(f"  Wrong length rejected: {length_caught}")
        print(f"  Result: {'PASS ✓' if results['address'] else 'FAIL ✗'}")
    except Exception as e:
        results["address"] = False
        print(f"  Error: {e}")
        print("  Result: FAIL ✗")
    
    # Test 7: Close session
    print("\n[Test 7] Close Session")
    print("-" * 40)
    
    try:
        close_env = alice.close_session(bob_addr)
        
        results["close"] = (
            close_env is not None and
            alice.get_session(bob_addr) is None
        )
        print(f"  Close envelope: {close_env is not None}")
        print(f"  Session removed: {alice.get_session(bob_addr) is None}")
        print(f"  Result: {'PASS ✓' if results['close'] else 'FAIL ✗'}")
    except Exception as e:
        results["close"] = False
        print(f"  Error: {e}")
        print("  Result: FAIL ✗")
    
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
