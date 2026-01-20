# meteor_nc/block/adapters/base.py
"""
Meteor-NC Block Adapters: Abstract Wallet Interface

Provides a unified interface for integrating Meteor-NC post-quantum
cryptography with various wallet implementations.

Supported Operations:
    - Connection management (connect, disconnect, reconnect)
    - Address and identity management
    - Message signing (EIP-712, personal_sign)
    - Meteor-NC key management (pk_blob registration/retrieval)
    - Encrypted messaging through transport layer

Wallet Implementations:
    - MetaMaskAdapter: MetaMask Snap integration
    - WalletConnectAdapter: WalletConnect v2 protocol
    - (Future) LedgerAdapter, TrezorAdapter, etc.

Usage:
    # Using a concrete adapter
    adapter = MetaMaskAdapter()
    await adapter.connect()
    
    # Get Meteor identity
    pk_blob = await adapter.get_meteor_pk_blob()
    
    # Sign with EIP-712
    signature = await adapter.sign_typed_data(domain, types, value)
    
    # Send encrypted message
    await adapter.send_encrypted(peer_address, b"Hello!")

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import hashlib
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from typing import Optional, Dict, Any, List, Callable, Awaitable, TypeVar, Generic

from ..wire import SecureEnvelope
from ..transport import WalletChannel, WalletSession, WalletMessage


# =============================================================================
# Type Variables
# =============================================================================

T = TypeVar('T')


# =============================================================================
# Enums
# =============================================================================

class WalletState(Enum):
    """Wallet connection state."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    ERROR = auto()


class WalletCapability(IntEnum):
    """Wallet capability flags."""
    # Basic operations
    SIGN_MESSAGE = 0x01          # personal_sign
    SIGN_TYPED_DATA = 0x02       # EIP-712
    SIGN_TRANSACTION = 0x04      # eth_signTransaction
    SEND_TRANSACTION = 0x08      # eth_sendTransaction
    
    # Meteor-NC specific
    METEOR_KEY_GEN = 0x10        # Generate Meteor keys
    METEOR_ENCRYPT = 0x20        # Encrypt with Meteor
    METEOR_DECRYPT = 0x40        # Decrypt with Meteor
    METEOR_CHANNEL = 0x80        # P2P secure channel
    
    # Advanced
    MULTI_ACCOUNT = 0x100        # Multiple accounts
    HARDWARE_KEY = 0x200         # Hardware key storage


class SignatureType(Enum):
    """Signature type for signing operations."""
    PERSONAL = "personal_sign"
    TYPED_DATA = "eth_signTypedData_v4"
    TRANSACTION = "eth_signTransaction"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class WalletInfo:
    """Information about connected wallet."""
    name: str
    version: str
    chain_id: int
    address: str
    capabilities: int = 0  # Bitmask of WalletCapability
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def has_capability(self, cap: WalletCapability) -> bool:
        """Check if wallet has a capability."""
        return bool(self.capabilities & cap)
    
    @property
    def supports_meteor(self) -> bool:
        """Check if wallet supports Meteor-NC operations."""
        return self.has_capability(WalletCapability.METEOR_KEY_GEN)


@dataclass
class MeteorIdentity:
    """Meteor-NC identity for a wallet address."""
    address: str
    pk_blob: bytes  # 64B: pk_seed + b_hash
    seed: Optional[bytes] = None  # Only available if generated locally
    created_at: float = field(default_factory=time.time)
    
    @property
    def pk_seed(self) -> bytes:
        """Extract pk_seed from pk_blob."""
        return self.pk_blob[:32]
    
    @property
    def b_hash(self) -> bytes:
        """Extract b_hash from pk_blob."""
        return self.pk_blob[32:64]
    
    @property
    def key_id(self) -> bytes:
        """Compute key_id from pk_blob."""
        return hashlib.sha256(b"key_id" + self.pk_seed + self.b_hash).digest()


@dataclass
class SignRequest:
    """Signature request."""
    sig_type: SignatureType
    data: bytes
    from_address: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SignResult:
    """Signature result."""
    signature: bytes
    recovery_id: Optional[int] = None
    sig_type: SignatureType = SignatureType.PERSONAL


@dataclass
class EIP712Domain:
    """EIP-712 domain separator."""
    name: str
    version: str
    chain_id: int
    verifying_contract: Optional[str] = None
    salt: Optional[bytes] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to EIP-712 format."""
        domain = {
            "name": self.name,
            "version": self.version,
            "chainId": self.chain_id,
        }
        if self.verifying_contract:
            domain["verifyingContract"] = self.verifying_contract
        if self.salt:
            domain["salt"] = "0x" + self.salt.hex()
        return domain


# =============================================================================
# Event System
# =============================================================================

class WalletEvent(Enum):
    """Wallet events."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ACCOUNT_CHANGED = "accountChanged"
    CHAIN_CHANGED = "chainChanged"
    MESSAGE_RECEIVED = "messageReceived"
    ERROR = "error"


EventCallback = Callable[[WalletEvent, Any], Awaitable[None]]


# =============================================================================
# Exceptions
# =============================================================================

class WalletAdapterError(Exception):
    """Base exception for wallet adapter errors."""
    pass


class NotConnectedError(WalletAdapterError):
    """Wallet not connected."""
    pass


class UnsupportedOperationError(WalletAdapterError):
    """Operation not supported by wallet."""
    pass


class SignatureRejectedError(WalletAdapterError):
    """User rejected signature request."""
    pass


class ConnectionError(WalletAdapterError):
    """Failed to connect to wallet."""
    pass


# =============================================================================
# Abstract Base Class
# =============================================================================

class WalletAdapter(ABC):
    """
    Abstract base class for wallet adapters.
    
    Provides unified interface for:
    - Wallet connection/disconnection
    - Account management
    - Message signing (personal_sign, EIP-712)
    - Meteor-NC key management
    - Encrypted P2P communication
    """
    
    def __init__(self, chain_id: int = 1):
        """
        Initialize wallet adapter.
        
        Args:
            chain_id: Default chain ID
        """
        self._chain_id = chain_id
        self._state = WalletState.DISCONNECTED
        self._info: Optional[WalletInfo] = None
        self._meteor_identity: Optional[MeteorIdentity] = None
        self._wallet_channel: Optional[WalletChannel] = None
        self._sessions: Dict[str, WalletSession] = {}
        self._event_handlers: Dict[WalletEvent, List[EventCallback]] = {
            e: [] for e in WalletEvent
        }
    
    # =========================================================================
    # Properties
    # =========================================================================
    
    @property
    def state(self) -> WalletState:
        """Get current connection state."""
        return self._state
    
    @property
    def is_connected(self) -> bool:
        """Check if wallet is connected."""
        return self._state == WalletState.CONNECTED
    
    @property
    def info(self) -> Optional[WalletInfo]:
        """Get wallet info (if connected)."""
        return self._info
    
    @property
    def address(self) -> Optional[str]:
        """Get connected address."""
        return self._info.address if self._info else None
    
    @property
    def chain_id(self) -> int:
        """Get current chain ID."""
        return self._info.chain_id if self._info else self._chain_id
    
    @property
    def meteor_identity(self) -> Optional[MeteorIdentity]:
        """Get Meteor-NC identity."""
        return self._meteor_identity
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get adapter name."""
        pass
    
    @property
    @abstractmethod
    def capabilities(self) -> int:
        """Get supported capabilities bitmask."""
        pass
    
    # =========================================================================
    # Connection Management
    # =========================================================================
    
    @abstractmethod
    async def connect(self) -> WalletInfo:
        """
        Connect to wallet.
        
        Returns:
            WalletInfo with connection details
        
        Raises:
            ConnectionError: If connection fails
        """
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from wallet."""
        pass
    
    async def reconnect(self) -> WalletInfo:
        """Reconnect to wallet."""
        await self.disconnect()
        return await self.connect()
    
    # =========================================================================
    # Account Management
    # =========================================================================
    
    @abstractmethod
    async def get_accounts(self) -> List[str]:
        """
        Get available accounts.
        
        Returns:
            List of account addresses
        """
        pass
    
    @abstractmethod
    async def switch_account(self, address: str) -> None:
        """
        Switch to a different account.
        
        Args:
            address: Account address to switch to
        """
        pass
    
    @abstractmethod
    async def switch_chain(self, chain_id: int) -> None:
        """
        Switch to a different chain.
        
        Args:
            chain_id: Chain ID to switch to
        """
        pass
    
    # =========================================================================
    # Signing Operations
    # =========================================================================
    
    @abstractmethod
    async def sign_message(self, message: bytes) -> SignResult:
        """
        Sign a message using personal_sign.
        
        Args:
            message: Message to sign
        
        Returns:
            SignResult with signature
        
        Raises:
            SignatureRejectedError: If user rejects
        """
        pass
    
    @abstractmethod
    async def sign_typed_data(
        self,
        domain: EIP712Domain,
        types: Dict[str, List[Dict[str, str]]],
        value: Dict[str, Any],
    ) -> SignResult:
        """
        Sign typed data using EIP-712.
        
        Args:
            domain: EIP-712 domain
            types: Type definitions
            value: Data to sign
        
        Returns:
            SignResult with signature
        """
        pass
    
    # =========================================================================
    # Meteor-NC Key Management
    # =========================================================================
    
    async def ensure_meteor_identity(self) -> MeteorIdentity:
        """
        Ensure Meteor-NC identity exists, creating if needed.
        
        Returns:
            MeteorIdentity for current address
        """
        if not self.is_connected:
            raise NotConnectedError("Wallet not connected")
        
        if self._meteor_identity is None:
            self._meteor_identity = await self._create_meteor_identity()
            await self._init_wallet_channel()
        
        return self._meteor_identity
    
    async def _create_meteor_identity(self) -> MeteorIdentity:
        """
        Create new Meteor-NC identity.
        
        Default implementation derives seed from wallet signature.
        Subclasses may override for hardware-backed keys.
        """
        if not self.address:
            raise NotConnectedError("No address available")
        
        # Derive seed from signature (deterministic)
        # This allows recovery if user signs the same message
        derivation_message = (
            f"Meteor-NC Identity Derivation\n"
            f"Chain: {self.chain_id}\n"
            f"Address: {self.address}\n"
            f"Version: 1"
        ).encode()
        
        result = await self.sign_message(derivation_message)
        
        # Derive 32-byte seed from signature
        seed = hashlib.sha256(b"meteor-nc-seed-v1" + result.signature).digest()
        
        # Create WalletChannel to get pk_blob
        from ..transport import WalletChannel
        channel = WalletChannel.create(
            address=self.address,
            chain_id=self.chain_id,
            seed=seed,
        )
        
        return MeteorIdentity(
            address=self.address,
            pk_blob=channel.pk_blob,
            seed=seed,
        )
    
    async def _init_wallet_channel(self) -> None:
        """Initialize WalletChannel with Meteor identity."""
        if self._meteor_identity is None:
            raise NotConnectedError("No Meteor identity")
        
        from ..transport import WalletChannel
        self._wallet_channel = WalletChannel.create(
            address=self._meteor_identity.address,
            chain_id=self.chain_id,
            seed=self._meteor_identity.seed,
        )
    
    async def get_meteor_pk_blob(self) -> bytes:
        """
        Get Meteor-NC public key blob for sharing.
        
        Returns:
            64-byte pk_blob
        """
        identity = await self.ensure_meteor_identity()
        return identity.pk_blob
    
    # =========================================================================
    # Encrypted Communication
    # =========================================================================
    
    async def initiate_session(
        self,
        peer_address: str,
        peer_pk_blob: bytes,
    ) -> tuple[WalletSession, SecureEnvelope]:
        """
        Initiate encrypted session with peer.
        
        Args:
            peer_address: Peer's Ethereum address
            peer_pk_blob: Peer's Meteor pk_blob
        
        Returns:
            Tuple of (session, handshake envelope)
        """
        await self.ensure_meteor_identity()
        
        if self._wallet_channel is None:
            raise NotConnectedError("Wallet channel not initialized")
        
        session, handshake = self._wallet_channel.initiate_handshake(
            peer_address, peer_pk_blob
        )
        self._sessions[peer_address.lower()] = session
        
        return session, handshake
    
    async def accept_session(
        self,
        peer_address: str,
        handshake: SecureEnvelope,
    ) -> tuple[WalletSession, SecureEnvelope]:
        """
        Accept session handshake from peer.
        
        Args:
            peer_address: Peer's Ethereum address
            handshake: Handshake envelope from peer
        
        Returns:
            Tuple of (session, response envelope)
        """
        await self.ensure_meteor_identity()
        
        if self._wallet_channel is None:
            raise NotConnectedError("Wallet channel not initialized")
        
        session, response = self._wallet_channel.accept_handshake(
            peer_address, handshake
        )
        self._sessions[peer_address.lower()] = session
        
        return session, response
    
    async def finalize_session(
        self,
        peer_address: str,
        response: SecureEnvelope,
    ) -> WalletSession:
        """
        Finalize session with peer's response.
        
        Args:
            peer_address: Peer's Ethereum address
            response: Response envelope from peer
        
        Returns:
            Connected session
        """
        if self._wallet_channel is None:
            raise NotConnectedError("Wallet channel not initialized")
        
        return self._wallet_channel.finalize_handshake(peer_address, response)
    
    def get_session(self, peer_address: str) -> Optional[WalletSession]:
        """Get existing session with peer."""
        return self._sessions.get(peer_address.lower())
    
    async def send_encrypted(
        self,
        peer_address: str,
        message: bytes | str | WalletMessage,
    ) -> SecureEnvelope:
        """
        Send encrypted message to peer.
        
        Args:
            peer_address: Peer's address
            message: Message to send
        
        Returns:
            Encrypted envelope
        
        Raises:
            NotConnectedError: If no session with peer
        """
        session = self.get_session(peer_address)
        if session is None:
            raise NotConnectedError(f"No session with {peer_address}")
        
        return session.send_message(message)
    
    async def receive_encrypted(
        self,
        peer_address: str,
        envelope: SecureEnvelope,
    ) -> WalletMessage:
        """
        Receive and decrypt message from peer.
        
        Args:
            peer_address: Peer's address
            envelope: Encrypted envelope
        
        Returns:
            Decrypted message
        """
        session = self.get_session(peer_address)
        if session is None:
            raise NotConnectedError(f"No session with {peer_address}")
        
        return session.receive_message(envelope)
    
    # =========================================================================
    # Event Handling
    # =========================================================================
    
    def on(self, event: WalletEvent, callback: EventCallback) -> None:
        """Register event handler."""
        self._event_handlers[event].append(callback)
    
    def off(self, event: WalletEvent, callback: EventCallback) -> None:
        """Unregister event handler."""
        if callback in self._event_handlers[event]:
            self._event_handlers[event].remove(callback)
    
    async def _emit(self, event: WalletEvent, data: Any = None) -> None:
        """Emit event to all handlers."""
        for handler in self._event_handlers[event]:
            try:
                await handler(event, data)
            except Exception:
                pass  # Don't let handler errors break event loop
    
    # =========================================================================
    # Utility
    # =========================================================================
    
    def _require_connected(self) -> None:
        """Raise if not connected."""
        if not self.is_connected:
            raise NotConnectedError("Wallet not connected")
    
    def _require_capability(self, cap: WalletCapability) -> None:
        """Raise if capability not supported."""
        if self._info and not self._info.has_capability(cap):
            raise UnsupportedOperationError(
                f"Wallet does not support {cap.name}"
            )


# =============================================================================
# Mock Adapter (for testing)
# =============================================================================

class MockWalletAdapter(WalletAdapter):
    """
    Mock wallet adapter for testing.
    
    Simulates wallet behavior without real wallet connection.
    """
    
    def __init__(
        self,
        chain_id: int = 1,
        address: str = "0x" + "1" * 40,
        auto_approve: bool = True,
    ):
        super().__init__(chain_id)
        self._mock_address = address.lower()
        self._auto_approve = auto_approve
        self._mock_accounts = [self._mock_address]
    
    @property
    def name(self) -> str:
        return "MockWallet"
    
    @property
    def capabilities(self) -> int:
        return (
            WalletCapability.SIGN_MESSAGE |
            WalletCapability.SIGN_TYPED_DATA |
            WalletCapability.METEOR_KEY_GEN |
            WalletCapability.METEOR_ENCRYPT |
            WalletCapability.METEOR_DECRYPT |
            WalletCapability.METEOR_CHANNEL
        )
    
    async def connect(self) -> WalletInfo:
        self._state = WalletState.CONNECTING
        
        self._info = WalletInfo(
            name="MockWallet",
            version="1.0.0",
            chain_id=self._chain_id,
            address=self._mock_address,
            capabilities=self.capabilities,
        )
        
        self._state = WalletState.CONNECTED
        await self._emit(WalletEvent.CONNECTED, self._info)
        
        return self._info
    
    async def disconnect(self) -> None:
        self._state = WalletState.DISCONNECTED
        self._info = None
        self._meteor_identity = None
        self._wallet_channel = None
        self._sessions.clear()
        await self._emit(WalletEvent.DISCONNECTED)
    
    async def get_accounts(self) -> List[str]:
        return self._mock_accounts.copy()
    
    async def switch_account(self, address: str) -> None:
        address = address.lower()
        if address not in self._mock_accounts:
            self._mock_accounts.append(address)
        
        if self._info:
            self._info.address = address
            self._mock_address = address
        
        await self._emit(WalletEvent.ACCOUNT_CHANGED, address)
    
    async def switch_chain(self, chain_id: int) -> None:
        self._chain_id = chain_id
        if self._info:
            self._info.chain_id = chain_id
        await self._emit(WalletEvent.CHAIN_CHANGED, chain_id)
    
    async def sign_message(self, message: bytes) -> SignResult:
        self._require_connected()
        
        if not self._auto_approve:
            raise SignatureRejectedError("User rejected")
        
        # Mock signature (not cryptographically valid)
        sig_hash = hashlib.sha256(
            b"mock_sign" + message + self._mock_address.encode()
        ).digest()
        
        # 65-byte signature: r(32) + s(32) + v(1)
        signature = sig_hash + sig_hash[:32] + b'\x1b'
        
        return SignResult(
            signature=signature,
            recovery_id=0,
            sig_type=SignatureType.PERSONAL,
        )
    
    async def sign_typed_data(
        self,
        domain: EIP712Domain,
        types: Dict[str, List[Dict[str, str]]],
        value: Dict[str, Any],
    ) -> SignResult:
        self._require_connected()
        
        if not self._auto_approve:
            raise SignatureRejectedError("User rejected")
        
        # Mock EIP-712 signature
        import json
        data_hash = hashlib.sha256(
            json.dumps({"domain": domain.to_dict(), "value": value}).encode()
        ).digest()
        
        signature = data_hash + data_hash[:32] + b'\x1c'
        
        return SignResult(
            signature=signature,
            recovery_id=1,
            sig_type=SignatureType.TYPED_DATA,
        )


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test wallet adapter base classes."""
    import asyncio
    
    print("=" * 70)
    print("Meteor-NC Block Adapters: Base Test")
    print("=" * 70)
    
    results = {}
    
    async def async_tests():
        # Test 1: Create mock adapter
        print("\n[Test 1] Create MockWalletAdapter")
        print("-" * 40)
        
        try:
            adapter = MockWalletAdapter(chain_id=1)
            results["create"] = (
                adapter.state == WalletState.DISCONNECTED and
                adapter.name == "MockWallet"
            )
            print(f"  State: {adapter.state.name}")
            print(f"  Name: {adapter.name}")
            print(f"  Result: {'PASS ✓' if results['create'] else 'FAIL ✗'}")
        except Exception as e:
            results["create"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
            return
        
        # Test 2: Connect
        print("\n[Test 2] Connect")
        print("-" * 40)
        
        try:
            info = await adapter.connect()
            results["connect"] = (
                adapter.is_connected and
                info.address == "0x" + "1" * 40 and
                info.chain_id == 1
            )
            print(f"  Connected: {adapter.is_connected}")
            print(f"  Address: {info.address[:10]}...")
            print(f"  Chain: {info.chain_id}")
            print(f"  Result: {'PASS ✓' if results['connect'] else 'FAIL ✗'}")
        except Exception as e:
            results["connect"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
            return
        
        # Test 3: Sign message
        print("\n[Test 3] Sign Message")
        print("-" * 40)
        
        try:
            result = await adapter.sign_message(b"Hello Meteor!")
            results["sign"] = (
                len(result.signature) == 65 and
                result.sig_type == SignatureType.PERSONAL
            )
            print(f"  Signature length: {len(result.signature)}B")
            print(f"  Type: {result.sig_type.name}")
            print(f"  Result: {'PASS ✓' if results['sign'] else 'FAIL ✗'}")
        except Exception as e:
            results["sign"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
        
        # Test 4: Create Meteor identity
        print("\n[Test 4] Create Meteor Identity")
        print("-" * 40)
        
        try:
            identity = await adapter.ensure_meteor_identity()
            results["identity"] = (
                len(identity.pk_blob) == 64 and
                identity.address == adapter.address and
                identity.seed is not None
            )
            print(f"  pk_blob size: {len(identity.pk_blob)}B")
            print(f"  Address: {identity.address[:10]}...")
            print(f"  Has seed: {identity.seed is not None}")
            print(f"  Result: {'PASS ✓' if results['identity'] else 'FAIL ✗'}")
        except Exception as e:
            results["identity"] = False
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print("  Result: FAIL ✗")
        
        # Test 5: Get pk_blob
        print("\n[Test 5] Get Meteor PK Blob")
        print("-" * 40)
        
        try:
            pk_blob = await adapter.get_meteor_pk_blob()
            results["pk_blob"] = len(pk_blob) == 64
            print(f"  pk_blob size: {len(pk_blob)}B")
            print(f"  pk_seed: {pk_blob[:8].hex()}...")
            print(f"  Result: {'PASS ✓' if results['pk_blob'] else 'FAIL ✗'}")
        except Exception as e:
            results["pk_blob"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
        
        # Test 6: Session with another adapter
        print("\n[Test 6] P2P Session")
        print("-" * 40)
        
        try:
            # Create second adapter (Bob)
            bob = MockWalletAdapter(chain_id=1, address="0x" + "2" * 40)
            await bob.connect()
            bob_identity = await bob.ensure_meteor_identity()
            
            # Alice initiates
            session_a, handshake = await adapter.initiate_session(
                bob.address, bob_identity.pk_blob
            )
            
            # Bob accepts
            session_b, response = await bob.accept_session(
                adapter.address, handshake
            )
            
            # Alice finalizes
            await adapter.finalize_session(bob.address, response)
            
            results["session"] = (
                session_a.is_connected and
                session_b.is_connected
            )
            print(f"  Alice connected: {session_a.is_connected}")
            print(f"  Bob connected: {session_b.is_connected}")
            print(f"  Result: {'PASS ✓' if results['session'] else 'FAIL ✗'}")
        except Exception as e:
            results["session"] = False
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print("  Result: FAIL ✗")
        
        # Test 7: Encrypted messaging
        print("\n[Test 7] Encrypted Messaging")
        print("-" * 40)
        
        try:
            # Alice sends
            env = await adapter.send_encrypted(bob.address, "Hello Bob! 🔐")
            
            # Bob receives
            msg = await bob.receive_encrypted(adapter.address, env)
            
            results["messaging"] = msg.as_text() == "Hello Bob! 🔐"
            print(f"  Sent: 'Hello Bob! 🔐'")
            print(f"  Received: '{msg.as_text()}'")
            print(f"  Result: {'PASS ✓' if results['messaging'] else 'FAIL ✗'}")
        except Exception as e:
            results["messaging"] = False
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print("  Result: FAIL ✗")
        
        # Test 8: Disconnect
        print("\n[Test 8] Disconnect")
        print("-" * 40)
        
        try:
            await adapter.disconnect()
            results["disconnect"] = (
                not adapter.is_connected and
                adapter.meteor_identity is None
            )
            print(f"  Connected: {adapter.is_connected}")
            print(f"  Identity cleared: {adapter.meteor_identity is None}")
            print(f"  Result: {'PASS ✓' if results['disconnect'] else 'FAIL ✗'}")
        except Exception as e:
            results["disconnect"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
    
    # Run async tests
    asyncio.run(async_tests())
    
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
