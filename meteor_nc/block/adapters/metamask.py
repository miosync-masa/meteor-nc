# meteor_nc/block/adapters/metamask.py
"""
Meteor-NC Block Adapters: MetaMask Snap Integration

Provides MetaMask integration via:
1. MetaMask Snap for in-wallet Meteor-NC operations
2. Standard JSON-RPC for signing and transactions

MetaMask Snap Architecture:
    ┌─────────────────────────────────────────────────┐
    │                  MetaMask                       │
    │  ┌─────────────────────────────────────────┐   │
    │  │           Meteor-NC Snap                │   │
    │  │  ┌─────────┐  ┌─────────┐  ┌────────┐  │   │
    │  │  │ KeyGen  │  │ Encrypt │  │ Decrypt│  │   │
    │  │  └─────────┘  └─────────┘  └────────┘  │   │
    │  └─────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────┘
                           │
                    JSON-RPC Bridge
                           │
    ┌─────────────────────────────────────────────────┐
    │              MetaMaskAdapter                    │
    │  - connect() / disconnect()                    │
    │  - sign_message() / sign_typed_data()          │
    │  - get_meteor_pk_blob()                        │
    │  - initiate_session() / send_encrypted()       │
    └─────────────────────────────────────────────────┘

Snap Methods:
    meteor_getPublicKey    - Get Meteor pk_blob
    meteor_encrypt         - Encrypt data
    meteor_decrypt         - Decrypt data
    meteor_signAuth        - Sign authentication data

Browser Integration:
    The adapter communicates with MetaMask through window.ethereum
    in browser environments, or can use a mock provider for testing.

Usage:
    # In browser environment
    adapter = MetaMaskAdapter()
    await adapter.connect()
    
    # If Snap not installed, prompt installation
    if not await adapter.is_snap_installed():
        await adapter.install_snap()
    
    # Use Meteor features
    pk_blob = await adapter.get_meteor_pk_blob()
    session, handshake = await adapter.initiate_session(peer_addr, peer_pk)

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import json
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable, Awaitable
from abc import ABC, abstractmethod

from .base import (
    WalletAdapter,
    WalletState,
    WalletInfo,
    WalletCapability,
    MeteorIdentity,
    SignResult,
    SignatureType,
    EIP712Domain,
    WalletEvent,
    WalletAdapterError,
    NotConnectedError,
    UnsupportedOperationError,
    SignatureRejectedError,
    ConnectionError,
)


# =============================================================================
# Constants
# =============================================================================

# Meteor-NC Snap ID (would be real npm package in production)
METEOR_SNAP_ID = "npm:@miosync/meteor-nc-snap"
METEOR_SNAP_VERSION = "^0.3.0"

# Snap RPC methods
SNAP_METHOD_GET_PK = "meteor_getPublicKey"
SNAP_METHOD_ENCRYPT = "meteor_encrypt"
SNAP_METHOD_DECRYPT = "meteor_decrypt"
SNAP_METHOD_SIGN_AUTH = "meteor_signAuth"

# Standard Ethereum methods
ETH_REQUEST_ACCOUNTS = "eth_requestAccounts"
ETH_ACCOUNTS = "eth_accounts"
ETH_CHAIN_ID = "eth_chainId"
ETH_SIGN = "personal_sign"
ETH_SIGN_TYPED_DATA = "eth_signTypedData_v4"
WALLET_GET_SNAPS = "wallet_getSnaps"
WALLET_REQUEST_SNAPS = "wallet_requestSnaps"
WALLET_INVOKE_SNAP = "wallet_invokeSnap"
WALLET_SWITCH_CHAIN = "wallet_switchEthereumChain"


# =============================================================================
# Provider Interface
# =============================================================================

class EthereumProvider(ABC):
    """
    Abstract Ethereum provider interface.
    
    Represents window.ethereum in browser or mock for testing.
    """
    
    @abstractmethod
    async def request(self, method: str, params: Any = None) -> Any:
        """Send JSON-RPC request."""
        pass
    
    @abstractmethod
    def on(self, event: str, callback: Callable) -> None:
        """Subscribe to events."""
        pass
    
    @abstractmethod
    def remove_listener(self, event: str, callback: Callable) -> None:
        """Unsubscribe from events."""
        pass


class MockEthereumProvider(EthereumProvider):
    """
    Mock Ethereum provider for testing.
    
    Simulates MetaMask JSON-RPC responses.
    """
    
    def __init__(
        self,
        accounts: Optional[List[str]] = None,
        chain_id: int = 1,
        has_snap: bool = True,
        auto_approve: bool = True,
    ):
        self._accounts = accounts or ["0x" + "1" * 40]
        self._chain_id = chain_id
        self._has_snap = has_snap
        self._auto_approve = auto_approve
        self._snap_state: Dict[str, Any] = {}
        self._event_handlers: Dict[str, List[Callable]] = {}
    
    async def request(self, method: str, params: Any = None) -> Any:
        """Handle JSON-RPC request."""
        
        if method == ETH_REQUEST_ACCOUNTS:
            return self._accounts
        
        elif method == ETH_ACCOUNTS:
            return self._accounts
        
        elif method == ETH_CHAIN_ID:
            return hex(self._chain_id)
        
        elif method == ETH_SIGN:
            if not self._auto_approve:
                raise Exception("User rejected request")
            # params: [message_hex, address]
            message = bytes.fromhex(params[0][2:]) if params else b""
            sig = self._mock_sign(message)
            return "0x" + sig.hex()
        
        elif method == ETH_SIGN_TYPED_DATA:
            if not self._auto_approve:
                raise Exception("User rejected request")
            # params: [address, typed_data_json]
            data = params[1] if len(params) > 1 else "{}"
            sig = self._mock_sign(data.encode() if isinstance(data, str) else data)
            return "0x" + sig.hex()
        
        elif method == WALLET_GET_SNAPS:
            if self._has_snap:
                return {METEOR_SNAP_ID: {"version": "0.3.0"}}
            return {}
        
        elif method == WALLET_REQUEST_SNAPS:
            self._has_snap = True
            return {METEOR_SNAP_ID: {"version": "0.3.0"}}
        
        elif method == WALLET_INVOKE_SNAP:
            return await self._handle_snap_request(params)
        
        elif method == WALLET_SWITCH_CHAIN:
            chain_id = int(params[0]["chainId"], 16)
            self._chain_id = chain_id
            return None
        
        else:
            raise Exception(f"Unsupported method: {method}")
    
    async def _handle_snap_request(self, params: Dict) -> Any:
        """Handle Snap RPC request."""
        snap_id = params.get("snapId", "")
        request = params.get("request", {})
        method = request.get("method", "")
        snap_params = request.get("params", {})
        
        if snap_id != METEOR_SNAP_ID:
            raise Exception(f"Unknown snap: {snap_id}")
        
        if method == SNAP_METHOD_GET_PK:
            # Generate deterministic pk_blob from address
            address = snap_params.get("address", self._accounts[0])
            seed = hashlib.sha256(
                b"meteor-snap-seed-v1" + address.encode()
            ).digest()
            
            # Store seed for later use
            self._snap_state[f"seed:{address}"] = seed
            
            # Generate pk_blob using WalletChannel
            from ..transport import WalletChannel
            channel = WalletChannel.create(
                address=address,
                chain_id=self._chain_id,
                seed=seed,
            )
            
            pk_blob = channel.pk_blob
            self._snap_state[f"pk_blob:{address}"] = pk_blob
            
            return "0x" + pk_blob.hex()
        
        elif method == SNAP_METHOD_ENCRYPT:
            # Would use Snap's internal encryption in production
            data = bytes.fromhex(snap_params.get("data", "")[2:])
            recipient_pk = bytes.fromhex(snap_params.get("recipientPk", "")[2:])
            # Return mock encrypted data
            return "0x" + hashlib.sha256(data + recipient_pk).hexdigest()
        
        elif method == SNAP_METHOD_DECRYPT:
            # Would use Snap's internal decryption in production
            return "0x" + b"decrypted_data".hex()
        
        elif method == SNAP_METHOD_SIGN_AUTH:
            # Sign authentication data
            data = bytes.fromhex(snap_params.get("data", "")[2:])
            sig = self._mock_sign(data)
            return "0x" + sig.hex()
        
        else:
            raise Exception(f"Unknown snap method: {method}")
    
    def _mock_sign(self, data: bytes) -> bytes:
        """Generate mock signature."""
        sig_hash = hashlib.sha256(
            b"mock_metamask_sign" + data + self._accounts[0].encode()
        ).digest()
        # 65-byte signature: r(32) + s(32) + v(1)
        return sig_hash + sig_hash[:32] + b'\x1b'
    
    def on(self, event: str, callback: Callable) -> None:
        """Subscribe to events."""
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(callback)
    
    def remove_listener(self, event: str, callback: Callable) -> None:
        """Unsubscribe from events."""
        if event in self._event_handlers:
            if callback in self._event_handlers[event]:
                self._event_handlers[event].remove(callback)
    
    async def _emit(self, event: str, data: Any) -> None:
        """Emit event to handlers."""
        if event in self._event_handlers:
            for handler in self._event_handlers[event]:
                try:
                    result = handler(data)
                    if hasattr(result, '__await__'):
                        await result
                except Exception:
                    pass


# =============================================================================
# MetaMask Adapter
# =============================================================================

class MetaMaskAdapter(WalletAdapter):
    """
    MetaMask wallet adapter with Snap support.
    
    Provides integration with MetaMask browser extension,
    including Meteor-NC Snap for post-quantum operations.
    """
    
    def __init__(
        self,
        provider: Optional[EthereumProvider] = None,
        chain_id: int = 1,
        snap_id: str = METEOR_SNAP_ID,
    ):
        """
        Initialize MetaMask adapter.
        
        Args:
            provider: Ethereum provider (window.ethereum or mock)
            chain_id: Default chain ID
            snap_id: Meteor-NC Snap ID
        """
        super().__init__(chain_id)
        self._provider = provider
        self._snap_id = snap_id
        self._snap_installed = False
    
    @property
    def name(self) -> str:
        return "MetaMask"
    
    @property
    def capabilities(self) -> int:
        base_caps = (
            WalletCapability.SIGN_MESSAGE |
            WalletCapability.SIGN_TYPED_DATA |
            WalletCapability.SIGN_TRANSACTION |
            WalletCapability.SEND_TRANSACTION
        )
        
        if self._snap_installed:
            base_caps |= (
                WalletCapability.METEOR_KEY_GEN |
                WalletCapability.METEOR_ENCRYPT |
                WalletCapability.METEOR_DECRYPT |
                WalletCapability.METEOR_CHANNEL
            )
        
        return base_caps
    
    def _require_provider(self) -> EthereumProvider:
        """Get provider, raising if not available."""
        if self._provider is None:
            raise ConnectionError("No Ethereum provider available")
        return self._provider
    
    # =========================================================================
    # Connection
    # =========================================================================
    
    async def connect(self) -> WalletInfo:
        """Connect to MetaMask."""
        self._state = WalletState.CONNECTING
        
        try:
            provider = self._require_provider()
            
            # Request accounts
            accounts = await provider.request(ETH_REQUEST_ACCOUNTS)
            if not accounts:
                raise ConnectionError("No accounts available")
            
            # Get chain ID
            chain_id_hex = await provider.request(ETH_CHAIN_ID)
            chain_id = int(chain_id_hex, 16)
            
            # Check if Snap is installed
            await self._check_snap_installed()
            
            # Create wallet info
            self._info = WalletInfo(
                name="MetaMask",
                version="11.x",  # Would detect from provider
                chain_id=chain_id,
                address=accounts[0].lower(),
                capabilities=self.capabilities,
                metadata={"snap_installed": self._snap_installed},
            )
            
            self._chain_id = chain_id
            self._state = WalletState.CONNECTED
            
            # Set up event listeners
            self._setup_event_listeners()
            
            await self._emit(WalletEvent.CONNECTED, self._info)
            
            return self._info
            
        except Exception as e:
            self._state = WalletState.ERROR
            raise ConnectionError(f"Failed to connect: {e}")
    
    async def disconnect(self) -> None:
        """Disconnect from MetaMask."""
        self._state = WalletState.DISCONNECTED
        self._info = None
        self._meteor_identity = None
        self._wallet_channel = None
        self._sessions.clear()
        
        await self._emit(WalletEvent.DISCONNECTED)
    
    def _setup_event_listeners(self) -> None:
        """Set up MetaMask event listeners."""
        provider = self._provider
        if provider is None:
            return
        
        def on_accounts_changed(accounts: List[str]) -> None:
            if accounts and self._info:
                self._info.address = accounts[0].lower()
                # Clear Meteor identity on account change
                self._meteor_identity = None
                self._wallet_channel = None
        
        def on_chain_changed(chain_id_hex: str) -> None:
            chain_id = int(chain_id_hex, 16)
            if self._info:
                self._info.chain_id = chain_id
            self._chain_id = chain_id
        
        provider.on("accountsChanged", on_accounts_changed)
        provider.on("chainChanged", on_chain_changed)
    
    # =========================================================================
    # Snap Management
    # =========================================================================
    
    async def _check_snap_installed(self) -> bool:
        """Check if Meteor-NC Snap is installed."""
        try:
            provider = self._require_provider()
            snaps = await provider.request(WALLET_GET_SNAPS)
            self._snap_installed = self._snap_id in snaps
            return self._snap_installed
        except Exception:
            self._snap_installed = False
            return False
    
    async def is_snap_installed(self) -> bool:
        """Check if Meteor-NC Snap is installed."""
        return await self._check_snap_installed()
    
    async def install_snap(self) -> bool:
        """
        Install Meteor-NC Snap.
        
        Returns:
            True if installation successful
        """
        try:
            provider = self._require_provider()
            
            result = await provider.request(
                WALLET_REQUEST_SNAPS,
                {self._snap_id: {"version": METEOR_SNAP_VERSION}}
            )
            
            self._snap_installed = self._snap_id in result
            
            # Update capabilities
            if self._info:
                self._info.capabilities = self.capabilities
                self._info.metadata["snap_installed"] = self._snap_installed
            
            return self._snap_installed
            
        except Exception:
            return False
    
    async def _invoke_snap(self, method: str, params: Dict = None) -> Any:
        """Invoke Snap method."""
        if not self._snap_installed:
            if not await self.install_snap():
                raise UnsupportedOperationError("Snap not installed")
        
        provider = self._require_provider()
        
        return await provider.request(
            WALLET_INVOKE_SNAP,
            {
                "snapId": self._snap_id,
                "request": {
                    "method": method,
                    "params": params or {},
                },
            }
        )
    
    # =========================================================================
    # Account Management
    # =========================================================================
    
    async def get_accounts(self) -> List[str]:
        """Get available accounts."""
        self._require_connected()
        provider = self._require_provider()
        
        accounts = await provider.request(ETH_ACCOUNTS)
        return [a.lower() for a in accounts]
    
    async def switch_account(self, address: str) -> None:
        """
        Switch to a different account.
        
        Note: MetaMask doesn't support programmatic account switching.
        This will prompt user to switch manually.
        """
        self._require_connected()
        
        accounts = await self.get_accounts()
        if address.lower() not in accounts:
            raise WalletAdapterError(f"Account {address} not available")
        
        # Update local state
        if self._info:
            self._info.address = address.lower()
        
        # Clear Meteor identity
        self._meteor_identity = None
        self._wallet_channel = None
        
        await self._emit(WalletEvent.ACCOUNT_CHANGED, address)
    
    async def switch_chain(self, chain_id: int) -> None:
        """Switch to a different chain."""
        self._require_connected()
        provider = self._require_provider()
        
        await provider.request(
            WALLET_SWITCH_CHAIN,
            [{"chainId": hex(chain_id)}]
        )
        
        self._chain_id = chain_id
        if self._info:
            self._info.chain_id = chain_id
        
        await self._emit(WalletEvent.CHAIN_CHANGED, chain_id)
    
    # =========================================================================
    # Signing
    # =========================================================================
    
    async def sign_message(self, message: bytes) -> SignResult:
        """Sign message using personal_sign."""
        self._require_connected()
        provider = self._require_provider()
        
        try:
            # personal_sign expects hex-encoded message
            message_hex = "0x" + message.hex()
            
            signature_hex = await provider.request(
                ETH_SIGN,
                [message_hex, self.address]
            )
            
            signature = bytes.fromhex(signature_hex[2:])
            
            return SignResult(
                signature=signature,
                recovery_id=signature[-1] - 27 if len(signature) == 65 else None,
                sig_type=SignatureType.PERSONAL,
            )
            
        except Exception as e:
            if "rejected" in str(e).lower():
                raise SignatureRejectedError("User rejected signature")
            raise WalletAdapterError(f"Signing failed: {e}")
    
    async def sign_typed_data(
        self,
        domain: EIP712Domain,
        types: Dict[str, List[Dict[str, str]]],
        value: Dict[str, Any],
    ) -> SignResult:
        """Sign typed data using EIP-712."""
        self._require_connected()
        provider = self._require_provider()
        
        try:
            # Build EIP-712 message
            typed_data = {
                "types": {
                    "EIP712Domain": [
                        {"name": "name", "type": "string"},
                        {"name": "version", "type": "string"},
                        {"name": "chainId", "type": "uint256"},
                    ],
                    **types,
                },
                "primaryType": list(types.keys())[0],
                "domain": domain.to_dict(),
                "message": value,
            }
            
            # Add optional domain fields
            if domain.verifying_contract:
                typed_data["types"]["EIP712Domain"].append(
                    {"name": "verifyingContract", "type": "address"}
                )
            
            signature_hex = await provider.request(
                ETH_SIGN_TYPED_DATA,
                [self.address, json.dumps(typed_data)]
            )
            
            signature = bytes.fromhex(signature_hex[2:])
            
            return SignResult(
                signature=signature,
                recovery_id=signature[-1] - 27 if len(signature) == 65 else None,
                sig_type=SignatureType.TYPED_DATA,
            )
            
        except Exception as e:
            if "rejected" in str(e).lower():
                raise SignatureRejectedError("User rejected signature")
            raise WalletAdapterError(f"Signing failed: {e}")
    
    # =========================================================================
    # Meteor-NC Operations (via Snap)
    # =========================================================================
    
    async def _create_meteor_identity(self) -> MeteorIdentity:
        """
        Create Meteor identity using Snap.
        
        If Snap is installed, uses Snap's key generation.
        Otherwise, falls back to signature-derived keys.
        """
        if not self.address:
            raise NotConnectedError("No address available")
        
        if self._snap_installed:
            # Use Snap for key generation
            pk_blob_hex = await self._invoke_snap(
                SNAP_METHOD_GET_PK,
                {"address": self.address}
            )
            pk_blob = bytes.fromhex(pk_blob_hex[2:])
            
            return MeteorIdentity(
                address=self.address,
                pk_blob=pk_blob,
                seed=None,  # Snap manages keys internally
            )
        else:
            # Fall back to base implementation (signature-derived)
            return await super()._create_meteor_identity()
    
    async def snap_encrypt(self, data: bytes, recipient_pk: bytes) -> bytes:
        """
        Encrypt data using Snap.
        
        Args:
            data: Data to encrypt
            recipient_pk: Recipient's pk_blob
        
        Returns:
            Encrypted data
        """
        result_hex = await self._invoke_snap(
            SNAP_METHOD_ENCRYPT,
            {
                "data": "0x" + data.hex(),
                "recipientPk": "0x" + recipient_pk.hex(),
            }
        )
        return bytes.fromhex(result_hex[2:])
    
    async def snap_decrypt(self, encrypted: bytes) -> bytes:
        """
        Decrypt data using Snap.
        
        Args:
            encrypted: Encrypted data
        
        Returns:
            Decrypted data
        """
        result_hex = await self._invoke_snap(
            SNAP_METHOD_DECRYPT,
            {"data": "0x" + encrypted.hex()}
        )
        return bytes.fromhex(result_hex[2:])
    
    async def snap_sign_auth(self, data: bytes) -> bytes:
        """
        Sign authentication data using Snap.
        
        Used for mutual authentication in secure channels.
        
        Args:
            data: Data to sign
        
        Returns:
            Signature
        """
        result_hex = await self._invoke_snap(
            SNAP_METHOD_SIGN_AUTH,
            {"data": "0x" + data.hex()}
        )
        return bytes.fromhex(result_hex[2:])


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test MetaMask adapter."""
    import asyncio
    
    print("=" * 70)
    print("Meteor-NC Block Adapters: MetaMask Test")
    print("=" * 70)
    
    results = {}
    
    async def async_tests():
        # Test 1: Create adapter with mock provider
        print("\n[Test 1] Create MetaMaskAdapter")
        print("-" * 40)
        
        try:
            provider = MockEthereumProvider(
                accounts=["0x" + "A" * 40],
                chain_id=1,
                has_snap=True,
            )
            adapter = MetaMaskAdapter(provider=provider, chain_id=1)
            
            results["create"] = (
                adapter.name == "MetaMask" and
                adapter.state == WalletState.DISCONNECTED
            )
            print(f"  Name: {adapter.name}")
            print(f"  State: {adapter.state.name}")
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
                info.address == ("0x" + "a" * 40) and
                info.chain_id == 1 and
                info.metadata.get("snap_installed") == True
            )
            print(f"  Connected: {adapter.is_connected}")
            print(f"  Address: {info.address[:10]}...")
            print(f"  Snap installed: {info.metadata.get('snap_installed')}")
            print(f"  Result: {'PASS ✓' if results['connect'] else 'FAIL ✗'}")
        except Exception as e:
            results["connect"] = False
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print("  Result: FAIL ✗")
            return
        
        # Test 3: Check Snap
        print("\n[Test 3] Snap Status")
        print("-" * 40)
        
        try:
            snap_installed = await adapter.is_snap_installed()
            supports_meteor = adapter._info.supports_meteor if adapter._info else False
            
            results["snap"] = snap_installed and supports_meteor
            print(f"  Snap installed: {snap_installed}")
            print(f"  Supports Meteor: {supports_meteor}")
            print(f"  Result: {'PASS ✓' if results['snap'] else 'FAIL ✗'}")
        except Exception as e:
            results["snap"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
        
        # Test 4: Sign message
        print("\n[Test 4] Sign Message")
        print("-" * 40)
        
        try:
            result = await adapter.sign_message(b"Hello MetaMask!")
            results["sign"] = (
                len(result.signature) == 65 and
                result.sig_type == SignatureType.PERSONAL
            )
            print(f"  Signature: {result.signature[:8].hex()}...")
            print(f"  Length: {len(result.signature)}B")
            print(f"  Result: {'PASS ✓' if results['sign'] else 'FAIL ✗'}")
        except Exception as e:
            results["sign"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
        
        # Test 5: EIP-712 signing
        print("\n[Test 5] EIP-712 Sign")
        print("-" * 40)
        
        try:
            domain = EIP712Domain(
                name="Meteor-NC",
                version="1",
                chain_id=1,
            )
            types = {
                "Message": [
                    {"name": "content", "type": "string"},
                    {"name": "timestamp", "type": "uint256"},
                ]
            }
            value = {
                "content": "Hello!",
                "timestamp": 1234567890,
            }
            
            result = await adapter.sign_typed_data(domain, types, value)
            results["eip712"] = (
                len(result.signature) == 65 and
                result.sig_type == SignatureType.TYPED_DATA
            )
            print(f"  Signature: {result.signature[:8].hex()}...")
            print(f"  Type: {result.sig_type.name}")
            print(f"  Result: {'PASS ✓' if results['eip712'] else 'FAIL ✗'}")
        except Exception as e:
            results["eip712"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
        
        # Test 6: Get Meteor pk_blob via Snap
        print("\n[Test 6] Get Meteor PK Blob (Snap)")
        print("-" * 40)
        
        try:
            identity = await adapter.ensure_meteor_identity()
            pk_blob = await adapter.get_meteor_pk_blob()
            
            results["pk_blob"] = (
                len(pk_blob) == 64 and
                identity.address == adapter.address
            )
            print(f"  pk_blob size: {len(pk_blob)}B")
            print(f"  pk_seed: {pk_blob[:8].hex()}...")
            print(f"  Result: {'PASS ✓' if results['pk_blob'] else 'FAIL ✗'}")
        except Exception as e:
            results["pk_blob"] = False
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print("  Result: FAIL ✗")
        
        # Test 7: P2P Session
        print("\n[Test 7] P2P Session")
        print("-" * 40)
        
        try:
            # Create second adapter (Bob)
            bob_provider = MockEthereumProvider(
                accounts=["0x" + "B" * 40],
                chain_id=1,
            )
            bob = MetaMaskAdapter(provider=bob_provider, chain_id=1)
            await bob.connect()
            bob_pk = await bob.get_meteor_pk_blob()
            
            # Alice initiates
            session_a, handshake = await adapter.initiate_session(
                bob.address, bob_pk
            )
            
            # Bob accepts
            alice_pk = await adapter.get_meteor_pk_blob()
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
        
        # Test 8: Switch chain
        print("\n[Test 8] Switch Chain")
        print("-" * 40)
        
        try:
            await adapter.switch_chain(137)  # Polygon
            results["chain"] = adapter.chain_id == 137
            print(f"  New chain: {adapter.chain_id}")
            print(f"  Result: {'PASS ✓' if results['chain'] else 'FAIL ✗'}")
        except Exception as e:
            results["chain"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
        
        # Test 9: Disconnect
        print("\n[Test 9] Disconnect")
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
