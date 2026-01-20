# meteor_nc/block/adapters/walletconnect.py
"""
Meteor-NC Block Adapters: WalletConnect v2 Integration

Provides WalletConnect v2 protocol integration for connecting
mobile wallets and hardware wallets to Meteor-NC.

WalletConnect Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │                    Mobile Wallet                        │
    │  (Trust Wallet, Rainbow, MetaMask Mobile, etc.)        │
    └─────────────────────────────────────────────────────────┘
                              │
                     WalletConnect v2
                      (Relay Server)
                              │
    ┌─────────────────────────────────────────────────────────┐
    │                WalletConnectAdapter                     │
    │  - Pairing via QR code or deep link                    │
    │  - Session management                                   │
    │  - RPC request/response                                 │
    │  - Event handling                                       │
    └─────────────────────────────────────────────────────────┘

Protocol Flow:
    1. Generate pairing URI (QR code)
    2. User scans with mobile wallet
    3. Wallet approves connection
    4. Session established
    5. Send JSON-RPC requests through relay

Features:
    - Multi-chain support
    - Session persistence
    - Push notifications (optional)
    - Deep link support

Usage:
    adapter = WalletConnectAdapter(
        project_id="your_wc_project_id",
        metadata={"name": "My dApp", ...}
    )
    
    # Get pairing URI for QR code
    uri = await adapter.get_pairing_uri()
    
    # Wait for connection
    info = await adapter.connect()
    
    # Use Meteor features
    pk_blob = await adapter.get_meteor_pk_blob()

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import json
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable, Awaitable
from enum import Enum, auto

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

# WalletConnect Relay
DEFAULT_RELAY_URL = "wss://relay.walletconnect.com"

# JSON-RPC methods
WC_SESSION_PROPOSE = "wc_sessionPropose"
WC_SESSION_SETTLE = "wc_sessionSettle"
WC_SESSION_UPDATE = "wc_sessionUpdate"
WC_SESSION_DELETE = "wc_sessionDelete"
WC_SESSION_PING = "wc_sessionPing"
WC_SESSION_REQUEST = "wc_sessionRequest"

# Ethereum methods
ETH_SIGN = "personal_sign"
ETH_SIGN_TYPED_DATA = "eth_signTypedData_v4"
ETH_SEND_TRANSACTION = "eth_sendTransaction"
ETH_SIGN_TRANSACTION = "eth_signTransaction"

# Default metadata
DEFAULT_METADATA = {
    "name": "Meteor-NC dApp",
    "description": "Post-quantum secure blockchain application",
    "url": "https://meteor-nc.example.com",
    "icons": ["https://meteor-nc.example.com/icon.png"],
}


# =============================================================================
# WalletConnect Types
# =============================================================================

@dataclass
class WCMetadata:
    """WalletConnect metadata for dApp or wallet."""
    name: str
    description: str
    url: str
    icons: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "url": self.url,
            "icons": self.icons,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WCMetadata':
        return cls(
            name=data.get("name", "Unknown"),
            description=data.get("description", ""),
            url=data.get("url", ""),
            icons=data.get("icons", []),
        )


@dataclass
class WCSession:
    """WalletConnect session."""
    topic: str
    relay: str
    controller_public_key: str
    namespaces: Dict[str, Any]
    expiry: int
    peer_metadata: Optional[WCMetadata] = None
    
    @property
    def is_expired(self) -> bool:
        return time.time() > self.expiry
    
    def get_accounts(self, namespace: str = "eip155") -> List[str]:
        """Get accounts for a namespace."""
        ns = self.namespaces.get(namespace, {})
        accounts = ns.get("accounts", [])
        # Format: eip155:1:0x... -> extract address
        return [a.split(":")[-1] for a in accounts]
    
    def get_chains(self, namespace: str = "eip155") -> List[int]:
        """Get chain IDs for a namespace."""
        ns = self.namespaces.get(namespace, {})
        chains = ns.get("chains", [])
        # Format: eip155:1 -> extract chain ID
        return [int(c.split(":")[-1]) for c in chains]


@dataclass 
class WCPairing:
    """WalletConnect pairing."""
    topic: str
    uri: str
    expiry: int
    active: bool = True
    
    @property
    def is_expired(self) -> bool:
        return time.time() > self.expiry


# =============================================================================
# Mock WalletConnect Client
# =============================================================================

class MockWCClient:
    """
    Mock WalletConnect client for testing.
    
    Simulates WalletConnect v2 protocol without real relay.
    """
    
    def __init__(
        self,
        project_id: str,
        metadata: WCMetadata,
        relay_url: str = DEFAULT_RELAY_URL,
    ):
        self.project_id = project_id
        self.metadata = metadata
        self.relay_url = relay_url
        
        self._pairings: Dict[str, WCPairing] = {}
        self._sessions: Dict[str, WCSession] = {}
        self._pending_proposals: Dict[str, Dict] = {}
        
        # Mock wallet state
        self._mock_accounts = ["0x" + "1" * 40]
        self._mock_chain_id = 1
        self._auto_approve = True
        
        # Event handlers
        self._event_handlers: Dict[str, List[Callable]] = {}
    
    async def init(self) -> None:
        """Initialize client."""
        pass  # No-op for mock
    
    async def pair(self, uri: Optional[str] = None) -> WCPairing:
        """Create or join pairing."""
        topic = secrets.token_hex(32)
        expiry = int(time.time()) + 300  # 5 minutes
        
        pairing_uri = (
            f"wc:{topic}@2"
            f"?relay-protocol=irn"
            f"&symKey={secrets.token_hex(32)}"
        )
        
        pairing = WCPairing(
            topic=topic,
            uri=pairing_uri,
            expiry=expiry,
        )
        
        self._pairings[topic] = pairing
        return pairing
    
    async def connect(
        self,
        required_namespaces: Dict[str, Any],
        pairing_topic: Optional[str] = None,
    ) -> WCSession:
        """
        Connect to wallet.
        
        In real implementation, this would:
        1. Send session proposal through relay
        2. Wait for wallet approval
        3. Return settled session
        """
        if not self._auto_approve:
            raise ConnectionError("User rejected connection")
        
        topic = secrets.token_hex(32)
        expiry = int(time.time()) + 86400  # 24 hours
        
        # Build namespaces from required
        namespaces = {}
        for ns_key, ns_req in required_namespaces.items():
            chains = ns_req.get("chains", ["eip155:1"])
            accounts = [
                f"{chain}:{self._mock_accounts[0]}" 
                for chain in chains
            ]
            namespaces[ns_key] = {
                "chains": chains,
                "accounts": accounts,
                "methods": ns_req.get("methods", []),
                "events": ns_req.get("events", []),
            }
        
        session = WCSession(
            topic=topic,
            relay=self.relay_url,
            controller_public_key=secrets.token_hex(32),
            namespaces=namespaces,
            expiry=expiry,
            peer_metadata=WCMetadata(
                name="Mock Wallet",
                description="Mock wallet for testing",
                url="https://mock-wallet.example.com",
                icons=[],
            ),
        )
        
        self._sessions[topic] = session
        return session
    
    async def request(
        self,
        topic: str,
        chain_id: str,
        request: Dict[str, Any],
    ) -> Any:
        """
        Send JSON-RPC request to wallet.
        
        Args:
            topic: Session topic
            chain_id: Chain ID (e.g., "eip155:1")
            request: JSON-RPC request {method, params}
        """
        session = self._sessions.get(topic)
        if not session:
            raise WalletAdapterError("Session not found")
        
        if session.is_expired:
            raise WalletAdapterError("Session expired")
        
        method = request.get("method", "")
        params = request.get("params", [])
        
        if not self._auto_approve:
            raise SignatureRejectedError("User rejected request")
        
        # Handle different methods
        if method == ETH_SIGN:
            return self._mock_personal_sign(params)
        elif method == ETH_SIGN_TYPED_DATA:
            return self._mock_sign_typed_data(params)
        elif method == ETH_SEND_TRANSACTION:
            return self._mock_send_transaction(params)
        else:
            raise UnsupportedOperationError(f"Method not supported: {method}")
    
    def _mock_personal_sign(self, params: List) -> str:
        """Mock personal_sign."""
        message = params[0] if params else ""
        if message.startswith("0x"):
            message_bytes = bytes.fromhex(message[2:])
        else:
            message_bytes = message.encode()
        
        sig_hash = hashlib.sha256(
            b"wc_mock_sign" + message_bytes + self._mock_accounts[0].encode()
        ).digest()
        
        return "0x" + (sig_hash + sig_hash[:32] + b'\x1b').hex()
    
    def _mock_sign_typed_data(self, params: List) -> str:
        """Mock eth_signTypedData_v4."""
        address = params[0] if params else ""
        typed_data = params[1] if len(params) > 1 else "{}"
        
        data_bytes = typed_data.encode() if isinstance(typed_data, str) else typed_data
        sig_hash = hashlib.sha256(
            b"wc_mock_typed" + data_bytes + address.encode()
        ).digest()
        
        return "0x" + (sig_hash + sig_hash[:32] + b'\x1c').hex()
    
    def _mock_send_transaction(self, params: List) -> str:
        """Mock eth_sendTransaction."""
        tx = params[0] if params else {}
        tx_hash = hashlib.sha256(
            b"wc_mock_tx" + json.dumps(tx).encode()
        ).digest()
        return "0x" + tx_hash.hex()
    
    async def disconnect(self, topic: str, reason: str = "User disconnected") -> None:
        """Disconnect session."""
        if topic in self._sessions:
            del self._sessions[topic]
    
    def on(self, event: str, callback: Callable) -> None:
        """Subscribe to events."""
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(callback)


# =============================================================================
# WalletConnect Adapter
# =============================================================================

class WalletConnectAdapter(WalletAdapter):
    """
    WalletConnect v2 wallet adapter.
    
    Connects to mobile wallets and hardware wallets via
    WalletConnect relay protocol.
    """
    
    def __init__(
        self,
        project_id: str = "test_project_id",
        metadata: Optional[Dict[str, Any]] = None,
        relay_url: str = DEFAULT_RELAY_URL,
        chain_id: int = 1,
        client: Optional[MockWCClient] = None,
    ):
        """
        Initialize WalletConnect adapter.
        
        Args:
            project_id: WalletConnect Cloud project ID
            metadata: dApp metadata
            relay_url: Relay server URL
            chain_id: Default chain ID
            client: WC client (uses mock if None)
        """
        super().__init__(chain_id)
        
        meta_dict = metadata or DEFAULT_METADATA
        self._metadata = WCMetadata(
            name=meta_dict.get("name", "Meteor-NC"),
            description=meta_dict.get("description", ""),
            url=meta_dict.get("url", ""),
            icons=meta_dict.get("icons", []),
        )
        
        self._project_id = project_id
        self._relay_url = relay_url
        
        # WalletConnect client
        self._client = client or MockWCClient(
            project_id=project_id,
            metadata=self._metadata,
            relay_url=relay_url,
        )
        
        # Session state
        self._pairing: Optional[WCPairing] = None
        self._session: Optional[WCSession] = None
    
    @property
    def name(self) -> str:
        return "WalletConnect"
    
    @property
    def capabilities(self) -> int:
        return (
            WalletCapability.SIGN_MESSAGE |
            WalletCapability.SIGN_TYPED_DATA |
            WalletCapability.SIGN_TRANSACTION |
            WalletCapability.SEND_TRANSACTION |
            WalletCapability.METEOR_KEY_GEN |
            WalletCapability.METEOR_ENCRYPT |
            WalletCapability.METEOR_CHANNEL |
            WalletCapability.MULTI_ACCOUNT
        )
    
    @property
    def pairing_uri(self) -> Optional[str]:
        """Get current pairing URI for QR code."""
        return self._pairing.uri if self._pairing else None
    
    @property
    def session(self) -> Optional[WCSession]:
        """Get current session."""
        return self._session
    
    # =========================================================================
    # Connection
    # =========================================================================
    
    async def get_pairing_uri(self) -> str:
        """
        Generate new pairing URI for QR code.
        
        Returns:
            WalletConnect pairing URI
        """
        await self._client.init()
        self._pairing = await self._client.pair()
        return self._pairing.uri
    
    async def connect(self) -> WalletInfo:
        """
        Connect to wallet via WalletConnect.
        
        If no pairing exists, creates one first.
        Waits for wallet to approve connection.
        """
        self._state = WalletState.CONNECTING
        
        try:
            # Initialize client
            await self._client.init()
            
            # Create pairing if needed
            if not self._pairing:
                self._pairing = await self._client.pair()
            
            # Define required namespaces
            required_namespaces = {
                "eip155": {
                    "chains": [f"eip155:{self._chain_id}"],
                    "methods": [
                        ETH_SIGN,
                        ETH_SIGN_TYPED_DATA,
                        ETH_SEND_TRANSACTION,
                        ETH_SIGN_TRANSACTION,
                    ],
                    "events": ["accountsChanged", "chainChanged"],
                }
            }
            
            # Connect (wait for wallet approval)
            self._session = await self._client.connect(
                required_namespaces=required_namespaces,
                pairing_topic=self._pairing.topic,
            )
            
            # Get account info
            accounts = self._session.get_accounts()
            chains = self._session.get_chains()
            
            if not accounts:
                raise ConnectionError("No accounts received")
            
            # Create wallet info
            peer_name = "Unknown Wallet"
            if self._session.peer_metadata:
                peer_name = self._session.peer_metadata.name
            
            self._info = WalletInfo(
                name=peer_name,
                version="WC2",
                chain_id=chains[0] if chains else self._chain_id,
                address=accounts[0].lower(),
                capabilities=self.capabilities,
                metadata={
                    "session_topic": self._session.topic,
                    "peer_metadata": self._session.peer_metadata.to_dict() if self._session.peer_metadata else {},
                },
            )
            
            self._state = WalletState.CONNECTED
            await self._emit(WalletEvent.CONNECTED, self._info)
            
            return self._info
            
        except Exception as e:
            self._state = WalletState.ERROR
            raise ConnectionError(f"Failed to connect: {e}")
    
    async def disconnect(self) -> None:
        """Disconnect from wallet."""
        if self._session:
            try:
                await self._client.disconnect(self._session.topic)
            except Exception:
                pass
        
        self._state = WalletState.DISCONNECTED
        self._session = None
        self._pairing = None
        self._info = None
        self._meteor_identity = None
        self._wallet_channel = None
        self._sessions.clear()
        
        await self._emit(WalletEvent.DISCONNECTED)
    
    # =========================================================================
    # Account Management
    # =========================================================================
    
    async def get_accounts(self) -> List[str]:
        """Get available accounts."""
        self._require_connected()
        
        if self._session:
            return [a.lower() for a in self._session.get_accounts()]
        return []
    
    async def switch_account(self, address: str) -> None:
        """
        Switch to a different account.
        
        Note: Account switching depends on wallet support.
        """
        self._require_connected()
        
        accounts = await self.get_accounts()
        if address.lower() not in accounts:
            raise WalletAdapterError(f"Account {address} not available")
        
        if self._info:
            self._info.address = address.lower()
        
        # Clear Meteor identity
        self._meteor_identity = None
        self._wallet_channel = None
        
        await self._emit(WalletEvent.ACCOUNT_CHANGED, address)
    
    async def switch_chain(self, chain_id: int) -> None:
        """
        Switch to a different chain.
        
        Note: May require wallet_switchEthereumChain support.
        """
        self._require_connected()
        
        # Update local state
        self._chain_id = chain_id
        if self._info:
            self._info.chain_id = chain_id
        
        await self._emit(WalletEvent.CHAIN_CHANGED, chain_id)
    
    # =========================================================================
    # Signing
    # =========================================================================
    
    async def _send_request(self, method: str, params: List) -> Any:
        """Send request through WalletConnect."""
        self._require_connected()
        
        if not self._session:
            raise NotConnectedError("No active session")
        
        chain_id = f"eip155:{self.chain_id}"
        
        return await self._client.request(
            topic=self._session.topic,
            chain_id=chain_id,
            request={"method": method, "params": params},
        )
    
    async def sign_message(self, message: bytes) -> SignResult:
        """Sign message using personal_sign."""
        try:
            message_hex = "0x" + message.hex()
            signature_hex = await self._send_request(
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
        try:
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
            
            if domain.verifying_contract:
                typed_data["types"]["EIP712Domain"].append(
                    {"name": "verifyingContract", "type": "address"}
                )
            
            signature_hex = await self._send_request(
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


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test WalletConnect adapter."""
    import asyncio
    
    print("=" * 70)
    print("Meteor-NC Block Adapters: WalletConnect Test")
    print("=" * 70)
    
    results = {}
    
    async def async_tests():
        # Test 1: Create adapter
        print("\n[Test 1] Create WalletConnectAdapter")
        print("-" * 40)
        
        try:
            adapter = WalletConnectAdapter(
                project_id="test_project",
                chain_id=1,
            )
            results["create"] = (
                adapter.name == "WalletConnect" and
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
        
        # Test 2: Get pairing URI
        print("\n[Test 2] Get Pairing URI")
        print("-" * 40)
        
        try:
            uri = await adapter.get_pairing_uri()
            results["pairing"] = (
                uri.startswith("wc:") and
                "@2" in uri
            )
            print(f"  URI: {uri[:40]}...")
            print(f"  Valid format: {results['pairing']}")
            print(f"  Result: {'PASS ✓' if results['pairing'] else 'FAIL ✗'}")
        except Exception as e:
            results["pairing"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
        
        # Test 3: Connect
        print("\n[Test 3] Connect")
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
            print(f"  Wallet: {info.name}")
            print(f"  Result: {'PASS ✓' if results['connect'] else 'FAIL ✗'}")
        except Exception as e:
            results["connect"] = False
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print("  Result: FAIL ✗")
            return
        
        # Test 4: Sign message
        print("\n[Test 4] Sign Message")
        print("-" * 40)
        
        try:
            result = await adapter.sign_message(b"Hello WalletConnect!")
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
                ]
            }
            value = {"content": "Hello!"}
            
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
        
        # Test 6: Get Meteor pk_blob
        print("\n[Test 6] Get Meteor PK Blob")
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
            import traceback
            traceback.print_exc()
            print("  Result: FAIL ✗")
        
        # Test 7: P2P Session
        print("\n[Test 7] P2P Session")
        print("-" * 40)
        
        try:
            # Create Bob adapter
            bob = WalletConnectAdapter(project_id="bob", chain_id=1)
            bob._client._mock_accounts = ["0x" + "2" * 40]
            await bob.connect()
            bob_pk = await bob.get_meteor_pk_blob()
            
            # Alice initiates
            session_a, handshake = await adapter.initiate_session(
                bob.address, bob_pk
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
        
        # Test 8: Get accounts
        print("\n[Test 8] Get Accounts")
        print("-" * 40)
        
        try:
            accounts = await adapter.get_accounts()
            results["accounts"] = len(accounts) > 0
            print(f"  Accounts: {accounts}")
            print(f"  Result: {'PASS ✓' if results['accounts'] else 'FAIL ✗'}")
        except Exception as e:
            results["accounts"] = False
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
