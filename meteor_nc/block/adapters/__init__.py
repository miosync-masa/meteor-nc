# meteor_nc/block/adapters/__init__.py
"""
Meteor-NC Block Adapters: Wallet Integration Layer

Provides unified interfaces for integrating Meteor-NC post-quantum
cryptography with various wallet implementations.

Adapters:
    WalletAdapter     - Abstract base class for all wallet adapters
    MockWalletAdapter - Mock implementation for testing
    MetaMaskAdapter   - MetaMask browser extension + Snap
    WalletConnectAdapter - WalletConnect v2 protocol

Features:
    - Connection management (connect, disconnect, reconnect)
    - Message signing (personal_sign, EIP-712)
    - Meteor-NC key generation and management
    - Encrypted P2P communication
    - Event handling (accountChanged, chainChanged, etc.)

Quick Start:
    # MetaMask integration
    from meteor_nc.block.adapters import MetaMaskAdapter
    
    adapter = MetaMaskAdapter()
    await adapter.connect()
    
    # Get Meteor identity for sharing
    pk_blob = await adapter.get_meteor_pk_blob()
    
    # Initiate encrypted session
    session, handshake = await adapter.initiate_session(peer_addr, peer_pk)
    
    # WalletConnect integration
    from meteor_nc.block.adapters import WalletConnectAdapter
    
    adapter = WalletConnectAdapter(project_id="your_project_id")
    uri = await adapter.get_pairing_uri()  # Show as QR code
    await adapter.connect()  # Wait for wallet approval

Test Results:
    - base.py: 8/8 tests passed
    - metamask.py: 9/9 tests passed
    - walletconnect.py: 9/9 tests passed
    - Total: 26/26 tests passed

Updated: 2025-01-20
Version: 0.3.0
"""

# Base classes and types
from .base import (
    # Abstract adapter
    WalletAdapter,
    MockWalletAdapter,
    
    # States and capabilities
    WalletState,
    WalletCapability,
    SignatureType,
    WalletEvent,
    
    # Data classes
    WalletInfo,
    MeteorIdentity,
    SignRequest,
    SignResult,
    EIP712Domain,
    
    # Exceptions
    WalletAdapterError,
    NotConnectedError,
    UnsupportedOperationError,
    SignatureRejectedError,
    ConnectionError,
)

# MetaMask adapter
from .metamask import (
    MetaMaskAdapter,
    MockEthereumProvider,
    EthereumProvider,
    METEOR_SNAP_ID,
)

# WalletConnect adapter
from .walletconnect import (
    WalletConnectAdapter,
    MockWCClient,
    WCSession,
    WCPairing,
    WCMetadata,
)

__all__ = [
    # === Base ===
    "WalletAdapter",
    "MockWalletAdapter",
    "WalletState",
    "WalletCapability",
    "SignatureType",
    "WalletEvent",
    "WalletInfo",
    "MeteorIdentity",
    "SignRequest",
    "SignResult",
    "EIP712Domain",
    "WalletAdapterError",
    "NotConnectedError",
    "UnsupportedOperationError",
    "SignatureRejectedError",
    "ConnectionError",
    
    # === MetaMask ===
    "MetaMaskAdapter",
    "MockEthereumProvider",
    "EthereumProvider",
    "METEOR_SNAP_ID",
    
    # === WalletConnect ===
    "WalletConnectAdapter",
    "MockWCClient",
    "WCSession",
    "WCPairing",
    "WCMetadata",
]

__version__ = "0.3.0"
