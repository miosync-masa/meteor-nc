# meteor_nc/block/transport/__init__.py
"""
Meteor-NC Block Transport Layer

Off-chain encrypted communication using SecureEnvelope v0.3 wire format.
Integrates with cryptography/ primitives (LWEKEM, StreamDEM, compression).

Modules:
    channel: SecureChannel for encrypted P2P communication
    wallet: WalletChannel for Ethereum wallet-to-wallet messaging
    rpc: SecureRPCClient for encrypted RPC communication

Usage:
    # Basic channel
    from meteor_nc.block.transport import SecureChannel, ChannelState
    channel = SecureChannel.create(chain_id=1)
    
    # Wallet-to-wallet
    from meteor_nc.block.transport import WalletChannel, WalletMessage
    wallet = WalletChannel.create(address="0x...", chain_id=1)
    session, handshake = wallet.initiate_handshake(peer_addr, peer_pk_blob)
    
    # Secure RPC
    from meteor_nc.block.transport import SecureRPCClient
    client = SecureRPCClient(endpoint="https://...", builder_pk_bytes=pk, chain_id=1)
    tx_hash = await client.send_private_transaction(raw_tx)
"""

from .channel import (
    SecureChannel,
    ChannelState,
    ChannelError,
    HandshakeError,
    DecryptionError,
)

from .wallet import (
    WalletChannel,
    WalletSession,
    WalletMessage,
    MessageType,
    WalletError,
    AddressError,
    ResolutionError,
    MessageError,
)

from .rpc import (
    SecureRPCClient,
    SecureRPCHandler,
    RPCRequest,
    RPCResponse,
    PrivateTxRequest,
    RPCError,
    ResponseError,
    EncryptionError,
    MockHTTPTransport,
    METHOD_SEND_PRIVATE_TX,
    METHOD_PRIVATE_CALL,
    METHOD_GET_BUILDER_PK,
    METHOD_SUBMIT_COMMIT,
    METHOD_SUBMIT_REVEAL,
)

__all__ = [
    # Channel
    "SecureChannel",
    "ChannelState",
    "ChannelError",
    "HandshakeError",
    "DecryptionError",
    # Wallet
    "WalletChannel",
    "WalletSession",
    "WalletMessage",
    "MessageType",
    "WalletError",
    "AddressError",
    "ResolutionError",
    "MessageError",
    # RPC
    "SecureRPCClient",
    "SecureRPCHandler",
    "RPCRequest",
    "RPCResponse",
    "PrivateTxRequest",
    "RPCError",
    "ResponseError",
    "EncryptionError",
    "MockHTTPTransport",
    "METHOD_SEND_PRIVATE_TX",
    "METHOD_PRIVATE_CALL",
    "METHOD_GET_BUILDER_PK",
    "METHOD_SUBMIT_COMMIT",
    "METHOD_SUBMIT_REVEAL",
]

__version__ = "0.3.0"
