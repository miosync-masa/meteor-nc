# meteor_nc/block/transport/__init__.py
"""
Meteor-NC Block Transport Layer

Off-chain encrypted communication using SecureEnvelope v0.3 wire format.
Integrates with cryptography/ primitives (LWEKEM, StreamDEM, compression).

Modules:
    channel: SecureChannel for encrypted P2P communication

Usage:
    from meteor_nc.block.transport import SecureChannel, ChannelState
    
    # Create channel with identity
    channel = SecureChannel.create(
        chain_id=1,
        suite_id=0x01,  # Level 1
    )
    
    # Get pk_blob for sharing
    my_pk_blob = channel.get_pk_blob()
    
    # Connect to peer (initiator side)
    handshake = channel.connect(peer_pk_blob)
    # Send handshake envelope to peer...
    
    # Accept handshake (responder side)
    response = peer_channel.accept(handshake)
    # Send response back...
    
    # Send encrypted data
    envelope = channel.send(b"Hello!")
    
    # Receive and decrypt
    data = channel.receive(envelope)
"""

from .channel import (
    SecureChannel,
    ChannelState,
    ChannelError,
    HandshakeError,
    DecryptionError,
)

__all__ = [
    "SecureChannel",
    "ChannelState",
    "ChannelError",
    "HandshakeError",
    "DecryptionError",
]

__version__ = "0.3.0"
