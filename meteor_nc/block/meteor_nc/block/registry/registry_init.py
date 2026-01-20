# meteor_nc/block/registry/__init__.py
"""
Meteor-NC Block Registry Layer

On-chain public key registry for EVM chains.
Enables key discovery, rotation, and revocation.

Components:
    PKStore: Contract interaction layer
    KeyResolver: Address/KeyID → pk_blob resolution

Usage:
    from meteor_nc.block.registry import PKStore, KeyResolver, KeyType
    
    # Connect to registry
    store = PKStore(
        contract_address="0x...",
        rpc_url="https://...",
        private_key="0x...",  # For write operations
    )
    
    # Register a key
    key_id = await store.register_key(
        pk_seed=alice.pk_seed,
        b_hash=alice.b_hash,
        suite_id=0x01,
        key_type=KeyType.ENCRYPTION,
    )
    
    # Resolve key
    resolver = KeyResolver(store)
    pk_blob = await resolver.resolve_pk_blob(key_id)
    
    # Or by address
    pk_blob = await resolver.resolve_by_address(
        address="0x...",
        key_type=KeyType.ENCRYPTION,
    )
"""

from .pk_store import (
    PKStore,
    KeyType,
    MeteorKeyInfo,
    RegistryError,
    KeyNotFoundError,
    KeyAlreadyRegisteredError,
    NotKeyOwnerError,
)

from .resolver import (
    KeyResolver,
    ResolverError,
)

__all__ = [
    # PKStore
    "PKStore",
    "KeyType",
    "MeteorKeyInfo",
    "RegistryError",
    "KeyNotFoundError",
    "KeyAlreadyRegisteredError",
    "NotKeyOwnerError",
    # Resolver
    "KeyResolver",
    "ResolverError",
]

__version__ = "0.3.0"
