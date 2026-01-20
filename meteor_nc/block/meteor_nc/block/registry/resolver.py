# meteor_nc/block/registry/resolver.py
"""
Meteor-NC Block Registry: Key Resolver

High-level API for resolving keys from various identifiers.
Wraps PKStore with caching and convenience methods.

Usage:
    from meteor_nc.block.registry import KeyResolver, PKStore
    
    store = PKStore(contract_address, rpc_url, private_key)
    resolver = KeyResolver(store)
    
    # Resolve by key ID
    pk_blob = resolver.resolve_pk_blob(key_id)
    
    # Resolve by address (get latest encryption key)
    pk_blob = resolver.resolve_by_address(address)
    
    # Resolve multiple keys
    pk_blobs = resolver.batch_resolve([key_id1, key_id2, key_id3])

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from .pk_store import PKStore, MockPKStore, MeteorKeyInfo, KeyType


# =============================================================================
# Exceptions
# =============================================================================

class ResolverError(Exception):
    """Base resolver error."""
    pass


class KeyNotValidError(ResolverError):
    """Key exists but is not valid (revoked or expired)."""
    def __init__(self, key_id: bytes, reason: str):
        self.key_id = key_id
        self.reason = reason
        super().__init__(f"Key {key_id.hex()[:16]}... is not valid: {reason}")


class NoKeyFoundError(ResolverError):
    """No suitable key found for the query."""
    def __init__(self, query: str):
        self.query = query
        super().__init__(f"No key found: {query}")


# =============================================================================
# Cache Entry
# =============================================================================

@dataclass
class CacheEntry:
    """Cache entry for resolved keys."""
    pk_blob: bytes
    key_id: bytes
    valid_until: int  # 0 = no expiry
    cached_at: float
    ttl: float  # Cache TTL in seconds
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        return time.time() > self.cached_at + self.ttl


# =============================================================================
# KeyResolver
# =============================================================================

class KeyResolver:
    """
    High-level key resolver with caching.
    
    Provides convenient methods for resolving keys from:
    - Key ID (32 bytes)
    - Owner address (returns latest key)
    - Address + KeyType (returns latest key of type)
    
    Features:
    - In-memory caching with TTL
    - Batch resolution
    - Validation (revocation, expiration)
    """
    
    def __init__(
        self,
        store: Union["PKStore", "MockPKStore"],
        cache_ttl: float = 300.0,  # 5 minutes
        enable_cache: bool = True,
    ):
        """
        Initialize resolver.
        
        Args:
            store: PKStore or MockPKStore instance
            cache_ttl: Cache TTL in seconds (default: 300)
            enable_cache: Enable caching (default: True)
        """
        self._store = store
        self._cache_ttl = cache_ttl
        self._enable_cache = enable_cache
        
        # Cache: key_id -> CacheEntry
        self._cache: Dict[bytes, CacheEntry] = {}
        
        # Address cache: (address, key_type) -> key_id
        self._address_cache: Dict[Tuple[str, int], bytes] = {}
    
    # =========================================================================
    # Primary Resolution Methods
    # =========================================================================
    
    def resolve_pk_blob(
        self,
        key_id: bytes,
        require_valid: bool = True,
    ) -> bytes:
        """
        Resolve pk_blob by key ID.
        
        Args:
            key_id: 32-byte key ID
            require_valid: Require key to be valid (not revoked/expired)
        
        Returns:
            64-byte pk_blob (pk_seed || b_hash)
        
        Raises:
            KeyNotValidError: If key is revoked/expired and require_valid=True
            ResolverError: If key not found
        """
        # Check cache
        if self._enable_cache and key_id in self._cache:
            entry = self._cache[key_id]
            if not entry.is_expired():
                return entry.pk_blob
            else:
                del self._cache[key_id]
        
        # Fetch from store
        try:
            if require_valid and not self._store.is_key_valid(key_id):
                # Get key info for detailed error
                try:
                    key_info = self._store.get_key(key_id)
                    if key_info.revoked:
                        raise KeyNotValidError(key_id, "revoked")
                    elif key_info.is_expired:
                        raise KeyNotValidError(key_id, "expired")
                    else:
                        raise KeyNotValidError(key_id, "invalid")
                except KeyNotValidError:
                    raise
                except Exception:
                    raise KeyNotValidError(key_id, "invalid")
            
            pk_blob = self._store.get_pk_blob(key_id)
            
            # Get validity info for cache
            try:
                key_info = self._store.get_key(key_id)
                valid_until = key_info.valid_until
            except Exception:
                valid_until = 0
            
            # Cache result
            if self._enable_cache:
                self._cache[key_id] = CacheEntry(
                    pk_blob=pk_blob,
                    key_id=key_id,
                    valid_until=valid_until,
                    cached_at=time.time(),
                    ttl=self._cache_ttl,
                )
            
            return pk_blob
            
        except KeyNotValidError:
            raise
        except Exception as e:
            raise ResolverError(f"Failed to resolve key {key_id.hex()[:16]}...: {e}")
    
    def resolve_by_address(
        self,
        address: str,
        key_type: Optional["KeyType"] = None,
    ) -> bytes:
        """
        Resolve pk_blob by owner address.
        
        Gets the latest active key for the address.
        
        Args:
            address: Owner address
            key_type: Optional key type filter (default: ENCRYPTION)
        
        Returns:
            64-byte pk_blob
        
        Raises:
            NoKeyFoundError: If no valid key found for address
        """
        # Import here to avoid circular imports
        from .pk_store import KeyType as KT
        
        if key_type is None:
            key_type = KT.ENCRYPTION
        
        # Check address cache
        cache_key = (address.lower(), int(key_type))
        if self._enable_cache and cache_key in self._address_cache:
            key_id = self._address_cache[cache_key]
            # Verify still valid
            if key_id in self._cache and not self._cache[key_id].is_expired():
                if self._store.is_key_valid(key_id):
                    return self._cache[key_id].pk_blob
            # Invalidate
            del self._address_cache[cache_key]
        
        # Fetch from store
        try:
            key_info = self._store.get_latest_key(address, key_type)
            
            # Cache address -> key_id mapping
            if self._enable_cache:
                self._address_cache[cache_key] = key_info.key_id
            
            # Use resolve_pk_blob to populate cache
            return self.resolve_pk_blob(key_info.key_id, require_valid=True)
            
        except Exception as e:
            raise NoKeyFoundError(f"address={address}, type={key_type.name}")
    
    def resolve_key_info(self, key_id: bytes) -> "MeteorKeyInfo":
        """
        Resolve full key info by key ID.
        
        Returns:
            MeteorKeyInfo struct
        """
        return self._store.get_key(key_id)
    
    # =========================================================================
    # Batch Resolution
    # =========================================================================
    
    def batch_resolve(
        self,
        key_ids: List[bytes],
        require_valid: bool = True,
    ) -> Dict[bytes, Optional[bytes]]:
        """
        Batch resolve pk_blobs.
        
        Args:
            key_ids: List of key IDs
            require_valid: Require keys to be valid
        
        Returns:
            Dict[key_id, pk_blob or None]
        """
        result: Dict[bytes, Optional[bytes]] = {}
        uncached: List[bytes] = []
        
        # Check cache first
        for key_id in key_ids:
            if self._enable_cache and key_id in self._cache:
                entry = self._cache[key_id]
                if not entry.is_expired():
                    result[key_id] = entry.pk_blob
                    continue
            uncached.append(key_id)
            result[key_id] = None
        
        if not uncached:
            return result
        
        # Batch fetch from store
        try:
            if require_valid:
                validities = self._store.batch_is_key_valid(uncached)
            else:
                validities = [True] * len(uncached)
            
            pk_blobs = self._store.batch_get_pk_blob(uncached)
            
            for key_id, valid, pk_blob in zip(uncached, validities, pk_blobs):
                if valid and pk_blob:
                    result[key_id] = pk_blob
                    # Cache
                    if self._enable_cache:
                        self._cache[key_id] = CacheEntry(
                            pk_blob=pk_blob,
                            key_id=key_id,
                            valid_until=0,
                            cached_at=time.time(),
                            ttl=self._cache_ttl,
                        )
                else:
                    result[key_id] = None
                    
        except Exception as e:
            # On error, leave uncached entries as None
            pass
        
        return result
    
    # =========================================================================
    # Validation
    # =========================================================================
    
    def is_key_valid(self, key_id: bytes) -> bool:
        """Check if key is valid (exists, not revoked, not expired)."""
        return self._store.is_key_valid(key_id)
    
    def validate_envelope_keys(
        self,
        sender_id: bytes,
        recipient_id: bytes,
    ) -> Tuple[bool, bool]:
        """
        Validate sender and recipient keys from envelope.
        
        Returns:
            (sender_valid, recipient_valid)
        """
        return (
            self._store.is_key_valid(sender_id),
            self._store.is_key_valid(recipient_id),
        )
    
    # =========================================================================
    # Cache Management
    # =========================================================================
    
    def clear_cache(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()
        self._address_cache.clear()
    
    def invalidate(self, key_id: bytes) -> None:
        """Invalidate cache entry for a key."""
        if key_id in self._cache:
            del self._cache[key_id]
        # Also clear address cache entries pointing to this key
        to_remove = [
            k for k, v in self._address_cache.items()
            if v == key_id
        ]
        for k in to_remove:
            del self._address_cache[k]
    
    def cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        valid = sum(1 for e in self._cache.values() if not e.is_expired())
        expired = len(self._cache) - valid
        return {
            "total": len(self._cache),
            "valid": valid,
            "expired": expired,
            "address_mappings": len(self._address_cache),
        }


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test KeyResolver with MockPKStore."""
    print("=" * 70)
    print("Meteor-NC Block Registry: KeyResolver Test")
    print("=" * 70)
    
    import secrets
    from .pk_store import MockPKStore, KeyType
    
    results = {}
    
    # Setup
    print("\n[Setup]")
    print("-" * 40)
    
    store = MockPKStore()
    store.set_account("0x" + "A" * 40)
    resolver = KeyResolver(store, cache_ttl=60.0)
    
    # Register test keys
    pk_seed1 = secrets.token_bytes(32)
    b_hash1 = secrets.token_bytes(32)
    key_id1 = store.register_key(pk_seed1, b_hash1, 0x01, KeyType.ENCRYPTION)
    
    pk_seed2 = secrets.token_bytes(32)
    b_hash2 = secrets.token_bytes(32)
    key_id2 = store.register_key(pk_seed2, b_hash2, 0x02, KeyType.SIGNING)
    
    print(f"  Registered 2 keys")
    print(f"  Key 1 (ENCRYPTION): {key_id1.hex()[:16]}...")
    print(f"  Key 2 (SIGNING): {key_id2.hex()[:16]}...")
    
    # Test 1: Resolve by key ID
    print("\n[Test 1] Resolve by Key ID")
    print("-" * 40)
    
    pk_blob = resolver.resolve_pk_blob(key_id1)
    expected = pk_seed1 + b_hash1
    
    results["resolve_by_id"] = pk_blob == expected
    print(f"  pk_blob: {pk_blob.hex()[:32]}...")
    print(f"  Match: {results['resolve_by_id']}")
    print(f"  Result: {'PASS ✓' if results['resolve_by_id'] else 'FAIL ✗'}")
    
    # Test 2: Resolve by address
    print("\n[Test 2] Resolve by Address")
    print("-" * 40)
    
    pk_blob = resolver.resolve_by_address(store._current_address, KeyType.ENCRYPTION)
    
    results["resolve_by_address"] = pk_blob == expected
    print(f"  Address: {store._current_address[:10]}...")
    print(f"  pk_blob: {pk_blob.hex()[:32]}...")
    print(f"  Match: {results['resolve_by_address']}")
    print(f"  Result: {'PASS ✓' if results['resolve_by_address'] else 'FAIL ✗'}")
    
    # Test 3: Cache hit
    print("\n[Test 3] Cache Hit")
    print("-" * 40)
    
    stats_before = resolver.cache_stats()
    pk_blob_cached = resolver.resolve_pk_blob(key_id1)
    stats_after = resolver.cache_stats()
    
    results["cache"] = (
        pk_blob_cached == pk_blob and
        stats_after["valid"] > 0
    )
    print(f"  Cache valid entries: {stats_after['valid']}")
    print(f"  Cache hit: {pk_blob_cached == pk_blob}")
    print(f"  Result: {'PASS ✓' if results['cache'] else 'FAIL ✗'}")
    
    # Test 4: Batch resolve
    print("\n[Test 4] Batch Resolve")
    print("-" * 40)
    
    fake_key = secrets.token_bytes(32)
    batch_result = resolver.batch_resolve([key_id1, key_id2, fake_key])
    
    results["batch"] = (
        batch_result[key_id1] == pk_seed1 + b_hash1 and
        batch_result[key_id2] == pk_seed2 + b_hash2 and
        batch_result[fake_key] is None
    )
    print(f"  Key 1: {'found' if batch_result[key_id1] else 'not found'}")
    print(f"  Key 2: {'found' if batch_result[key_id2] else 'not found'}")
    print(f"  Fake: {'found' if batch_result[fake_key] else 'not found (expected)'}")
    print(f"  Result: {'PASS ✓' if results['batch'] else 'FAIL ✗'}")
    
    # Test 5: Validate envelope keys
    print("\n[Test 5] Validate Envelope Keys")
    print("-" * 40)
    
    sender_valid, recipient_valid = resolver.validate_envelope_keys(key_id1, key_id2)
    
    results["validate"] = sender_valid and recipient_valid
    print(f"  Sender valid: {sender_valid}")
    print(f"  Recipient valid: {recipient_valid}")
    print(f"  Result: {'PASS ✓' if results['validate'] else 'FAIL ✗'}")
    
    # Test 6: Revoked key handling
    print("\n[Test 6] Revoked Key Handling")
    print("-" * 40)
    
    resolver.invalidate(key_id1)  # Clear cache first
    store.revoke_key(key_id1)
    
    error_ok = False
    try:
        resolver.resolve_pk_blob(key_id1, require_valid=True)
    except KeyNotValidError as e:
        error_ok = "revoked" in str(e)
        print(f"  KeyNotValidError: {e}")
    
    results["revoked"] = error_ok
    print(f"  Result: {'PASS ✓' if results['revoked'] else 'FAIL ✗'}")
    
    # Test 7: Cache invalidation
    print("\n[Test 7] Cache Invalidation")
    print("-" * 40)
    
    resolver.clear_cache()
    stats = resolver.cache_stats()
    
    results["invalidation"] = stats["total"] == 0
    print(f"  Cache cleared: {stats['total']} entries")
    print(f"  Result: {'PASS ✓' if results['invalidation'] else 'FAIL ✗'}")
    
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
