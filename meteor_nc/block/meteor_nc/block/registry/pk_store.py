# meteor_nc/block/registry/pk_store.py
"""
Meteor-NC Block Registry: PKStore

Python interface to PKRegistry smart contract.
Supports key registration, rotation, revocation, and queries.

Requirements:
    pip install web3

Usage:
    store = PKStore(
        contract_address="0x...",
        rpc_url="https://...",
        private_key="0x...",  # Optional, for write ops
    )
    
    # Register key
    key_id = await store.register_key(pk_seed, b_hash, suite_id, KeyType.ENCRYPTION)
    
    # Query key
    key_info = await store.get_key(key_id)
    pk_blob = await store.get_pk_blob(key_id)
    is_valid = await store.is_key_valid(key_id)

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

# Optional web3 import
try:
    from web3 import Web3, AsyncWeb3
    from web3.contract import Contract, AsyncContract
    from web3.middleware import geth_poa_middleware
    from eth_account import Account
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    Web3 = None
    AsyncWeb3 = None


# =============================================================================
# Constants
# =============================================================================

# Load ABI
ABI_PATH = Path(__file__).parent / "contracts" / "abi" / "PKRegistry.json"

def _load_abi() -> List[Dict]:
    """Load contract ABI from JSON file."""
    if ABI_PATH.exists():
        with open(ABI_PATH) as f:
            data = json.load(f)
            return data.get("abi", data)
    return []

CONTRACT_ABI = _load_abi()


# =============================================================================
# Types
# =============================================================================

class KeyType(IntEnum):
    """Key type enumeration (matches Solidity enum)."""
    ENCRYPTION = 0  # For Meteor-NC KEM encryption
    SIGNING = 1     # For digital signatures


@dataclass
class MeteorKeyInfo:
    """
    Meteor key information from registry.
    
    Attributes:
        key_id: 32-byte key identifier
        pk_seed: 32-byte public key seed
        b_hash: 32-byte hash of public key vector b
        suite_id: Cryptographic suite (0x01, 0x02, 0x03)
        key_type: ENCRYPTION or SIGNING
        valid_from: Registration timestamp
        valid_until: Expiration timestamp (0 = no expiry)
        revoked: Whether key is revoked
        owner: Owner address (if known)
    """
    key_id: bytes
    pk_seed: bytes
    b_hash: bytes
    suite_id: int
    key_type: KeyType
    valid_from: int
    valid_until: int
    revoked: bool
    owner: Optional[str] = None
    
    @property
    def pk_blob(self) -> bytes:
        """64-byte pk_blob (pk_seed || b_hash)."""
        return self.pk_seed + self.b_hash
    
    @property
    def is_expired(self) -> bool:
        """Check if key is expired."""
        if self.valid_until == 0:
            return False
        return int(time.time()) > self.valid_until
    
    @property
    def is_valid(self) -> bool:
        """Check if key is valid (not revoked, not expired)."""
        return not self.revoked and not self.is_expired
    
    @classmethod
    def from_contract_tuple(cls, data: Tuple, owner: Optional[str] = None) -> MeteorKeyInfo:
        """Create from contract return tuple."""
        return cls(
            key_id=data[0] if isinstance(data[0], bytes) else bytes.fromhex(data[0].hex()),
            pk_seed=data[1] if isinstance(data[1], bytes) else bytes.fromhex(data[1].hex()),
            b_hash=data[2] if isinstance(data[2], bytes) else bytes.fromhex(data[2].hex()),
            suite_id=data[3],
            key_type=KeyType(data[4]),
            valid_from=data[5],
            valid_until=data[6],
            revoked=data[7],
            owner=owner,
        )


# =============================================================================
# Exceptions
# =============================================================================

class RegistryError(Exception):
    """Base registry error."""
    pass


class KeyNotFoundError(RegistryError):
    """Key not found in registry."""
    def __init__(self, key_id: bytes):
        self.key_id = key_id
        super().__init__(f"Key not found: {key_id.hex()}")


class KeyAlreadyRegisteredError(RegistryError):
    """Key already registered."""
    def __init__(self, key_id: bytes):
        self.key_id = key_id
        super().__init__(f"Key already registered: {key_id.hex()}")


class NotKeyOwnerError(RegistryError):
    """Caller is not key owner."""
    def __init__(self, key_id: bytes, caller: str):
        self.key_id = key_id
        self.caller = caller
        super().__init__(f"Not key owner: {key_id.hex()}, caller: {caller}")


class Web3NotAvailableError(RegistryError):
    """web3.py not installed."""
    def __init__(self):
        super().__init__("web3.py not available. Install with: pip install web3")


# =============================================================================
# Helper Functions
# =============================================================================

def compute_key_id(pk_seed: bytes, b_hash: bytes) -> bytes:
    """
    Compute key ID from pk_seed and b_hash.
    
    Uses keccak256 to match Solidity:
        keyId = keccak256(abi.encodePacked(pkSeed, bHash))
    """
    if WEB3_AVAILABLE:
        return Web3.keccak(pk_seed + b_hash)
    else:
        # Fallback: use SHA3-256 (close to keccak256)
        import hashlib
        return hashlib.sha3_256(pk_seed + b_hash).digest()


# =============================================================================
# PKStore
# =============================================================================

class PKStore:
    """
    PKRegistry contract interface.
    
    Supports both sync and async operations.
    For async, use methods with `_async` suffix.
    """
    
    def __init__(
        self,
        contract_address: str,
        rpc_url: str,
        private_key: Optional[str] = None,
        chain_id: Optional[int] = None,
    ):
        """
        Initialize PKStore.
        
        Args:
            contract_address: Deployed PKRegistry address
            rpc_url: RPC endpoint URL
            private_key: Private key for write operations (optional)
            chain_id: Chain ID (auto-detected if not provided)
        """
        if not WEB3_AVAILABLE:
            raise Web3NotAvailableError()
        
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.rpc_url = rpc_url
        self._private_key = private_key
        self._chain_id = chain_id
        
        # Sync Web3
        self._w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        # Add PoA middleware for networks like Polygon
        try:
            self._w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        except Exception:
            pass  # Not all networks need this
        
        # Contract instance
        self._contract = self._w3.eth.contract(
            address=self.contract_address,
            abi=CONTRACT_ABI,
        )
        
        # Account (if private key provided)
        self._account = None
        if private_key:
            self._account = Account.from_key(private_key)
        
        # Chain ID
        if chain_id is None:
            self._chain_id = self._w3.eth.chain_id
    
    @property
    def account_address(self) -> Optional[str]:
        """Get account address (if private key provided)."""
        return self._account.address if self._account else None
    
    # =========================================================================
    # Write Operations (Sync)
    # =========================================================================
    
    def register_key(
        self,
        pk_seed: bytes,
        b_hash: bytes,
        suite_id: int,
        key_type: KeyType,
        valid_until: int = 0,
        gas_limit: Optional[int] = None,
        gas_price: Optional[int] = None,
    ) -> bytes:
        """
        Register a new key.
        
        Args:
            pk_seed: 32-byte pk_seed
            b_hash: 32-byte b_hash
            suite_id: Suite ID (0x01, 0x02, 0x03)
            key_type: ENCRYPTION or SIGNING
            valid_until: Expiration timestamp (0 = no expiry)
            gas_limit: Gas limit (auto if None)
            gas_price: Gas price (auto if None)
        
        Returns:
            key_id: 32-byte key ID
        """
        if not self._account:
            raise RegistryError("Private key required for write operations")
        
        if len(pk_seed) != 32 or len(b_hash) != 32:
            raise ValueError("pk_seed and b_hash must be 32 bytes")
        
        # Build transaction
        tx = self._contract.functions.registerKey(
            pk_seed,
            b_hash,
            suite_id,
            int(key_type),
            valid_until,
        ).build_transaction({
            'from': self._account.address,
            'chainId': self._chain_id,
            'nonce': self._w3.eth.get_transaction_count(self._account.address),
            'gas': gas_limit or 200000,
            'gasPrice': gas_price or self._w3.eth.gas_price,
        })
        
        # Sign and send
        signed = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.rawTransaction)
        
        # Wait for receipt
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt['status'] != 1:
            raise RegistryError(f"Transaction failed: {tx_hash.hex()}")
        
        # Extract key_id from event
        logs = self._contract.events.KeyRegistered().process_receipt(receipt)
        if logs:
            return logs[0]['args']['keyId']
        
        # Fallback: compute key_id
        return compute_key_id(pk_seed, b_hash)
    
    def rotate_key(
        self,
        old_key_id: bytes,
        new_pk_seed: bytes,
        new_b_hash: bytes,
        new_suite_id: int,
        new_valid_until: int = 0,
        gas_limit: Optional[int] = None,
        gas_price: Optional[int] = None,
    ) -> bytes:
        """
        Rotate key: revoke old and register new.
        
        Returns:
            new_key_id: 32-byte new key ID
        """
        if not self._account:
            raise RegistryError("Private key required for write operations")
        
        tx = self._contract.functions.rotateKey(
            old_key_id,
            new_pk_seed,
            new_b_hash,
            new_suite_id,
            new_valid_until,
        ).build_transaction({
            'from': self._account.address,
            'chainId': self._chain_id,
            'nonce': self._w3.eth.get_transaction_count(self._account.address),
            'gas': gas_limit or 250000,
            'gasPrice': gas_price or self._w3.eth.gas_price,
        })
        
        signed = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt['status'] != 1:
            raise RegistryError(f"Transaction failed: {tx_hash.hex()}")
        
        # Extract new key_id from event
        logs = self._contract.events.KeyRotated().process_receipt(receipt)
        if logs:
            return logs[0]['args']['newKeyId']
        
        return compute_key_id(new_pk_seed, new_b_hash)
    
    def revoke_key(
        self,
        key_id: bytes,
        gas_limit: Optional[int] = None,
        gas_price: Optional[int] = None,
    ) -> str:
        """
        Revoke a key.
        
        Returns:
            tx_hash: Transaction hash
        """
        if not self._account:
            raise RegistryError("Private key required for write operations")
        
        tx = self._contract.functions.revokeKey(
            key_id,
        ).build_transaction({
            'from': self._account.address,
            'chainId': self._chain_id,
            'nonce': self._w3.eth.get_transaction_count(self._account.address),
            'gas': gas_limit or 100000,
            'gasPrice': gas_price or self._w3.eth.gas_price,
        })
        
        signed = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt['status'] != 1:
            raise RegistryError(f"Transaction failed: {tx_hash.hex()}")
        
        return tx_hash.hex()
    
    # =========================================================================
    # Read Operations (Sync)
    # =========================================================================
    
    def get_key(self, key_id: bytes) -> MeteorKeyInfo:
        """Get key info by ID."""
        try:
            data = self._contract.functions.getKey(key_id).call()
            owner = self._contract.functions.getKeyOwnerAddress(key_id).call()
            return MeteorKeyInfo.from_contract_tuple(data, owner)
        except Exception as e:
            if "KeyNotFound" in str(e):
                raise KeyNotFoundError(key_id)
            raise RegistryError(f"Failed to get key: {e}")
    
    def get_pk_blob(self, key_id: bytes) -> bytes:
        """Get pk_blob (64 bytes) by key ID."""
        try:
            return bytes(self._contract.functions.getPkBlob(key_id).call())
        except Exception as e:
            if "KeyNotFound" in str(e):
                raise KeyNotFoundError(key_id)
            raise RegistryError(f"Failed to get pk_blob: {e}")
    
    def is_key_valid(self, key_id: bytes) -> bool:
        """Check if key is valid (exists, not revoked, not expired)."""
        return self._contract.functions.isKeyValid(key_id).call()
    
    def get_key_owner(self, key_id: bytes) -> str:
        """Get owner address of a key."""
        owner = self._contract.functions.getKeyOwnerAddress(key_id).call()
        if owner == "0x" + "0" * 40:
            raise KeyNotFoundError(key_id)
        return owner
    
    def get_keys_by_owner(self, owner: str) -> List[bytes]:
        """Get all key IDs for an owner."""
        owner = Web3.to_checksum_address(owner)
        return self._contract.functions.getKeyIdsByOwner(owner).call()
    
    def get_active_keys(self, owner: str) -> List[MeteorKeyInfo]:
        """Get active (non-revoked, non-expired) keys for an owner."""
        owner = Web3.to_checksum_address(owner)
        data = self._contract.functions.getActiveKeys(owner).call()
        return [MeteorKeyInfo.from_contract_tuple(d, owner) for d in data]
    
    def get_latest_key(self, owner: str, key_type: KeyType) -> MeteorKeyInfo:
        """Get latest active key of a specific type for an owner."""
        owner = Web3.to_checksum_address(owner)
        try:
            data = self._contract.functions.getLatestKey(owner, int(key_type)).call()
            return MeteorKeyInfo.from_contract_tuple(data, owner)
        except Exception as e:
            if "KeyNotFound" in str(e):
                raise KeyNotFoundError(bytes(32))
            raise RegistryError(f"Failed to get latest key: {e}")
    
    # =========================================================================
    # Batch Operations
    # =========================================================================
    
    def batch_is_key_valid(self, key_ids: List[bytes]) -> List[bool]:
        """Batch check key validity."""
        return self._contract.functions.batchIsKeyValid(key_ids).call()
    
    def batch_get_pk_blob(self, key_ids: List[bytes]) -> List[bytes]:
        """Batch get pk_blobs."""
        result = self._contract.functions.batchGetPkBlob(key_ids).call()
        return [bytes(b) for b in result]


# =============================================================================
# Mock PKStore (for testing without blockchain)
# =============================================================================

class MockPKStore:
    """
    In-memory PKStore for testing.
    
    No blockchain required - stores keys in memory.
    """
    
    def __init__(self):
        self._keys: Dict[bytes, MeteorKeyInfo] = {}
        self._owner_keys: Dict[str, List[bytes]] = {}
        self._key_owner: Dict[bytes, str] = {}
        self._current_address = "0x" + "1" * 40  # Mock address
    
    def set_account(self, address: str) -> None:
        """Set current account address."""
        self._current_address = address
    
    def register_key(
        self,
        pk_seed: bytes,
        b_hash: bytes,
        suite_id: int,
        key_type: KeyType,
        valid_until: int = 0,
        **kwargs,
    ) -> bytes:
        """Register a new key (in memory)."""
        key_id = compute_key_id(pk_seed, b_hash)
        
        if key_id in self._keys:
            raise KeyAlreadyRegisteredError(key_id)
        
        key_info = MeteorKeyInfo(
            key_id=key_id,
            pk_seed=pk_seed,
            b_hash=b_hash,
            suite_id=suite_id,
            key_type=key_type,
            valid_from=int(time.time()),
            valid_until=valid_until,
            revoked=False,
            owner=self._current_address,
        )
        
        self._keys[key_id] = key_info
        self._key_owner[key_id] = self._current_address
        
        if self._current_address not in self._owner_keys:
            self._owner_keys[self._current_address] = []
        self._owner_keys[self._current_address].append(key_id)
        
        return key_id
    
    def rotate_key(
        self,
        old_key_id: bytes,
        new_pk_seed: bytes,
        new_b_hash: bytes,
        new_suite_id: int,
        new_valid_until: int = 0,
        **kwargs,
    ) -> bytes:
        """Rotate key (in memory)."""
        if old_key_id not in self._keys:
            raise KeyNotFoundError(old_key_id)
        
        old_key = self._keys[old_key_id]
        if self._key_owner[old_key_id] != self._current_address:
            raise NotKeyOwnerError(old_key_id, self._current_address)
        
        # Revoke old
        old_key.revoked = True
        
        # Register new
        return self.register_key(
            new_pk_seed, new_b_hash, new_suite_id,
            old_key.key_type, new_valid_until
        )
    
    def revoke_key(self, key_id: bytes, **kwargs) -> str:
        """Revoke a key (in memory)."""
        if key_id not in self._keys:
            raise KeyNotFoundError(key_id)
        
        if self._key_owner[key_id] != self._current_address:
            raise NotKeyOwnerError(key_id, self._current_address)
        
        self._keys[key_id].revoked = True
        return "0x" + "0" * 64  # Mock tx hash
    
    def get_key(self, key_id: bytes) -> MeteorKeyInfo:
        """Get key info."""
        if key_id not in self._keys:
            raise KeyNotFoundError(key_id)
        return self._keys[key_id]
    
    def get_pk_blob(self, key_id: bytes) -> bytes:
        """Get pk_blob."""
        if key_id not in self._keys:
            raise KeyNotFoundError(key_id)
        return self._keys[key_id].pk_blob
    
    def is_key_valid(self, key_id: bytes) -> bool:
        """Check if key is valid."""
        if key_id not in self._keys:
            return False
        return self._keys[key_id].is_valid
    
    def get_key_owner(self, key_id: bytes) -> str:
        """Get key owner."""
        if key_id not in self._key_owner:
            raise KeyNotFoundError(key_id)
        return self._key_owner[key_id]
    
    def get_keys_by_owner(self, owner: str) -> List[bytes]:
        """Get keys by owner."""
        return self._owner_keys.get(owner, [])
    
    def get_active_keys(self, owner: str) -> List[MeteorKeyInfo]:
        """Get active keys for owner."""
        key_ids = self._owner_keys.get(owner, [])
        return [
            self._keys[kid] for kid in key_ids
            if self._keys[kid].is_valid
        ]
    
    def get_latest_key(self, owner: str, key_type: KeyType) -> MeteorKeyInfo:
        """Get latest active key of type."""
        active = [k for k in self.get_active_keys(owner) if k.key_type == key_type]
        if not active:
            raise KeyNotFoundError(bytes(32))
        return active[-1]
    
    def batch_is_key_valid(self, key_ids: List[bytes]) -> List[bool]:
        """Batch check validity."""
        return [self.is_key_valid(kid) for kid in key_ids]
    
    def batch_get_pk_blob(self, key_ids: List[bytes]) -> List[bytes]:
        """Batch get pk_blobs."""
        return [
            self._keys[kid].pk_blob if kid in self._keys else b""
            for kid in key_ids
        ]


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test PKStore with MockPKStore."""
    print("=" * 70)
    print("Meteor-NC Block Registry: PKStore Test")
    print("=" * 70)
    
    import secrets
    
    results = {}
    
    # Test 1: Create mock store
    print("\n[Test 1] MockPKStore Creation")
    print("-" * 40)
    
    store = MockPKStore()
    store.set_account("0x" + "A" * 40)
    print(f"  Store created with account: {store._current_address}")
    results["creation"] = True
    print("  Result: PASS ✓")
    
    # Test 2: Register key
    print("\n[Test 2] Register Key")
    print("-" * 40)
    
    pk_seed = secrets.token_bytes(32)
    b_hash = secrets.token_bytes(32)
    
    key_id = store.register_key(
        pk_seed=pk_seed,
        b_hash=b_hash,
        suite_id=0x01,
        key_type=KeyType.ENCRYPTION,
    )
    
    print(f"  pk_seed: {pk_seed.hex()[:16]}...")
    print(f"  b_hash: {b_hash.hex()[:16]}...")
    print(f"  key_id: {key_id.hex()[:16]}...")
    
    expected_id = compute_key_id(pk_seed, b_hash)
    results["register"] = key_id == expected_id
    print(f"  Key ID matches: {results['register']}")
    print(f"  Result: {'PASS ✓' if results['register'] else 'FAIL ✗'}")
    
    # Test 3: Get key
    print("\n[Test 3] Get Key")
    print("-" * 40)
    
    key_info = store.get_key(key_id)
    print(f"  suite_id: {key_info.suite_id}")
    print(f"  key_type: {key_info.key_type.name}")
    print(f"  revoked: {key_info.revoked}")
    print(f"  is_valid: {key_info.is_valid}")
    
    results["get_key"] = (
        key_info.pk_seed == pk_seed and
        key_info.b_hash == b_hash and
        key_info.is_valid
    )
    print(f"  Result: {'PASS ✓' if results['get_key'] else 'FAIL ✗'}")
    
    # Test 4: Get pk_blob
    print("\n[Test 4] Get pk_blob")
    print("-" * 40)
    
    pk_blob = store.get_pk_blob(key_id)
    expected_blob = pk_seed + b_hash
    
    results["pk_blob"] = pk_blob == expected_blob
    print(f"  pk_blob: {pk_blob.hex()[:32]}...")
    print(f"  Matches: {results['pk_blob']}")
    print(f"  Result: {'PASS ✓' if results['pk_blob'] else 'FAIL ✗'}")
    
    # Test 5: Rotate key
    print("\n[Test 5] Rotate Key")
    print("-" * 40)
    
    new_pk_seed = secrets.token_bytes(32)
    new_b_hash = secrets.token_bytes(32)
    
    new_key_id = store.rotate_key(
        old_key_id=key_id,
        new_pk_seed=new_pk_seed,
        new_b_hash=new_b_hash,
        new_suite_id=0x02,
    )
    
    old_key = store.get_key(key_id)
    new_key = store.get_key(new_key_id)
    
    results["rotate"] = (
        old_key.revoked == True and
        new_key.is_valid == True and
        new_key.suite_id == 0x02
    )
    
    print(f"  Old key revoked: {old_key.revoked}")
    print(f"  New key valid: {new_key.is_valid}")
    print(f"  New suite_id: {new_key.suite_id}")
    print(f"  Result: {'PASS ✓' if results['rotate'] else 'FAIL ✗'}")
    
    # Test 6: Revoke key
    print("\n[Test 6] Revoke Key")
    print("-" * 40)
    
    store.revoke_key(new_key_id)
    revoked_key = store.get_key(new_key_id)
    
    results["revoke"] = revoked_key.revoked == True
    print(f"  Key revoked: {revoked_key.revoked}")
    print(f"  Result: {'PASS ✓' if results['revoke'] else 'FAIL ✗'}")
    
    # Test 7: Get active keys
    print("\n[Test 7] Get Active Keys")
    print("-" * 40)
    
    # Register another key
    pk_seed3 = secrets.token_bytes(32)
    b_hash3 = secrets.token_bytes(32)
    key_id3 = store.register_key(pk_seed3, b_hash3, 0x03, KeyType.SIGNING)
    
    active = store.get_active_keys(store._current_address)
    results["active_keys"] = len(active) == 1 and active[0].key_id == key_id3
    
    print(f"  Total keys: {len(store._keys)}")
    print(f"  Active keys: {len(active)}")
    print(f"  Result: {'PASS ✓' if results['active_keys'] else 'FAIL ✗'}")
    
    # Test 8: Error handling
    print("\n[Test 8] Error Handling")
    print("-" * 40)
    
    error_ok = True
    
    # Key not found
    try:
        store.get_key(secrets.token_bytes(32))
        error_ok = False
    except KeyNotFoundError:
        print("  KeyNotFoundError: PASS ✓")
    
    # Duplicate registration
    try:
        store.register_key(pk_seed3, b_hash3, 0x01, KeyType.ENCRYPTION)
        error_ok = False
    except KeyAlreadyRegisteredError:
        print("  KeyAlreadyRegisteredError: PASS ✓")
    
    results["errors"] = error_ok
    print(f"  Result: {'PASS ✓' if results['errors'] else 'FAIL ✗'}")
    
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
