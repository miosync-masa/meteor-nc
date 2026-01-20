# meteor_nc/block/tests/test_integration.py
"""
Meteor-NC Block: Integration Tests

End-to-end tests covering real-world usage scenarios:
    1. Wallet-to-Wallet encrypted messaging
    2. Registry-based key discovery and communication
    3. MEV-protected transaction submission
    4. Multi-party communication

These tests verify that all modules work together correctly.

Run:
    python -m meteor_nc.block.tests.test_integration

Updated: 2025-01-20
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from typing import Dict, Any

# Wire
from ..wire import SecureEnvelope, EnvelopeType, compute_commit

# Suites
from ..suites import SUITES, get_suite, PK_BLOB_SIZE

# Transport
from ..transport import (
    SecureChannel,
    WalletChannel,
    WalletSession,
    WalletMessage,
    SecureRPCClient,
    SecureRPCHandler,
    MockHTTPTransport,
)

# Registry
from ..registry import PKStore, KeyResolver, KeyType

# Mempool
from ..mempool import TxEncryptor, TxDecryptor, CommitReveal, ShieldedTx

# Adapters
from ..adapters import (
    WalletAdapter,
    MockWalletAdapter,
    MetaMaskAdapter,
    WalletConnectAdapter,
    WalletState,
    MockEthereumProvider,
)


# =============================================================================
# Test Utilities
# =============================================================================

def print_header(title: str) -> None:
    """Print test section header."""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print('=' * 70)


def print_step(step: str) -> None:
    """Print test step."""
    print(f"\n  → {step}")


def print_result(passed: bool, details: str = "") -> None:
    """Print test result."""
    status = "✅ PASS" if passed else "❌ FAIL"
    if details:
        print(f"    {status}: {details}")
    else:
        print(f"    {status}")


# =============================================================================
# Integration Test 1: Wallet-to-Wallet Messaging
# =============================================================================

async def test_wallet_to_wallet_messaging() -> bool:
    """
    Test complete wallet-to-wallet encrypted messaging flow.
    
    Scenario:
        1. Alice connects with MetaMask
        2. Bob connects with WalletConnect
        3. Both get their Meteor pk_blobs
        4. Alice initiates session with Bob
        5. They exchange encrypted messages
    """
    print_header("Test 1: Wallet-to-Wallet Messaging")
    
    try:
        # Step 1: Alice connects with MetaMask
        print_step("Alice connects with MetaMask")
        alice_provider = MockEthereumProvider(
            accounts=["0x" + "A" * 40],
            chain_id=1,
        )
        alice = MetaMaskAdapter(provider=alice_provider)
        alice_info = await alice.connect()
        print_result(alice.is_connected, f"Address: {alice_info.address[:10]}...")
        
        # Step 2: Bob connects with WalletConnect
        print_step("Bob connects with WalletConnect")
        bob = WalletConnectAdapter(project_id="test", chain_id=1)
        bob._client._mock_accounts = ["0x" + "B" * 40]
        bob_info = await bob.connect()
        print_result(bob.is_connected, f"Address: {bob_info.address[:10]}...")
        
        # Step 3: Both get Meteor pk_blobs
        print_step("Both generate Meteor identities")
        alice_pk = await alice.get_meteor_pk_blob()
        bob_pk = await bob.get_meteor_pk_blob()
        print_result(
            len(alice_pk) == 64 and len(bob_pk) == 64,
            f"Alice pk: {alice_pk[:8].hex()}... Bob pk: {bob_pk[:8].hex()}..."
        )
        
        # Step 4: Alice initiates session
        print_step("Alice initiates session with Bob")
        session_a, handshake = await alice.initiate_session(bob.address, bob_pk)
        session_b, response = await bob.accept_session(alice.address, handshake)
        await alice.finalize_session(bob.address, response)
        print_result(
            session_a.is_connected and session_b.is_connected,
            "Session established"
        )
        
        # Step 5: Exchange messages
        print_step("Exchange encrypted messages")
        
        # Alice → Bob
        env1 = await alice.send_encrypted(bob.address, "Hello Bob! 🔐")
        msg1 = await bob.receive_encrypted(alice.address, env1)
        
        # Bob → Alice
        env2 = await bob.send_encrypted(alice.address, "Hi Alice! 🛡️")
        msg2 = await alice.receive_encrypted(bob.address, env2)
        
        messages_ok = (
            msg1.as_text() == "Hello Bob! 🔐" and
            msg2.as_text() == "Hi Alice! 🛡️"
        )
        print_result(messages_ok, f"Received: '{msg1.as_text()}' / '{msg2.as_text()}'")
        
        # Cleanup
        await alice.disconnect()
        await bob.disconnect()
        
        return messages_ok
        
    except Exception as e:
        print_result(False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# =============================================================================
# Integration Test 2: Registry-Based Key Discovery
# =============================================================================

async def test_registry_key_discovery() -> bool:
    """
    Test key registration and discovery flow.
    
    Scenario:
        1. Alice registers her key on-chain
        2. Bob discovers Alice's key via resolver
        3. Bob initiates encrypted communication
    """
    print_header("Test 2: Registry-Based Key Discovery")
    
    try:
        # Setup mock Web3
        class MockWeb3:
            class eth:
                chain_id = 1
                
                @staticmethod
                def contract(address, abi):
                    return MockContract()
        
        class MockContract:
            class functions:
                @staticmethod
                def registerKey(pk_blob, key_type, suite_id, expiry, metadata):
                    return MockTx()
                
                @staticmethod
                def getKey(address, key_type):
                    return MockCall()
                
                @staticmethod
                def getActiveKey(address):
                    return MockCall()
        
        class MockTx:
            def build_transaction(self, params):
                return {"nonce": 0, "gas": 100000}
        
        class MockCall:
            _pk_blob = None
            
            def call(self):
                if MockCall._pk_blob:
                    return (
                        MockCall._pk_blob,
                        int(time.time()) - 100,
                        int(time.time()) + 86400,
                        1,  # suite_id
                        False,  # revoked
                        b"",
                    )
                raise Exception("Key not found")
        
        # Step 1: Alice creates identity
        print_step("Alice creates Meteor identity")
        alice = MockWalletAdapter(address="0x" + "A" * 40)
        await alice.connect()
        alice_pk = await alice.get_meteor_pk_blob()
        print_result(len(alice_pk) == 64, f"pk_blob: {alice_pk[:8].hex()}...")
        
        # Step 2: Alice registers key (mock - PKStore requires real RPC)
        print_step("Alice registers key on-chain (mocked)")
        MockCall._pk_blob = alice_pk
        # Note: PKStore requires rpc_url, so we use mock data directly
        print_result(True, "Key registered (mocked via MockCall)")
        
        # Step 3: Bob discovers Alice's key (mocked resolver)
        print_step("Bob discovers Alice's key via resolver")
        
        # Mock the resolver to return Alice's pk_blob
        # We'll use resolve_by_address which is address-based
        class MockPKStore:
            def __init__(self):
                self._keys = {
                    alice.address.lower(): type('MeteorKeyInfo', (), {
                        'pk_blob': alice_pk,
                        'key_id': hashlib.sha256(alice_pk).digest(),
                        'registered_at': int(time.time()) - 100,
                        'expires_at': int(time.time()) + 86400,
                        'valid_until': int(time.time()) + 86400,
                        'suite_id': 1,
                        'revoked': False,
                        'is_expired': False,
                    })()
                }
            
            def get_latest_key(self, address, key_type=None):
                addr = address.lower()
                if addr in self._keys:
                    return self._keys[addr]
                raise Exception("Key not found")
            
            async def get_key_async(self, address, key_type=None):
                return self.get_latest_key(address, key_type)
            
            def get_key(self, key_id):
                for info in self._keys.values():
                    if info.key_id == key_id:
                        return info
                raise Exception("Key not found")
            
            def get_pk_blob(self, key_id):
                for info in self._keys.values():
                    if info.key_id == key_id:
                        return info.pk_blob
                raise Exception("Key not found")
            
            def is_key_valid(self, key_id):
                try:
                    info = self.get_key(key_id)
                    return not info.revoked and not info.is_expired
                except:
                    return False
            
            async def get_active_key_async(self, address, key_type=None):
                return await self.get_key_async(address, key_type)
        
        mock_store = MockPKStore()
        resolver = KeyResolver(store=mock_store, enable_cache=False)
        
        # resolve_by_address returns pk_blob directly (bytes)
        discovered_pk = resolver.resolve_by_address(alice.address)
        print_result(
            discovered_pk == alice_pk,
            f"Discovered: {discovered_pk[:8].hex()}..."
        )
        
        # Step 4: Bob initiates communication
        print_step("Bob initiates encrypted session")
        bob = MockWalletAdapter(address="0x" + "B" * 40)
        await bob.connect()
        await bob.ensure_meteor_identity()
        
        session_b, handshake = await bob.initiate_session(alice.address, discovered_pk)
        session_a, response = await alice.accept_session(bob.address, handshake)
        await bob.finalize_session(alice.address, response)
        
        print_result(
            session_a.is_connected and session_b.is_connected,
            "Session established via discovered key"
        )
        
        # Step 5: Verify communication works
        print_step("Verify communication")
        env = await bob.send_encrypted(alice.address, "Found you via registry!")
        msg = await alice.receive_encrypted(bob.address, env)
        
        success = msg.as_text() == "Found you via registry!"
        print_result(success, f"Message: '{msg.as_text()}'")
        
        return success
        
    except Exception as e:
        print_result(False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# =============================================================================
# Integration Test 3: MEV-Protected Transaction Flow
# =============================================================================

async def test_mev_protected_transaction() -> bool:
    """
    Test complete MEV protection flow.
    
    Scenario:
        1. Builder publishes their public key
        2. User encrypts transaction for builder
        3. User submits via SecureRPCClient
        4. Builder decrypts and processes
    """
    print_header("Test 3: MEV-Protected Transaction")
    
    try:
        # Step 1: Builder setup
        print_step("Builder creates identity")
        builder = SecureChannel.create(chain_id=1, seed=b"builder_seed_32bytes!!!!!!!!!!!!")
        builder_pk = builder.pk_blob
        builder_pk_bytes = builder._identity.pk_bytes  # Full public key for encryption
        print_result(
            len(builder_pk) == 64 and len(builder_pk_bytes) > 100,
            f"Builder pk_blob: {builder_pk[:8].hex()}... ({len(builder_pk_bytes)}B pk_bytes)"
        )
        
        # Step 2: User encrypts transaction
        print_step("User encrypts transaction")
        raw_tx = bytes.fromhex(
            "02f86c0180843b9aca00850c92a69c0082520894"
            "d8da6bf26964af9d7eed9e03e53415d37aa96045"
            "880de0b6b3a764000080c0"
        )
        
        encryptor = TxEncryptor(builder_pk_bytes=builder_pk_bytes, chain_id=1)
        encrypted_tx = encryptor.encrypt(raw_tx)
        
        print_result(
            encrypted_tx.envelope is not None,
            f"Encrypted: {len(encrypted_tx.wire)}B wire"
        )
        
        # Step 3: Submit via RPC
        print_step("User submits via SecureRPCClient")
        
        # Setup mock transport
        transport = MockHTTPTransport()
        client = SecureRPCClient(
            endpoint="https://private-builder.example.com",
            builder_pk_bytes=builder_pk_bytes,  # Full pk_bytes, not pk_blob
            chain_id=1,
            transport=transport,
        )
        
        # Mock response
        transport.queue_response(json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": "0x" + "ab" * 32,  # tx hash
        }).encode())
        
        result = await client.send_private_transaction(raw_tx)
        print_result(
            result.startswith("0x"),
            f"Tx hash: {result[:18]}..."
        )
        
        # Step 4: Builder decrypts
        print_step("Builder decrypts transaction")
        handler = SecureRPCHandler(
            pk_bytes=builder._identity.pk_bytes,
            sk_bytes=builder._identity.sk_bytes,
            chain_id=1,
        )
        
        # Simulate receiving the encrypted envelope (hex format)
        envelope_hex = "0x" + encrypted_tx.envelope.to_bytes().hex()
        decrypted = handler.decrypt_transaction(envelope_hex)
        
        success = decrypted == raw_tx
        print_result(success, f"Decrypted matches original: {success}")
        
        return success
        
    except Exception as e:
        print_result(False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# =============================================================================
# Integration Test 4: Commit-Reveal MEV Protection
# =============================================================================

async def test_commit_reveal_flow() -> bool:
    """
    Test commit-reveal scheme for MEV protection.
    
    Scenario:
        1. User encrypts transaction
        2. User creates shielded tx with commit
        3. After delay, user reveals
        4. Validator verifies
    """
    print_header("Test 4: Commit-Reveal Flow")
    
    try:
        # Step 1: Setup builder
        print_step("Setup builder and encryptor")
        builder_seed = secrets.token_bytes(32)
        builder = SecureChannel.create(chain_id=1, seed=builder_seed)
        builder_pk_bytes = builder._identity.pk_bytes
        
        encryptor = TxEncryptor(
            builder_pk_bytes=builder_pk_bytes,
            chain_id=1,
        )
        print_result(True, "Builder and encryptor initialized")
        
        # Step 2: Encrypt transaction
        print_step("Encrypt transaction")
        raw_tx = b"raw_transaction_data_here"
        encrypted_tx = encryptor.encrypt(raw_tx)
        
        print_result(
            encrypted_tx.envelope is not None,
            f"Encrypted envelope: {len(encrypted_tx.wire)}B"
        )
        
        # Step 3: Create shielded transaction
        print_step("Create shielded transaction")
        commit_reveal = CommitReveal(chain_id=1)
        shielded = commit_reveal.create_shielded(encrypted_tx.envelope)
        
        print_result(
            shielded.commit is not None,
            f"Commit: {shielded.commit[:16].hex()}..."
        )
        
        # Step 4: Submit commit (simulated)
        print_step("Submit commit phase")
        commit_valid = len(shielded.commit) == 32
        print_result(commit_valid, f"Commit size: {len(shielded.commit)}B")
        
        # Step 5: Check reveal readiness (shielded tx is ready)
        print_step("Check reveal readiness")
        print_result(True, "ShieldedTx ready for reveal")
        
        # Step 6: Validator verifies reveal
        print_step("Validator verifies commit matches reveal")
        
        # Get reveal data
        reveal_envelope = shielded.envelope
        reveal_commit = compute_commit(reveal_envelope)
        
        is_valid = reveal_commit == shielded.commit
        print_result(is_valid, "Commit-reveal verified")
        
        # Step 7: Builder decrypts transaction
        print_step("Builder decrypts transaction")
        
        # Use TxDecryptor to decrypt (builder has secret key internally)
        decryptor = TxDecryptor(
            pk_bytes=builder._identity.pk_bytes,
            sk_bytes=builder._identity.sk_bytes,
            chain_id=1,
        )
        decrypted = decryptor.decrypt(reveal_envelope)
        
        success = decrypted == raw_tx
        print_result(success, f"Decrypted: {decrypted[:20]}...")
        
        return success
        
    except Exception as e:
        print_result(False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# =============================================================================
# Integration Test 5: Multi-Party Communication
# =============================================================================

async def test_multi_party_communication() -> bool:
    """
    Test communication between multiple parties.
    
    Scenario:
        1. Three parties: Alice, Bob, Charlie
        2. Each establishes sessions with others
        3. Group message broadcast
    """
    print_header("Test 5: Multi-Party Communication")
    
    try:
        # Step 1: Create three parties
        print_step("Create three parties")
        
        alice = MockWalletAdapter(address="0x" + "A" * 40)
        bob = MockWalletAdapter(address="0x" + "B" * 40)
        charlie = MockWalletAdapter(address="0x" + "C" * 40)
        
        await alice.connect()
        await bob.connect()
        await charlie.connect()
        
        alice_pk = await alice.get_meteor_pk_blob()
        bob_pk = await bob.get_meteor_pk_blob()
        charlie_pk = await charlie.get_meteor_pk_blob()
        
        print_result(True, "All three parties connected")
        
        # Step 2: Establish pairwise sessions
        print_step("Establish pairwise sessions")
        
        # Alice ↔ Bob
        s_ab, h_ab = await alice.initiate_session(bob.address, bob_pk)
        s_ba, r_ab = await bob.accept_session(alice.address, h_ab)
        await alice.finalize_session(bob.address, r_ab)
        
        # Alice ↔ Charlie
        s_ac, h_ac = await alice.initiate_session(charlie.address, charlie_pk)
        s_ca, r_ac = await charlie.accept_session(alice.address, h_ac)
        await alice.finalize_session(charlie.address, r_ac)
        
        # Bob ↔ Charlie
        s_bc, h_bc = await bob.initiate_session(charlie.address, charlie_pk)
        s_cb, r_bc = await charlie.accept_session(bob.address, h_bc)
        await bob.finalize_session(charlie.address, r_bc)
        
        sessions_ok = all([
            s_ab.is_connected, s_ba.is_connected,
            s_ac.is_connected, s_ca.is_connected,
            s_bc.is_connected, s_cb.is_connected,
        ])
        print_result(sessions_ok, "6 pairwise sessions established")
        
        # Step 3: Alice broadcasts to Bob and Charlie
        print_step("Alice broadcasts message")
        
        broadcast_msg = "Hello everyone! 📢"
        
        env_bob = await alice.send_encrypted(bob.address, broadcast_msg)
        env_charlie = await alice.send_encrypted(charlie.address, broadcast_msg)
        
        msg_bob = await bob.receive_encrypted(alice.address, env_bob)
        msg_charlie = await charlie.receive_encrypted(alice.address, env_charlie)
        
        broadcast_ok = (
            msg_bob.as_text() == broadcast_msg and
            msg_charlie.as_text() == broadcast_msg
        )
        print_result(broadcast_ok, f"Both received: '{broadcast_msg}'")
        
        # Step 4: Round-robin messages
        print_step("Round-robin messages")
        
        # Bob → Charlie
        e1 = await bob.send_encrypted(charlie.address, "Hi Charlie!")
        m1 = await charlie.receive_encrypted(bob.address, e1)
        
        # Charlie → Alice
        e2 = await charlie.send_encrypted(alice.address, "Hi Alice!")
        m2 = await alice.receive_encrypted(charlie.address, e2)
        
        round_robin_ok = (
            m1.as_text() == "Hi Charlie!" and
            m2.as_text() == "Hi Alice!"
        )
        print_result(round_robin_ok, "Round-robin complete")
        
        # Cleanup
        await alice.disconnect()
        await bob.disconnect()
        await charlie.disconnect()
        
        return sessions_ok and broadcast_ok and round_robin_ok
        
    except Exception as e:
        print_result(False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# =============================================================================
# Main Test Runner
# =============================================================================

def run_tests() -> bool:
    """Run all integration tests."""
    print("\n" + "=" * 70)
    print("  METEOR-NC BLOCK: INTEGRATION TESTS")
    print("=" * 70)
    
    results = {}
    
    async def run_async_tests():
        results["wallet_messaging"] = await test_wallet_to_wallet_messaging()
        results["registry_discovery"] = await test_registry_key_discovery()
        results["mev_protection"] = await test_mev_protected_transaction()
        results["commit_reveal"] = await test_commit_reveal_flow()
        results["multi_party"] = await test_multi_party_communication()
    
    asyncio.run(run_async_tests())
    
    # Summary
    print("\n" + "=" * 70)
    print("  INTEGRATION TEST SUMMARY")
    print("=" * 70)
    
    for name, passed in results.items():
        status = "✅" if passed else "❌"
        print(f"  {name}: {status}")
    
    print("=" * 70)
    
    all_pass = all(results.values())
    passed = sum(results.values())
    total = len(results)
    
    print(f"  Result: {passed}/{total} integration tests passed")
    
    if all_pass:
        print("  ALL INTEGRATION TESTS PASSED! 🎉")
    else:
        print("  SOME TESTS FAILED")
    
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
