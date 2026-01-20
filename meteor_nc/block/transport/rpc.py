# meteor_nc/block/transport/rpc.py
"""
Meteor-NC Block Transport: Secure RPC Communication

Encrypted communication between wallets and RPC endpoints for:
- MEV protection (encrypted transactions)
- Private calls (encrypted eth_call)
- Secure state queries

Architecture:
    Wallet → SecureRPCClient → [Encrypted] → RPC Endpoint → Builder
    
    1. Wallet creates encrypted request using builder's public key
    2. Request sent via standard JSON-RPC
    3. Builder decrypts and processes
    4. Response encrypted back (optional)

Usage:
    # Create secure RPC client
    client = SecureRPCClient(
        endpoint="https://rpc.example.com",
        builder_pk_bytes=builder_pk,
        chain_id=1,
    )
    
    # Send encrypted transaction
    tx_hash = await client.send_private_transaction(signed_tx)
    
    # Make encrypted call
    result = await client.private_call(call_data)

Updated: 2025-01-20
Version: 0.3.0
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Dict, Any, Union, List
from abc import ABC, abstractmethod

from ..wire import (
    SecureEnvelope,
    EnvelopeType,
    EnvelopeFlags,
    DEFAULT_SUITE_ID,
)

from ..mempool import TxEncryptor, TxDecryptor


# =============================================================================
# Constants
# =============================================================================

# JSON-RPC version
JSONRPC_VERSION = "2.0"

# Custom Meteor-NC RPC methods
class MeteorMethod(IntEnum):
    """Meteor-NC custom RPC methods."""
    # Encrypted transaction
    SEND_PRIVATE_TX = 0x01
    # Encrypted call
    PRIVATE_CALL = 0x02
    # Get builder public key
    GET_BUILDER_PK = 0x03
    # Submit commit (MEV protection)
    SUBMIT_COMMIT = 0x10
    # Submit reveal
    SUBMIT_REVEAL = 0x11


# Standard method names
METHOD_SEND_PRIVATE_TX = "meteor_sendPrivateTransaction"
METHOD_PRIVATE_CALL = "meteor_privateCall"
METHOD_GET_BUILDER_PK = "meteor_getBuilderPublicKey"
METHOD_SUBMIT_COMMIT = "meteor_submitCommit"
METHOD_SUBMIT_REVEAL = "meteor_submitReveal"


# =============================================================================
# Exceptions
# =============================================================================

class RPCError(Exception):
    """Base RPC error."""
    def __init__(self, message: str, code: int = -32000, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


class ConnectionError(RPCError):
    """Failed to connect to RPC endpoint."""
    pass


class EncryptionError(RPCError):
    """Encryption/decryption failed."""
    pass


class ResponseError(RPCError):
    """Invalid or error response from RPC."""
    pass


# =============================================================================
# Request/Response Types
# =============================================================================

@dataclass
class RPCRequest:
    """JSON-RPC request."""
    method: str
    params: List[Any] = field(default_factory=list)
    id: Union[int, str] = field(default_factory=lambda: secrets.randbelow(2**32))
    jsonrpc: str = JSONRPC_VERSION
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-RPC dict."""
        return {
            "jsonrpc": self.jsonrpc,
            "method": self.method,
            "params": self.params,
            "id": self.id,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


@dataclass
class RPCResponse:
    """JSON-RPC response."""
    id: Union[int, str]
    result: Any = None
    error: Optional[Dict[str, Any]] = None
    jsonrpc: str = JSONRPC_VERSION
    
    @property
    def is_error(self) -> bool:
        """Check if response is an error."""
        return self.error is not None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RPCResponse':
        """Parse from dict."""
        return cls(
            id=data.get("id"),
            result=data.get("result"),
            error=data.get("error"),
            jsonrpc=data.get("jsonrpc", JSONRPC_VERSION),
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'RPCResponse':
        """Parse from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class PrivateTxRequest:
    """
    Private transaction request.
    
    Contains encrypted transaction data for MEV protection.
    """
    # Encrypted envelope (serialized)
    encrypted_envelope: bytes
    # Commitment hash (for commit-reveal)
    commit_hash: Optional[bytes] = None
    # Metadata
    max_block_number: Optional[int] = None
    preferences: Dict[str, Any] = field(default_factory=dict)
    
    def to_params(self) -> List[Any]:
        """Convert to RPC params."""
        params = {
            "envelope": self.encrypted_envelope.hex(),
        }
        if self.commit_hash:
            params["commit"] = self.commit_hash.hex()
        if self.max_block_number:
            params["maxBlockNumber"] = hex(self.max_block_number)
        if self.preferences:
            params["preferences"] = self.preferences
        return [params]


# =============================================================================
# HTTP Transport (Abstract)
# =============================================================================

class HTTPTransport(ABC):
    """Abstract HTTP transport for RPC calls."""
    
    @abstractmethod
    async def post(self, url: str, data: bytes, headers: Dict[str, str]) -> bytes:
        """Send POST request and return response body."""
        pass


class MockHTTPTransport(HTTPTransport):
    """Mock HTTP transport for testing."""
    
    def __init__(self):
        self.requests: List[Dict] = []
        self.responses: List[bytes] = []
        self._response_queue: List[bytes] = []
    
    def queue_response(self, response: bytes) -> None:
        """Queue a response to return."""
        self._response_queue.append(response)
    
    async def post(self, url: str, data: bytes, headers: Dict[str, str]) -> bytes:
        """Record request and return queued response."""
        self.requests.append({
            "url": url,
            "data": data,
            "headers": headers,
        })
        if self._response_queue:
            return self._response_queue.pop(0)
        # Default success response
        return json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": "0x" + "0" * 64,
        }).encode()


# =============================================================================
# SecureRPCClient
# =============================================================================

class SecureRPCClient:
    """
    Secure RPC client with encryption support.
    
    Provides encrypted communication with RPC endpoints for:
    - Private transactions (MEV protection)
    - Private calls
    - Commit-reveal schemes
    """
    
    def __init__(
        self,
        endpoint: str,
        builder_pk_bytes: bytes,
        chain_id: int,
        transport: Optional[HTTPTransport] = None,
        suite_id: int = DEFAULT_SUITE_ID,
        timeout: float = 30.0,
    ):
        """
        Initialize secure RPC client.
        
        Args:
            endpoint: RPC endpoint URL
            builder_pk_bytes: Builder's full public key (~1KB)
            chain_id: EVM chain ID
            transport: HTTP transport (uses default if None)
            suite_id: Cryptographic suite
            timeout: Request timeout in seconds
        """
        self._endpoint = endpoint
        self._chain_id = chain_id
        self._suite_id = suite_id
        self._timeout = timeout
        
        # Create encryptor
        self._encryptor = TxEncryptor(
            builder_pk_bytes=builder_pk_bytes,
            chain_id=chain_id,
            suite_id=suite_id,
        )
        
        # HTTP transport
        self._transport = transport or MockHTTPTransport()
        
        # Request counter
        self._request_id = 0
    
    def _next_id(self) -> int:
        """Get next request ID."""
        self._request_id += 1
        return self._request_id
    
    async def _call(self, method: str, params: List[Any]) -> Any:
        """
        Make RPC call.
        
        Args:
            method: RPC method name
            params: Method parameters
        
        Returns:
            Result from RPC response
        
        Raises:
            ResponseError: If RPC returns error
        """
        request = RPCRequest(
            method=method,
            params=params,
            id=self._next_id(),
        )
        
        headers = {
            "Content-Type": "application/json",
        }
        
        response_bytes = await self._transport.post(
            self._endpoint,
            request.to_json().encode(),
            headers,
        )
        
        response = RPCResponse.from_json(response_bytes.decode())
        
        if response.is_error:
            error = response.error
            raise ResponseError(
                message=error.get("message", "Unknown error"),
                code=error.get("code", -32000),
                data=error.get("data"),
            )
        
        return response.result
    
    # =========================================================================
    # Public API
    # =========================================================================
    
    async def send_private_transaction(
        self,
        raw_tx: bytes,
        max_block_number: Optional[int] = None,
        **preferences,
    ) -> str:
        """
        Send encrypted private transaction.
        
        The transaction is encrypted using the builder's public key,
        providing MEV protection.
        
        Args:
            raw_tx: Signed transaction bytes (RLP encoded)
            max_block_number: Maximum block for inclusion
            **preferences: Additional preferences for the builder
        
        Returns:
            Transaction hash (hex string)
        """
        # Encrypt transaction
        encrypted_tx = self._encryptor.encrypt(raw_tx)
        
        # Build request
        request = PrivateTxRequest(
            encrypted_envelope=encrypted_tx.envelope.to_bytes(),
            max_block_number=max_block_number,
            preferences=preferences,
        )
        
        # Send
        result = await self._call(METHOD_SEND_PRIVATE_TX, request.to_params())
        
        return result
    
    async def send_private_transaction_with_commit(
        self,
        raw_tx: bytes,
        max_block_number: Optional[int] = None,
        **preferences,
    ) -> tuple[str, bytes, bytes]:
        """
        Send private transaction with commit-reveal scheme.
        
        This provides stronger MEV protection by separating
        commit and reveal phases.
        
        Args:
            raw_tx: Signed transaction bytes
            max_block_number: Maximum block for inclusion
            **preferences: Additional preferences
        
        Returns:
            Tuple of (tx_hash, commit_hash, reveal_data)
        """
        # Encrypt with commit
        encrypted_tx = self._encryptor.encrypt(raw_tx)
        
        # Build request
        request = PrivateTxRequest(
            encrypted_envelope=encrypted_tx.envelope.to_bytes(),
            commit_hash=encrypted_tx.commit,
            max_block_number=max_block_number,
            preferences=preferences,
        )
        
        # Send commit phase
        result = await self._call(METHOD_SUBMIT_COMMIT, request.to_params())
        
        # Return commit info for later reveal
        return result, encrypted_tx.commit, encrypted_tx.envelope.to_bytes()
    
    async def reveal_transaction(
        self,
        commit_hash: bytes,
        envelope_bytes: bytes,
    ) -> str:
        """
        Reveal a previously committed transaction.
        
        Args:
            commit_hash: Commit hash from send_private_transaction_with_commit
            envelope_bytes: Encrypted envelope bytes
        
        Returns:
            Transaction hash
        """
        params = [{
            "commit": commit_hash.hex(),
            "envelope": envelope_bytes.hex(),
        }]
        
        return await self._call(METHOD_SUBMIT_REVEAL, params)
    
    async def private_call(
        self,
        to: str,
        data: bytes,
        from_addr: Optional[str] = None,
        block: str = "latest",
    ) -> bytes:
        """
        Make encrypted eth_call.
        
        Args:
            to: Contract address
            data: Call data
            from_addr: From address (optional)
            block: Block number or tag
        
        Returns:
            Call result (decrypted if encrypted response)
        """
        # Build call object
        call_obj = {
            "to": to,
            "data": "0x" + data.hex(),
        }
        if from_addr:
            call_obj["from"] = from_addr
        
        # Encrypt call data
        call_json = json.dumps(call_obj).encode()
        encrypted_tx = self._encryptor.encrypt(call_json)
        
        params = [{
            "envelope": encrypted_tx.envelope.to_bytes().hex(),
            "block": block,
        }]
        
        result = await self._call(METHOD_PRIVATE_CALL, params)
        
        # Result may be hex string
        if isinstance(result, str) and result.startswith("0x"):
            return bytes.fromhex(result[2:])
        return result
    
    async def get_builder_public_key(self) -> bytes:
        """
        Get builder's public key from endpoint.
        
        Returns:
            Builder's public key bytes
        """
        result = await self._call(METHOD_GET_BUILDER_PK, [])
        
        if isinstance(result, str):
            return bytes.fromhex(result.replace("0x", ""))
        return result
    
    # =========================================================================
    # Standard RPC (Passthrough)
    # =========================================================================
    
    async def eth_send_raw_transaction(self, raw_tx: bytes) -> str:
        """
        Send raw transaction (unencrypted, standard).
        
        Use send_private_transaction for MEV protection.
        """
        return await self._call(
            "eth_sendRawTransaction",
            ["0x" + raw_tx.hex()],
        )
    
    async def eth_call(
        self,
        to: str,
        data: bytes,
        from_addr: Optional[str] = None,
        block: str = "latest",
    ) -> bytes:
        """
        Standard eth_call (unencrypted).
        
        Use private_call for encrypted calls.
        """
        call_obj = {
            "to": to,
            "data": "0x" + data.hex(),
        }
        if from_addr:
            call_obj["from"] = from_addr
        
        result = await self._call("eth_call", [call_obj, block])
        
        if isinstance(result, str) and result.startswith("0x"):
            return bytes.fromhex(result[2:])
        return result
    
    async def eth_block_number(self) -> int:
        """Get current block number."""
        result = await self._call("eth_blockNumber", [])
        return int(result, 16)
    
    async def eth_chain_id(self) -> int:
        """Get chain ID."""
        result = await self._call("eth_chainId", [])
        return int(result, 16)


# =============================================================================
# Builder Side (Decryption)
# =============================================================================

class SecureRPCHandler:
    """
    Server-side handler for encrypted RPC requests.
    
    Used by builders/sequencers to decrypt and process
    private transactions.
    """
    
    def __init__(
        self,
        pk_bytes: bytes,
        sk_bytes: bytes,
        chain_id: int,
        suite_id: int = DEFAULT_SUITE_ID,
    ):
        """
        Initialize RPC handler.
        
        Args:
            pk_bytes: Builder's public key
            sk_bytes: Builder's secret key
            chain_id: EVM chain ID
            suite_id: Cryptographic suite
        """
        self._decryptor = TxDecryptor(
            pk_bytes=pk_bytes,
            sk_bytes=sk_bytes,
            chain_id=chain_id,
            suite_id=suite_id,
        )
        self._chain_id = chain_id
    
    def decrypt_transaction(self, envelope_hex: str) -> bytes:
        """
        Decrypt a private transaction.
        
        Args:
            envelope_hex: Hex-encoded encrypted envelope
        
        Returns:
            Decrypted transaction bytes
        """
        envelope_bytes = bytes.fromhex(envelope_hex.replace("0x", ""))
        envelope = SecureEnvelope.from_bytes(envelope_bytes)
        
        return self._decryptor.decrypt(envelope)
    
    def verify_commit(self, commit_hex: str, envelope_hex: str) -> bool:
        """
        Verify commit matches envelope.
        
        Args:
            commit_hex: Hex-encoded commit hash
            envelope_hex: Hex-encoded envelope
        
        Returns:
            True if valid
        """
        from ..mempool import verify_commit
        
        envelope_bytes = bytes.fromhex(envelope_hex.replace("0x", ""))
        envelope = SecureEnvelope.from_bytes(envelope_bytes)
        commit = bytes.fromhex(commit_hex.replace("0x", ""))
        
        return verify_commit(envelope, commit)
    
    def handle_request(self, request: RPCRequest) -> RPCResponse:
        """
        Handle incoming RPC request.
        
        Args:
            request: RPC request
        
        Returns:
            RPC response
        """
        try:
            if request.method == METHOD_SEND_PRIVATE_TX:
                return self._handle_send_private_tx(request)
            elif request.method == METHOD_SUBMIT_COMMIT:
                return self._handle_submit_commit(request)
            elif request.method == METHOD_SUBMIT_REVEAL:
                return self._handle_submit_reveal(request)
            elif request.method == METHOD_GET_BUILDER_PK:
                return self._handle_get_pk(request)
            else:
                return RPCResponse(
                    id=request.id,
                    error={
                        "code": -32601,
                        "message": f"Method not found: {request.method}",
                    },
                )
        except Exception as e:
            return RPCResponse(
                id=request.id,
                error={
                    "code": -32000,
                    "message": str(e),
                },
            )
    
    def _handle_send_private_tx(self, request: RPCRequest) -> RPCResponse:
        """Handle meteor_sendPrivateTransaction."""
        params = request.params[0] if request.params else {}
        envelope_hex = params.get("envelope", "")
        
        raw_tx = self.decrypt_transaction(envelope_hex)
        
        # In real implementation, would submit to mempool
        # For now, return mock tx hash
        tx_hash = "0x" + hashlib.sha256(raw_tx).hexdigest()
        
        return RPCResponse(id=request.id, result=tx_hash)
    
    def _handle_submit_commit(self, request: RPCRequest) -> RPCResponse:
        """Handle meteor_submitCommit."""
        params = request.params[0] if request.params else {}
        commit_hex = params.get("commit", "")
        
        # Store commit (would be stored in real implementation)
        return RPCResponse(id=request.id, result=commit_hex)
    
    def _handle_submit_reveal(self, request: RPCRequest) -> RPCResponse:
        """Handle meteor_submitReveal."""
        params = request.params[0] if request.params else {}
        commit_hex = params.get("commit", "")
        envelope_hex = params.get("envelope", "")
        
        # Verify commit
        if not self.verify_commit(commit_hex, envelope_hex):
            return RPCResponse(
                id=request.id,
                error={
                    "code": -32000,
                    "message": "Commit verification failed",
                },
            )
        
        # Decrypt and process
        raw_tx = self.decrypt_transaction(envelope_hex)
        tx_hash = "0x" + hashlib.sha256(raw_tx).hexdigest()
        
        return RPCResponse(id=request.id, result=tx_hash)
    
    def _handle_get_pk(self, request: RPCRequest) -> RPCResponse:
        """Handle meteor_getBuilderPublicKey."""
        # Would return actual pk_bytes
        return RPCResponse(id=request.id, result="0x" + "00" * 32)


# =============================================================================
# Test
# =============================================================================

def run_tests() -> bool:
    """Test SecureRPCClient."""
    import asyncio
    
    print("=" * 70)
    print("Meteor-NC Block Transport: SecureRPCClient Test")
    print("=" * 70)
    
    results = {}
    
    async def async_tests():
        # Setup: Generate builder keys
        from ...cryptography.core import LWEKEM
        from ..wire import get_suite
        
        suite = get_suite(DEFAULT_SUITE_ID)
        kem = LWEKEM(n=suite.n, seed=b"builder_test_seed_32bytes_here!")
        pk_bytes, sk_bytes = kem.key_gen()
        
        # Test 1: Create client
        print("\n[Test 1] Create SecureRPCClient")
        print("-" * 40)
        
        try:
            transport = MockHTTPTransport()
            client = SecureRPCClient(
                endpoint="https://rpc.example.com",
                builder_pk_bytes=pk_bytes,
                chain_id=1,
                transport=transport,
            )
            results["create"] = True
            print(f"  Endpoint: {client._endpoint}")
            print(f"  Chain ID: {client._chain_id}")
            print("  Result: PASS ✓")
        except Exception as e:
            results["create"] = False
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print("  Result: FAIL ✗")
            return
        
        # Test 2: Send private transaction
        print("\n[Test 2] Send Private Transaction")
        print("-" * 40)
        
        try:
            # Queue mock response
            transport.queue_response(json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "result": "0x" + "ab" * 32,
            }).encode())
            
            raw_tx = b"\x02\xf8\x6c\x01..."  # Mock RLP tx
            tx_hash = await client.send_private_transaction(raw_tx)
            
            results["send_private"] = (
                tx_hash.startswith("0x") and
                len(transport.requests) == 1
            )
            print(f"  TX Hash: {tx_hash[:20]}...")
            print(f"  Request sent: {len(transport.requests) == 1}")
            print(f"  Result: {'PASS ✓' if results['send_private'] else 'FAIL ✗'}")
        except Exception as e:
            results["send_private"] = False
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print("  Result: FAIL ✗")
        
        # Test 3: Handler decrypts
        print("\n[Test 3] Handler Decrypts Transaction")
        print("-" * 40)
        
        try:
            # Create handler
            handler = SecureRPCHandler(
                pk_bytes=pk_bytes,
                sk_bytes=sk_bytes,
                chain_id=1,
            )
            
            # Get the request that was sent
            request_data = json.loads(transport.requests[0]["data"])
            envelope_hex = request_data["params"][0]["envelope"]
            
            # Decrypt
            decrypted = handler.decrypt_transaction(envelope_hex)
            
            results["decrypt"] = decrypted == raw_tx
            print(f"  Original: {raw_tx[:10]}...")
            print(f"  Decrypted: {decrypted[:10]}...")
            print(f"  Match: {decrypted == raw_tx}")
            print(f"  Result: {'PASS ✓' if results['decrypt'] else 'FAIL ✗'}")
        except Exception as e:
            results["decrypt"] = False
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            print("  Result: FAIL ✗")
        
        # Test 4: RPCRequest/Response
        print("\n[Test 4] RPCRequest/Response")
        print("-" * 40)
        
        try:
            req = RPCRequest(
                method="eth_call",
                params=[{"to": "0x1234"}, "latest"],
                id=42,
            )
            req_json = req.to_json()
            req_dict = json.loads(req_json)
            
            resp = RPCResponse(id=42, result="0xabcd")
            
            results["rpc_types"] = (
                req_dict["method"] == "eth_call" and
                req_dict["id"] == 42 and
                not resp.is_error and
                resp.result == "0xabcd"
            )
            print(f"  Request method: {req_dict['method']}")
            print(f"  Response result: {resp.result}")
            print(f"  Result: {'PASS ✓' if results['rpc_types'] else 'FAIL ✗'}")
        except Exception as e:
            results["rpc_types"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
        
        # Test 5: Error handling
        print("\n[Test 5] Error Handling")
        print("-" * 40)
        
        try:
            # Queue error response
            transport.queue_response(json.dumps({
                "jsonrpc": "2.0",
                "id": 2,
                "error": {
                    "code": -32000,
                    "message": "Test error",
                },
            }).encode())
            
            try:
                await client.eth_block_number()
                error_caught = False
            except ResponseError as e:
                error_caught = e.code == -32000
            
            results["error"] = error_caught
            print(f"  Error caught: {error_caught}")
            print(f"  Result: {'PASS ✓' if results['error'] else 'FAIL ✗'}")
        except Exception as e:
            results["error"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
        
        # Test 6: Standard RPC passthrough
        print("\n[Test 6] Standard RPC Passthrough")
        print("-" * 40)
        
        try:
            transport.queue_response(json.dumps({
                "jsonrpc": "2.0",
                "id": 3,
                "result": "0x100",  # Block 256
            }).encode())
            
            block = await client.eth_block_number()
            
            results["passthrough"] = block == 256
            print(f"  Block number: {block}")
            print(f"  Result: {'PASS ✓' if results['passthrough'] else 'FAIL ✗'}")
        except Exception as e:
            results["passthrough"] = False
            print(f"  Error: {e}")
            print("  Result: FAIL ✗")
        
        # Test 7: Handler request processing
        print("\n[Test 7] Handler Request Processing")
        print("-" * 40)
        
        try:
            # Create a fresh encrypted tx
            from ..mempool import TxEncryptor
            encryptor = TxEncryptor(
                builder_pk_bytes=pk_bytes,
                chain_id=1,
            )
            test_tx = b"test_transaction_data"
            encrypted_tx = encryptor.encrypt(test_tx)
            
            # Create request
            req = RPCRequest(
                method=METHOD_SEND_PRIVATE_TX,
                params=[{"envelope": encrypted_tx.envelope.to_bytes().hex()}],
                id=100,
            )
            
            # Handle
            resp = handler.handle_request(req)
            
            results["handler"] = (
                not resp.is_error and
                resp.result.startswith("0x")
            )
            print(f"  Response error: {resp.is_error}")
            print(f"  TX hash: {resp.result[:20]}...")
            print(f"  Result: {'PASS ✓' if results['handler'] else 'FAIL ✗'}")
        except Exception as e:
            results["handler"] = False
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
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
