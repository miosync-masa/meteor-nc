# meteor_nc/auth/core.py
"""
Meteor-Auth: Device-Bound Quantum-Resistant Authentication

The world's first passwordless authentication system combining
device binding with post-quantum cryptography.

Features:
    - Device-bound keys (2FA: Knowledge + Possession)
    - Passwordless authentication via QR code
    - Quantum-resistant (Meteor-NC LWE-KEM)
    - Zero server trust (no password storage)
    - Full P2P integration

Updated for Meteor-NC v2.0 API
"""

from __future__ import annotations

import hashlib
import uuid
import platform
import secrets
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

from ..cryptography.common import _sha256, GPU_AVAILABLE
from ..protocols.meteor_protocol import MeteorNode, MeteorMessage


# =============================================================================
# Client Authentication
# =============================================================================

class MeteorAuth:
    """
    Meteor-Auth Client: Device-Bound Quantum-Resistant Authentication
    
    Provides passwordless authentication using:
    - User seed (Knowledge factor): 32-byte secret, stored as QR code
    - Device fingerprint (Possession factor): Hardware-bound identifier
    
    The combination creates a device-bound seed that generates
    quantum-resistant keys for authentication.
    
    Example:
        >>> auth = MeteorAuth()
        >>> user_seed = auth.generate_seed()  # Save as QR!
        >>> meteor_id = auth.get_meteor_id(user_seed)  # Public identity
        >>> node = auth.login(user_seed)  # Create P2P node
    """
    
    def __init__(self, gpu: bool = True, device_id: int = 0):
        """
        Initialize Meteor-Auth client.
        
        Args:
            gpu: Use GPU acceleration
            device_id: GPU device ID
        """
        self.gpu = gpu and GPU_AVAILABLE
        self.device_id = device_id
    
    def get_device_fingerprint(self) -> bytes:
        """
        Generate device fingerprint (Possession factor).
        
        Components:
        - MAC address (hardware identifier)
        - Platform info (OS, machine, version)
        - Processor info
        
        Returns:
            bytes: 32-byte device fingerprint
        """
        # MAC address (hardware bound)
        mac = uuid.getnode()
        
        # Platform info
        system = platform.system()
        machine = platform.machine()
        version = platform.version()
        processor = platform.processor()
        
        # Combine all components
        device_info = f"{mac}|{system}|{machine}|{version}|{processor}"
        
        # Hash to 32 bytes (deterministic)
        fingerprint = hashlib.sha256(device_info.encode('utf-8')).digest()
        
        return fingerprint
    
    def generate_seed(self) -> bytes:
        """
        Generate user seed (Knowledge factor).
        
        ⚠️ SAVE THIS SECURELY!
        - Print as QR code
        - Store in password manager
        - Write on paper (secure location)
        
        Returns:
            bytes: 32-byte cryptographically secure random seed
        """
        return secrets.token_bytes(32)
    
    def create_device_bound_seed(self, user_seed: bytes) -> bytes:
        """
        Create device-bound seed from user seed and device fingerprint.
        
        This combines:
        - User seed (Knowledge: what you know)
        - Device fingerprint (Possession: what you have)
        
        Args:
            user_seed: 32-byte user seed
            
        Returns:
            bytes: 32-byte device-bound seed
        """
        if len(user_seed) != 32:
            raise ValueError("User seed must be 32 bytes")
        
        device_fp = self.get_device_fingerprint()
        
        # Domain separation for security
        return _sha256(b"METEOR_AUTH_DEVICE_BOUND_v2", user_seed + device_fp)
    
    def get_meteor_id(self, user_seed: bytes) -> bytes:
        """
        Get MeteorID (public identifier) from user seed.
        
        The MeteorID is derived from the device-bound seed,
        so the same user_seed produces different IDs on different devices.
        
        Args:
            user_seed: 32-byte user seed
            
        Returns:
            bytes: 32-byte MeteorID (safe to share publicly)
        """
        device_seed = self.create_device_bound_seed(user_seed)
        return _sha256(b"meteor-id", device_seed)
    
    def login(self, user_seed: bytes, node_name: Optional[str] = None) -> MeteorNode:
        """
        Login and create P2P node with device-bound keys.
        
        Args:
            user_seed: 32-byte user seed
            node_name: Optional node display name
            
        Returns:
            MeteorNode: P2P node with quantum-resistant keys
        """
        # Create device-bound seed
        auth_seed = self.create_device_bound_seed(user_seed)
        
        # Create node with device-bound keys
        node = MeteorNode(
            name=node_name or "AuthClient",
            seed=auth_seed,
            gpu=self.gpu,
            device_id=self.device_id,
        )
        
        return node
    
    def export_qr_data(self, user_seed: bytes) -> str:
        """
        Export seed as QR-compatible string.
        
        Args:
            user_seed: 32-byte user seed
            
        Returns:
            str: Hex-encoded seed for QR code
        """
        return user_seed.hex()
    
    def import_qr_data(self, qr_data: str) -> bytes:
        """
        Import seed from QR code.
        
        Args:
            qr_data: Hex-encoded seed from QR scan
            
        Returns:
            bytes: 32-byte user seed
        """
        seed = bytes.fromhex(qr_data)
        if len(seed) != 32:
            raise ValueError("Invalid QR data: seed must be 32 bytes")
        return seed


# =============================================================================
# Server Authentication
# =============================================================================

@dataclass
class UserRecord:
    """User record stored by server."""
    meteor_id: bytes
    public_key: Any  # LWEPublicKey
    token: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: float = field(default_factory=time.time)
    last_auth: Optional[float] = None


class MeteorAuthServer:
    """
    Meteor-Auth Server: Zero-Trust Authentication Server
    
    Features:
    - Zero password storage (only MeteorIDs + public keys)
    - Challenge-response authentication
    - Full P2P integration
    - Quantum-resistant verification
    
    Example:
        >>> server = MeteorAuthServer("AuthServer")
        >>> token = server.register(meteor_id, public_key, {"username": "alice"})
        >>> challenge = server.create_challenge(token)
        >>> is_valid = server.authenticate(token, encrypted_response)
    """
    
    def __init__(
        self,
        node_name: str = "AuthServer",
        gpu: bool = True,
        device_id: int = 0,
    ):
        """
        Initialize authentication server.
        
        Args:
            node_name: Server node name
            gpu: Use GPU acceleration
            device_id: GPU device ID
        """
        self.node = MeteorNode(
            name=node_name,
            gpu=gpu,
            device_id=device_id,
        )
        self.gpu = gpu
        self.device_id = device_id
        
        # User database (token -> UserRecord)
        self.users: Dict[str, UserRecord] = {}
        
        # Active challenges (token -> challenge bytes)
        self.challenges: Dict[str, bytes] = {}
    
    def get_server_id(self) -> bytes:
        """Get server's MeteorID."""
        return self.node.get_meteor_id()
    
    def get_server_public_key(self):
        """Get server's public key for client registration."""
        return self.node.get_public_key()
    
    def register(
        self,
        meteor_id: bytes,
        public_key: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Register user with MeteorID and public key.
        
        Args:
            meteor_id: 32-byte MeteorID (public identifier)
            public_key: User's LWEPublicKey
            metadata: Optional user metadata (username, email, etc.)
            
        Returns:
            str: User token (hex string)
        """
        if len(meteor_id) != 32:
            raise ValueError("MeteorID must be 32 bytes")
        
        # Generate unique token
        token = hashlib.sha256(
            meteor_id + secrets.token_bytes(16)
        ).hexdigest()
        
        # Create user record
        record = UserRecord(
            meteor_id=meteor_id,
            public_key=public_key,
            token=token,
            metadata=metadata or {},
        )
        self.users[token] = record
        
        # Add as peer for P2P communication
        self.node.add_peer(token, meteor_id, public_key)
        
        print(f"[{self.node.name}] Registered user: {token[:16]}...")
        print(f"  MeteorID: {meteor_id.hex()[:16]}...")
        
        return token
    
    def create_challenge(self, token: str) -> bytes:
        """
        Create authentication challenge.
        
        Args:
            token: User token
            
        Returns:
            bytes: 32-byte random challenge (plaintext)
        """
        if token not in self.users:
            raise ValueError(f"Unknown token: {token[:16]}...")
        
        # Generate random challenge
        challenge = secrets.token_bytes(32)
        
        # Store for verification
        self.challenges[token] = challenge
        
        print(f"[{self.node.name}] Challenge created for {token[:16]}...")
        
        return challenge
    
    def authenticate(self, token: str, encrypted_response: MeteorMessage) -> bool:
        """
        Authenticate user via challenge-response.
        
        Flow:
        1. Server creates challenge (plaintext)
        2. Client encrypts challenge with their private key
        3. Server decrypts with peer's public key and verifies
        
        Args:
            token: User token
            encrypted_response: Client's encrypted challenge (MeteorMessage)
            
        Returns:
            bool: True if authentication successful
        """
        if token not in self.users:
            print(f"[Auth Failed] Unknown token")
            return False
        
        if token not in self.challenges:
            print(f"[Auth Failed] No challenge for token")
            return False
        
        try:
            # Decrypt response using P2P
            decrypted = self.node.receive(encrypted_response)
            
            # Verify it matches the challenge
            expected = self.challenges[token]
            
            if decrypted == expected:
                print(f"[{self.node.name}] ✅ Authentication SUCCESS for {token[:16]}...")
                
                # Update last auth time
                self.users[token].last_auth = time.time()
                
                # Clean up challenge
                del self.challenges[token]
                return True
            else:
                print(f"[Auth Failed] Challenge mismatch")
                return False
                
        except Exception as e:
            print(f"[Auth Failed] Decryption error: {e}")
            return False
    
    def get_user(self, token: str) -> Optional[UserRecord]:
        """Get user record by token."""
        return self.users.get(token)
    
    def get_user_by_meteor_id(self, meteor_id: bytes) -> Optional[UserRecord]:
        """Get user record by MeteorID."""
        for record in self.users.values():
            if record.meteor_id == meteor_id:
                return record
        return None
    
    def revoke(self, token: str) -> bool:
        """
        Revoke user token.
        
        Args:
            token: User token to revoke
            
        Returns:
            bool: True if revoked successfully
        """
        if token not in self.users:
            return False
        
        # Remove user
        del self.users[token]
        
        # Remove from peers
        if token in self.node.peers:
            del self.node.peers[token]
        
        # Remove any pending challenges
        self.challenges.pop(token, None)
        
        print(f"[{self.node.name}] Revoked: {token[:16]}...")
        return True
    
    def list_users(self) -> List[Dict[str, Any]]:
        """List all registered users."""
        return [
            {
                'token': record.token[:16] + '...',
                'meteor_id': record.meteor_id.hex()[:16] + '...',
                'metadata': record.metadata,
                'registered_at': record.registered_at,
                'last_auth': record.last_auth,
            }
            for record in self.users.values()
        ]


# =============================================================================
# Utility Functions
# =============================================================================

def verify_device_binding(user_seed: bytes, expected_meteor_id: bytes) -> bool:
    """
    Verify that user_seed produces expected MeteorID on this device.
    
    Args:
        user_seed: 32-byte user seed
        expected_meteor_id: Expected 32-byte MeteorID
        
    Returns:
        bool: True if this device + seed produces the expected ID
    """
    auth = MeteorAuth()
    actual_id = auth.get_meteor_id(user_seed)
    return actual_id == expected_meteor_id


def generate_recovery_codes(user_seed: bytes, count: int = 8) -> List[str]:
    """
    Generate recovery codes for backup authentication.
    
    Args:
        user_seed: 32-byte user seed
        count: Number of recovery codes to generate
        
    Returns:
        list: Recovery code strings
    """
    codes = []
    for i in range(count):
        # Derive code from seed + index
        code_bytes = _sha256(
            b"METEOR_RECOVERY_v2",
            user_seed + i.to_bytes(4, 'big'),
        )[:8]
        
        # Format as readable code (e.g., "ABCD-EFGH-IJKL-MNOP")
        code_hex = code_bytes.hex().upper()
        code = f"{code_hex[:4]}-{code_hex[4:8]}-{code_hex[8:12]}-{code_hex[12:16]}"
        codes.append(code)
    
    return codes


# =============================================================================
# Test Suite
# =============================================================================

def run_tests() -> bool:
    """Execute MeteorAuth tests."""
    print("=" * 70)
    print("Meteor-Auth Test Suite")
    print("=" * 70)
    
    results = {}
    
    # Test 1: Seed generation
    print("\n[Test 1] Seed Generation")
    print("-" * 40)
    
    auth = MeteorAuth(gpu=GPU_AVAILABLE)
    seed1 = auth.generate_seed()
    seed2 = auth.generate_seed()
    
    seed_ok = len(seed1) == 32 and len(seed2) == 32 and seed1 != seed2
    results["seed_generation"] = seed_ok
    print(f"  Seed 1: {seed1.hex()[:32]}...")
    print(f"  Seed 2: {seed2.hex()[:32]}...")
    print(f"  Result: {'PASS' if seed_ok else 'FAIL'}")
    
    # Test 2: Device fingerprint
    print("\n[Test 2] Device Fingerprint")
    print("-" * 40)
    
    fp1 = auth.get_device_fingerprint()
    fp2 = auth.get_device_fingerprint()
    
    fp_ok = len(fp1) == 32 and fp1 == fp2  # Same device = same fingerprint
    results["device_fingerprint"] = fp_ok
    print(f"  Fingerprint: {fp1.hex()[:32]}...")
    print(f"  Deterministic: {fp1 == fp2}")
    print(f"  Result: {'PASS' if fp_ok else 'FAIL'}")
    
    # Test 3: Device-bound seed
    print("\n[Test 3] Device-Bound Seed")
    print("-" * 40)
    
    user_seed = auth.generate_seed()
    bound1 = auth.create_device_bound_seed(user_seed)
    bound2 = auth.create_device_bound_seed(user_seed)
    
    bound_ok = len(bound1) == 32 and bound1 == bound2  # Same seed + device = same bound
    results["device_bound_seed"] = bound_ok
    print(f"  User seed: {user_seed.hex()[:32]}...")
    print(f"  Bound seed: {bound1.hex()[:32]}...")
    print(f"  Result: {'PASS' if bound_ok else 'FAIL'}")
    
    # Test 4: MeteorID derivation
    print("\n[Test 4] MeteorID Derivation")
    print("-" * 40)
    
    meteor_id1 = auth.get_meteor_id(user_seed)
    meteor_id2 = auth.get_meteor_id(user_seed)
    
    id_ok = len(meteor_id1) == 32 and meteor_id1 == meteor_id2
    results["meteor_id"] = id_ok
    print(f"  MeteorID: {meteor_id1.hex()[:32]}...")
    print(f"  Deterministic: {meteor_id1 == meteor_id2}")
    print(f"  Result: {'PASS' if id_ok else 'FAIL'}")
    
    # Test 5: Login
    print("\n[Test 5] Login")
    print("-" * 40)
    
    node = auth.login(user_seed, "TestClient")
    
    login_ok = node is not None and node.get_meteor_id() is not None
    results["login"] = login_ok
    print(f"  Node name: {node.name}")
    print(f"  Node ID: {node.get_meteor_id().hex()[:32]}...")
    print(f"  Result: {'PASS' if login_ok else 'FAIL'}")
    
    # Test 6: QR export/import
    print("\n[Test 6] QR Export/Import")
    print("-" * 40)
    
    qr_data = auth.export_qr_data(user_seed)
    imported = auth.import_qr_data(qr_data)
    
    qr_ok = imported == user_seed
    results["qr_roundtrip"] = qr_ok
    print(f"  QR data: {qr_data[:32]}...")
    print(f"  Roundtrip: {qr_ok}")
    print(f"  Result: {'PASS' if qr_ok else 'FAIL'}")
    
    # Test 7: Recovery codes
    print("\n[Test 7] Recovery Codes")
    print("-" * 40)
    
    codes = generate_recovery_codes(user_seed)
    
    codes_ok = len(codes) == 8 and all(len(c) == 19 for c in codes)  # "XXXX-XXXX-XXXX-XXXX"
    results["recovery_codes"] = codes_ok
    print(f"  Codes generated: {len(codes)}")
    for i, code in enumerate(codes[:3]):
        print(f"    {i+1}. {code}")
    print(f"    ...")
    print(f"  Result: {'PASS' if codes_ok else 'FAIL'}")
    
    # Test 8: Server registration & auth
    print("\n[Test 8] Server Registration & Auth")
    print("-" * 40)
    
    server = MeteorAuthServer("TestServer", gpu=GPU_AVAILABLE)
    client_node = auth.login(user_seed, "Client")
    
    # Register
    token = server.register(
        client_node.get_meteor_id(),
        client_node.get_public_key(),
        {"username": "alice"},
    )
    
    # Setup bidirectional connection
    client_node.add_peer(
        "server",
        server.get_server_id(),
        server.get_server_public_key(),
    )
    
    # Challenge-response
    challenge = server.create_challenge(token)
    response = client_node.send("server", challenge)
    auth_result = server.authenticate(token, response)
    
    server_ok = token is not None and auth_result
    results["server_auth"] = server_ok
    print(f"  Token: {token[:32]}...")
    print(f"  Auth result: {auth_result}")
    print(f"  Result: {'PASS' if server_ok else 'FAIL'}")
    
    # Summary
    print("\n" + "=" * 70)
    all_pass = all(results.values())
    print(f"Result: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    print("=" * 70)
    
    return all_pass


if __name__ == "__main__":
    run_tests()
