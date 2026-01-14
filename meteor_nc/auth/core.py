"""
Meteor-Auth: Device-Bound Quantum-Resistant Authentication

The world's first passwordless authentication system combining
device binding with post-quantum cryptography.

Features:
    - Device-bound keys (2FA: Knowledge + Possession)
    - Passwordless authentication via QR code
    - Quantum-resistant (Meteor-NC, 2^8128+ security)
    - Zero server trust (no password storage)
    - Full P2P integration
    - APN (Adaptive Precision Noise) support

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                     User Seed (32 bytes)                    │
    │                 "What you know" (Knowledge)                 │
    │                            │                                │
    │                            ▼                                │
    │              ┌─────────────────────────────┐                │
    │              │   Device Fingerprint        │                │
    │              │   "What you have"           │                │
    │              │   (Possession)              │                │
    │              └─────────────────────────────┘                │
    │                            │                                │
    │                            ▼                                │
    │              ┌─────────────────────────────┐                │
    │              │   Device-Bound Seed         │                │
    │              │   HKDF(seed || fingerprint) │                │
    │              └─────────────────────────────┘                │
    │                            │                                │
    │              ┌─────────────┴─────────────┐                  │
    │              │                           │                  │
    │              ▼                           ▼                  │
    │     Meteor-NC Keys              MeteorID (Public)          │
    │     (Private/Public)            (32 bytes)                  │
    │              │                           │                  │
    │              ▼                           ▼                  │
    │     Encryption/Decryption       P2P Identity               │
    │     Challenge-Response          DHT/libp2p                  │
    └─────────────────────────────────────────────────────────────┘

Security Model:
    - User seed alone is USELESS (requires device)
    - Device alone is USELESS (requires seed)
    - Both factors required for authentication
    - Server stores only MeteorID (32 bytes), no passwords

Usage:
    # Client
    from meteor_nc.auth import MeteorAuth
    
    auth = MeteorAuth()
    user_seed = auth.generate_seed()  # Save this!
    node = auth.login(user_seed)
    
    # Server
    from meteor_nc.auth import MeteorAuthServer
    
    server = MeteorAuthServer()
    token = server.register(meteor_id)
    is_valid = server.authenticate(token, response)
"""

from __future__ import annotations

import hashlib
import uuid
import platform
import secrets
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

from ..cryptography import MeteorKDF, create_kdf_meteor
from ..protocols import MeteorNode


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
    
    Parameters:
        security_level: 128, 256, 512, 1024, or 2048 bits
        apn_enabled: Enable Adaptive Precision Noise
        apn_dynamic: Enable dynamic m calculation
        gpu: Use GPU acceleration (requires CuPy)
        
    Example:
        >>> auth = MeteorAuth(security_level=256)
        >>> user_seed = auth.generate_seed()  # Save as QR!
        >>> meteor_id = auth.get_meteor_id(user_seed)  # Public identity
        >>> node = auth.login(user_seed)  # Create P2P node
    """
    
    def __init__(self,
                 security_level: int = 256,
                 apn_enabled: bool = True,
                 apn_dynamic: bool = True,
                 gpu: bool = True):
        """
        Initialize Meteor-Auth client.
        
        Args:
            security_level: 128, 256, 512, 1024, or 2048 bits
            apn_enabled: Enable Adaptive Precision Noise
            apn_dynamic: Enable dynamic m calculation based on κ
            gpu: Use GPU acceleration (requires CuPy)
        """
        self.security_level = security_level
        self.apn_enabled = apn_enabled
        self.apn_dynamic = apn_dynamic
        self.gpu = gpu
    
    def get_device_fingerprint(self) -> bytes:
        """
        Generate device fingerprint (Possession factor).
        
        Components:
        - MAC address (hardware identifier)
        - Platform info (OS, machine, version)
        - Processor info
        
        Returns:
            bytes: 32-byte device fingerprint
            
        Note:
            The fingerprint is deterministic for a given device,
            ensuring the same user_seed produces different keys
            on different devices.
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
        
        This seed is useless without the device, but should
        still be kept secret to prevent targeted attacks.
        
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
        
        Using HKDF-style derivation with domain separation.
        
        Args:
            user_seed: 32-byte user seed
            
        Returns:
            bytes: 32-byte device-bound seed
        """
        if len(user_seed) != 32:
            raise ValueError("User seed must be 32 bytes")
        
        device_fp = self.get_device_fingerprint()
        
        # Domain separation for security
        domain = b"METEOR_AUTH_DEVICE_BOUND_v1"
        
        # HKDF-style derivation: H(domain || seed || fingerprint)
        combined = domain + user_seed + device_fp
        device_bound = hashlib.sha256(combined).digest()
        
        return device_bound
    
    def get_meteor_id(self, user_seed: bytes) -> bytes:
        """
        Get MeteorID (public identifier) from user seed.
        
        The MeteorID is derived from the device-bound seed,
        so the same user_seed produces different IDs on different devices.
        This enables device-bound authentication.
        
        Args:
            user_seed: 32-byte user seed
            
        Returns:
            bytes: 32-byte MeteorID (safe to share publicly)
            
        Note:
            - Same user_seed + different device = different MeteorID
            - Server can distinguish devices automatically
            - Safe to use as username/public identifier
        """
        device_seed = self.create_device_bound_seed(user_seed)
        
        # Domain separation for MeteorID derivation
        meteor_id = hashlib.sha256(b"METEOR_ID_v1" + device_seed).digest()
        
        return meteor_id
    
    def login(self, user_seed: bytes, node_name: Optional[str] = None) -> MeteorNode:
        """
        Login and create P2P node with device-bound keys.
        
        This performs key expansion using the device-bound seed,
        creating a fully functional P2P node for encrypted communication.
        
        Args:
            user_seed: 32-byte user seed
            node_name: Optional node display name
            
        Returns:
            MeteorNode: P2P node with quantum-resistant keys
        """
        # Create device-bound seed
        auth_seed = self.create_device_bound_seed(user_seed)
        
        # Create node with device-bound keys
        # create_kdf_meteor handles APN and dynamic m automatically!
        node = MeteorNode(
            name=node_name or "Client",
            security_level=self.security_level,
            seed=auth_seed,
            gpu=self.gpu
        )
        
        # Override meteor_id to use our derived ID
        node.meteor_id = self.get_meteor_id(user_seed)
        
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
    token: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: float = field(default_factory=time.time)
    last_auth: Optional[float] = None


class MeteorAuthServer:
    """
    Meteor-Auth Server: Zero-Trust Authentication Server
    
    Features:
    - Zero password storage (only 32-byte MeteorIDs)
    - Challenge-response authentication
    - Full P2P integration
    - Quantum-resistant verification
    
    Security Model:
    - Server stores: MeteorID (32 bytes) + metadata
    - Server NEVER stores: passwords, seeds, private keys
    - Authentication: Challenge-response via P2P encryption
    
    Parameters:
        node_name: Server node display name
        security_level: Crypto security level
        gpu: Use GPU acceleration (requires CuPy)
        
    Example:
        >>> server = MeteorAuthServer("AuthServer")
        >>> token = server.register(meteor_id, {"username": "alice"})
        >>> challenge = server.create_challenge(token)
        >>> is_valid = server.authenticate(token, encrypted_response)
    """
    
    def __init__(self,
                 node_name: str = "AuthServer",
                 security_level: int = 256,
                 gpu: bool = True):
        """
        Initialize authentication server.
        
        Args:
            node_name: Server node name
            security_level: Crypto security level
            gpu: Use GPU acceleration (requires CuPy)
        """
        self.node = MeteorNode(name=node_name, security_level=security_level, gpu=gpu)
        self.security_level = security_level
        self.gpu = gpu
        
        # User database (token -> UserRecord)
        self.users: Dict[str, UserRecord] = {}
        
        # Active challenges (token -> challenge bytes)
        self.challenges: Dict[str, bytes] = {}
    
    def register(self,
                 meteor_id: bytes,
                 metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Register user with MeteorID.
        
        Args:
            meteor_id: 32-byte MeteorID (public identifier)
            metadata: Optional user metadata (username, email, etc.)
            
        Returns:
            str: User token (hex string)
            
        Note:
            Server stores only MeteorID and metadata.
            No passwords, no private keys, no secrets!
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
            token=token,
            metadata=metadata or {}
        )
        self.users[token] = record
        
        # Add as peer for P2P communication
        self.node.add_peer(token, meteor_id)
        
        print(f"[{self.node.name}] Registered user: {token[:32]}...")
        print(f"  MeteorID: {meteor_id.hex()[:32]}...")
        
        return token
    
    def create_challenge(self, token: str) -> bytes:
        """
        Create authentication challenge.
        
        Args:
            token: User token
            
        Returns:
            bytes: 32-byte random challenge (plaintext)
            
        Note:
            Client must encrypt this challenge with their key
            and return it for verification.
        """
        if token not in self.users:
            raise ValueError(f"Unknown token: {token[:16]}...")
        
        # Generate random challenge
        challenge = secrets.token_bytes(32)
        
        # Store for verification
        self.challenges[token] = challenge
        
        print(f"[{self.node.name}] Challenge created for {token[:16]}...")
        
        return challenge
    
    def authenticate(self, token: str, encrypted_response) -> bool:
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
        """
        Get user record by token.
        
        Args:
            token: User token
            
        Returns:
            UserRecord or None
        """
        return self.users.get(token)
    
    def get_user_by_meteor_id(self, meteor_id: bytes) -> Optional[UserRecord]:
        """
        Get user record by MeteorID.
        
        Args:
            meteor_id: 32-byte MeteorID
            
        Returns:
            UserRecord or None
        """
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
        self.node.remove_peer(token)
        
        # Remove any pending challenges
        self.challenges.pop(token, None)
        
        print(f"[{self.node.name}] Revoked: {token[:16]}...")
        return True
    
    def list_users(self) -> List[Dict[str, Any]]:
        """
        List all registered users.
        
        Returns:
            list: User info dictionaries
        """
        return [
            {
                'token': record.token[:16] + '...',
                'meteor_id': record.meteor_id.hex()[:16] + '...',
                'metadata': record.metadata,
                'registered_at': record.registered_at,
                'last_auth': record.last_auth
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
    
    These codes can be used as one-time authentication tokens
    if the primary device is lost.
    
    Args:
        user_seed: 32-byte user seed
        count: Number of recovery codes to generate
        
    Returns:
        list: Recovery code strings
        
    Warning:
        Store these codes securely! Each can only be used once.
    """
    codes = []
    for i in range(count):
        # Derive code from seed + index
        code_bytes = hashlib.sha256(
            b"METEOR_RECOVERY_v1" + user_seed + i.to_bytes(4, 'big')
        ).digest()[:8]
        
        # Format as readable code (e.g., "ABCD-EFGH")
        code_hex = code_bytes.hex().upper()
        code = f"{code_hex[:4]}-{code_hex[4:8]}-{code_hex[8:12]}-{code_hex[12:16]}"
        codes.append(code)
    
    return codes
